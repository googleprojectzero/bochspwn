/////////////////////////////////////////////////////////////////////////
//
// Authors: Mateusz Jurczyk (mjurczyk@google.com)
//          Gynvael Coldwind (gynvael@google.com)
//
// Copyright 2013 Google Inc. All Rights Reserved.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "symbols.h"

#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include "DbgHelp.h"

#include "common.h"

namespace symbols {

uint64_t cur_base_address;
std::map<std::string, driver_sym *> known_modules;

std::string symbolize(const std::string module, uint32_t offset) {
  static char pdb_path[256];
  static char buffer[256];
  std::map<std::string, driver_sym *>::iterator it;
  uint64_t pdb_base;
  uint64_t module_base;
  uint32_t file_size;

  // Check if module is already loaded.
  if (it = known_modules.find(module), it == known_modules.end()) {
    // Construct a full path of the corresponding .pdb file.
    snprintf(pdb_path, sizeof(pdb_path), "%s\\%s.pdb", globals::config.symbol_path,
             strip_ext(module).c_str());

    if (!get_file_params(pdb_path, &module_base, &file_size)) {
      fprintf(stderr, "Unable to find \"%s\" debug file\n", pdb_path);

      known_modules[module] = new driver_sym(0, 0);
      snprintf(buffer, sizeof(buffer), "%s+%x", module.c_str(), offset);
      return std::string(buffer);
    }

    pdb_base = SymLoadModule64(GetCurrentProcess(), NULL, pdb_path, NULL, module_base, file_size);
    if (!pdb_base) {
      fprintf(stderr, "SymLoadModule64 failed, %lu\n", GetLastError());

      known_modules[module] = new driver_sym(0, 0);
      snprintf(buffer, sizeof(buffer), "%s+%x", module.c_str(), offset);
      return std::string(buffer);
    }

    known_modules[module] = new driver_sym(pdb_base, module_base);
  } else if (!it->second->pdb_base) {
    snprintf(buffer, sizeof(buffer), "%s+%x", module.c_str(), offset);
    return std::string(buffer);
  } else {
    module_base = it->second->module_base;
  }

  symbol_info_package sip;
  DWORD64 displacement = 0;

  if (!SymFromAddr(GetCurrentProcess(), module_base + offset, &displacement, &sip.si)) {
    snprintf(buffer, sizeof(buffer), "%s+%x", module.c_str(), offset);
  } else {
    snprintf(buffer, sizeof(buffer), "%s!%s+%.8llx", module.c_str(), sip.si.Name, displacement);
  }

  return std::string(buffer);
}

void initialize() {
  cur_base_address = 0x20000000;

  uint32_t options = SymGetOptions();
  options |= SYMOPT_DEBUG;
  SymSetOptions(options);

  if (!SymInitialize(GetCurrentProcess(), NULL, FALSE)) {
    fprintf(stderr, "SymInitialize() failed, %lu. Consider setting \"symbolize=0\" "
                    "in your configuration file.\n", GetLastError());
    abort();
  }
}

void destroy() {
  for (std::map<std::string, driver_sym *>::iterator it = known_modules.begin();
       it != known_modules.end(); it++) {
    SymUnloadModule64(GetCurrentProcess(), it->second->pdb_base);
    delete it->second;
  }

  known_modules.clear();
}

const std::string strip_ext(const std::string file_name) {
  size_t x = file_name.find_last_of(".");
  if (x == std::string::npos) {
    return file_name;
  }

  return file_name.substr(0, x);
}

bool get_file_params(const char *file_name, uint64_t *base_address, uint32_t *file_size) {
  bool ret;

  if (!file_name) {
    return false;
  }

  ret = get_file_size(file_name, file_size);
  if (ret) {
    *base_address = cur_base_address;
    cur_base_address += *file_size;
  }

  return ret;
}

bool get_file_size(const char *file_name, uint32_t *file_size) {
  if (!file_name) {
    return false;
  }

  HANDLE file = CreateFile(file_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }

  *file_size = GetFileSize(file, NULL);
  CloseHandle(file);

  return (*file_size != INVALID_FILE_SIZE);
}

}  // namespace symbols

