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

#ifndef KFETCH_TOOLKIT_SYMBOLS_H_
#define KFETCH_TOOLKIT_SYMBOLS_H_

#include <stdint.h>
#include <map>
#include <string>
#include <windows.h>
#include "DbgHelp.h"

#include "common.h"

namespace symbols {

// ------------------------------------------------------------------
// Structures.
// ------------------------------------------------------------------
struct driver_sym {
  uint64_t pdb_base;
  uint64_t module_base;

  driver_sym(uint64_t pbase, uint64_t mbase) : pdb_base(pbase), module_base(mbase) {}
};

struct symbol_info_package : public SYMBOL_INFO_PACKAGE {
  symbol_info_package() {
    si.SizeOfStruct = sizeof(SYMBOL_INFO);
    si.MaxNameLen = sizeof(name);
  }
};

// ------------------------------------------------------------------
// Public interface.
// ------------------------------------------------------------------
std::string symbolize(std::string module, uint32_t offset);

// ------------------------------------------------------------------
// Helper functions.
// ------------------------------------------------------------------
void initialize();
void destroy();

const std::string strip_ext(const std::string file_name);

bool get_file_params(const char *file_name, uint64_t *base_address, uint32_t *file_size);
bool get_file_size(const char *file_name, uint32_t *file_size);

// ------------------------------------------------------------------
// Globals.
// ------------------------------------------------------------------
extern uint64_t cur_base_address;
extern std::map<std::string, driver_sym *> known_modules;

}  // namespace symbols

#endif  // KFETCH_TOOLKIT_SYMBOLS_H_

