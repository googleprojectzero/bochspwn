/////////////////////////////////////////////////////////////////////////
//
// Authors: Mateusz Jurczyk (mjurczyk@google.com)
//          Gynvael Coldwind (gynvael@google.com)
//
// Copyright 2013-2018 Google LLC
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

#include "common.h"

#define __STDC_FORMAT_MACROS
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <cstdio>
#include <string>
#include <vector>

#include "logging.pb.h"

const char *translate_mem_access(log_data_st::mem_access_type type) {
  switch (type) {
    case log_data_st::MEM_READ: return "READ";
    case log_data_st::MEM_WRITE: return "WRITE";
    case log_data_st::MEM_EXEC: return "EXEC";
    case log_data_st::MEM_RW: return "R/W";
  }

  return "INVALID";
}

bool LoadModuleList(const std::string& module_list_path, std::vector<module_info> *module_list) {
  // Arbitrarily chosen maximum length of a module descriptor.
  const unsigned int kAssumedMaxLength = 128;
  static uint8_t buffer[kAssumedMaxLength];

  module_list->clear();

  FILE *f = fopen(module_list_path.c_str(), "rb");
  if (f == NULL) {
    return false;
  }

  while (!feof(f)) {
    uint32_t size;
    if (fread(&size, sizeof(uint32_t), 1, f) != 1) {
      break;
    }

    if (size > kAssumedMaxLength) {
      fprintf(stderr, "Malformed protocol buffer of length %u encountered.\n", size);
      return false;
    }

    if (fread(buffer, sizeof(uint8_t), size, f) != size) {
      return false;
    }

    std::string protobuf;
    protobuf.assign((const char *)buffer, size);

    module_st module;
    if (!module.ParseFromString(protobuf)) {
      return false;
    }

    module_info mod_info = {module.base_addr(), module.size(), module.name()};
    module_list->push_back(mod_info);
  }

  fclose(f);
  return true;
}

std::string LogDataAsText(const log_data_st& ld, const std::vector<module_info>& modules) {
  char buffer[256];
  std::string ret;

  snprintf(buffer, sizeof(buffer),
           "[pid/tid/ct: %.8x/%.8x/%.8x%.8x] {%16s} %.8x, %.8x: %s of %" PRIx64 " "
           "(%u * %u bytes), pc = %" PRIx64 " [ %40s ]\n",
           ld.process_id(), ld.thread_id(),
           (unsigned)(ld.create_time() >> 32),
           (unsigned)(ld.create_time()),
           ld.image_file_name().c_str(),
           (unsigned)ld.syscall_count(),
           (unsigned)ld.syscall_id(),
           translate_mem_access(ld.access_type()),
           ld.lin(),
           (unsigned)ld.repeated(),
           (unsigned)ld.len(),
           ld.pc(),
           ld.pc_disasm().c_str());
  ret = buffer;

  if (ld.has_previous_mode()) {
    snprintf(buffer, sizeof(buffer), "[previous mode: %d]\n", ld.previous_mode());
    ret += buffer;
  }

  for (int i = 0; i < ld.stack_trace_size(); i++) {
    int module_idx = ld.stack_trace(i).module_idx();
    if (module_idx == -1) {
      snprintf(buffer, sizeof(buffer), " #%i  0x%" PRIx64 " (???"")",
               i, ld.stack_trace(i).relative_pc());
    } else {
      assert((unsigned)module_idx < modules.size());
      snprintf(buffer, sizeof(buffer), " #%i  0x%" PRIx64 " (%s+%.8x)", i,
               (modules[module_idx].base + ld.stack_trace(i).relative_pc()),
               modules[module_idx].name.c_str(),
               (unsigned)ld.stack_trace(i).relative_pc());
    }
    ret += buffer;

    if (ld.stack_trace(i).has_try_level()) {
      uint32_t try_level = ld.stack_trace(i).try_level();
      if (try_level == 0xFFFFFFFE) {
        snprintf(buffer, sizeof(buffer), " <===== SEH disabled");
      } else {
        snprintf(buffer, sizeof(buffer), " <===== SEH enabled (#%u)", try_level);
      }
      ret += buffer;
    }

    ret += "\n";
  }

  return ret;
}

log_data_st *LoadNextRecord(FILE *f, std::string *out_protobuf, log_data_st *ld) {
  // Arbitrarily chosen maximum length of a memory access descriptor.
  // Currently, the size is somewhere between 50 and 150.
  const unsigned int kAssumedMaxLength = 1024;

  static uint8_t buffer[kAssumedMaxLength];
  uint32_t size;

  if (fread(&size, sizeof(uint32_t), 1, f) != 1) {
    return NULL;
  }

  if (size > kAssumedMaxLength) {
    fprintf(stderr, "Malformed protocol buffer of length %u encountered.\n", size);
    return NULL;
  }

  if (fread(buffer, sizeof(uint8_t), size, f) != size) {
    return NULL;
  }

  std::string protobuf;
  protobuf.assign((const char *)buffer, size);

  log_data_st *new_ld;

  if (!ld) {
    new_ld = new log_data_st;
  } else {
    new_ld = ld;
  }

  if (!new_ld->ParseFromString(protobuf)) {
    fprintf(stderr, "ParseFromString failed\n");
    delete new_ld;
    return NULL;
  }

  if (out_protobuf != NULL) {
    *out_protobuf = protobuf;
  }

  return new_ld;
}
