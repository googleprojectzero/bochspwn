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

#include <cstdio>
#include <map>
#include <vector>

#include "logging.pb.h"
#include "symbols.h"

// See instrumentation.h for globals' documentation.
namespace globals {
  bochspwn_config config;
  std::vector<module_info *> modules;
  std::map<client_id, thread_info> thread_states;

  log_data_st last_ld;
  bool last_ld_present;

  bool has_instr_before_execution_handler;
}  // namespace globals

// Given a kernel-mode virtual address, returns an index of the corresponding
// module descriptor in globals::modules, or -1, if it's not found. Assuming
// that every executed address belongs to a valid PE address at any given time,
// not finding an address should be interpreted as a signal to update the current
// module database.
int find_module(bx_address item) {
  unsigned int sz = globals::modules.size();
  for (unsigned int i = 0; i < sz; i++) {
    if (globals::modules[i]->module_base <= item &&
        globals::modules[i]->module_base + globals::modules[i]->module_size > item) {
      return i;
    }
  }

  return -1;
}

// Given a kernel driver name, returns an index of the corresponding module
// descriptor in globals::modules, or -1, if it's not found.
int find_module_by_name(const std::string& module) {
  unsigned int sz = globals::modules.size();
  for (unsigned int i = 0; i < sz; i++) {
    if (!strcmp(globals::modules[i]->module_name, module.c_str())) {
      return i;
    }
  }

  return -1;
}

std::string LogDataAsText(const log_data_st& ld) {
  char buffer[256];
  std::string ret;

  snprintf(buffer, sizeof(buffer),
           "[pid/tid/ct: %.8x/%.8x/%.8x%.8x] {%16s} %.8x, %.8x: %s of %llx "
           "(%u * %u bytes), pc = %llx [ %40s ]\n",
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

    if (module_idx != -1) {
      if (globals::config.symbolize) {
        snprintf(buffer, sizeof(buffer), " #%u  0x%llx (%s)", i,
                 (globals::modules[module_idx]->module_base + ld.stack_trace(i).relative_pc()),
                 symbols::symbolize(globals::modules[module_idx]->module_name,
                                    ld.stack_trace(i).relative_pc()).c_str());
      } else {
        snprintf(buffer, sizeof(buffer), " #%u  0x%llx (%s+%.8x)", i,
                 (globals::modules[module_idx]->module_base + ld.stack_trace(i).relative_pc()),
                 globals::modules[module_idx]->module_name,
                 (unsigned)ld.stack_trace(i).relative_pc());
      }
    } else {
      snprintf(buffer, sizeof(buffer), " #%u  0x%llx (???"")",
               i, (ld.stack_trace(i).relative_pc()));
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

const char *translate_mem_access(log_data_st::mem_access_type type) {
  switch (type) {
    case log_data_st::MEM_READ: return "READ";
    case log_data_st::MEM_WRITE: return "WRITE";
    case log_data_st::MEM_EXEC: return "EXEC";
    case log_data_st::MEM_RW: return "R/W";
  }
  return "INVALID";
}

