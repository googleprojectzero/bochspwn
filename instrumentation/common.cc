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

#include "common.h"

#include <vector>
#include <map>

#include "logging.pb.h"
#include "symbols.h"

// See instrumentation.h for globals' documentation.
namespace globals {
  kfetch_config config;
  std::vector<module_info *> special_modules;
  std::vector<module_info *> modules;
  std::map<client_id, thread_info> thread_states;

  log_data_st last_ld;
  bool last_ld_present;

  bool has_instr_before_execution_handler;

namespace online {
  std::set<bx_address> known_callstack_item;
}  // namespace online

}  // namespace globals

// Debugging helper function.
int dbg_print(const char *fmt, ...) {
  va_list args;
  int ret = 0;

  va_start(args, fmt);
  ret = vfprintf(stderr, fmt, args);
  va_end(args);

  return ret;
}

// Given a kernel-mode virtual address, returns the image base of the
// corresponding module or NULL, if one is not found. Assuming that every
// executed address belongs to a valid PE address at any given time, not finding
// an address should be interpreted as a signal to update the current module
// database.
module_info* find_module(bx_address item) {
  unsigned int sz = globals::special_modules.size();

  // Prioritize the special_modules list, as it contains the most commonly
  // encountered images (e.g. ntoskrnl, win32k for Windows).
  for (unsigned int i = 0; i < sz; i++) {
    if (globals::special_modules[i]->module_base <= item &&
        globals::special_modules[i]->module_base + globals::special_modules[i]->module_size > item) {
      return globals::special_modules[i];
    }
  }

  // Search through the remaining known modules.
  sz = globals::modules.size();
  for (unsigned int i = 0; i < sz; i++) {
    if (globals::modules[i]->module_base <= item &&
        globals::modules[i]->module_base + globals::modules[i]->module_size > item) {
      return globals::modules[i];
    }
  }

  return NULL;
}

// Returns the contents of a single log record in formatted, textual form.
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

  for (unsigned int i = 0; i < ld.stack_trace_size(); i++) {
    if (globals::config.symbolize) {
      snprintf(buffer, sizeof(buffer), " #%u  0x%llx (%s)\n", i,
               (ld.stack_trace(i).module_base() + ld.stack_trace(i).relative_pc()),
               symbols::symbolize(ld.stack_trace(i).module_name(),
                                  ld.stack_trace(i).relative_pc()).c_str());
    } else {
      snprintf(buffer, sizeof(buffer), " #%u  0x%llx (%s+%.8x)\n", i,
               (ld.stack_trace(i).module_base() + ld.stack_trace(i).relative_pc()),
               ld.stack_trace(i).module_name().c_str(),
               (unsigned)ld.stack_trace(i).relative_pc());
    }
    ret += buffer;
  }

  return ret;
}

// Translate memory access type enum into textual representation.
const char *translate_mem_access(log_data_st::mem_access_type type) {
  switch (type) {
    case log_data_st::MEM_READ: return "READ";
    case log_data_st::MEM_WRITE: return "WRITE";
    case log_data_st::MEM_EXEC: return "EXEC";
    case log_data_st::MEM_RW: return "R/W";
  }
  return "INVALID";
}

