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

#ifndef BOCHSPWN_COMMON_H_
#define BOCHSPWN_COMMON_H_

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <vector>

#include "logging.pb.h"

// ------------------------------------------------------------------
// Constants.
// ------------------------------------------------------------------
const char kConfFileEnvVariable[] = "BOCHSPWN_CONF";

// ------------------------------------------------------------------
// Internal enumerations and structures.
// ------------------------------------------------------------------

// Generic settings read from .ini configuration file.
struct bochspwn_config {
  // Path to the trace log output file.
  char *trace_log_path;

  // Path to the modules output file.
  char *modules_list_path;

  // Handle to the trace log output file.
  FILE *trace_file;

  // Handle to the modules output file.
  FILE *modules_file;

  // Guest operating system name. Currently allowed: {"windows", "linux",
  // "freebsd"}
  char *system;

  // Guest operating system version, used as the name for system-specific
  // .ini configuration section.
  char *os_version;

  // Guest operating system bitness. Allowed values: {32, 64}
  uint32_t bitness;

  // Minimum and maximum lengths of single memory reads.
  uint32_t min_read_size, max_read_size;

  // Minimum and maximum lengths of single memory writes.
  uint32_t min_write_size, max_write_size;

  // Maximum number of stack frames stored in a single memory access
  // descriptor.
  uint32_t callstack_length;

  // If non-zero, indicates that output logs should be printed in plain
  // text instead of binary blobs. Useful for debugging.
  uint32_t write_as_text;

  // If non-zero, indicates that stack traces in the logs should be
  // symbolized using provided .pdb files.
  uint32_t symbolize;

  // Specifies path to directory containing .pdb files for the kernel
  // modules of the guest system. Valid only if globals::symbolize is
  // non-zero.
  char *symbol_path;

  // Initialize fields with typical values for safety.
  bochspwn_config() : trace_log_path(strdup("memlog.bin")), modules_list_path(strdup("modules.bin")),
                      trace_file(NULL), modules_file(NULL), system(strdup("windows")),
                      os_version(strdup("win7_32")), bitness(32), min_read_size(1), max_read_size(16),
                      min_write_size(1), max_write_size(16), callstack_length(64), write_as_text(0),
                      symbolize(0), symbol_path(NULL) {}

  ~bochspwn_config() {
    free(trace_log_path);
    free(modules_list_path);
    free(system);
    free(os_version);
    free(symbol_path);

    if (trace_file != NULL) {
      fclose(trace_file);
    }
    if (modules_file != NULL) {
      fclose(modules_file);
    }
  }
};

// Included here to mitigate the header hell.
#include "bochs.h"
#include "cpu/cpu.h"
#include "mem_interface.h"

// Stack-trace descriptor, contains a full list of absolute virtual
// function call addresses.
struct stack_trace {
  std::vector<uint64_t> trace;

  bool operator< (const stack_trace& a) const {
    return (trace < a.trace);
  }
  bool operator != (const stack_trace& a) const {
    return (trace != a.trace);
  }
};

// Unique thread identifier.
struct client_id {
  uint64_t process_id;
  uint64_t thread_id;

  client_id() : process_id(0), thread_id(0) {}
  client_id(uint64_t pid, uint64_t tid) : process_id(pid), thread_id(tid) {}

  // The operator is required by C++ STL structures such as map<> to
  // deterministically and accurately compare structures used as keys.
  // The specified order is not relevant here.
  bool operator< (const client_id& a) const {
    if (process_id == a.process_id) {
      return (thread_id < a.thread_id);
    }
    return (process_id < a.process_id);
  }
};

// Per-thread information describing system call activity: number of
// services invoked by the point in time the structure is saved and the
// last-seen syscall id.
struct thread_info {
  uint32_t syscall_count;
  uint16_t last_syscall_id;

  // Only used by Linux and FreeBSD - this is the return address
  // for a couple of user-memory-to-kernel-memory copying functions.
  uint64_t last_ret_addr;

  thread_info() : syscall_count(0), last_syscall_id(0) {}
};

// Information about a known kernel module currently loaded in the
// operating system.
struct module_info {
  uint64_t module_base;
  uint64_t module_size;
  char *module_name;

  module_info() : module_base(0), module_size(0), module_name(NULL) {}
  module_info(bx_address b, bx_address s, const char *n) :
    module_base(b), module_size(s), module_name(strdup(n)) {}
  ~module_info() { if (module_name) free(module_name); }
};

// ------------------------------------------------------------------
// Global helper functions.
// ------------------------------------------------------------------

// Find kernel module descriptor by address or name.
int find_module(bx_address item);
int find_module_by_name(const std::string& module);

// Print out log record as nicely formatted text.
std::string LogDataAsText(const log_data_st& ld);

// Translate memory access type enum into textual representation.
const char *translate_mem_access(log_data_st::mem_access_type type);

// ------------------------------------------------------------------
// Global helper macros.
// ------------------------------------------------------------------
#define READ_INI_STRING(file, section, name, buf, size) \
  if (!GetPrivateProfileStringA((section), (name), NULL, (buf), (size), (file))) {\
    fprintf(stderr, "Unable to read the %s/%s string from configuration file.\n", \
            (section), (name));\
    return false;\
  }

#define READ_INI_INT(file, section, name, buf, size, dest) \
  READ_INI_STRING((file), (section), (name), (buf), (size))\
  if (!sscanf(buf, "%i", (dest))) {\
    fprintf(stderr, "Unable to parse the %s/%s value as integer.\n", \
            (section), (name));\
    return false;\
  }

#define READ_INI_ULL(file, section, name, buf, size, dest) \
  READ_INI_STRING((file), (section), (name), (buf), (size))\
  if (!sscanf(buf, "%llx", (dest))) {\
    fprintf(stderr, "Unable to parse the %s/%s value as integer.\n", \
            (section), (name));\
    return false;\
  }

// ------------------------------------------------------------------
// Global objects.
// ------------------------------------------------------------------
namespace globals {

// Generic configuration.
extern bochspwn_config config;

// Global information about all currently known kernel modules. Updated
// lazily, only when an unknown driver is encountered.
extern std::vector<module_info *> modules;

// Thread descriptors including syscall stats / pending memory references.
extern std::map<client_id, thread_info> thread_states;

// Last known memory access descriptor.
extern log_data_st last_ld;
extern bool last_ld_present;

// If set to true by a system-module, an additional callback gets invoked
// before an instruction is executed.
extern bool has_instr_before_execution_handler;

}  // namespace globals

#endif  // BOCHSPWN_COMMON_H_

