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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <assert.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <cstring>
#include <vector>
#include <map>
#include <set>

#include "common.h"
#include "logging.pb.h"

#ifndef MAX_PATH
# define MAX_PATH 256
#endif

// Structure characterizes a stack trace by storing a list of absolute
// addresses. Used to uniquely identify code paths.
struct StackTrace {
  std::vector<uint64_t> trace;

  bool operator< (const StackTrace& a) const {
    return (trace < a.trace);
  }
  bool operator!= (const StackTrace& a) const {
    return (trace != a.trace);
  }
};

namespace globals {

// The STL structure stores information about unhandled accesses already found
// by examining the logs.
//
// unique_traces.size() is equal to the number of potential
// vulnerabilities found so far. The structure lives throughout the entire
// lifespan of the tool.
std::set<StackTrace> unique_traces;

// Output files are written on a per-kernel module basis. To avoid
// opening/closing file handles once for every single double fetch, we
// cache them in the log_file_handles structure.
std::map<std::string, FILE*> log_file_handles;

};  // namespace globals

// The routine takes information about an unhandled access, verifies it
// against the currently known database of vulnerabilities and prints out
// its details to an adequate log file, if the provided report is unique.
//
// Parameters:
//  * output_path - Contains a path to the output directory, where all
//                  output log files are stored.
//
//  * address - virtual address of the memory being referenced multiple
//              times.
//
//  * accesses - a list of memory access descriptors, of size greater or
//               equal to 2 (otherwise, it wouldn't be a vulnerability).
//
void HandleBadAccess(const char *output_path, 
                     const std::vector<module_info>& modules,
                     const log_data_st& access) {
  // Create a signature of the multi-fetch report.
  StackTrace signature;

  for (int j = 0; j < access.stack_trace_size(); j++) {
    int module_idx = access.stack_trace(j).module_idx();
    if (module_idx == -1) {
      signature.trace.push_back(access.stack_trace(j).relative_pc());
    } else {
      signature.trace.push_back(modules[module_idx].base +
                                access.stack_trace(j).relative_pc());
    }
  }

  // See if the signature has already been observed, and if there's any
  // stack trace available for the first read.
  if (globals::unique_traces.find(signature) == globals::unique_traces.end() &&
      access.stack_trace_size() > 0) {
    int module_idx = access.stack_trace(0).module_idx();
    std::string module_name;

    if (module_idx == -1) {
      module_name = "unknown";
    } else {
      module_name = modules[module_idx].name;
    }

    // If module was encountered for the first time, attempt to open a
    // corresponding output file.
    if (!globals::log_file_handles[module_name]) {
      char full_path[MAX_PATH];
      FILE *f;

      snprintf(full_path, MAX_PATH, "%s/%s", output_path, module_name.c_str());

      f = fopen(full_path, "a+");
      if (!f) {
        fprintf(stderr, "Unable to open output file \"%s\"\n", full_path);
        abort();
      } else {
        globals::log_file_handles[module_name] = f;
      }
    }

    FILE *f = globals::log_file_handles[module_name];
    assert(f != NULL);

    // Print out some detailed information regarding the memory access.
    fprintf(f, "------------------------------ found unhandled-access of address %#llx\n\n", access.lin());
    fprintf(f, "%s\n", LogDataAsText(access, modules).c_str());
    fflush(f);

    // Save the signature to avoid duplicates in the future.
    globals::unique_traces.insert(signature);
  }
}

int main(int argc, const char **argv) {
  if (argc < 4) {
    fprintf(stderr, "Usage: %s /path/to/memory/logs /path/to/modules/list /path/to/output/logs\n", argv[0]);
    return EXIT_SUCCESS;
  }

  const char *logs_path = argv[1];
  const char *modules_list_path = argv[2];
  const char *output_path = argv[3];

  DIR *dirp = opendir(logs_path);
  if (!dirp) {
    fprintf(stderr, "Unable to open the \"%s\" directory\n", logs_path);
    return EXIT_FAILURE;
  }

  // Load the module list.
  std::vector<module_info> modules;
  if (!LoadModuleList(modules_list_path, &modules)) {
    fprintf(stderr, "Unable to load the module list from \"%s\".\n", modules_list_path);
    return EXIT_FAILURE;
  }

  unsigned int file_count = 1;
  uint64_t bytes_processed = 0;

  // List all files in the specified directory.
  struct dirent *dp;
  while ((dp = readdir(dirp)) != NULL) {
    static char buffer[MAX_PATH];

    if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..")) {
      continue;
    }

    snprintf(buffer, MAX_PATH, "%s/%s", logs_path, dp->d_name);

    FILE *f = fopen(buffer, "rb");
    if (!f) {
      fprintf(stderr, "Unable to load file \"%s\"\n", buffer);
      return EXIT_FAILURE;
    }

    fprintf(stderr, "[%.4u] Loaded file \"%s\" (%" PRIu64 " bytes processed)\n",
            file_count++, dp->d_name, bytes_processed);

    // Read records until the file is over, or we're out of memory.
    static log_data_st ld;
    while (LoadNextRecord(f, NULL, &ld)) {
      bytes_processed += ld.ByteSize();

      bool handler_active = false;
      for (int i = 0; i < ld.stack_trace_size(); i++) {
        if (ld.stack_trace(i).has_try_level() && ld.stack_trace(i).try_level() != 0xFFFFFFFE) {
          handler_active = true;
          break;
        }
      }

      if (!handler_active) {
        HandleBadAccess(output_path, modules, ld);
      }
    }

    fclose(f);
  }

  for (const auto& it : globals::log_file_handles) {
    fclose(it.second);
  }
  globals::log_file_handles.clear();

  return EXIT_SUCCESS;
}
