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

// A container of unique stack traces encountered by the tool so far.
std::set<StackTrace> unique_traces;

}  // namespace globals

int main(int argc, const char **argv) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s /path/to/memory/logs /path/to/modules/list\n", argv[0]);
    return EXIT_SUCCESS;
  }

  const char *logs_path = argv[1];
  const char *modules_list_path = argv[2];

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
  std::map<int, uint64_t> try_levels;

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

    // Read records until the file is over.
    static log_data_st ld;
    while (LoadNextRecord(f, NULL, &ld)) {
      bytes_processed += ld.ByteSize();

      StackTrace signature;

      for (int j = 0; j < ld.stack_trace_size(); j++) {
        int module_idx = ld.stack_trace(j).module_idx();
        if (module_idx == -1) {
          signature.trace.push_back(ld.stack_trace(j).relative_pc());
        } else {
          signature.trace.push_back(modules[module_idx].base +
                                    ld.stack_trace(j).relative_pc());
        }
      }

      if (globals::unique_traces.find(signature) == globals::unique_traces.end()) {
        int first_handler_idx = -1;
        for (int i = 0; i < ld.stack_trace_size(); i++) {
          if (ld.stack_trace(i).has_try_level() && ld.stack_trace(i).try_level() != 0xFFFFFFFE) {
            first_handler_idx = i;
            break;
          }
        }

        try_levels[first_handler_idx]++;

        // Save the signature to avoid duplicates in the future.
        globals::unique_traces.insert(signature);
      }
    }

    fclose(f);
  }

  printf("--------------------------------------- Depths:\n");
  for (std::map<int, uint64_t>::iterator it = try_levels.begin(); it != try_levels.end(); it++) {
    printf("%.2d: %10llu\n", it->first, it->second);
  }

  return EXIT_SUCCESS;
}

