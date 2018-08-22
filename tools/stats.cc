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

#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <stdint.h>

#include "common.h"
#include "logging.pb.h"

namespace globals {

uint64_t total_records;
uint64_t total_reads, total_writes;
uint64_t total_memory_read, total_memory_written;
std::map<std::string, uint64_t> per_exe_reads, per_exe_writes;
std::map<std::string, uint64_t> per_module_reads, per_module_writes;
  
}  // namespace globals

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <input file> <modules list>\n", argv[0]);
    return EXIT_FAILURE;
  }

  std::vector<module_info> modules;
  if (!LoadModuleList(argv[2], &modules)) {
    fprintf(stderr, "Unable to load the module list from \"%s\".\n", argv[2]);
    return EXIT_FAILURE;
  }

  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    fprintf(stderr, "Unable to open input file \"%s\".\n", argv[1]);
    return EXIT_FAILURE;
  }

  log_data_st ld;
  while (LoadNextRecord(f, NULL, &ld)) {
    globals::total_records++;

    if (ld.access_type() == log_data_st::MEM_READ) {
      globals::total_reads++;
      globals::total_memory_read += ld.len() * ld.repeated();
      globals::per_exe_reads[ld.image_file_name()]++;

      std::set<int> seen_modules;
      for (int i = 0; i < ld.stack_trace_size(); i++) {
        int module_idx = ld.stack_trace(i).module_idx();

        if (seen_modules.find(module_idx) != seen_modules.end()) {
          continue;
        }

        seen_modules.insert(module_idx);

        std::string name;
        if (module_idx == -1) {
          name = "unknown";
        } else {
          name = modules[module_idx].name;
        }

        globals::per_module_reads[name]++;
      }
    } else if (ld.access_type() == log_data_st::MEM_WRITE) {
      globals::total_writes++;
      globals::total_memory_written += ld.len() * ld.repeated();
      globals::per_exe_writes[ld.image_file_name()]++;

      std::set<int> seen_modules;
      for (int i = 0; i < ld.stack_trace_size(); i++) {
        int module_idx = ld.stack_trace(i).module_idx();

        if (seen_modules.find(module_idx) != seen_modules.end()) {
          continue;
        }

        seen_modules.insert(module_idx);

        std::string name;
        if (module_idx == -1) {
          name = "unknown";
        } else {
          name = modules[module_idx].name;
        }

        globals::per_module_writes[name]++;
      }
    }
  }

  printf("Total records: %lld\n", globals::total_records);
  printf("  Reads: %lld\n", globals::total_reads);
  printf("  Writes: %lld\n", globals::total_writes);
  
  printf("Total memory read: %lld\n", globals::total_memory_read);
  printf("Total memory written: %lld\n", globals::total_memory_written);

  printf("Per executable memory reads:\n");
  for (const auto& it : globals::per_exe_reads) {
    printf("  %s: %lld\n", it.first.c_str(), it.second);
  }

  printf("Per executable memory writes:\n");
  for (const auto& it : globals::per_exe_writes) {
    printf("  %s: %lld\n", it.first.c_str(), it.second);
  }

  printf("Per module memory reads:\n");
  for (const auto& it : globals::per_module_reads) {
    printf("  %s: %lld\n", it.first.c_str(), it.second);
  }

  printf("Per module memory writes:\n");
  for (const auto& it : globals::per_module_writes) {
    printf("  %s: %lld\n", it.first.c_str(), it.second);
  }

  fclose(f);
  return EXIT_SUCCESS;
}
