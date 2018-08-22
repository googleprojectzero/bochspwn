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

// The STL structure stores information about double fetch candidates
// already found by examining the logs.
//
// unique_mult_fetches.size() is equal to the number of potential
// vulnerabilities found so far. The structure lives throughout the entire
// lifespan of the tool.
std::set<std::vector<StackTrace> > unique_mult_fetches;

// The two STL structures store information about all memory accesses
// encountered during the currently processed syscall (meaning that when
// the next syscall in order is found in the logs, both structures are
// wiped).
//
// For memory_accesses[key] = {acc1, acc2, ...}, "key" is the absolute
// virtual address being referenced, while {acc1, acc2, ...} is a list of
// corresponding memory access descriptors.
//
// If memory_accesses[key].size() > 1 for any "key", it means that the
// "key" address was referenced more than once, and therefore becomes a
// double fetch candidate.
//
// The access_structs list is used for correct memory management: multiple
// keys in memory_accesses can reference the same memory access descriptor,
// so in order to clean up the allocation properly, we need to store a list
// of unique log_data_st structures referenced by memory_accesses.
std::map<uint64_t, std::vector<log_data_st *> > memory_accesses;
std::vector<log_data_st *> access_structs;

// Output files are written on a per-kernel module basis. To avoid
// opening/closing file handles once for every single double fetch, we
// cache them in the log_file_handles structure.
std::map<std::string, FILE*> log_file_handles;

};  // namespace globals

// The routine takes information about a multiple fetch, verifies it
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
void HandleMultipleFetch(const char *output_path, 
                         const std::vector<module_info>& modules,
                         uint64_t address,
                         const std::vector<log_data_st *>& accesses) {
  // Some memory locations are referenced tens or hundreds of times within
  // a single syscall. In order to optimize CPU consumption, we assume that
  // a maximum of four first stack traces are enough to uniquely
  // characterize a multiple-fetch.
  const unsigned int kMaxMeaningfulAccesses = 4;
  // For the very same reason, we want to limit the number of memory
  // references printed out in the output logs. Otherwise, they become
  // blown away with records of >100 memory references.
  const unsigned int kMaxOutputAccesses = 4;

  // Create a signature of the multi-fetch report.
  std::vector<StackTrace> signature;
  for (unsigned int i = 0; i < accesses.size() &&
                           i < kMaxMeaningfulAccesses; i++) {
    StackTrace local_trace;

    for (int j = 0; j < accesses[i]->stack_trace_size(); j++) {
      int module_idx = accesses[i]->stack_trace(j).module_idx();
      if (module_idx == -1) {
        local_trace.trace.push_back(accesses[i]->stack_trace(j).relative_pc());
      } else {
        local_trace.trace.push_back(modules[module_idx].base +
                                    accesses[i]->stack_trace(j).relative_pc());
      }
    }
    signature.push_back(local_trace);
  }

  // See if the signature has already been observed, and if there's any
  // stack trace available for the first read.
  if (globals::unique_mult_fetches.find(signature) == globals::unique_mult_fetches.end() &&
      accesses[0]->stack_trace_size() > 0) {
    int module_idx = accesses[0]->stack_trace(0).module_idx();
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

    // Print out some detailed information regarding the double read.
    fprintf(f, "------------------------------ found double-read of address 0x%.8x%.8x\n",
            (unsigned)(address >> 32), (unsigned)(address));

    for (unsigned int i = 0; i < accesses.size(); ) {
      if (i >= kMaxOutputAccesses) {
        fprintf(f, "[... %u more reads to follow ...]\n", (unsigned)(accesses.size() - i));
        break;
      }

      unsigned int j;
      for (j = 1; i + j < signature.size(); j++) {
        if (signature[i] != signature[i + j]) break;
      }

      fprintf(f, "Read no. %u", i + 1);
      if (j > 1) {
        fprintf(f, " (X %u):\n", j);
      } else {
        fprintf(f, ":\n");
      }
      fprintf(f, "%s\n", LogDataAsText(*accesses[i], modules).c_str());

      i += j;
    }
    fflush(f);

    // Save the multifetch signature to avoid duplicates in the future.
    globals::unique_mult_fetches.insert(signature);
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
  uint32_t cur_syscall_count = (uint32_t)(-1);
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

      if (ld.syscall_count() != cur_syscall_count) {
        // We have a new syscall: go through all memory accesses encountered
        // during the last one and print out information about double fetches.
        for (const auto& it : globals::memory_accesses) {
          if (it.second.size() > 1) {
            HandleMultipleFetch(output_path, modules, it.first, it.second);
          }
        }

        // Free all old structures for the last syscall and cleanup information
        // about accessed addresses.
        for (auto access_struct : globals::access_structs) {
          delete access_struct;
        }

        globals::access_structs.clear();
        globals::memory_accesses.clear();

        // Remember the currently handled syscall count.
        cur_syscall_count = ld.syscall_count();
      }

      // If syscall_count is 0 or the size of the memory access is 1 byte, ignore the entry.
      if (ld.syscall_count() == 0 || ld.len() < 2) {
        continue;
      }

      // Catch OOM exceptions and handle them gracefully.
      try {
        if (ld.access_type() == log_data_st::MEM_READ) {
          // If it's a READ, save information about it.
          log_data_st *new_ld = new log_data_st;
          *new_ld = ld;

          globals::access_structs.push_back(new_ld);

          // For atomic accesses, save only the base access address. For longer ones
          // (e.g. memcpy-like records), mark each single byte of the region as accessed
          // for further analysis.
          if (ld.repeated() == 1) {
            globals::memory_accesses[ld.lin()].push_back(new_ld);
          } else {
            for (uint64_t i = 0; i < ld.len() * ld.repeated(); i++) {
              globals::memory_accesses[ld.lin() + i].push_back(new_ld);
            }
          }
        } else if (ld.access_type() == log_data_st::MEM_WRITE) {
          // If it's a WRITE, check if it's a part of an inlined
          // ProbeForWrite() call.
          if (!globals::access_structs.empty()) {
            log_data_st *last_ld = globals::access_structs.back();

            if (last_ld->lin() == ld.lin() &&
                last_ld->pc() >= ld.pc() - 8 && last_ld->pc() < ld.pc() &&
                last_ld->repeated() == ld.repeated() && last_ld->repeated() == 1 &&
                last_ld->len() == ld.len() &&
                last_ld->access_type() == log_data_st::MEM_READ) {
              // All conditions for a ProbeForWrite() are met, remove the
              // last READ record.
              globals::memory_accesses[ld.lin()].pop_back();

              delete last_ld;
              globals::access_structs.pop_back();
            }
          }
        }
      } catch (std::bad_alloc& ba) {
        // Reset the current syscall count, which will cause the overall state to be reset.
        cur_syscall_count = (uint32_t)(-1);
      }
    }

    fclose(f);

    // Go through the list of memory accesses one last time.
    for (const auto& it : globals::memory_accesses) {
      if (it.second.size() > 1) {
        HandleMultipleFetch(output_path, modules, it.first, it.second);
      }
    }

    // Free all old structures for the last syscall and cleanup information
    // about accessed addresses.
    for (auto access_struct : globals::access_structs) {
      delete access_struct;
    }

    globals::access_structs.clear();
    globals::memory_accesses.clear();
    cur_syscall_count = (uint32_t)(-1);
  }

  for (const auto& it : globals::log_file_handles) {
    fclose(it.second);
  }
  globals::log_file_handles.clear();

  return EXIT_SUCCESS;
}
