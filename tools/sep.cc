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

#include <stdint.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#include "common.h"
#include "logging.pb.h"

typedef std::map<std::string, FILE*> file_map_t;

void FinishFileMap(file_map_t *m) {
  for (file_map_t::iterator it = m->begin(); it != m->end(); it++) {
    fflush(it->second);
    fclose(it->second);
  }

  m->clear();
}

void AddRecordToFile(file_map_t *m, char *file_path, const std::string& protobuf,
                     bool append = false) {
  FILE *f;

  if (m->find(file_path) == m->end()) {
    f = fopen(file_path, "ab");

    if (!f) {
      if (append) {
        fprintf(stderr, "Unable to create file \"%s\" on second try.\n",
                file_path);
        exit(EXIT_FAILURE);
      }

      fprintf(stderr, "Unable to create file \"%s\" on first try, retrying\n",
              file_path);
      FinishFileMap(m);
      AddRecordToFile(m, file_path, protobuf, true);
      return;
    }

    if (append) {
      fprintf(stderr, "Retry successful.\n");
    }

    (*m)[file_path] = f;
  } else {
    f = (*m)[file_path];
  }

  uint32_t size = protobuf.size();
  if (fwrite(&size, sizeof(uint32_t), 1, f) != 1 ||
      fwrite(protobuf.data(), sizeof(uint8_t), size, f) != size) {
    fprintf(stderr, "Unable to write record to \"%s\"\n", file_path);
  }
}

int main(int argc, char **argv) {
  static char unique_thread_path[256];
  char *log_file_path;
  char *output_dir;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s <log file> <output directory>\n", argv[0]);
    return EXIT_FAILURE;
  }

  log_file_path = argv[1];
  output_dir = argv[2];

  FILE *f = fopen(log_file_path, "rb");
  if (!f) {
    fprintf(stderr, "Unable to open \"%s\"\n", log_file_path);
    return EXIT_FAILURE;
  }

  file_map_t thread_logs;
  log_data_st ld;
  std::string protobuf;
  while (LoadNextRecord(f, &protobuf, &ld)) {
    snprintf(unique_thread_path, sizeof(unique_thread_path),
             "%s/%.8x%.8x-%.8x-%.8x.bin",
             output_dir,
             (uint32_t)(ld.create_time() >> 32),
             (uint32_t)(ld.create_time()),
             ld.process_id(),
             ld.thread_id());

    AddRecordToFile(&thread_logs, unique_thread_path, protobuf);
  }

  FinishFileMap(&thread_logs);
  fclose(f);

  return EXIT_SUCCESS;
}

