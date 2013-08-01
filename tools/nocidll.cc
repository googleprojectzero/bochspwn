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

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <input file> <output file>\n", argv[0]);
    return EXIT_FAILURE;
  }

  FILE *fi = fopen(argv[1], "rb");
  FILE *fo = fopen(argv[2], "wb+");
  if (!fi || !fo) {
    fprintf(stderr, "Unable to open input and/or output file\n");
    return EXIT_FAILURE;
  }

  log_data_st ld;
  std::string protobuf;
  while (LoadNextRecord(fi, &protobuf, &ld)) {
    uint32_t size = protobuf.size();

    bool allowed = true;
    for (int i = 0; i < ld.stack_trace_size(); i++) {
      if (!strcmp(ld.stack_trace(i).module_name().c_str(), "CI.dll")) {
        allowed = false;
        break;
      }
    }

    if (allowed) {
      if (fwrite(&size, sizeof(uint32_t), 1, fo) != 1 ||
          fwrite(protobuf.data(), sizeof(uint8_t), size, fo) != size) {
        fprintf(stderr, "Unable to write protobuf back to output file\n");
        break;
      }
    }
  }

  fclose(fi);
  fclose(fo);

  return EXIT_SUCCESS;
}

