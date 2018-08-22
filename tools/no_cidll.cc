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

#include <assert.h>
#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "common.h"
#include "logging.pb.h"

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <input file> <modules list> <output file>\n", argv[0]);
    return EXIT_FAILURE;
  }

  std::vector<module_info> modules;
  if (!LoadModuleList(argv[2], &modules)) {
    fprintf(stderr, "Unable to load the module list from \"%s\".\n", argv[2]);
    return EXIT_FAILURE;
  }

  int cidll_module_idx = -1;
  for (unsigned int i = 0; i < modules.size(); i++) {
    if (modules[i].name == "CI.dll") {
      cidll_module_idx = i;
    }
  }
  assert(cidll_module_idx != -1);

  FILE *fi = fopen(argv[1], "rb");
  FILE *fo = fopen(argv[3], "wb+");
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
      if (ld.stack_trace(i).module_idx() == cidll_module_idx) {
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
