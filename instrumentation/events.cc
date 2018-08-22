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

#include "events.h"

#include "bochs.h"
#include "cpu/cpu.h"

#include "common.h"
#include "invoke.h"
#include "logging.pb.h"

namespace events {

bool event_new_syscall(BX_CPU_C *pcpu, client_id *cid) {
  thread_info& thread = globals::thread_states[*cid];

  thread.syscall_count++;
  thread.last_syscall_id = pcpu->gen_reg[BX_16BIT_REG_AX].word.rx;
  return true;
}

bool event_new_module(module_info *mi) {
  // Save the new module in the internal list.
  globals::modules.push_back(mi);

  // Save information about the new module to an output file.
  module_st new_module;

  new_module.set_name(mi->module_name);
  new_module.set_base_addr(mi->module_base);
  new_module.set_size(mi->module_size);

  std::string data;
  uint32_t data_size;

  if (!new_module.SerializeToString(&data)) {
    fprintf(stderr, "Unable to serialize protocol buffer to string.\n");
    abort();
  }
  data_size = data.size();

  FILE *f = globals::config.modules_file;
  if (fwrite(&data_size, sizeof(uint32_t), 1, f) != 1 ||
      fwrite(data.c_str(), 1, data.size(), f) != data.size()) {
    fprintf(stderr, "Unable to write serialized protobuf to file.\n");
    abort();
  }

  return true;
}

bool event_process_log() {
  FILE *f = globals::config.trace_file;

  if (globals::config.write_as_text) {
    fprintf(f, "%s\n", LogDataAsText(globals::last_ld).c_str());
  } else {
    std::string data;
    uint32_t data_size;

    if (!globals::last_ld.SerializeToString(&data)) {
      fprintf(stderr, "Unable to serialize protocol buffer to string.\n");
      abort();
    }
    data_size = data.size();

    if (fwrite(&data_size, sizeof(uint32_t), 1, f) != 1 ||
        fwrite(data.c_str(), 1, data.size(), f) != data.size()) {
      fprintf(stderr, "Unable to write serialized protobuf to file.\n");
      abort();
    }
  }

  return true;
}

}  // namespace events

