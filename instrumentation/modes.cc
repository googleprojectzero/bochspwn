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

#include "modes.h"

#include "bochs.h"
#include "cpu/cpu.h"

#include "common.h"
#include "invoke.h"

namespace modes {

bool offline_new_syscall(BX_CPU_C *pcpu, client_id *cid) {
  thread_info& thread = globals::thread_states[*cid];

  thread.syscall_count++;
  thread.last_syscall_id = pcpu->gen_reg[BX_16BIT_REG_AX].word.rx;
  return true;
}

bool offline_process_log(void *unused1, void *unused2) {
  FILE *f = globals::config.file_handle;

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

bool online_df_new_syscall(BX_CPU_C *pcpu, client_id *cid) {
  // If there is a pending descriptor of memory access in this thread,
  // flush it now (before the next syscall takes place).
  if (globals::last_ld.thread_id() == cid->thread_id &&
      globals::last_ld.process_id() == cid->process_id &&
      globals::last_ld_present) {
    invoke_mode_handler(BX_MODE_EVENT_PROCESS_LOG, NULL, NULL);
    globals::last_ld_present = false;
  }

  thread_info& thread = globals::thread_states[*cid];
  for (std::map<uint64_t, std::vector<log_data_st *> >::iterator it = thread.memory_accesses.begin();
       it != thread.memory_accesses.end(); it++) {
    if (it->second.size() > 1) {
      handle_mult_fetch(it->first, it->second);
    }
  }

  for (unsigned int i = 0; i < thread.access_structs.size(); i++) {
    delete thread.access_structs[i];
  }
  thread.access_structs.clear();
  thread.memory_accesses.clear();

  thread.syscall_count++;
  thread.last_syscall_id = pcpu->gen_reg[BX_16BIT_REG_AX].word.rx;

  return true;
}

bool online_df_process_log(void *unused1, void *unused2) {
  thread_info& thread = globals::thread_states[client_id(globals::last_ld.process_id(),
                                                         globals::last_ld.thread_id())];

  if (globals::last_ld.access_type() == log_data_st::MEM_READ) {
    log_data_st *new_ld = new log_data_st(globals::last_ld);

    if (thread.access_structs.size() > 4096) {
      for (unsigned int i = 0; i < thread.access_structs.size(); i++) {
        delete thread.access_structs[i];
      }

      thread.access_structs.clear();
      thread.memory_accesses.clear();
    }

    thread.access_structs.push_back(new_ld);
    if (new_ld->repeated() == 1) {
      thread.memory_accesses[new_ld->lin()].push_back(new_ld);
    } else {
      for (uint64_t i = 0; i < new_ld->len() * new_ld->repeated(); i++) {
        thread.memory_accesses[new_ld->lin() + i].push_back(new_ld);
      }
    }
  } else /* log_data_st::MEM_WRITE */ {
    log_data_st *ld = &globals::last_ld;

    if (!thread.access_structs.empty()) {
      log_data_st *prev_ld = thread.access_structs.back();

      if (prev_ld->lin() == ld->lin() &&
          prev_ld->pc() >= ld->pc() - 8 && prev_ld->pc() < ld->pc() &&
          prev_ld->repeated() == ld->repeated() && prev_ld->repeated() == 1 &&
          prev_ld->len() == ld->len() &&
          prev_ld->access_type() == log_data_st::MEM_READ) {
        // This read-write sequence is an indication of inlined
        // ProbeForWrite(), so cut it out.
        thread.memory_accesses[ld->lin()].pop_back();

        delete prev_ld;
        thread.access_structs.pop_back();
      }
    }
  }

  return true;
}

void handle_mult_fetch(uint64_t address, const std::vector<log_data_st *>& accesses) {
  // Some memory locations are referenced tens or hundreds of times within
  // a single syscall. In order to optimize CPU consumption, we assume that
  // a maximum of four first stack traces are enough to uniquely
  // characterize a multiple-fetch.
  const unsigned int kMaxMeaningfulAccesses = 4;
  // For the very same reason, we want to limit the number of memory
  // references printed out in the output logs. Otherwise, they become
  // blown away with records of >100 memory references.
  const unsigned int kMaxOutputAccesses = 4;

  // Create a signature of the fetch list.
  std::vector<stack_trace> signature;
  for (unsigned int i = 0; i < accesses.size() && i < kMaxMeaningfulAccesses; i++) {
    stack_trace local_trace;
    log_data_st *cur_access = accesses[i];

    for (int j = 0; j < cur_access->stack_trace_size(); j++) {
      local_trace.trace.push_back(cur_access->stack_trace(j).module_base() +
                                  cur_access->stack_trace(j).relative_pc());
    }
    signature.push_back(local_trace);
  }

  bool new_signature = false;
  for (unsigned int i = 0; i < signature.size(); i++) {
    std::vector<uint64_t>& cur_trace = signature[i].trace;

    for (unsigned int j = 0; j < cur_trace.size(); j++) {
      if (globals::online::known_callstack_item.find(cur_trace[j]) ==
          globals::online::known_callstack_item.end()) {
        new_signature = true;
        globals::online::known_callstack_item.insert(cur_trace[j]);
      }
    }
  }

  // See if the signature has already been observed.
  if (new_signature) {
    FILE *f = globals::config.file_handle;

    // Print out some detailed information regarding the double read.
    fprintf(f, "------------------------------ found double-read of address 0x%.8x%.8x\n",
            (unsigned)(address >> 32), (unsigned)(address));

    for (unsigned int i = 0; i < accesses.size(); ) {
      if (i >= kMaxOutputAccesses) {
        fprintf(f, "[... %lu more reads to follow ...]\n", accesses.size() - i);
        break;
      }

      unsigned int j;
      for (j = 1; i + j < accesses.size(); j++) {
        if (signature[i] != signature[i + j]) break;
      }

      fprintf(f, "Read no. %u", i + 1);
      if (j > 1) {
        fprintf(f, " (X %u):\n", j);
      } else {
        fprintf(f, ":\n");
      }
      fprintf(f, "%s\n", LogDataAsText(*accesses[i]).c_str());

      i += j;
    }
    fflush(f);
  }
}

}  // namespace modes

