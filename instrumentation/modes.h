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

#ifndef KFETCH_TOOLKIT_MODES_H_
#define KFTECH_TOOLKIT_MODES_H_

#include <stdint.h>

#include <vector>

#include "bochs.h"
#include "cpu/cpu.h"

#include "common.h"

namespace modes {

// ------------------------------------------------------------------
// Offline mode interface.
// ------------------------------------------------------------------
bool offline_new_syscall(BX_CPU_C *, client_id *);
bool offline_process_log(void *, void *);

// ------------------------------------------------------------------
// Online double-fetch mode interface and helper routines.
// ------------------------------------------------------------------
bool online_df_new_syscall(BX_CPU_C *, client_id *);
bool online_df_process_log(void *, void *);

void handle_mult_fetch(uint64_t address, const std::vector<log_data_st *>& accesses);

}  // namespace modes

#endif  // KFETCH_TOOLKIT_MODES_H_

