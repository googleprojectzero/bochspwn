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

#ifndef BOCHSPWN_OS_FREEBSD_H_
#define BOCHSPWN_OS_FREEBSD_H_

#include <cstdint>

#include "common.h"

#ifndef MAX_PROC_COMM_LEN
#  define MAX_PROC_COMM_LEN 256
#endif

#ifndef MAX_MODULE_NAME_LEN
#  define MAX_MODULE_NAME_LEN 256
#endif

#ifndef MAX_MODULE_SIZE
// 2MB to be safe, but this is quite excessive anyway.
#  define MAX_MODULE_SIZE (2 * 1024 * 1024)
#endif

namespace freebsd {

// ------------------------------------------------------------------
// System events public interface.
// ------------------------------------------------------------------
bool init(const char *, void *);
bool check_kernel_addr(uint64_t *, void *);
bool check_user_addr(uint64_t *, void *);
bool fill_cid(BX_CPU_C *, client_id *);
bool fill_info(BX_CPU_C *, void *);
bool instr_before_execution(BX_CPU_C *, bxInstruction_c *);

}  // namespace freebsd

#endif  // BOCHSPWN_OS_FREEBSD_H_

