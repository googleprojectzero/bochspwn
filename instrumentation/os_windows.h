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

#ifndef BOCHSPWN_OS_WINDOWS_H_
#define BOCHSPWN_OS_WINDOWS_H_

#include <cstdint>

#include "common.h"

namespace windows {

// ------------------------------------------------------------------
// Constants.
// ------------------------------------------------------------------
#define APC_MODE 1

// ------------------------------------------------------------------
// System events public interface.
// ------------------------------------------------------------------
bool init(const char *, void *);
bool check_kernel_addr(uint64_t *, void *);
bool check_user_addr(uint64_t *, void *);
bool fill_cid(BX_CPU_C *, client_id *);
bool fill_info(BX_CPU_C *, void *);

// ------------------------------------------------------------------
// Helper routines.
// ------------------------------------------------------------------
int update_module_list(BX_CPU_C *pcpu, bx_address pc);

// ------------------------------------------------------------------
// Windows-specific offsets and information.
// ------------------------------------------------------------------
extern uint32_t guest_ptr_size;       // initialized based on bitness
extern uint64_t user_space_boundary;  // initialized based on bitness

extern uint32_t off_kprcb;            // in KPCR
extern uint32_t off_current_thread;   // in KPRCB
extern uint32_t off_tcb;              // in ETHREAD
extern uint32_t off_process;          // in TCB
extern uint32_t off_client_id;        // in ETHREAD
extern uint32_t off_process_id;       // in CLIENT_ID
extern uint32_t off_thread_id;        // in CLIENT_ID
extern uint32_t off_create_time;      // in ETHREAD
extern uint32_t off_image_filename;   // in EPROCESS
extern uint32_t off_loadorder_flink;  // in LDR_MODULE
extern uint32_t off_basedllname;      // in LDR_MODULE
extern uint32_t off_baseaddress;      // in LDR_MODULE
extern uint32_t off_sizeofimage;      // in LDR_MODULE
extern uint32_t off_us_len;           // in UNICODE_STRING
extern uint32_t off_us_buffer;        // in UNICODE_STRING
extern uint32_t off_teb_cid;          // in TEB
extern uint32_t off_irql;             // in KPCR
// Note: this value has a different meaning between X86 and X64
// architectures.
//
// On 32-bit Windows, it is the offset of the PsLoadedModuleList field against
// the base of the DBGKD_GET_VERSION64 structure.
// On 64-bit Windows, it is the offset of the global PsLoadedModuleList
// symbol relative to the nt image base address.
extern uint64_t off_psloadedmodulelist;

// 32-bit only
extern unsigned int off_kdversionblock;  // in KPCR

// 64-bit only
extern unsigned int off_64bit_teb;  // gs:[off_64bit_teb] == TEB

}  // namespace windows

#endif  // BOCHSPWN_OS_WINDOWS_H_

