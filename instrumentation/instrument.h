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

#ifndef KFETCH_TOOLKIT_INSTRUMENT_H_
#define KFETCH_TOOLKIT_INSTRUMENT_H_

#include <map>
#include <vector>

#include "bochs.h"
#include "cpu/cpu.h"

#include "common.h"
#include "logging.pb.h"

// This code is based on GPL code. Make sure the copyrights are resolved
// before publishing this.

// ------------------------------------------------------------------
// Implemented instrumentation.
// ------------------------------------------------------------------
void bx_instr_initialize(unsigned cpu);
void bx_instr_exit(unsigned cpu);

void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_phy_address phy, unsigned len, unsigned memtype, unsigned rw);

void bx_instr_before_execution(unsigned cpu, bxInstruction_c *i);

#define BX_INSTR_INITIALIZE(cpu_id) \
  bx_instr_initialize(cpu_id)

#define BX_INSTR_EXIT(cpu_id) \
  bx_instr_exit(cpu_id)

#define BX_INSTR_LIN_ACCESS(cpu_id, lin, phy, len, memtype, rw) \
                bx_instr_lin_access(cpu_id, lin, phy, len, memtype, rw)

#define BX_INSTR_PHY_ACCESS(cpu_id, phy, len, memtype, rw)

#define BX_INSTR_BEFORE_EXECUTION(cpu_id, i) \
  bx_instr_before_execution(cpu_id, i)

// ------------------------------------------------------------------
// Stubs for the rest of macros.
// ------------------------------------------------------------------
/* initialization/deinitialization of instrumentalization */
#define BX_INSTR_INIT_ENV()
#define BX_INSTR_EXIT_ENV()

/* simulation init, shutdown, reset */
#define BX_INSTR_RESET(cpu_id, type)
#define BX_INSTR_HLT(cpu_id)
#define BX_INSTR_MWAIT(cpu_id, addr, len, flags)

/* called from command line debugger */
#define BX_INSTR_DEBUG_PROMPT()
#define BX_INSTR_DEBUG_CMD(cmd)

/* branch resolution */
#define BX_INSTR_CNEAR_BRANCH_TAKEN(cpu_id, branch_eip, new_eip)
#define BX_INSTR_CNEAR_BRANCH_NOT_TAKEN(cpu_id, branch_eip)
#define BX_INSTR_UCNEAR_BRANCH(cpu_id, what, branch_eip, new_eip)
#define BX_INSTR_FAR_BRANCH(cpu_id, what, prev_cs, prev_eip, new_cs, new_eip)

/* decoding completed */
#define BX_INSTR_OPCODE(cpu_id, i, opcode, len, is32, is64)

/* exceptional case and interrupt */
#define BX_INSTR_EXCEPTION(cpu_id, vector, error_code)
#define BX_INSTR_INTERRUPT(cpu_id, vector)
#define BX_INSTR_HWINTERRUPT(cpu_id, vector, cs, eip)

/* TLB/CACHE control instruction executed */
#define BX_INSTR_CLFLUSH(cpu_id, laddr, paddr)
#define BX_INSTR_CACHE_CNTRL(cpu_id, what)
#define BX_INSTR_TLB_CNTRL(cpu_id, what, new_cr3)
#define BX_INSTR_PREFETCH_HINT(cpu_id, what, seg, offset)

/* execution */
#define BX_INSTR_AFTER_EXECUTION(cpu_id, i)
#define BX_INSTR_REPEAT_ITERATION(cpu_id, i)

/* feedback from device units */
#define BX_INSTR_INP(addr, len)
#define BX_INSTR_INP2(addr, len, val)
#define BX_INSTR_OUTP(addr, len, val)

/* wrmsr callback */
#define BX_INSTR_WRMSR(cpu_id, addr, value)

#endif  // KFETCH_TOOLKIT_INSTRUMENT_H_

