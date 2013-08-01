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

#include "os_openbsd.h"

#include <cstdio>
#include <cstdlib>

#include "common.h"
#include "instrument.h"
#include "logging.pb.h"

namespace openbsd {

uint32_t guest_ptr_size;
uint64_t user_space_boundary;
uint64_t kernel_space_boundary;

uint32_t off_cpu_info_ci_curproc;
uint32_t off_proc_p_addr;
uint32_t off_proc_p_pid;
uint32_t off_proc_p_comm;
uint32_t conf_comm_size;  // MAXCOMLEN +1 (17 usually)
uint32_t off_proc_p_p;
uint32_t off_process_ps_pgrp;
uint32_t off_pgrp_id;

// Supposedly there are no external kernel modules in OpenBSD.
uint64_t kernel_start;
uint64_t kernel_end;

uint64_t copyin_addr;
uint64_t copyinstr_addr;

uint64_t copyin_addr_end;
uint64_t copyinstr_addr_end;

struct module_summary_st {
  uint64_t l_prev, l_next;
  uint64_t core_addr;
  uint32_t core_size;
  char name[256];
};

// Helper routines.
static bool get_kernel_gs_base(BX_CPU_C *pcpu, uint64_t *kernel_gs_base);
static bool get_proc_pgid_pid(BX_CPU_C *pcpu, uint64_t kernel_gs_base,
                              uint64_t *addr_proc_struct, uint32_t *pgid, uint32_t *pid);

bool init(const char *config_path, void *unused) {
  char buffer[256];

  // Read Linux-specific configuration.
  READ_INI_INT(config_path, globals::config.os_version, "cpu_info_ci_curproc",
               buffer, sizeof(buffer), &off_cpu_info_ci_curproc);
  READ_INI_INT(config_path, globals::config.os_version, "proc_p_addr",
               buffer, sizeof(buffer), &off_proc_p_addr);
  READ_INI_INT(config_path, globals::config.os_version, "proc_p_pid",
               buffer, sizeof(buffer), &off_proc_p_pid);
  READ_INI_INT(config_path, globals::config.os_version, "proc_p_comm",
               buffer, sizeof(buffer), &off_proc_p_comm);
  READ_INI_INT(config_path, globals::config.os_version, "comm_size",
               buffer, sizeof(buffer), &conf_comm_size);

  READ_INI_INT(config_path, globals::config.os_version, "proc_p_p",
               buffer, sizeof(buffer), &off_proc_p_p);
  READ_INI_INT(config_path, globals::config.os_version, "process_ps_pgrp",
               buffer, sizeof(buffer), &off_process_ps_pgrp);
  READ_INI_INT(config_path, globals::config.os_version, "pgrp_id",
               buffer, sizeof(buffer), &off_pgrp_id);

  READ_INI_ULL(config_path, globals::config.os_version, "kernel_start",
               buffer, sizeof(buffer), &kernel_start);
  READ_INI_ULL(config_path, globals::config.os_version, "kernel_end",
               buffer, sizeof(buffer), &kernel_end);

  READ_INI_ULL(config_path, globals::config.os_version, "copyin",
               buffer, sizeof(buffer), &copyin_addr);
  READ_INI_ULL(config_path, globals::config.os_version, "copyinstr",
               buffer, sizeof(buffer), &copyinstr_addr);

  READ_INI_ULL(config_path, globals::config.os_version, "copyin_end",
               buffer, sizeof(buffer), &copyin_addr_end);
  READ_INI_ULL(config_path, globals::config.os_version, "copyinstr_end",
               buffer, sizeof(buffer), &copyinstr_addr_end);

  // If addresses of these functions are given, then enable grabbing the RET
  // address when they are called.
  if (copyin_addr != 0 || copyinstr_addr != 0) {
    globals::has_instr_before_execution_handler = true;
  }

  // Put the kernel address and size in the special module list.
  module_info *mi = new module_info(kernel_start, kernel_end - kernel_start, "kernel");
  globals::special_modules.push_back(mi);

  // Check some assumptions.
  if (conf_comm_size >= MAX_PROC_COMM_LEN) {
    fprintf(stderr,
        "error: conf_proc_p_comm_size in config is larger than MAX_PROC_COMM_LEN;\n"
        "       you can recompile with -DMAX_PROC_COMM_LEN=<SizeYouNeed>\n"
        "       and try again.\n");
    abort();
  }

  // Read the configuration specific to guest bitness.
  if (globals::config.bitness == 32) {
    /*guest_ptr_size = 4;
    user_space_boundary = 0xC0000000;
    kernel_space_boundary = 0xC0000000;*/
    fprintf(stderr, "error: 32-bit OpenBSD support is not supported.\n");
    abort();
  } else {
    guest_ptr_size = 8;
    user_space_boundary = 0x0000080000000000LL;
    kernel_space_boundary = 0xffff800000000000LL;
  }

  return true;
}

bool check_kernel_addr(uint64_t *addr, void *unused) {
  if (guest_ptr_size == 4) {
    return (*addr >= 0xC0000000);
  }

  return (*addr >= 0xffff800000000000LL);
}

bool check_user_addr(uint64_t *addr, void *unused) {
  if (guest_ptr_size == 4) {
    return (*addr < 0xC0000000);
  }

  return (*addr < 0x0000080000000000LL);
}

bool fill_cid(BX_CPU_C *pcpu, client_id *cid) {
  // Get kernel GS base which points to PCPU structure.
  uint64_t kernel_gs_base;
  if (!get_kernel_gs_base(pcpu, &kernel_gs_base)) {
    return false;
  }

  // Fetch the data.
  uint32_t pgid, pid;  // Process group ID, process (thread) ID.
  uint64_t addr_proc_struct;  // This is unused later on.

  if (!get_proc_pgid_pid(pcpu, kernel_gs_base, &addr_proc_struct, &pgid, &pid)) {
    return false;
  }

  // Fill the struct.
  cid->process_id = pgid;
  cid->thread_id  = pid;

  return true;
}

bool fill_info(BX_CPU_C *pcpu, void *unused) {
  bx_address pc = globals::last_ld.pc();

  // Get kernel GS base which points to PCPU structure.
  uint64_t kernel_gs_base;
  if (!get_kernel_gs_base(pcpu, &kernel_gs_base)) {
    return false;
  }

  // Fetch the data.
  uint32_t pgid, pid;
  uint64_t addr_proc_struct;

  if (!get_proc_pgid_pid(pcpu, kernel_gs_base, &addr_proc_struct, &pgid, &pid)) {
    return false;
  }

  globals::last_ld.set_process_id(pgid);
  globals::last_ld.set_thread_id(pid);

  // Get the image file name.
  // Note: The conf_proc_p_comm_size vs MAX_PROC_COMM_LEN is checked in the
  //       init() function.
  char name_buffer[MAX_PROC_COMM_LEN + 1] = {0};
  if (!read_lin_mem(pcpu, addr_proc_struct + off_proc_p_comm, conf_comm_size, name_buffer)) {
    return false;
  }
  globals::last_ld.set_image_file_name(name_buffer);

  // Get the thread create time.
  // TODO(gynvael): Check if this is possible. If not, just use proc address.
  //                Btw, maybe a hash(addr_proc : addr_thread) would be better.
  globals::last_ld.set_create_time(addr_proc_struct);

  // Fill in the syscall count.
  thread_info& info = globals::thread_states[client_id(pgid, pid)];
  globals::last_ld.set_syscall_count(info.syscall_count);
  globals::last_ld.set_syscall_id(info.last_syscall_id);

  // Should the last_ret_addr be injected after the IP/top entry in the callstack?
  bool inject_last_ret_addr = false;
  if ((pc >= copyin_addr && pc < copyin_addr_end) ||
     (pc >= copyinstr_addr && pc < copyinstr_addr_end)) {
    inject_last_ret_addr = true;
  }

  // Set the call stack.
  uint64_t ip = pc;
  uint64_t bp = pcpu->gen_reg[BX_64BIT_REG_RBP].rrx;

  for (unsigned int i = 0; i < globals::config.callstack_length &&
                           ip >= kernel_space_boundary &&
                           bp >= kernel_space_boundary; i++) {
    log_data_st::callstack_item *new_item = globals::last_ld.add_stack_trace();

    if (ip >= kernel_start && ip <= kernel_end) {
      new_item->set_relative_pc(ip - kernel_start);
      new_item->set_module_base(kernel_start);
      new_item->set_module_name("kernel");
    } else {
      new_item->set_relative_pc(ip);
      new_item->set_module_base(0);
      new_item->set_module_name("unknown");
    }

    // Inject?
    if (inject_last_ret_addr) {
      ip = info.last_ret_addr;
      inject_last_ret_addr = false;
      continue;
    }

    if (!bp || !read_lin_mem(pcpu, bp + guest_ptr_size, guest_ptr_size, &ip) ||
        !read_lin_mem(pcpu, bp, guest_ptr_size, &bp)) {
      break;
    }
  }

  return true;
}

bool instr_before_execution(BX_CPU_C *pcpu, bxInstruction_c *i) {
  uint64_t rip = pcpu->prev_rip;

  // In not what we are looking for, just return.
  if (rip != copyin_addr && rip != copyinstr_addr) {
    return false;
  }

  // This is just after the call, so the return address is on the
  // top of the stack.
  uint64_t sp = pcpu->gen_reg[BX_64BIT_REG_RSP].rrx;
  uint64_t ret = 0;
  if (!read_lin_mem(pcpu, sp, guest_ptr_size, &ret)) {
    return false;
  }

  // Get kernel GS base which points to PCPU structure.
  uint64_t kernel_gs_base;
  if (!get_kernel_gs_base(pcpu, &kernel_gs_base)) {
    return false;
  }

  // Need to get pgid and pid.
  uint32_t pgid, pid;
  uint64_t addr_proc_struct;  // This is unused later on.

  if (!get_proc_pgid_pid(pcpu, kernel_gs_base, &addr_proc_struct,
                       &pgid, &pid)) {
    return false;
  }

  // Mark this as the latest jump.
  thread_info& info = globals::thread_states[client_id(pgid, pid)];
  info.last_ret_addr = ret;

  return true;
}

// ------------------------------------------------------------------
// Helper routines.
// ------------------------------------------------------------------
static bool get_kernel_gs_base(BX_CPU_C *pcpu, uint64_t *kernel_gs_base)  {
  // This is called before a system call is made either by an int, syscall or
  // systenter instruction. So, the GS segment is not yet in kernel mode.
  // It's best to read the kernel_gs_base from MSR C0000102H (MSR_KERNELGSbase).
  // There might be a case where an int, or sth, is invoked from ring0, so the
  // MSR will contain a user-mode address. In such case the GS base itself should
  // be read instead.
  uint64_t base = pcpu->msr.kernelgsbase;
  if (check_kernel_addr(&base, NULL)) {
    *kernel_gs_base = base;
    return true;
  }

  // Maybe the current GS is already "in kernel mode"?
  base = pcpu->get_segment_base(BX_SEG_REG_GS);
  if (check_kernel_addr(&base, NULL)) {
    *kernel_gs_base = base;
    return true;
  }

  // No luck.
  return false;
}

static bool get_proc_pgid_pid(BX_CPU_C *pcpu, uint64_t kernel_gs_base,
                              uint64_t *addr_proc_struct, uint32_t *pgid, uint32_t *pid) {
  // Get proc address from cpu_info.
  uint64_t proc_addr;
  if (!read_lin_mem(pcpu, kernel_gs_base + off_cpu_info_ci_curproc, guest_ptr_size, &proc_addr)) {
    return false;
  }

  if (proc_addr < user_space_boundary) {
    return false;
  }

  // Get Process ID.
  if (!read_lin_mem(pcpu, proc_addr + off_proc_p_pid, 4, pgid)) {
    return false;
  }

  *addr_proc_struct = proc_addr;

  // Get pid (or actually p_addr, which should be enough).
  if (!read_lin_mem(pcpu, proc_addr + off_proc_p_addr, 4, &pid)) {
    return false;
  }

  return true;
}

}  // namespace openbsd

