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

#include "os_freebsd.h"

#include <cstdio>
#include <cstdlib>

#include "common.h"
#include "instrument.h"
#include "logging.pb.h"

namespace freebsd {

uint32_t guest_ptr_size;
uint64_t user_space_boundary;
uint64_t kernel_space_boundary;

uint32_t off_thread_td_pid;
uint32_t off_thread_td_proc;
uint32_t off_proc_p_pid;
uint32_t off_proc_p_comm;
uint32_t conf_proc_p_comm_size;  // MAXCOMLEN +1 in sys/param.h

// TODO(gynvael): Support modules in the future... maybe.
// There area over 400 modules on the list in our test OS and all
// of them (every single one) points to the kernel image. So no
// sense of supporting it atm.

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
  char name[MAX_MODULE_NAME_LEN];
};

// Helper routines.
static bool get_kernel_gs_base(BX_CPU_C *pcpu, uint64_t *kernel_gs_base);
static bool get_proc_pid_gid(BX_CPU_C *pcpu, uint64_t kernel_gs_base,
                             uint64_t *addr_proc_struct, uint32_t *pid, uint32_t *tid);

bool init(const char *config_path, void *unused) {
  char buffer[256];

  // Read Linux-specific configuration.
  READ_INI_INT(config_path, globals::config.os_version, "thread_td_tid",
               buffer, sizeof(buffer), &off_thread_td_pid);
  READ_INI_INT(config_path, globals::config.os_version, "thread_td_proc",
               buffer, sizeof(buffer), &off_thread_td_proc);
  READ_INI_INT(config_path, globals::config.os_version, "proc_p_pid",
               buffer, sizeof(buffer), &off_proc_p_pid);
  READ_INI_INT(config_path, globals::config.os_version, "proc_p_comm",
               buffer, sizeof(buffer), &off_proc_p_comm);
  READ_INI_INT(config_path, globals::config.os_version, "proc_p_comm_size",
               buffer, sizeof(buffer), &conf_proc_p_comm_size);

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
  module_info *mi = new module_info(kernel_start, kernel_end - kernel_start,
                                    "kernel");
  globals::special_modules.push_back(mi);

  // Check some assumptions.
  if (conf_proc_p_comm_size >= MAX_PROC_COMM_LEN) {
    fprintf(stderr,
        "error: conf_proc_p_comm_size in config is larger than MAX_PROC_COMM_LEN;\n"
        "       you can recompile with -DMAX_PROC_COMM_LEN=<SizeYouNeed>\n"
        "       and try again.\n");
    abort();
  }

  // Read the configuration specific to guest bitness.
  if (globals::config.bitness == 32) {
    guest_ptr_size = 4;
    user_space_boundary = 0xbfffffff;
    kernel_space_boundary = 0xc0000000;
  } else {
    guest_ptr_size = 8;
    user_space_boundary = 0x0000080000000000LL;
    kernel_space_boundary = 0xffff800000000000LL;
  }

  return true;
}

bool check_kernel_addr(uint64_t *addr, void *unused) {
  if (guest_ptr_size == 4) {
    return (*addr >= 0xbfc00000);
  }

  return (*addr >= 0xffff800000000000LL);
}

bool check_user_addr(uint64_t *addr, void *unused) {
  if (guest_ptr_size == 4) {
    return (*addr < 0xbfc00000);
  }

  return (*addr < 0x0000080000000000LL);
}

static bool get_kernel_gs_base(BX_CPU_C *pcpu, uint64_t *kernel_gs_base)  {

  // Is this 32-bit x86?
  if (guest_ptr_size == 4) {

    // Handle 32-bit x86.

    // First try the FS.base - if it's "in kernel mode" then there is nothing
    // mode to do. Otherwise read it from GDT (GPRIV_SEL offset 8).
    uint64_t base = pcpu->get_segment_base(BX_SEG_REG_FS);
    if (check_kernel_addr(&base, NULL)) {
      *kernel_gs_base = base;
      return true;
    }

    // Read the GDT entry.
    uint8_t seg_raw[8] = {0};
    if (!read_lin_mem(pcpu, pcpu->gdtr.base + 8, 8, seg_raw)) {
      return false;
    }

    // Put together the base address.
    base = (uint32_t)seg_raw[2] |
           ((uint32_t)seg_raw[3] << 8) | 
           ((uint32_t)seg_raw[4] << 16) | 
           ((uint32_t)seg_raw[7] << 24);

    if (!check_kernel_addr(&base, NULL)) {
      return false;
    }

    *kernel_gs_base = base;

    return true;
  }

  // Handle 64-bit x86.

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

bool fill_cid(BX_CPU_C *pcpu, client_id *cid) {
  // Get kernel GS base which points to PCPU structure.
  uint64_t kernel_gs_base;
  if (!get_kernel_gs_base(pcpu, &kernel_gs_base)) {
    return false;
  }

  // Fetch the data.
  uint32_t pid, tid;
  uint64_t addr_proc_struct;  // This is unused later on.

  if (!get_proc_pid_gid(pcpu, kernel_gs_base, &addr_proc_struct, &pid, &tid)) {
    return false;
  }

  // Fill the structure.
  cid->process_id = pid;
  cid->thread_id  = tid;

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
  uint32_t pid, tid;
  uint64_t addr_proc_struct;  // This is unused later on.

  if (!get_proc_pid_gid(pcpu, kernel_gs_base, &addr_proc_struct,
                       &pid, &tid)) {
    return false;
  }

  globals::last_ld.set_process_id(pid);
  globals::last_ld.set_thread_id(tid);

  // Get the image file name.
  // Note: The conf_proc_p_comm_size vs MAX_PROC_COMM_LEN is checked in the
  //       init() function.
  char name_buffer[MAX_PROC_COMM_LEN + 1] = {0};
  if (!read_lin_mem(pcpu, addr_proc_struct + off_proc_p_comm,
                   conf_proc_p_comm_size, name_buffer)) {
    return false;
  }
  globals::last_ld.set_image_file_name(name_buffer);

  // Get the thread create time.
  // TODO(gynvael): Check if this is possible. If not, just use proc address.
  //                Btw, maybe a hash(addr_proc : addr_thread) would be better.
  globals::last_ld.set_create_time(addr_proc_struct);

  // Fill in the syscall count.
  thread_info& info = globals::thread_states[client_id(pid, tid)];
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

  // Need to get pid and tid.
  uint32_t pid, tid;
  uint64_t addr_proc_struct;  // This is unused later on.

  if (!get_proc_pid_gid(pcpu, kernel_gs_base, &addr_proc_struct,
                       &pid, &tid)) {
    return false;
  }

  // Mark this as the latest jump.
  thread_info& info = globals::thread_states[client_id(pid, tid)];
  info.last_ret_addr = ret;

  return true;
}

// ------------------------------------------------------------------
// Helper routines.
// ------------------------------------------------------------------
static bool get_proc_pid_gid(BX_CPU_C *pcpu, uint64_t kernel_gs_base, uint64_t *addr_proc_struct,
                             uint32_t *pid, uint32_t *tid) {
  // Get thread address.
  uint64_t thread_addr;
  if (!read_lin_mem(pcpu, kernel_gs_base,
                   guest_ptr_size, &thread_addr)) {
    return false;
  }

  if (thread_addr < user_space_boundary) {
    return false;
  }

  // Get Thread ID.
  if (!read_lin_mem(pcpu, thread_addr + off_thread_td_pid, 4, tid)) {
    return false;
  }

  // Get proc structure address.
  if (!read_lin_mem(pcpu, thread_addr + off_thread_td_proc, guest_ptr_size, addr_proc_struct)) {
    return false;
  }

  if (*addr_proc_struct < user_space_boundary) {
    return false;
  }

  // Get Process ID.
  if (!read_lin_mem(pcpu, *addr_proc_struct + off_proc_p_pid, 4, pid)) {
    return false;
  }

  return true;
}

}  // namespace freebsd

