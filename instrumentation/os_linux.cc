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

#include "os_linux.h"

#include <cstdio>
#include <cstdlib>

#include "common.h"
#include "instrument.h"
#include "logging.pb.h"

namespace linux {

// TODO(gynvael): move this to os_linux.h
#ifndef MAX_TASK_COMM_LEN
#  define MAX_TASK_COMM_LEN 256
#endif

#ifndef MAX_MODULE_NAME_LEN
#  define MAX_MODULE_NAME_LEN 256
#endif

#ifndef MAX_MODULE_SIZE
// 2MB to be safe, but this is quite excessive anyway.
#  define MAX_MODULE_SIZE (2 * 1024 * 1024)
#endif

uint32_t guest_ptr_size;
uint64_t user_space_boundary;
uint64_t kernel_space_boundary;

// Read from config.
uint32_t conf_thread_size;  // THREAD_SIZE const in TODO(gynvael)
uint32_t off_thread_info_task;
uint32_t off_task_struct_pid;
uint32_t off_task_struct_tgid;

uint32_t conf_task_comm_len;  // TASK_COMM_LEN const in /include/linux/sched.h
uint32_t off_task_struct_comm;

uint64_t addr_modules;
uint32_t off_module_list;
uint32_t off_module_name;
uint32_t off_module_core;
uint32_t off_module_core_size;
uint32_t conf_module_name_len;  // (64 - sizeof(unsigned long))

uint64_t kernel_start;
uint64_t kernel_end;

struct module_summary_st {
  uint64_t l_prev, l_next;
  uint64_t core_addr;
  uint32_t core_size;
  char name[MAX_MODULE_NAME_LEN];
};

// Helper routines.
static bool get_task_struct_pid_gid(BX_CPU_C *pcpu, uint64_t rsp, uint64_t *addr_task_struct,
                                    uint32_t *tgid, uint32_t *pid);
static bool fetch_module_info(BX_CPU_C *pcpu, uint64_t module_ptr, module_summary_st *m);
static module_info *update_module_list(BX_CPU_C *pcpu, uint64_t pc);

bool init(const char *config_path, void *unused) {
  char buffer[256];

  // Read Linux-specific configuration.
  READ_INI_INT(config_path, globals::config.os_version, "thread_size",
               buffer, sizeof(buffer), &conf_thread_size);
  READ_INI_INT(config_path, globals::config.os_version, "thread_info_task",
               buffer, sizeof(buffer), &off_thread_info_task);
  READ_INI_INT(config_path, globals::config.os_version, "task_struct_pid",
               buffer, sizeof(buffer), &off_task_struct_pid);
  READ_INI_INT(config_path, globals::config.os_version, "task_struct_tgid",
               buffer, sizeof(buffer), &off_task_struct_tgid);
  READ_INI_INT(config_path, globals::config.os_version, "task_struct_comm",
               buffer, sizeof(buffer), &off_task_struct_comm);
  READ_INI_INT(config_path, globals::config.os_version, "task_comm_len",
               buffer, sizeof(buffer), &conf_task_comm_len);

  READ_INI_ULL(config_path, globals::config.os_version, "modules",
               buffer, sizeof(buffer), &addr_modules);
  READ_INI_INT(config_path, globals::config.os_version, "module_list",
               buffer, sizeof(buffer), &off_module_list);
  READ_INI_INT(config_path, globals::config.os_version, "module_name",
               buffer, sizeof(buffer), &off_module_name);
  READ_INI_INT(config_path, globals::config.os_version, "module_core",
               buffer, sizeof(buffer), &off_module_core);
  READ_INI_INT(config_path, globals::config.os_version, "module_core_size",
               buffer, sizeof(buffer), &off_module_core_size);
  READ_INI_INT(config_path, globals::config.os_version, "module_name_len",
               buffer, sizeof(buffer), &conf_module_name_len);

  READ_INI_ULL(config_path, globals::config.os_version, "kernel_start",
               buffer, sizeof(buffer), &kernel_start);
  READ_INI_ULL(config_path, globals::config.os_version, "kernel_end",
               buffer, sizeof(buffer), &kernel_end);

  // Put the kernel address and size in the special module list.
  module_info *mi = new module_info(kernel_start, kernel_end - kernel_start,
                                    "kernel");
  globals::special_modules.push_back(mi);

  // Check some assumptions.
  if (conf_task_comm_len >= MAX_TASK_COMM_LEN) {
    fprintf(stderr,
        "error: task_comm_len in config is larger than MAX_TASK_COMM_LEN;\n"
        "       you can recompile with -DMAX_TASK_COMM_LEN=<SizeYouNeed>\n"
        "       and try again\n");
    abort();
  }

  if (conf_module_name_len >= MAX_MODULE_NAME_LEN) {
    fprintf(stderr,
        "error: conf_module_name_len in config is larger than MAX_MODULE_NAME_LEN;\n"
        "       you can recompile with -DMAX_MODULE_NAME_LEN=<SizeYouNeed>\n"
        "       and try again\n");
    abort();
  }


  // Read the configuration specific to guest bitness.
  if (globals::config.bitness == 32) {
    guest_ptr_size = 4;
    // This depends on the kernel configuration options
    // (quote from Linux kernel - x86/Kconfig):
    // config PAGE_OFFSET
    //   hex
    //   default 0xB0000000 if VMSPLIT_3G_OPT
    //   default 0x80000000 if VMSPLIT_2G
    //   default 0x78000000 if VMSPLIT_2G_OPT
    //   default 0x40000000 if VMSPLIT_1G
    //   default 0xC0000000
    //   depends on X86_32
    // We assume it's 0xC0000000.
    //
    // TODO(gynvael): Move this to config and fetch it in init().
    user_space_boundary = 0xC0000000;
    kernel_space_boundary = 0xC0000000;
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
  }

  return (*addr < 0x0000080000000000LL);
}

bool fill_cid(BX_CPU_C *pcpu, client_id *cid) {
  // This is called before a system call is made either by an int, syscall or
  // systenter instruction. The ESP/RSP is not yet set to kernel mode, so
  // the first thing to do is to get the kernel-mode value. This can be done
  // in one of two ways:
  // (int way) from TSS+4 (either 4 or 8 bytes)
  // (sysenter way) from MSR IA32_SYSENTER_ESP 176h
  // The second way is the easiest. The problem would be only if Linux would
  // never register it.
  uint64_t kernel_rsp = 0;
  if (!read_lin_mem(pcpu, pcpu->tr.cache.u.segment.base + 4, guest_ptr_size, &kernel_rsp)) {
    return false;
  }

  // Fetch the data.
  uint32_t tgid, pid;
  uint64_t addr_task_struct;  // This is later unused.

  // Note the kernel_rsp - 1 here - it's needed since the kernel_rsp
  // points past the end of the stack, and we later do a mask on it.
  // So we need to move the kernel_rsp into the stack itself for this
  // to work.
  if (!get_task_struct_pid_gid(pcpu, kernel_rsp - 1, &addr_task_struct, &tgid, &pid)) {
    return false;
  }

  // Fill the struct.
  cid->process_id = tgid;  // Sic! Process ID is in tgid (thread group id).
  cid->thread_id  = pid;   // Sic! Thread ID is in pid.

  return true;
}

bool fill_info(BX_CPU_C *pcpu, void *unused) {
  bx_address pc = globals::last_ld.pc();

  // Fetch task structure address, and pid and tgid fields.
  uint32_t tgid, pid;
  uint64_t addr_task_struct;

  if (!get_task_struct_pid_gid(pcpu, pcpu->gen_reg[BX_64BIT_REG_RBP].rrx,
                               &addr_task_struct, &tgid, &pid)) {
    return false;
  }

  globals::last_ld.set_process_id(tgid);
  globals::last_ld.set_thread_id(pid);

  // Get the image file name.
  // Note: The task_comm_len vs MAX_TASK_COMM_LEN is checked in the
  //       init() function.
  char name_buffer[MAX_TASK_COMM_LEN + 1] = {0};
  if (!read_lin_mem(pcpu, addr_task_struct + off_task_struct_comm,
                    conf_task_comm_len, name_buffer)) {
    return false;
  }
  globals::last_ld.set_image_file_name(name_buffer);

  // Get the thread create time.
  // Note: It seems linux kernel doesn't explicitly store the time,
  // but the time can be get from /proc/PID creation time - this might
  // be a little tricky from CPU level though. Will see.
  // Note2: address of task_struct or thread_info is good enough here btw.
  globals::last_ld.set_create_time(addr_task_struct);

  // Fill in the syscall cound.
  thread_info& info = globals::thread_states[client_id(tgid, pid)];
  globals::last_ld.set_syscall_count(info.syscall_count);
  globals::last_ld.set_syscall_id(info.last_syscall_id);

  // Set the call stack.
  uint64_t ip = pc;
  uint64_t bp = pcpu->gen_reg[BX_64BIT_REG_RBP].rrx;
  module_info *mi = NULL;

  for (unsigned int i = 0; i < globals::config.callstack_length &&
                           ip >= kernel_space_boundary &&
                           bp >= kernel_space_boundary; i++) {
    // Optimization: check last module first.
    if (!mi || mi->module_base > ip || mi->module_base + mi->module_size <= ip) {
      mi = find_module(ip);
      if (!mi) {
        mi = update_module_list(pcpu, ip);
      }
    }

    log_data_st::callstack_item *new_item = globals::last_ld.add_stack_trace();
    if (mi) {
      new_item->set_relative_pc(ip - mi->module_base);
      new_item->set_module_base(mi->module_base);
      new_item->set_module_name(mi->module_name);
    } else {
      new_item->set_relative_pc(ip);
      new_item->set_module_base(0);
      new_item->set_module_name("unknown");
    }

    if (!bp || !read_lin_mem(pcpu, bp + guest_ptr_size, guest_ptr_size, &ip) ||
        !read_lin_mem(pcpu, bp, guest_ptr_size, &bp)) {
      break;
    }
  }

  return true;
}

// ------------------------------------------------------------------
// Helper routines.
// ------------------------------------------------------------------

// Traverse the kernel module list to get the information about the
// driver that the "pc" is in.
static module_info *update_module_list(BX_CPU_C *pcpu, uint64_t pc) {
  // Get the address of the beginning of the list.
  uint64_t modules_start;
  if (!read_lin_mem(pcpu, addr_modules, guest_ptr_size, &modules_start)) {
    // It may be not yet loaded.
    return NULL;
  }

  // Traverse the list.
  uint64_t pm = modules_start;
  for (;;) {
    // Fetch the module info.
    module_summary_st m;
    bool ret = fetch_module_info(pcpu, pm, &m);
    if (!ret) {
      break;
    }

    // Is this it?
    if (pc >= m.core_addr && pc < m.core_addr + m.core_size) {
      // Yes. We found it!
      module_info *mi = new module_info(m.core_addr, m.core_size, m.name);
      globals::modules.push_back(mi);
      return mi;
    }

    // Iteratre.
    // TODO(gynvael): Check the actual terminator.
    pm = m.l_next;
    if (pm == addr_modules || pm == 0 || pm == modules_start) {
      break;
    }
  }

  // Not found.
  return NULL;
}

// Note: This expects module_ptr to be passed without offset correction.
//       The correction will be made in this function.
static bool fetch_module_info(BX_CPU_C *pcpu, uint64_t module_ptr,
    module_summary_st *m) {

  // Correct offset.
  module_ptr -= off_module_list;
  if (module_ptr < kernel_space_boundary) {
    return false;
  }

  // Clear the summary.
  memset(m, 0, sizeof(module_summary_st));

  // Try to fetch name.
  if (!read_lin_mem(pcpu, module_ptr + off_module_name,
                   conf_module_name_len, m->name)) {
    return false;
  }

  // Fetch list pointers in one read.
  unsigned char temp_buffer[2 * 8];  // At most: two 64-bit pointers.
  if (!read_lin_mem(pcpu, module_ptr + off_module_list,
                   2 * guest_ptr_size, temp_buffer)) {
    return false;
  }

  if (guest_ptr_size == 4) {
    m->l_next = *(uint32_t*)(temp_buffer + 0);
    m->l_prev = *(uint32_t*)(temp_buffer + 4);
  } else {
    m->l_next = *(uint64_t*)(temp_buffer + 0);
    m->l_prev = *(uint64_t*)(temp_buffer + 8);
  }

  // Check sanity of these pointers. If they are not sane, something's wrong.
  if (m->l_next < kernel_space_boundary ||
     m->l_prev < kernel_space_boundary) {
    return false;
  }

  // Get module address and size in the kernel memory space.
  if (!read_lin_mem(pcpu, module_ptr + off_module_core, guest_ptr_size, &m->core_addr) ||
      !read_lin_mem(pcpu, module_ptr + off_module_core_size, 4, &m->core_size)) {
    return false;
  }

  // Check sanity of both core address and size.
  if (m->core_addr < kernel_space_boundary ||
     m->core_size > MAX_MODULE_SIZE) {
    return false;
  }

  return true;
}

static bool get_task_struct_pid_gid(BX_CPU_C *pcpu, uint64_t rsp, uint64_t *addr_task_struct,
                                    uint32_t *tgid, uint32_t *pid) {
  // Dervie the thread_info address from the kernel stack address.
  // It is found at the beginning of the stack area.
  // Note: this is the exact method this used in the kernel.
  uint64_t addr_thread_info = rsp;
  addr_thread_info &= ~((uint64_t)conf_thread_size - 1);

  // The thread_info structure should be in kernel memory.
  if (addr_thread_info < user_space_boundary) {
    return false;
  }

  // Get the task_struct address.
  if (!read_lin_mem(pcpu, addr_thread_info + off_thread_info_task,
                    guest_ptr_size, addr_task_struct)) {
    return false;
  }

  // Check the address.
  if (*addr_task_struct < user_space_boundary) {
    return false;
  }

  // Fetch the process ID (tgid) and thread ID (pid; sic).
  // Note: We're assuming sizeof(pid_t) is always 4 bytes - this might
  // not be futureproof.
  if (!read_lin_mem(pcpu, *addr_task_struct + off_task_struct_tgid, 4, tgid) ||
      !read_lin_mem(pcpu, *addr_task_struct + off_task_struct_pid, 4, pid)) {
    return false;
  }

  return true;
}

}  // namespace linux

