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

#include "os_windows.h"

#ifdef _WIN32
#include <stdint.h>
#include <windows.h>

#include "common.h"
#include "instrument.h"
#include "logging.pb.h"

// ------------------------------------------------------------------
// Configuration data, for detailed information see os_windows.h.
// ------------------------------------------------------------------
namespace windows {

uint32_t guest_ptr_size;
uint64_t user_space_boundary;

uint32_t off_kprcb;
uint32_t off_current_thread;
uint32_t off_tcb;
uint32_t off_process;
uint32_t off_client_id;
uint32_t off_process_id;
uint32_t off_thread_id;
uint32_t off_create_time;
uint32_t off_image_filename;
uint32_t off_loadorder_flink;
uint32_t off_basedllname;
uint32_t off_baseaddress;
uint32_t off_sizeofimage;
uint32_t off_us_len;
uint32_t off_us_buffer;
uint32_t off_teb_cid;
uint64_t off_psloadedmodulelist;
uint32_t off_irql;
uint32_t off_kdversionblock;
uint32_t off_64bit_teb;

// ------------------------------------------------------------------
// Public Windows-specific interface.
// ------------------------------------------------------------------
bool init(const char *config_path, void *unused) {
  char buffer[256];

  // Read generic Windows-specific configuration.
  READ_INI_INT(config_path, globals::config.os_version, "kprcb",
               buffer, sizeof(buffer), &off_kprcb);
  READ_INI_INT(config_path, globals::config.os_version, "current_thread",
               buffer, sizeof(buffer), &off_current_thread);
  READ_INI_INT(config_path, globals::config.os_version, "tcb",
               buffer, sizeof(buffer), &off_tcb);
  READ_INI_INT(config_path, globals::config.os_version, "process",
               buffer, sizeof(buffer), &off_process);
  READ_INI_INT(config_path, globals::config.os_version, "client_id",
               buffer, sizeof(buffer), &off_client_id);
  READ_INI_INT(config_path, globals::config.os_version, "process_id",
               buffer, sizeof(buffer), &off_process_id);
  READ_INI_INT(config_path, globals::config.os_version, "thread_id",
               buffer, sizeof(buffer), &off_thread_id);
  READ_INI_INT(config_path, globals::config.os_version, "create_time",
               buffer, sizeof(buffer), &off_create_time);
  READ_INI_INT(config_path, globals::config.os_version, "image_filename",
               buffer, sizeof(buffer), &off_image_filename);
  READ_INI_INT(config_path, globals::config.os_version, "loadorder_flink",
               buffer, sizeof(buffer), &off_loadorder_flink);
  READ_INI_INT(config_path, globals::config.os_version, "basedllname",
               buffer, sizeof(buffer), &off_basedllname);
  READ_INI_INT(config_path, globals::config.os_version, "baseaddress",
               buffer, sizeof(buffer), &off_baseaddress);
  READ_INI_INT(config_path, globals::config.os_version, "sizeofimage",
               buffer, sizeof(buffer), &off_sizeofimage);
  READ_INI_INT(config_path, globals::config.os_version, "us_len",
               buffer, sizeof(buffer), &off_us_len);
  READ_INI_INT(config_path, globals::config.os_version, "us_buffer",
               buffer, sizeof(buffer), &off_us_buffer);
  READ_INI_INT(config_path, globals::config.os_version, "teb_cid",
               buffer, sizeof(buffer), &off_teb_cid);
  READ_INI_ULL(config_path, globals::config.os_version, "psloadedmodulelist",
               buffer, sizeof(buffer), &off_psloadedmodulelist);
  READ_INI_INT(config_path, globals::config.os_version, "irql",
               buffer, sizeof(buffer), &off_irql);

  // Read configuration specific to guest bitness.
  if (globals::config.bitness == 32) {
    guest_ptr_size = 4;
    user_space_boundary = 0x7ff00000;

    READ_INI_INT(config_path, globals::config.os_version, "kdversionblock",
                 buffer, sizeof(buffer), &off_kdversionblock);
  } else {
    guest_ptr_size = 8;
    user_space_boundary = 0x000007ff00000000LL;

    READ_INI_INT(config_path, globals::config.os_version, "64bit_teb",
                 buffer, sizeof(buffer), &off_64bit_teb);
  }

  return true;
}

bool check_kernel_addr(uint64_t *addr, void *unused) {
  if (guest_ptr_size == 4) {
    return (*addr >= 0x80000000);
  }

  return (*addr >= 0xfffff80000000000LL);
}

bool check_user_addr(uint64_t *addr, void *unused) {
  if (guest_ptr_size == 4) {
    return (*addr < 0x7e000000);
  }

  return (*addr < 0x000007ff00000000LL);
}

bool fill_cid(BX_CPU_C *pcpu, client_id *cid) {
  uint64_t addr_teb = 0;

  // Obtain Thread Environment Block address
  if (guest_ptr_size == 4) {
    addr_teb = pcpu->get_segment_base(BX_SEG_REG_FS);
  } else {
    addr_teb = pcpu->get_segment_base(BX_SEG_REG_GS);
    if (!read_lin_mem(pcpu, addr_teb + off_64bit_teb, guest_ptr_size, &addr_teb)) {
      return false;
    }
  }

  if (addr_teb >= user_space_boundary) {
    return false;
  }

  // Read thread-specific TID/PID.
  uint64_t addr_clientid = addr_teb + off_teb_cid;
  if (!read_lin_mem(pcpu, addr_clientid + off_process_id, guest_ptr_size, &cid->process_id) ||
      !read_lin_mem(pcpu, addr_clientid + off_thread_id, guest_ptr_size, &cid->thread_id)) {
    return false;
  }

  return true;
}

bool fill_info(BX_CPU_C *pcpu, void *unused) {
  bx_address pc = globals::last_ld.pc();

  // Get PCR address.
  uint64_t addr_kpcr = 0;
  if (globals::config.bitness == 32) {
    addr_kpcr = pcpu->get_segment_base(BX_SEG_REG_FS);
  } else {
    addr_kpcr = pcpu->get_segment_base(BX_SEG_REG_GS);
  }

  if (addr_kpcr < user_space_boundary) {
    return false;
  }

  // Verify that current IRQL is not APC_MODE, as apparently there are lots
  // of false positives in kernel-mode APC callbacks referencing user-mode
  // memory.
  uint8_t irql;
  if (!read_lin_mem(pcpu, addr_kpcr + off_irql, 1, &irql) || irql == APC_MODE) {
    return false;
  }

  uint64_t addr_kprcb = addr_kpcr + off_kprcb;
  uint64_t addr_ethread = 0;
  if (!read_lin_mem(pcpu, addr_kprcb + off_current_thread, guest_ptr_size, &addr_ethread)) {
    return false;
  }

  uint64_t addr_clientid = addr_ethread + off_client_id;
  uint64_t pid = 0, tid = 0;
  read_lin_mem(pcpu, addr_clientid + off_process_id, guest_ptr_size, &pid);
  read_lin_mem(pcpu, addr_clientid + off_thread_id, guest_ptr_size, &tid);

  // We are not interested in the "System" process.
  if (pid == 0 || pid == 4) {
    return false;
  }

  globals::last_ld.set_process_id(pid);
  globals::last_ld.set_thread_id(tid);

  uint64_t addr_eprocess = 0;
  if (!read_lin_mem(pcpu, addr_ethread + off_tcb + off_process, guest_ptr_size, &addr_eprocess)) {
    return false;
  }

  static char image_file_name[16];
  if (!read_lin_mem(pcpu, addr_eprocess + off_image_filename, 15, image_file_name)) {
    return false;
  }
  globals::last_ld.set_image_file_name(image_file_name);

  uint64_t create_time;
  if (!read_lin_mem(pcpu, addr_ethread + off_create_time, 8, &create_time)) {
    return false;
  }
  globals::last_ld.set_create_time(create_time);

  // Read the stack trace.
  if (globals::config.bitness == 32) {
    uint64_t ip = pc;
    uint64_t bp = pcpu->gen_reg[BX_64BIT_REG_RBP].rrx;
    module_info *mi = NULL;

    for (unsigned int i = 0; i < globals::config.callstack_length &&
                             ip >= user_space_boundary &&
                             bp >= user_space_boundary; i++) {
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
        new_item->set_relative_pc(pc);
        new_item->set_module_base(0);
        new_item->set_module_name("unknown");
      }

      if (!bp || !read_lin_mem(pcpu, bp + guest_ptr_size, guest_ptr_size, &ip) ||
          !read_lin_mem(pcpu, bp, guest_ptr_size, &bp)) {
        break;
      }
    }
  } else {
    module_info *mi = find_module(pc);
    if (!mi) {
      mi = update_module_list(pcpu, pc);
    }

    log_data_st::callstack_item *new_item = globals::last_ld.add_stack_trace();
    if (mi) {
      new_item->set_relative_pc(pc - mi->module_base);
      new_item->set_module_base(mi->module_base);
      new_item->set_module_name(mi->module_name);
    } else {
      new_item->set_relative_pc(pc);
      new_item->set_module_base(0);
      new_item->set_module_name("unknown");
    }
  }

  // Fill in the syscall count.
  thread_info& info = globals::thread_states[client_id(pid, tid)];
  globals::last_ld.set_syscall_count(info.syscall_count);
  globals::last_ld.set_syscall_id(info.last_syscall_id);

  return true;
}

// ------------------------------------------------------------------
// Helper routines.
// ------------------------------------------------------------------

// Traverse the PsLoadedModuleList linked list of drivers in search of
// one that contains the "pc" address.
module_info *update_module_list(BX_CPU_C *pcpu, bx_address pc) {
  uint64_t addr_module = 0;

  if (globals::config.bitness == 32) {
    uint64_t addr_kpcr = pcpu->get_segment_base(BX_SEG_REG_FS);
    if (addr_kpcr < user_space_boundary) {
      return NULL;
    }

    uint64_t addr_dbg_block = 0;
    if (!read_lin_mem(pcpu, addr_kpcr + off_kdversionblock, guest_ptr_size,
                      &addr_dbg_block) || addr_dbg_block < user_space_boundary) {
      return NULL;
    }

    if (!read_lin_mem(pcpu, addr_dbg_block + off_psloadedmodulelist, guest_ptr_size,
                     &addr_module) || addr_module < user_space_boundary) {
      return NULL;
    }
  } else {
    uint64_t addr_kpcr = pcpu->get_segment_base(BX_SEG_REG_GS);
    if (addr_kpcr < user_space_boundary) {
      return NULL;
    }

    if (!read_lin_mem(pcpu, addr_kpcr + off_psloadedmodulelist, guest_ptr_size,
                      &addr_module)) {
      return NULL;
    }
  }

  // Iterate through driver information found in the kernel memory.
  uint64_t addr_module_start = addr_module;
  for (;;) {
    // Grab the base and image size.
    uint64_t base = 0;
    uint32_t imagesize = 0;
    if (!read_lin_mem(pcpu, addr_module + off_baseaddress, guest_ptr_size, &base) ||
        !read_lin_mem(pcpu, addr_module + off_sizeofimage, sizeof(uint32_t), &imagesize)) {
      return NULL;
    }

    // If "pc" belongs to the executable, read image name and insert a
    // descriptor in global database.
    if (imagesize != 0 && pc >= base && pc < base + imagesize) {
      uint16_t unicode_length = 0;
      uint64_t unicode_buffer = 0;

      if (!read_lin_mem(pcpu, addr_module + off_basedllname + off_us_len,
                        sizeof(uint16_t), &unicode_length)) {
        return NULL;
      }

      if (!read_lin_mem(pcpu, addr_module + off_basedllname + off_us_buffer,
                        guest_ptr_size, &unicode_buffer)) {
        return NULL;
      }

      if (unicode_length == 0 || unicode_buffer == 0) {
        return NULL;
      }

      static uint16_t unicode_name[130] = {0};
      unsigned to_fetch = unicode_length;
      if (to_fetch > 254) {
        to_fetch = 254;
      }

      if (!read_lin_mem(pcpu, unicode_buffer, to_fetch, &unicode_name)) {
        return NULL;
      }

      size_t half_fetch = to_fetch / 2;  // to_fetch in unicode characters.
      static char module_name[16];
      for (unsigned i = 0; i < half_fetch && i < sizeof(module_name) - 1; i++) {
        module_name[i] = unicode_name[i];
      }
      module_name[std::min(half_fetch, sizeof(module_name) - 1)] = '\0';

      // Add to cache for future reference.
      module_info *mi = new module_info(base, imagesize, module_name);

      // ntoskrnl and win32k are the two most frequently seen drivers, so
      // put them into a prioritized list.
      if (!strcmp(module_name, "ntoskrnl.exe") || !strcmp(module_name, "win32k.sys")) {
        globals::special_modules.push_back(mi);
      } else {
        globals::modules.push_back(mi);
      }

      return mi;
    }

    if (!read_lin_mem(pcpu, addr_module + off_loadorder_flink, guest_ptr_size,
        &addr_module) || addr_module < user_space_boundary ||
        addr_module - off_loadorder_flink == addr_module_start) {
      return NULL;
    }

    addr_module -= off_loadorder_flink;
  }

  return NULL;
}

}  // namespace windows

#endif  // _WIN32

