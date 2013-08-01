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

#ifndef KFETCH_TOOLKIT_INVOKE_H_
#define KFETCH_TOOLKIT_INVOKE_H_

#include "common.h"
#include "modes.h"
#include "os_linux.h"
#include "os_windows.h"
#include "os_freebsd.h"
#include "os_openbsd.h"

// ------------------------------------------------------------------
// kfetch-toolkit mode-related definitions.
// ------------------------------------------------------------------
const struct tag_kSupportedModes {
  const char *name;
  kfetch_mode mode;
} kSupportedModes[] = {
  {"offline", BX_MODE_OFFLINE},
  {"online_doublefetch", BX_MODE_ONLINE_DOUBLEFETCH},
  {NULL, BX_MODE_RESERVED}
};

enum mode_event_type {
  BX_MODE_EVENT_NEW_SYSCALL = 0,
  BX_MODE_EVENT_PROCESS_LOG,
  BX_MODE_EVENT_MAX
};

typedef bool (*m_event_handler_func)(void *, void *);

const struct tag_kModeEventHandlers {
  kfetch_mode mode;
  m_event_handler_func handlers[BX_MODE_EVENT_MAX];
} kModeEventHandlers[] = {
  {BX_MODE_OFFLINE,
   {(m_event_handler_func)modes::offline_new_syscall,
    (m_event_handler_func)modes::offline_process_log}
  },
  {BX_MODE_ONLINE_DOUBLEFETCH,
   {(m_event_handler_func)modes::online_df_new_syscall,
    (m_event_handler_func)modes::online_df_process_log}
  },
  {BX_MODE_RESERVED, {NULL, NULL}},
};

bool invoke_mode_handler(mode_event_type type, void *arg1, void *arg2);

// ------------------------------------------------------------------
// kfetch-toolkit system-related definitions.
// ------------------------------------------------------------------
const char *const kSupportedSystems[] = {
  "windows",
  "linux",
  "freebsd",
  "openbsd",
  NULL
};

enum os_event_type {
  BX_OS_EVENT_INIT = 0,
  BX_OS_EVENT_CHECK_KERNEL_ADDR,
  BX_OS_EVENT_CHECK_USER_ADDR,
  BX_OS_EVENT_FILL_CID,
  BX_OS_EVENT_FILL_INFO,
  BX_OS_EVENT_INSTR_BEFORE_EXECUTION,
  BX_OS_EVENT_MAX
};

typedef bool (*s_event_handler_func)(void *, void *);

const struct tag_kSystemEventHandlers {
  const char *system;
  s_event_handler_func handlers[BX_OS_EVENT_MAX];
} kSystemEventHandlers[] = {
  {"windows",
   {(s_event_handler_func)windows::init,
    (s_event_handler_func)windows::check_kernel_addr,
    (s_event_handler_func)windows::check_user_addr,
    (s_event_handler_func)windows::fill_cid,
    (s_event_handler_func)windows::fill_info,
    (s_event_handler_func)NULL}
  },
  {"linux",
   {(s_event_handler_func)linux::init,
    (s_event_handler_func)linux::check_kernel_addr,
    (s_event_handler_func)linux::check_user_addr,
    (s_event_handler_func)linux::fill_cid,
    (s_event_handler_func)linux::fill_info,
    (s_event_handler_func)NULL}
  },
  {"freebsd",
   {(s_event_handler_func)freebsd::init,
    (s_event_handler_func)freebsd::check_kernel_addr,
    (s_event_handler_func)freebsd::check_user_addr,
    (s_event_handler_func)freebsd::fill_cid,
    (s_event_handler_func)freebsd::fill_info,
    (s_event_handler_func)freebsd::instr_before_execution}
  },
  {"openbsd",
   {(s_event_handler_func)openbsd::init,
    (s_event_handler_func)openbsd::check_kernel_addr,
    (s_event_handler_func)openbsd::check_user_addr,
    (s_event_handler_func)openbsd::fill_cid,
    (s_event_handler_func)openbsd::fill_info,
    (s_event_handler_func)openbsd::instr_before_execution}
  },
  {NULL, {NULL, NULL, NULL, NULL, NULL}}
};

bool invoke_system_handler(os_event_type type, void *arg1, void *arg2);

#endif  // KFETCH_TOOLKIT_INVOKE_H_

