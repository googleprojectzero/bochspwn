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

#ifndef BOCHSPWN_INVOKE_H_
#define BOCHSPWN_INVOKE_H_

#include "common.h"
#include "events.h"
#include "os_linux.h"
#include "os_windows.h"
#include "os_freebsd.h"
#include "os_openbsd.h"

// ------------------------------------------------------------------
// Bochspwn system-related definitions.
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

#endif  // BOCHSPWN_INVOKE_H_

