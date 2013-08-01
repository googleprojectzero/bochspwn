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

#include "invoke.h"

#include <stdint.h>

#include "common.h"

bool invoke_mode_handler(mode_event_type type, void *arg1, void *arg2) {
  static const m_event_handler_func *h = NULL;

  if (!h) {
    kfetch_mode m = globals::config.mode;

    unsigned int i;
    for (i = 0; kModeEventHandlers[i].mode != BX_MODE_RESERVED; i++) {
      if (kModeEventHandlers[i].mode == m) {
        break;
      }
    }

    if (kModeEventHandlers[i].mode == BX_MODE_RESERVED) {
      abort();
    }

    h = kModeEventHandlers[i].handlers;
  }

  return h[type](arg1, arg2);
}

bool invoke_system_handler(os_event_type type, void *arg1, void *arg2) {
  static const s_event_handler_func *h = NULL;

  if (!h) {
    char *system = globals::config.system;

    unsigned int i;
    for (i = 0; kSystemEventHandlers[i].system != NULL; i++) {
      if (!strcmp(system, kSystemEventHandlers[i].system)) {
        break;
      }
    }

    if (!kSystemEventHandlers[i].system) {
      abort();
    }

    h = kSystemEventHandlers[i].handlers;
  }

  return h[type](arg1, arg2);
}


