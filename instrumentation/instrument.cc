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

#include <stdint.h>
#include <stdarg.h>
#include <map>
#include <string>
#include <vector>
#include <windows.h>

#include "bochs.h"
#include "cpu/cpu.h"
#include "disasm/disasm.h"

#include "common.h"
#include "instrument.h"
#include "invoke.h"
#include "logging.pb.h"
#include "symbols.h"

// ------------------------------------------------------------------
// Helper declarations.
// ------------------------------------------------------------------
static bool init_basic_config(const char *path, kfetch_config *instr_config);
static void process_mem_access(BX_CPU_C *pcpu, bx_address lin, unsigned len, bx_address pc,
                               log_data_st::mem_access_type access_type, char *disasm);
static void destroy_globals();

// ------------------------------------------------------------------
// Instrumentation implementation.
// ------------------------------------------------------------------

// Callback invoked on Bochs CPU initialization.
void bx_instr_initialize(unsigned cpu) {
  char *conf_path = NULL;
  BX_CPU_C *pcpu = BX_CPU(cpu);

  // Initialize symbols subsystem.
  symbols::initialize();

  // Obtain configuration file path.
  if (conf_path = getenv(kConfFileEnvVariable), !conf_path) {
    fprintf(stderr, "Configuration file not specified in \"%s\"\n",
            kConfFileEnvVariable);
    abort();
  }

  // Read basic configuration from .ini file.
  if (!init_basic_config(conf_path, &globals::config)) {
    fprintf(stderr, "Initialization with config file \"%s\" failed\n", conf_path);
    abort();
  }

  // Initialize output file handle for the first time.
  globals::config.file_handle = fopen(globals::config.log_path, "wb");
  if (!globals::config.file_handle) {
    fprintf(stderr, "Unable to open the \"%s\" log file\n", globals::config.log_path);
    abort();
  }
  // Set internal buffer size to 32kB for performance reasons.
  setvbuf(globals::config.file_handle, NULL, _IOFBF, 32 * 1024);

  // Allow the guest-specific part to initialize (read internal offsets etc).
  if (!invoke_system_handler(BX_OS_EVENT_INIT, conf_path, NULL)) {
    fprintf(stderr, "Guest-specific initialization with file \"%s\" failed\n", conf_path);
    abort();
  }
}

// Callback invoked on destroying a Bochs CPU object.
void bx_instr_exit(unsigned cpu) {
  // Free the symbols subsystem.
  symbols::destroy();

  // Free allocations in global structures.
  destroy_globals();
}

// Callback called on attempt to access linear memory.
//
// Note: the BX_INSTR_LIN_ACCESS instrumentation doesn't work when
// repeat-speedups feature is enabled. Always remember to set
// BX_SUPPORT_REPEAT_SPEEDUPS to 0 in config.h, otherwise kfetch-toolkit might
// not work correctly.

void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_phy_address phy, unsigned len, unsigned memtype, unsigned rw) {
  BX_CPU_C *pcpu = BX_CPU(cpu);

  // Not going to use physical memory address.
  (void)phy;

  // Read-write instructions are currently not interesting.
  if (rw == BX_RW)
    return;

  // Is the CPU in protected or long mode?
  unsigned mode = 0;

  // Note: DO NOT change order of these ifs. long64_mode must be called
  // before protected_mode, since it will also return "true" on protected_mode
  // query (well, long mode is technically protected mode).
  if (pcpu->long64_mode()) {
#if BX_SUPPORT_X86_64
    mode = 64;
#else
    return;
#endif  // BX_SUPPORT_X86_64
  } else if (pcpu->protected_mode()) {
    // This is either protected 32-bit mode or 32-bit compat. long mode.
    mode = 32;
  } else {
    // Nothing interesting.
    // TODO(gynvael): Well actually there is the smm_mode(), which
    // might be a little interesting, even if it's just the bochs BIOS
    // SMM code.
    return;
  }

  // Is pc in kernel memory area?
  // Is lin in user memory area?
  bx_address pc = pcpu->prev_rip;
  if (!invoke_system_handler(BX_OS_EVENT_CHECK_KERNEL_ADDR, &pc, NULL) ||
      !invoke_system_handler(BX_OS_EVENT_CHECK_USER_ADDR, &lin, NULL)) {
    return; /* pc not in ring-0 or lin not in ring-3 */
  }

  // Check if the access meets specified operand length criteria.
  if (rw == BX_READ) {
    if (len < globals::config.min_read_size || len > globals::config.max_read_size) {
      return;
    }
  } else {
    if (len < globals::config.min_write_size || len > globals::config.max_write_size) {
      return;
    }
  }

  // Save basic information about the access.
  log_data_st::mem_access_type access_type;
  switch (rw) {
    case BX_READ:
      access_type = log_data_st::MEM_READ;
      break;
    case BX_WRITE:
      access_type = log_data_st::MEM_WRITE;
      break;
    case BX_EXECUTE:
      access_type = log_data_st::MEM_EXEC;
      break;
    case BX_RW:
      access_type = log_data_st::MEM_RW;
      break;
    default: abort();
  }

  // Disassemble current instruction.
  static Bit8u ibuf[32] = {0};
  static char pc_disasm[64];
  if (read_lin_mem(pcpu, pc, sizeof(ibuf), ibuf)) {
    static disassembler bx_disassemble;
    bx_disassemble.disasm(mode == 32, mode == 64, 0,
                          pc, ibuf, pc_disasm);
  }

  // With basic information filled in, process the access further.
  process_mem_access(pcpu, lin, len, pc, access_type, pc_disasm);
}

// Callback invoked before execution of each instruction takes place.
// Used to intercept system call invocations.
void bx_instr_before_execution(unsigned cpu, bxInstruction_c *i) {
  static client_id thread;
  BX_CPU_C *pcpu = BX_CPU(cpu);
  unsigned opcode;

  // If the system needs an additional invokement from here, call it now.
  if (globals::has_instr_before_execution_handler) {
    invoke_system_handler(BX_OS_EVENT_INSTR_BEFORE_EXECUTION, pcpu, i);
  }

  // Any system-call invoking instruction is interesting - this
  // is mostly due to 64-bit Linux which allows various ways
  // to be used for system-call invocation.
  // Note: We're not checking for int1, int3 nor into instructions.
  opcode = i->getIaOpcode();
  if (opcode != BX_IA_SYSCALL && opcode != BX_IA_SYSENTER && opcode != BX_IA_INT_Ib) {
    return;
  }

  // Obtain information about the current process/thread IDs.
  if (!invoke_system_handler(BX_OS_EVENT_FILL_CID, pcpu, &thread)) {
    return;
  }

  // Process information about a new syscall depending on the current mode.
  if (!invoke_mode_handler(BX_MODE_EVENT_NEW_SYSCALL, pcpu, &thread)) {
    return;
  }
}

// ------------------------------------------------------------------
// Helper functions' implementation.
// ------------------------------------------------------------------

static bool init_basic_config(const char *config_path, kfetch_config *config) {
  static char buffer[256];

  // Output file path.
  READ_INI_STRING(config_path, "general", "log_path", buffer, sizeof(buffer));
  config->log_path = strdup(buffer);

  // Logging mode.
  READ_INI_STRING(config_path, "general", "mode", buffer, sizeof(buffer));

  bool found = false;
  for (unsigned int i = 0; kSupportedModes[i].name != NULL; i++) {
    if (!strcmp(buffer, kSupportedModes[i].name)) {
      config->mode = kSupportedModes[i].mode;
      found = true;
      break;
    }
  }
  if (!found) {
    fprintf(stderr, "Unsupported kfetch-toolkit mode \"%s\"\n", buffer);
    return false;
  }

  // Operating system.
  READ_INI_STRING(config_path, "general", "os", buffer, sizeof(buffer));

  found = false;
  for (unsigned int i = 0; kSupportedSystems[i] != NULL; i++) {
    if (!strcmp(buffer, kSupportedSystems[i])) {
      config->system = strdup(buffer);
      found = true;
      break;
    }
  }
  if (!found) {
    fprintf(stderr, "Unsupported system \"%s\"\n", buffer);
    return false;
  }

  // Bitness.
  READ_INI_INT(config_path, "general", "bitness", buffer, sizeof(buffer), &config->bitness);
  if (config->bitness != 32 && config->bitness != 64) {
    fprintf(stderr, "Only 32 and 64 bitness allowed\n");
    return false;
  }

  // System version.
  READ_INI_STRING(config_path, "general", "version", buffer, sizeof(buffer));
  config->os_version = strdup(buffer);

  // Minimum and maximum length of read and write operations.
  READ_INI_INT(config_path, "general", "min_read_size", buffer, sizeof(buffer),
               &config->min_read_size);
  READ_INI_INT(config_path, "general", "max_read_size", buffer, sizeof(buffer),
               &config->max_read_size);
  READ_INI_INT(config_path, "general", "min_write_size", buffer, sizeof(buffer),
               &config->min_write_size);
  READ_INI_INT(config_path, "general", "max_write_size", buffer, sizeof(buffer),
               &config->max_write_size);

  // Maximum length of callstack.
  READ_INI_INT(config_path, "general", "callstack_length", buffer, sizeof(buffer),
               &config->callstack_length);

  // "Write as text" debugging feature.
  READ_INI_INT(config_path, "general", "write_as_text", buffer, sizeof(buffer),
               &config->write_as_text);

  // Symbolization settings.
  READ_INI_INT(config_path, "general", "symbolize", buffer, sizeof(buffer),
               &config->symbolize);
  READ_INI_STRING(config_path, "general", "symbol_path", buffer, sizeof(buffer));
  config->symbol_path = strdup(buffer);

  return true;
}

static void process_mem_access(BX_CPU_C *pcpu, bx_address lin, unsigned len,
                               bx_address pc, log_data_st::mem_access_type access_type,
                               char *disasm) {
  static unsigned last_repeated = 0;

  // Is this a continuous memory access (e.g. inlined memcpy or memcmp)?
  if (globals::last_ld.pc() != pc   ||
      globals::last_ld.len() != len ||
      globals::last_ld.lin() + globals::last_ld.len() * last_repeated != lin ||
      globals::last_ld.access_type() != access_type ||
      !globals::last_ld_present) {
    // It's a separate one. Print out last_ld if it was present.
    if (globals::last_ld_present) {
      globals::last_ld.set_repeated(last_repeated);
      invoke_mode_handler(BX_MODE_EVENT_PROCESS_LOG, NULL, NULL);
    }

    globals::last_ld.Clear();
    globals::last_ld.set_lin(lin);
    globals::last_ld.set_len(len);
    globals::last_ld.set_pc(pc);
    globals::last_ld.set_access_type(access_type);
    globals::last_ld.set_pc_disasm(disasm);

    last_repeated = 1;
    globals::last_ld_present = invoke_system_handler(BX_OS_EVENT_FILL_INFO, pcpu, NULL);
  } else {
    // Continuation.
    last_repeated++;
  }
}

static void destroy_globals() {
  for (unsigned int i = 0; i < globals::modules.size(); i++) {
    delete globals::modules[i];
  }
  globals::modules.clear();

  for (unsigned int i = 0; i < globals::special_modules.size(); i++) {
    delete globals::special_modules[i];
  }
  globals::special_modules.clear();

  globals::thread_states.clear();

  globals::last_ld_present = false;

  globals::online::known_callstack_item.clear();
}

