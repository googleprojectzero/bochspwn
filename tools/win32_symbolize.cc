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

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#define _NO_CVCONST_H
#include <Dbghelp.h>

struct CSymbolInfoPackage : public SYMBOL_INFO_PACKAGE {
  CSymbolInfoPackage() {
    si.SizeOfStruct = sizeof(SYMBOL_INFO); 
    si.MaxNameLen = sizeof(name); 
  }
};

static void usage(const char *program_name) {
  fprintf(stderr, "Usage: %s <.pdb file path> <symbol offset>\n", program_name);
}

int main(int argc, char **argv) {
  bool ret;

  if (argc < 3) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  DWORD64 sym_offset = 0;
  if (sscanf(argv[2], "%x", &sym_offset) != 1) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  DWORD options = SymGetOptions(); 
  options |= SYMOPT_DEBUG; 
  SymSetOptions(options); 

  ret = SymInitialize(GetCurrentProcess(), NULL, FALSE);
  if (!ret) {
    printf("???+%.8x\n", sym_offset);
    fprintf(stderr, "SymInitialize() failed, %u\n", GetLastError());
    return EXIT_FAILURE;
  }

  do {
    // Since we are only loading a single symbol file with DbgHelp, we can "fake"
    // both the base address to have a constant, arbitrary value, and the image size
    // to be a fixed length that is guaranteed to be large enough to cover every
    // possible real image size.
    const PCHAR file_name = argv[1];
    const DWORD64 base_address  = 0x10000000;
    const DWORD image_size = 0x10000000;

    DWORD64 mod_base = SymLoadModule64(GetCurrentProcess(), NULL, file_name, NULL, base_address, image_size);
    if (!mod_base) {
      printf("???+%.8x\n", sym_offset);
      fprintf(stderr, "SymLoadModule64() failed, %u\n", GetLastError());
      break;
    }

    CSymbolInfoPackage sip;
    DWORD64 displacement = 0; 

    ret = SymFromAddr(GetCurrentProcess(), base_address + sym_offset, &displacement, &sip.si);
    if (!ret) {
      printf("???+%.8x\n", sym_offset);
      fprintf(stderr, "SymFromAddr() failed, %u\n", GetLastError());
      break;
    } else {
      printf("%s+%.8llx\n", sip.si.Name, displacement);
    }

    ret = SymUnloadModule64(GetCurrentProcess(), mod_base);
    if (!ret) {
      fprintf(stderr, "SymUnloadModule64() failed, %u\n", GetLastError());
    }
  } while (0);

  ret = SymCleanup(GetCurrentProcess());
  if (!ret) {
    fprintf(stderr, "SymCleanup() failed, %u\n", GetLastError());
  }

  return 0; 
}
