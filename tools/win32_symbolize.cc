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

#include <cstdio>
#include <cstdlib>
#include <string>
#include <windows.h>
#define _NO_CVCONST_H
#include <Dbghelp.h>

bool GetFileParams(const PCHAR file_name, DWORD64 *base_addr, DWORD *file_size);
bool GetFileSize(const PCHAR file_name, DWORD *file_size);
void ShowSymbolDetails(SYMBOL_INFO *sym_info, DWORD64 address); 

struct CSymbolInfoPackage : public SYMBOL_INFO_PACKAGE {
  CSymbolInfoPackage() {
    si.SizeOfStruct = sizeof(SYMBOL_INFO); 
    si.MaxNameLen = sizeof(name); 
  }
};

int main(int argc, char **argv) {
  bool ret;

  if (argc < 3) {
    fprintf(stderr, "Usage: %s <.pdb file path> <symbol offset>\n", argv[0]);
    return EXIT_FAILURE;
  }

  DWORD64 sym_offset = 0;
  if (sscanf(argv[2], "%x", &sym_offset) != 1) {
    fprintf(stderr, "Usage: %s <.pdb file path> <symbol offset>\n", argv[0]);
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
    const PCHAR file_name = argv[1];
    DWORD64 base_address  = 0; 
    DWORD file_size = 0; 

    if (!GetFileParams(file_name, &base_address, &file_size)) { 
      printf("???+%.8x\n", sym_offset);
      fprintf(stderr, "Cannot obtain file parameters\n");
      break;
    }

    DWORD64 mod_base = SymLoadModule64(GetCurrentProcess(), NULL, file_name, NULL, base_address, file_size);
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
      ShowSymbolDetails(&sip.si, displacement);
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

bool GetFileParams(const PCHAR file_name, DWORD64 *base_addr, DWORD *file_size) {
  if (!file_name) {
    return false;
  }

  *base_addr = 0x10000000;
  return GetFileSize(file_name, file_size);
}

bool GetFileSize(const PCHAR file_name, DWORD *file_size) {
  if (!file_name) {
    return false;
  }

  HANDLE file = CreateFile(file_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); 
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }

  *file_size = GetFileSize(file, NULL); 
  CloseHandle(file);

  return (*file_size != INVALID_FILE_SIZE);
}

void ShowSymbolDetails(SYMBOL_INFO *sym_info, DWORD64 displacement)  {
  printf("%s+%.8llx\n", sym_info->Name, displacement);
}

