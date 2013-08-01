/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001-2013  The Bochs Project
//
//  Modified by Google Inc.
//    Mateusz Jurczyk (mjurczyk@google.com)
//    and Gynvael Coldwind (gynvael@google.com)
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
//
//  Modification note:
//    The code below is a modified version of bx_dbg_read_linear from Bochs
//    file \bx_debug\dbg_main.cc.
//    The interface was slightly modified by us.
//
/////////////////////////////////////////////////////////////////////////

#include "mem_interface.h"

// Function reads data from specified virtual memory address. Returns false
// on failure.
bool read_lin_mem(BX_CPU_C *pcpu, bx_address laddr, unsigned len, void *buf) {
  unsigned remainsInPage;
  bx_phy_address paddr;
  unsigned read_len;
  bx_bool paddr_valid;

next_page:
  remainsInPage = 0x1000 - PAGE_OFFSET(laddr);
  read_len = (remainsInPage < len) ? remainsInPage : len;

  paddr_valid = pcpu->dbg_xlate_linear2phy(laddr, &paddr);
  if (paddr_valid) {
    if (!BX_MEM(0)->dbg_fetch_mem(pcpu, paddr, read_len, (Bit8u*)buf)) {
      return false;
    }
  } else {
    return false;
  }

  /* check for access across multiple pages */
  if (remainsInPage < len) {
    laddr += read_len;
    len -= read_len;
    buf += read_len;
    goto next_page;
  }

  return true;
}

