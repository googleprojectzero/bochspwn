/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001-2013  The Bochs Project
//
//  Modified by Google LLC
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
//    This is basically a very narrow version of Bochs' /bx_debug/debug.h.
//    It's cut down to only one function.
//
/////////////////////////////////////////////////////////////////////////

#ifndef BOCHSPWN_MEM_INTERFACE_H_
#define BOCHSPWN_MEM_INTERFACE_H_

#include "bochs.h"
#include "cpu/cpu.h"

// Read linear memory.
bool read_lin_mem(BX_CPU_C *pcpu, bx_address laddr, unsigned len, void *buf);

#endif  // BOCHSPWN_MEM_INTERFACE_H_

