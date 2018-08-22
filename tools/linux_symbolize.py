#!/usr/bin/python
#
# Authors: Mateusz Jurczyk (mjurczyk@google.com)
#          Gynvael Coldwind (gynvael@google.com)
#
# Copyright 2013 Google Inc. All Rights Reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http:#www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import popen2
import re
import sys

if len(sys.argv) < 3:
  print "usage: linux_symbolize.py <memlog.txt> <dbgsymbols> <kerneladdr>"
  sys.exit(1)

# KLine looks like this
# #0  0xffffffff813534bf (kernel+003534bf)

kerneladdr = 0xffffffff81000000
what_we_need = {}

f = open(sys.argv[1], "r")
for ln in f:
  m = re.match(r" #[0-9].*\(([^+]+)\+([0-9a-fA-F]+)\)", ln)
  if not m:
    continue

  what_we_need[(m.group(1), int(m.group(2), 16))] = 1

f.close()

# Send query.
(stdout, stdin) = popen2.popen2("addr2line -f -e %s" % sys.argv[2])
for k in what_we_need:
  stdin.write("%x\n" % (k[1] + kerneladdr))

stdin.close()

# Get answer.
for k in what_we_need:
  what_we_need[k] = "%24s %s" % (
      stdout.readline().strip(),
      stdout.readline().strip()
      )

f = open(sys.argv[1], "r")
for ln in f:
  m = re.match(r" #[0-9].*\(([^+]+)\+([0-9a-fA-F]+)\)", ln)
  if not m:
    sys.stdout.write(ln)
    continue

  k = (m.group(1), int(m.group(2), 16))
  print "%s %s" % (ln.rstrip(), what_we_need[k])

f.close()

