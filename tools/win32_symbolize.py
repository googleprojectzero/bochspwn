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

import os
import sys
import re
import subprocess

def main(argv):
  if len(argv) < 3:
    sys.stderr.write("Usage: %s <log file> <symbols directory>\n" % sys.argv[0])
    sys.exit(1)

  try:
    f = open(argv[1], "r")
  except:
    sys.stderr.write("Unable to open input file \"%s\"\n" % argv[1])
    sys.exit(1)

  symbols_path = sys.argv[2]
  for line in f:
    while True:

      match = re.match("([a-zA-Z0-9]+\.[a-z]+)\+([0-9a-fA-F]+).*", line)
      if match == None:
        match = re.match(".*[^a-zA-Z0-9.]+([a-zA-Z0-9]+\.[a-z]+)\+([0-9a-fA-F]+).*", line)
        if match == None:
          break
    
      image_name = match.group(1)
      offset = match.group(2)

      # Look up a corresponding pdb file
      file_name, file_ext = os.path.splitext(image_name)
      pdb_path = symbols_path + "/" + file_name + ".pdb"

      if os.path.isfile(pdb_path) == False:
        sys.stderr.write("PDB file \"%s\" for module \"%s\" not found\n" % (pdb_path, image_name))
        break

      p = subprocess.Popen(["win32_symbolize.exe", pdb_path, offset], 
                           stdout = subprocess.PIPE, stderr = subprocess.PIPE)
      stdout, stderr = p.communicate()
      
      if p.returncode != 0:
        sys.stderr.write("Native symbolizer failed with code %u: \"%s\"\n" % (p.returncode, stderr))
      else:
        line = line.replace("%s+%s" % (image_name, offset), "(%.8x) %s!%s" % (int(offset, 16), file_name, stdout.strip()))

    # Display the final version of the line
    print line.strip()

  f.close()

if __name__ == "__main__":
  main(sys.argv)

