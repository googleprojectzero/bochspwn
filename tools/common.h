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

#ifndef BOCHSPWN_COMMON_H_
#define BOCHSPWN_COMMON_H_

#include <stdint.h>
#include <string>
#include <vector>

#include "logging.pb.h"

struct module_info {
  uint64_t base;
  uint64_t size;
  std::string name;
};

bool LoadModuleList(const std::string& module_list_path, std::vector<module_info> *module_list);
std::string LogDataAsText(const log_data_st& ld, const std::vector<module_info>& modules);
log_data_st *LoadNextRecord(FILE *f, std::string *out_protobuf, log_data_st *ld);

#endif  // BOCHSPWN_COMMON_H_
