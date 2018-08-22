#
# Authors: Mateusz Jurczyk (mjurczyk@google.com)
#          Gynvael Coldwind (gynvael@google.com)
#
# Copyright 2013-2018 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

CXX = g++
CXXFLAGS = -Wall -Wextra -O3 -Wno-format
LDFLAGS = logging.pb.o common.o -lprotobuf
PROTOC = protoc

all: print stats doubleread separate unhandled_access count_callstack_depth count_excp_handlers no_cidll win32_symbolize

common.o: common.cc common.h
	${CXX} ${CXXFLAGS} -c $< -o $@

logging.pb.h logging.pb.cc: logging.proto
	${PROTOC} logging.proto --cpp_out=.

logging.pb.o: logging.pb.cc logging.pb.h
	${CXX} ${CXXFLAGS} -c logging.pb.cc -o $@

print: print.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

stats: stats.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

doubleread: doubleread.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

separate: separate.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

unhandled_access: unhandled_access.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

count_callstack_depth: count_callstack_depth.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

count_excp_handlers: count_excp_handlers.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

no_cidll: no_cidll.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

win32_symbolize: win32_symbolize.cc
	${CXX} ${CXXFLAGS} $< -o $@ -ldbghelp -lpsapi

clean:
	rm *.o
	rm logging.pb.*
