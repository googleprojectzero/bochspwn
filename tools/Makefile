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
# GNU make Linux Makefile
#

CXX = g++
CXXFLAGS = -Wall -Wextra
LDFLAGS = logging.pb.o common.o -lprotobuf
PROTOC = protoc

all: sep doubleread print nocidll imagefilename

common.o: common.cc common.h
	${CXX} ${CXXFLAGS} -c $< -o $@

logging.pb.h logging.pb.cc: logging.proto
	${PROTOC} logging.proto --cpp_out=.

logging.pb.o: logging.pb.cc logging.pb.h
	${CXX} ${CXXFLAGS} -c logging.pb.cc -o $@

sep: sep.cc logging.pb.o common.o
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

doubleread: doubleread.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

print: print.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

nocidll: nocidll.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

imagefilename: imagefilename.cc logging.pb.o common.o 
	${CXX} ${CXXFLAGS} $< -o $@ ${LDFLAGS}

clean:
	rm *.o
	rm logging.pb.*

