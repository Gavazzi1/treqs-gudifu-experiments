#!/bin/bash -eu
# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

mkdir -p /logs && chmod o+w /logs

cp -r $SRC/fuzz src/

cd src/fuzz
rm -rf genfiles && mkdir genfiles && $SRC/LPM/external.protobuf/bin/protoc http_request_proto.proto --cpp_out=genfiles
cd ../..

auto/configure \
    --with-cc-opt='-DNGX_DEBUG_PALLOC=1' \
    --with-http_v2_module 

sed 's/clang/clang -fsanitize=fuzzer-no-link/' -i /src/nginx/objs/Makefile

make
