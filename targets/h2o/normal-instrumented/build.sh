#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

pushd $SRC/h2o
sed 's/int fuzz_without_main(/int main(/' -i /src/h2o/src/main.c
cmake -DBUILD_FUZZER=ON -DOSS_FUZZ=ON -DOPENSSL_USE_STATIC_LIBS=TRUE .
sed 's/-O2/-fsanitize=fuzzer-no-link -O2/' -i /src/h2o/CMakeLists.txt
make

popd
