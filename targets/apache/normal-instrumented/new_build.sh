#!/bin/bash -eu
# Copyright 2021 Google LLC
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

unset CPP
unset CXX
export LDFLAGS="-l:libbsd.a"

# Download apr and place in httpd srclib folder. Apr-2.0 includes apr-utils
svn checkout https://svn.apache.org/repos/asf/apr/apr/trunk/ srclib/apr

# Build httpd
./buildconf
./configure --with-included-apr --enable-pool-debug
sed 's/clang/clang -fsanitize=fuzzer-no-link/g' -i /src/httpd/config.status
make
./configure --with-included-apr --enable-pool-debug --enable-proxy=static --enable-proxy-http=static --enable-unixd=static --enable-authz-core=static --enable-slotmem-shm=static
sed 's/clang/clang -fsanitize=fuzzer-no-link/g' -i /src/httpd/config.status
make
