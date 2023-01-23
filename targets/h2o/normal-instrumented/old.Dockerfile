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
FROM oss-fuzz-base/new-base-builder:v2.1

RUN apt-get update && apt-get install -y make vim
#RUN git clone https://github.com/haproxy/haproxy
RUN wget http://www.haproxy.org/download/2.7/src/haproxy-2.7.1.tar.gz && tar xvzf haproxy-2.7.1.tar.gz && mv haproxy-2.7.1 haproxy && rm haproxy-2.7.1.tar.gz

WORKDIR $SRC

COPY build.sh $SRC/build.sh
COPY fuzz* $SRC/
COPY echo_server.py $SRC/
COPY haproxy.cfg /tmp/haproxy.cfg
RUN cp /src/haproxy/src/haproxy.c /tmp/haproxy.c && cp /src/haproxy/src/tools.c /tmp/tools.c && sed '/broken tool/{n;s/if/if (1==3 \&\& /;s/ {/) {/}' -i /tmp/haproxy.c
RUN /usr/local/bin/compile_libfuzzer && mkdir /tmp/corpus && bash /src/build.sh
COPY seed /tmp/corpus/seed

ENTRYPOINT (python3 /src/echo_server.py haproxy &) && (/src/haproxy/haproxy -f /tmp/haproxy.cfg &) && tail -f /dev/null

#docker run -d -p 30005:8000 target/haproxy-normal:v0.2
