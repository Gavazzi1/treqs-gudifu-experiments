#!/bin/bash -eu
# Copyright 2018 Google Inc.
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

# These options are added to make sure that the code instrumentation happens.

pushd /src/envoy
sed 's/int fuzz_without_main(/int main(/' -i /src/envoy/source/exe/main.cc
python3 tools/github/write_current_source_version.py

#bazel build --verbose_failures --dynamic_mode=off --spawn_strategy=standalone --genrule_strategy=standalone --local_cpu_resources=HOST_CPUS*0.256 --//source/extensions/wasm_runtime/v8:enabled=false --build_tag_filters=-no_asan --config=oss-fuzz --linkopt=-fsanitize=fuzzer-no-link --copt=-fsanitize=fuzzer-no-link envoy

#echo "showme: BUILD 1 done!"

sed 's/int main(/int fuzz_without_main(/' -i /src/envoy/source/exe/main.cc

#bazel build //source/exe:envoy_main_entry_lib

#echo "showme: BUILD 2 done!"

#bazel build --copt="-fsanitize=fuzzer" --subcommands //source/exe:fuzz-diff
#sed 's/        linkopts = \[\],/        linkopts = [],\n        copts = [],/' -i /src/envoy/bazel/envoy_binary.bzl
if ! (grep -q "copts = \[\]" /src/envoy/bazel/envoy_binary.bzl); then
        sed 's/        linkopts = \[\],/        linkopts = [],\n        copts = [],/' -i /src/envoy/bazel/envoy_binary.bzl;
fi
if ! (grep -q "#\"-Wold-style-cast\"" /src/envoy/bazel/envoy_internal.bzl); then
        sed 's/"-Wold-style-cast"/#"-Wold-style-cast"/' -i /src/envoy/bazel/envoy_internal.bzl
fi

if ! (grep -q "fuzz-diff" /src/envoy/source/exe/BUILD); then

cat << END >> /src/envoy/source/exe/BUILD 

envoy_cc_binary(
    name = "fuzz-diff",
    srcs = ["fuzz-diff.cc"],
    features = select({
        "//bazel:windows_opt_build": ["generate_pdb_file"],
        "//conditions:default": [],
    }),
    stamped = True,
    deps = [":envoy_main_entry_lib"],
    copts = [ "-fsanitize=fuzzer",],
    linkopts = ["/usr/lib/libFuzzingEngine.a"],
)

END

fi

bazel build --verbose_failures --dynamic_mode=off --spawn_strategy=standalone --genrule_strategy=standalone --local_cpu_resources=HOST_CPUS*0.256 --//source/extensions/wasm_runtime/v8:enabled=false --build_tag_filters=-no_asan --config=oss-fuzz --copt=-fsanitize=fuzzer-no-link //source/exe:fuzz-diff
echo "showme: BUILD 3 done!"
popd

