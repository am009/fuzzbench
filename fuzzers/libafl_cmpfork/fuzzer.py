# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Integration code for a LibAFL-based fuzzer."""

import os
import shutil
import subprocess

from fuzzers import utils


def prepare_fuzz_environment(input_corpus):
    """Prepare to fuzz with a LibAFL-based fuzzer."""
    os.environ['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=0:'\
                                 'malloc_context_size=0:symbolize=0:'\
                                 'allocator_may_return_null=1:'\
                                 'detect_odr_violation=0:handle_segv=0:'\
                                 'handle_sigbus=0:handle_abort=0:'\
                                 'handle_sigfpe=0:handle_sigill=0'
    os.environ['UBSAN_OPTIONS'] =  'abort_on_error=1:'\
                                   'allocator_release_to_os_interval_ms=500:'\
                                   'handle_abort=0:handle_segv=0:'\
                                   'handle_sigbus=0:handle_sigfpe=0:'\
                                   'handle_sigill=0:print_stacktrace=0:'\
                                   'symbolize=0:symbolize_inline_frames=0'
    # Create at least one non-empty seed to start.
    utils.create_seed_file_for_empty_corpus(input_corpus)


def build():  # pylint: disable=too-many-branches,too-many-statements
    """Build benchmark."""

    os.environ['ASAN_OPTIONS'] = 'abort_on_error=0:allocator_may_return_null=1'
    os.environ['UBSAN_OPTIONS'] = 'abort_on_error=0'
    # CmpLog requires an build with different instrumentation.
    env2 = os.environ.copy()

    os.environ[
        'CC'] = '/libafl/fuzzers/fuzzbench/target/release-fuzzbench/libafl_clang_cc'
    os.environ[
        'CXX'] = '/libafl/fuzzers/fuzzbench/target/release-fuzzbench/libafl_clang_cxx'

    cflags = ['--libafl']
    utils.append_flags('CFLAGS', cflags)
    utils.append_flags('CXXFLAGS', cflags)
    utils.append_flags('LDFLAGS', cflags)

    os.environ['FUZZER_LIB'] = '/stub_rt.a'
    utils.build_benchmark()

    # For CmpLog build, set the OUT and FUZZ_TARGET environment
    # variable to point to the new CmpLog build directory.
    cmplog_build_directory = os.path.join(os.environ['OUT'], 'cmplog')
    os.makedirs(cmplog_build_directory, exist_ok=True)
    env2['OUT'] = cmplog_build_directory
    fuzz_target = os.getenv('FUZZ_TARGET')
    if fuzz_target:
        env2['FUZZ_TARGET'] = os.path.join(cmplog_build_directory,
                                                os.path.basename(fuzz_target))

    env2['CC'] = '/libafl/fuzzers/fuzzbench/target/release-fuzzbench/libafl_clang_cmplog_cc'
    env2['CXX'] = '/libafl/fuzzers/fuzzbench/target/release-fuzzbench/libafl_clang_cmplog_cxx'

    cflags = ['--libafl']
    utils.append_flags('CFLAGS', cflags, env=env2)
    utils.append_flags('CXXFLAGS', cflags, env=env2)
    utils.append_flags('LDFLAGS', cflags, env=env2)

    env2['FUZZER_LIB'] = '/stub_rt_cmplog.a'

    print('Re-building benchmark for CmpLog fuzzing target')
    path = os.environ['WORK']
    shutil.rmtree(path, ignore_errors=True)
    os.mkdir(path)
    utils.build_benchmark(env=env2)

def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    prepare_fuzz_environment(input_corpus)
    dictionary_path = utils.get_dictionary_path(target_binary)
    # add cmplog flag
    target_binary_directory = os.path.dirname(target_binary)
    cmplog_target_binary_directory = os.path.join(target_binary_directory, 'cmplog')
    target_binary_name = os.path.basename(target_binary)
    cmplog_target_binary = os.path.join(cmplog_target_binary_directory,
                                        target_binary_name)
    command = [target_binary, "-c", cmplog_target_binary]

    if dictionary_path:
        command += (['-x', dictionary_path])
    command += (['-o', output_corpus, '-i', input_corpus])
    fuzzer_env = os.environ.copy()
    fuzzer_env['LD_PRELOAD'] = '/usr/lib/x86_64-linux-gnu/libjemalloc.so.2'
    print(command)
    subprocess.check_call(command, cwd=os.environ['OUT'], env=fuzzer_env)
