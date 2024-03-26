# SBFT'24 Fuzzing Competition Writeup (Team Mystique)

In [SBFT'24 fuzzing competition](https://sbft24.github.io/tools/fuzzing), each fuzzer runs on 1 vCPU and 3.75 GB memory for 23h on different benchmarks.

The final code of our team Mystique is available [here](https://github.com/am009/LibAFL-SBFT24/tree/SBFT24-final).

TODO: 

- add link to our SBFT'24 paper

### Useful Links

1. [SBFT'23](https://sbft23.github.io/tools/fuzzing)：  [paper report](https://arxiv.org/pdf/2304.10070.pdf),  [papers for each tool](https://sbft23.github.io/papers/),  [slides](https://sbft23.github.io/share/fuzzing_slides.pdf)
   1. Fuzzbench reports: [Bug](https://storage.googleapis.com/www.fuzzbench.com/reports/experimental/SBFT23/Final-Bug/index.html) and  [Coverage](https://storage.googleapis.com/www.fuzzbench.com/reports/experimental/SBFT23/Final-Coverage/index.html). Related data files are on [www.fuzzbench.com](https://console.cloud.google.com/storage/browser/www.fuzzbench.com) and [fuzzbench-data](https://console.cloud.google.com/storage/browser/fuzzbench-data)
      1. SBFT'23 full benchmark is at [this commit](https://github.com/google/fuzzbench/commits/614a601b50ed154b3514e0eb65c1a9690c47bbef). Because they cannot afford running all these benchmarks, in [this PR](https://github.com/google/fuzzbench/pull/1789), many benchmarks are removed.
      2. yml files for reproduction：search sbft in [this page](https://storage.googleapis.com/fuzzbench-data/index.html)
   2. Hastefuzz：[paper](https://github.com/AAArdu/hastefuzz/blob/main/hastefuz_fuzzing_competition.pdf), [github](https://github.com/AAArdu/hastefuzz). Diff their code with AFL++ commit 33eba1fc5652060e8d877b02135fce2325813d0c.
   3. Pastis [blog](https://blog.quarkslab.com/pastis-for-the-win.html), [slides](https://sbft23.github.io/share/pastis.pdf),  [code](https://github.com/google/fuzzbench/pulls?q=is%3Apr+Pastis+), [paper](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=10190371). performs well on bug-based benchmarks. Integrates two fuzzers.
   4. AFLrustrust is the forkserver version of LibAFL: [paper](https://aflplus.plus/papers/aflrustrust-sbst23.pdf), [code](https://github.com/google/fuzzbench/pull/1616/files) 
   5. LibAFL_libFuzzer: [paper](https://aflplus.plus/papers/libafl_libfuzzer_sbst23.pdf), [code](https://github.com/AFLplusplus/LibAFL/tree/ed4178ecd12636fa054b18d1fc716ac414e90440/libafl_libfuzzer) 
2. learning existing fuzzers
   1. honggfuzz: [github repo](https://github.com/google/honggfuzz/blob/master/docs/USAGE.md), [website](https://honggfuzz.dev/)
   2. LibAFL: [book](https://aflplus.plus/libafl-book)
3. Existing fuzzing Techniques
   1. Input to state (redqueen) [paper](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04A-2_Aschermann_paper.pdf)
   2. Cmplog [afl++ readme](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.cmplog.md?ref=blog.isosceles.com)
4. Others
   1. [Improving honggfuzz for fuzzbench](https://groups.google.com/g/fuzzing-discuss/c/rv59P0svXjI/m/IYLZbiScAQAJ) 


## Preparations

We first decided to base our fuzzer on the latest [Libafl fuzzbench integration](https://github.com/AFLplusplus/LibAFL/tree/8c62d339a2652e224dbe15f626c87e512a5e1005/fuzzers/fuzzbench). It uses Rust, and works great on existing benchmarks. There is another integration called ["fuzzbench_forkserver"](https://github.com/AFLplusplus/LibAFL/tree/8c62d339a2652e224dbe15f626c87e512a5e1005/fuzzers/fuzzbench_forkserver) (aflrustrust). It uses various advanced features including forkserver, AFL++CmpLog, [dict2file](https://github.com/google/fuzzbench/blob/ae21be9dff84936e64b2525ab4ea1411a0b81529/fuzzers/aflrustrust/fuzzer.py#L28), but based on our local experiment, it is not as good as the "fuzzbench" one.

**Fixing compilation bugs**: First, we decided to base our fuzzer on the latest LibAFL. It uses a recent version of rust toolchain, so we installed clang-16. Then we encountered some compilation bugs. It turned out that, the libafl compiler wrapper also uses the clang-16, and the issue is caused by the change of the default values of some flags (during the compilation of ffmpeg, related to address sanitizer's ODR (`-fsanitize-address-use-odr-indicator`). See this [blog](http://wjk.moe/2023/FFmpeg+Santinizer%E7%BC%96%E8%AF%91%E6%97%B6%E7%9A%84%E5%A5%87%E6%80%AA%E9%97%AE%E9%A2%98/)). Instead of fixing these issues, we make the wrapper use the default clang 14.

**Trace Mutations**: See [this commit](https://github.com/am009/LibAFL-SBFT24/commit/7e302e743d6176f66f5cec70099dc962ee8f0689). There is some metadata attached to each testcase in the queue. We add some code to record its parent testcase (which testcase it is mutated from), and the mutator used. It only records the outmost mutator, which is not very informative, because most of the mutators are composed together in the `StdMOptMutator`. (It scheduled other mutators using techniques mentioned in the paper "MPot: optimized mutation scheduling for fuzzers")

In LibAFL, the code paths of saving a testcase to queue and saving a testcase that triggered a crash are completely different. When there is a crash, the input is saved in the crash handler.

## Optimizations

**Implement the "haste-mode"**: In SBFT'23, [HasteFuzz](https://github.com/AAArdu/hastefuzz/blob/main/hastefuz_fuzzing_competition.pdf) won the first prize in the coverage-based benchmarks. We first implemented their optimization to improve coverage in [this commit](https://github.com/am009/LibAFL-SBFT24/commit/5519a99e099c357e92d598de130cc130b5f4bffc).

As we all know AFL uses an edge coverage map. There is a global edge map containing all edges met in all testcases. Only when a testcase finds at least one previously undiscovered edge, it will be considered interesting.

For each run, before checking for new edges, hastefuzz has an additional filter step. It calculates a 30-bit hash (`xxhash_rust::xxh3`) of the coverage map and maintains a 10^30 map for the occurrence of each hash value. If a hash value is not new, then this run is recognized as uninteresting without further processing.

The initial implementation uses one byte for each hash value, but we only need 1 bit to signify the occurrence. [This commit](https://github.com/am009/LibAFL-SBFT24/commit/e08b44607f9813e6bd7626871887264924c71aa8) did the optimization.

We ran a 23h experiment with 5 retries for each benchmark.

|                               | libafl_haste | libafl_old  | aflrustrust |
| ----------------------------- | ------------ | ----------- | ----------- |
| FuzzerMean                    | 94.41666667  | 93.33333333 | 89.91666667 |
| bloaty_fuzz_target            | 96           | 98          | 96          |
| botan_tls_server              | 99           | 99          | 100         |
| draco_draco_pc_decoder_fuzzer | 86           | 88          | 80          |
| freetype2_ftfuzzer            | 97           | 94          | 85          |
| harfbuzz_hb-shape-fuzzer      | 98           | 99          | 98          |
| lcms_cms_transform_fuzzer     | 93           | 93          | 95          |
| libpcap_fuzz_both             | 97           | 94          | 87          |
| mbedtls_fuzz_dtlsclient       | 91           | 87          | 74          |
| openthread_ot-ip6-send-fuzzer | 91           | 79          | 79          |
| proj4_proj_crs_to_crs_fuzzer  | 95           | 97          | 95          |
| sqlite3_ossfuzz               | 96           | 99          | 97          |
| stb_stbi_read_fuzzer          | 94           | 93          | 93          |


**Add masks for Cmplog**: The input is first mutated by the cmplog mutator, then by other mutators. We think the cmplog mutations can bypass bytes checking and other mutators should not corrupt it but focus on other areas. To protect cmplog's mutation, we add a mask in each input's metadata to mark the mutations of cmplog mutator and add a final restore step to restore the masked area (with a pre-defined probability).

When there is a cmplog map entry reporting that A is compared with B, then the cmplog mutations will try to match A (or B) in the input and replace it with B (or A).

There are five kinds of cmplog mutations: u8, u16, u32, u64, and bytes. We excluded u8 and u16 from masks.

(The `libafl_n_16` stands for the probability of the mask restoration step is n/16.)

|                               | libafl_8_16 | libafl_5_16 | libafl_3_16 | libafl_1_16 |
| ----------------------------- | ----------- | ----------- | ----------- | ----------- |
| FuzzerMean                    | 94.9        | 94.4        | 94.8        | 94.7        |
| bloaty_fuzz_target            | 98          | 99          | 99          | 98          |
| draco_draco_pc_decoder_fuzzer | 93          | 93          | 89          | 97          |
| **freetype2_ftfuzzer**        | 94          | 91          | 92          | 86          |
| harfbuzz_hb-shape-fuzzer      | 99          | 99          | 99          | 99          |
| lcms_cms_transform_fuzzer     | 96          | 97          | 97          | 96          |
| libpcap_fuzz_both             | 98          | 94          | 95          | 94          |
| **mbedtls_fuzz_dtlsclient**   | 79          | 85          | 83          | 97          |
| openthread_ot-ip6-send-fuzzer | 98          | 92          | 99          | 85          |
| sqlite3_ossfuzz               | 98          | 99          | 99          | 99          |
| stb_stbi_read_fuzzer          | 96          | 95          | 96          | 96          |

The coverage of `freetype2_ftfuzzer` increases with the increase of mask probability, but the coverage of `mbedtls_fuzz_dtlsclient` decreases.

**Lightweight forkserver for cmplog**(not included in the final fuzzer): The instrumentation of cmplog is probably too heavy and will decrease the execution speed. Currently, the binary is instrumented for edge coverage and for cmplog. There is a global flag to turn off the cmplog instrumentation. It's on only when the cmplog info is needed during mutation. However, when it is off, the program still needs to check for the flag at each instrumented location. 

To further optimize the speed of cmplog using the fork server (with the persistent mode), We can build two binary, one with only coverage instrumentation, and the other with only cmplog instrumentation. Then use the shared memory to share the cmplog map. The parent process is still an in-process fuzzer. When cmplog info is needed, it signals and waits for the child. The child executes the program with the input(also passed by shared memory), and the cmplog map is filled. Then the child sends SIGSTOP to itself, and the parent resumes execution.

[This commit](https://github.com/am009/LibAFL-SBFT24/commit/617b0f8597e643cdb2b1bd788f45762be8f3f93c) implements the trick. However, we find the coverage dropped. Probably the inter-process communication overhead is larger than the instrumentation?


|                           | libafl_old  | libafl_haste | libafl_8_16 | libafl_cmpfork_8_16 | libafl_cmpfork |
| ------------------------- | ----------- | ------------ | ----------- | ------------------- | -------------- |
| FuzzerMean                | 96.14285714 | 95.28571429  | 94.85714286 | 88                  | 83.85714286    |
| bloaty_fuzz_target        | 99          | 97           | 98          | 91                  | 92             |
| freetype2_ftfuzzer        | 96          | 90           | 96          | 81                  | 80             |
| harfbuzz_hb-shape-fuzzer  | 99          | 99           | 99          | 96                  | 96             |
| lcms_cms_transform_fuzzer | 96          | 95           | 95          | 59                  | 59             |
| libpcap_fuzz_both         | 97          | 94           | 94          | 94                  | 88             |
| mbedtls_fuzz_dtlsclient   | 87          | 94           | 86          | 97                  | 75             |
| sqlite3_ossfuzz           | 99          | 98           | 96          | 98                  | 97             |

### Lessons learned

- run an experiment for each small improvement, and be careful about the variance.
  - `botan_tls_server` is really unstable and may add variance to the result. We did not run this benchmark after we noticed it.
  - For new machines, remember to do the setup to reduce variance. 

### Other possible improvements

- Add more mutators for diversity to work better on bug-based benchmarks. investigate bug-based benchmarks to find out which mutator is better.
  - use tools like afl-cmin to select a subset of test cases. Trace how inputs are mutated.
- Tune some flags like AFL++'s AFL_MAX_DET_EXTRAS
- ~~Add good bytes during cmplog into the dictionary mutation?~~
- Use [libtokencap](https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/libtokencap/README.md), or capture constant bytes for dictionary mutation: (Already implemented in AFL++ and used by AFLrustrust in SBFT'23)
- A small improvements that can be tested: prevent the CmpLog mutator from mutate a range repeatedly.
  - Because when there is a cmplog entry (byte seq A, byte seq B), it add two mutation (A -> B) and (B -> A). The CmpLog mutator is composed under the `StdScheduledMutator`, which means that it will be applied multiple times to form as a bigger mutator. So it is highly possible that first (A -> B) is applied, then (B -> A) is applied at the same place, effectively reverting previous mutation.
- We forgot that, we should add another checking step, to check if the mask is corrupted after the mutation (because our mask restore operation is done with a probability), and remove related masked range.

## Running the Fuzzbench

### Preparations

- Reduce possible variance according to [fuzzbench](https://github.com/google/benchmark/blob/main/docs/reducing_variance.md) [llvm benchmarking](https://llvm.org/docs/Benchmarking.html)
  - Disabling SMT is too demanding (halves your cpu power). I skipped it.
  - ```Bash
      sudo apt install linux-tools-common linux-tools-generic linux-cloud-tools-generic
      sudo cpupower frequency-set --governor performance
      cpupower frequency-info -o proc
      # echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost
      echo 0 > /proc/sys/kernel/randomize_va_space
      echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
      taskset -c 0 ./mybenchmark
      sudo apt install cpuset
      ```
- Running a [local experiment](https://google.github.io/fuzzbench/running-a-local-experiment)
  - required_cores = fuzzer_count * benchmark_count * retry
  - Requires a lot of CPU power. When experimenting with new optimizations, we select 5 trials and 2-3 fuzzers on 11 coverage-based benchmarks
- use an apt and pypi mirror for base iamge
    ```diff
    diff --git a/analysis/test_data/pairwise_unique_coverage_heatmap-failed-diff.png b/analysis/test_data/pairwise_unique_coverage_heatmap-failed-diff.png
    index 5dc618e4..7eb634b7 100644
    Binary files a/analysis/test_data/pairwise_unique_coverage_heatmap-failed-diff.png and b/analysis/test_data/pairwise_unique_coverage_heatmap-failed-diff.png differ
    diff --git a/docker/base-image/Dockerfile b/docker/base-image/Dockerfile
    index 3cf0b869..0c8bd161 100644
    --- a/docker/base-image/Dockerfile
    +++ b/docker/base-image/Dockerfile
    @@ -19,7 +19,9 @@ ENV DEBIAN_FRONTEND=noninteractive
    # Python 3.10.8 is not the default version in Ubuntu 20.04 (Focal Fossa).
    ENV PYTHON_VERSION 3.10.8
    # Install dependencies required by Python3 or Pip3.
    -RUN apt-get update && \
    +RUN sed -i "s/archive.ubuntu.com/mirrors.ustc.edu.cn/g" /etc/apt/sources.list && \
    +    sed -i "s/security.ubuntu.com/mirrors.ustc.edu.cn/g" /etc/apt/sources.list && \
    +    apt-get update && \
        apt-get upgrade -y && \
        apt-get install -y \
        curl \
    @@ -43,7 +45,8 @@ RUN cd /tmp/ && \
        make -j install > /dev/null && \
        rm -r /tmp/Python-$PYTHON_VERSION.tar.xz /tmp/Python-$PYTHON_VERSION && \
        ln -s /usr/local/bin/python3 /usr/local/bin/python && \
    -    ln -s /usr/local/bin/pip3 /usr/local/bin/pip
    +    ln -s /usr/local/bin/pip3 /usr/local/bin/pip && \
    +    cd /tmp && pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

    # Install common python dependencies.
    COPY ./requirements.txt /tmp
    ```

### Fuzzbench

**The startup of fuzzbench**: First you run `run_experiment.py`. It launches the dispatcher container, which bind mounts the host's docker sock file. Within the container it runs `dispatcher.py`, which invokes `scheduler.py` and calls `runner-startup-script-template.sh`

There is a docker flag `--cpus=1` to limit the fuzzer to single core.

To keep the containers after the experiment, remove the `--rm` in the [`runner-startup-script-template.sh`](https://github.com/google/fuzzbench/blob/e33cd5a459ce5b309a07355472ef889b6724bea0/experiment/resources/runner-startup-script-template.sh#L38).

**Commands to clean up docker containers and images**:

[The github gist](https://gist.github.com/mikea/d23a839cba68778d94e0302e8a2c200f) in the fuzzbench documentation.

```Bash
# filter by start command
docker ps -a | grep '/bin/bash -c '| awk '{print $1}' | xargs -I {} docker rm {}

docker images -a -q "gcr.io/fuzzbench/*/*/*" | xargs -I {} docker rmi -f {};
docker images -q -f dangling=true | xargs -I {} docker rmi -f {};

docker builder prune
```
