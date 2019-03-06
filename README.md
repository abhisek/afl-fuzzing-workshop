# AFL Fuzzing Workshop

## What is AFL

> American fuzzy lop is a security-oriented fuzzer that employs a novel type of compile-time instrumentation and genetic algorithms to automatically discover clean, interesting test cases that trigger new internal states in the targeted binary. This substantially improves the functional coverage for the fuzzed code. The compact synthesized corpora produced by the tool are also useful for seeding other, more labor- or resource-intensive testing regimes down the road.

[http://lcamtuf.coredump.cx/afl/](http://lcamtuf.coredump.cx/afl/)

To learn about AFL, start with its [README](http://lcamtuf.coredump.cx/afl/README.txt)

## Requirements

* Vagrant
* Virtualbox

## Setup

Create virtual machine with AFL installed

```
vagrant up
```

SSH into the VM

```
vagrant ssh
```

> Everything else is done inside the VM

## Change Core Pattern for AFL

```
sudo -i
echo core >/proc/sys/kernel/core_pattern
```

## Taking AFL for a Ride

Compile damn vulnerable programs:

```
cd /vagrant
make
```

Lets fuzz `hello-vulnerable-world`

```
mkdir -p /tmp/hello-vulnerable-workspace/input
mkdir -p /tmp/hello-vulnerable-workspace/output
dd if=/dev/urandom of=/tmp/hello-vulnerable-workspace/input/input.dat bs=1024 count=1
```

Start fuzzer

```
afl-fuzz -i /tmp/hello-vulnerable-workspace/input -o /tmp/hello-vulnerable-workspace/output -- ./bin/hello-vulnerable-world
```

## Fuzzing in Persistent Mode

[Detailed](http://lcamtuf.blogspot.com/2015/06/new-in-afl-persistent-mode.html) description of fuzzing in *Persistent Mode*.

Example program

```c
main() {
  while(__AFL_LOOP(1000)) {
    char buf[100];
    int n = 0;

    memset(buf, 0, sizeof(buf));
    n = read(0, buf, sizeof(buf));

    target_function(buf, n)
  }
}
```

Forking is expensive as it involves creating process context and its associated data structure. To optimize further, AFL supports in-process fuzzing where appropriate instrumentation code is generated to re-run the fuzz target with mutated input. `__AFL_LOOP` provides an indicator to AFL on each iteration of in-process fuzzing.

**Note:** For this to work, `afl-clang-fast` or `afl-clang-fast++` wrapper along with LLVM `clang` has to be used to build the fuzz target.

## Distributed Fuzzing

AFL can be used for parallel fuzzing using a shared volume. [See here](http://lcamtuf.coredump.cx/afl/README.txt) for more information.

[AFL in the Cloud](https://github.com/abhisek/afl-in-the-cloud) is a PoC implementation of running parallel fuzzing in AWS cloud with automated provisioning.

## Lets Get Real

We will fuzz `libgit2` as a real-life target. The reason for choosing this target is due to ready availability of stub code meant for fuzzing with `libFuzzer` i.e. a `fuzz target`. This can easily be re-purposed for fuzzing with AFL. For other targets, we need to re-purpose the program or write a new program using interesting functions if the target is a shared library.

[https://github.com/libgit2/libgit2](https://github.com/libgit2/libgit2)

For fuzzing with AFL, we have to slightly re-purpose `fuzzers/standalone_driver.c` to read input from `STDIN` instead of from a corpus directory.

```c
// Snipped code

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);
extern int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char **argv)
{
    if (git_libgit2_init() < 0) {
      fprintf(stderr, "Failed to initialize libgit2\n");
      exit(1);
    }

    LLVMFuzzerInitialize(&argc, &argv);
    while (__AFL_LOOP(1000)) {
      char buf[1024];
      int n = 0;

      memset(buf, 0, sizeof(buf));
      n = read(0, buf, sizeof(buf) - 1);

      if (n > 0)
        LLVMFuzzerTestOneInput((const unsigned char *) buf, n);
    }

    git_libgit2_shutdown();
    return 0;
}
```

Build with the fuzzing target

```
mkdir build && cd build
cmake -D BUILD_FUZZERS:BOOL=ON -D USE_STANDALONE_FUZZERS:BOOL=ON ..
cmake --build .
```

## Am I doing it right?

One of things about finding bugs continuously is to ensure incremental improvement in fuzzing strategy. That means, when you start the fuzzing process, you must have the means to measure effectiveness of the current strategy.

This can be done using basic coverage analysis i.e. measure the code coverage ratio (or percentage) observed during fuzzing within a reasonable time period. If this is very less, then we must look into better strategy for fuzzing.

### Static Analysis of Fuzz Target

[Basic Block](https://en.wikipedia.org/wiki/Basic_block) count in a program can be used as an indicator to measure coverage during fuzzing. However, a process consists of a main binary and associated shared libraries. In such a case, we need to identify the basic block count in the fuzz target i.e. the library or program that contains our target code.

### Fuzzer Coverage

AFL provides `path` count during fuzzing. If no new `path` is discovered for a while during fuzzing, it might mean that the fuzzer need to be improved for better coverage.

## Reference

* http://lcamtuf.coredump.cx/afl/
* https://llvm.org/docs/LibFuzzer.html
* https://github.com/google/fuzzer-test-suite/blob/master/tutorial/structure-aware-fuzzing.md
