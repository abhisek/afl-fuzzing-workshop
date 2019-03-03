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

## Distributed Fuzzing

AFL can be used for parallel fuzzing using a shared volume. [See here](#) for more information.

[AFL in the Cloud](https://github.com/abhisek/afl-in-the-cloud) is a PoC implementation of running parallel fuzzing in AWS cloud with automated provisioning.

## Lets Get Real

We will fuzz `libgit2` as a real-life target. The reason for choosing this target is due to ready availability of stub code meant for fuzzing with AFL i.e. a `fuzz target`. For other targets, we need to re-purpose the program or write a program using interesting functions if the target is a shared library.

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

