# Fuzzing in Persistent Mode

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

> Forking is expensive as it involves creating process context and its associated data structure. To optimize further, AFL supports in-process fuzzing where appropriate instrumentation code is generated to re-run the fuzz target with mutated input. `__AFL_LOOP` provides an indicator to AFL on each iteration of in-process fuzzing.

**Note:** For this to work, `afl-clang-fast` or `afl-clang-fast++` wrapper along with LLVM `clang` has to be used to build the fuzz target.