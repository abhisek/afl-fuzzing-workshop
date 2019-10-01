# Fuzzing LibGit2

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

Build `libgit2` with our modified fuzz target using `afl-clang-fast` to leverage persistent mode fuzzing.

```
mkdir build && cd build
cmake -D BUILD_FUZZERS:BOOL=ON \
  -D USE_STANDALONE_FUZZERS:BOOL=ON \
  -D CMAKE_C_COMPILER=afl-clang-fast \
  -D CMAKE_CXX_COMPILER=afl-clang-fast++ \
  ..
cmake --build .
```