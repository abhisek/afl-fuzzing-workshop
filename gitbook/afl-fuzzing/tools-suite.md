# AFL Tools Suite

## afl-fuzz

The main fuzzer

## Compiler Wrappers

* afl-gcc
* afl-g++
* afl-clang
* afl-clang++
* afl-clang-fast
* afl-clang-fast++

The compiler wrappers inject instrumentation code at compile time.

## afl-cmin

Corpus minimizer

## afl-tmin

Test case minimizer used to minimize a test case that generated a crash

## afl-whatsup

Status check tool, useful during parallel fuzzing

## afl-analyze

Analyze and guess the structure of input file format based on code coverage at runtime