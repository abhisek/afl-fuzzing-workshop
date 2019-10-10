# Fuzzing Primitives

## What is the purpose of fuzzing?

> Fuzzing or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program.

In most real-world scenario, a fuzzing process consist of a set of tools (fuzzer) and a program (fuzz target) and a workflow such as below for the fuzzer:

1. Generates random, valid or invalid input
2. Executes target program with generated input
3. Monitors target program execution for possible fault (e.g. crash)
4. Observes runtime behavior which may influence it's input generation
5. Logs everything

## Fuzzer Types

* Generation
* Mutation
* Evolutionary

> There are many other types, with new names being invented on a regular basis.

## Fuzzer Components

### Fuzz Target

The program being tested for fault by feeding generated input.

### Code Coverage Analyser

A program that can monitor execution of target process and identify [Basic Blocks](https://en.wikipedia.org/wiki/Basic_block) executed for a given input.

This allows a guided or smart fuzzer to generate input with increased code coverage, thereby automatically improving the effectiveness of the fuzzing processs.

### Corpus

List of input files fed in to a fuzzer to mutate on.

### Fault Detection

A program, usually a debugger that can monitor a target program and detect and log faults.

### Memory Analyser

External tools (e.g. Valgrind) or compiler injected instrumention (e.g. ASAN/MSAN) that can detect a variety of memory related security vulnerabilities at runtime.

## Reference

* https://llvm.org/docs/LibFuzzer.html
* https://gitlab.com/akihe/radamsa
* https://en.wikipedia.org/wiki/Fuzzing
* https://llvm.org/docs/LibFuzzer.html