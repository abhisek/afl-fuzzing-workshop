# Parallel or Distributed Fuzzing

AFL can be used for parallel fuzzing using a shared volume. [See here](http://lcamtuf.coredump.cx/afl/README.txt) for more information.

## Parallel Fuzzing

AFL can run multiple fuzzer instance in a system with a shared `output` directory for synchronising across multiple instance of the fuzzer.

More information:
https://github.com/mirrorer/afl/blob/master/docs/parallel_fuzzing.txt


## Distributed Fuzzing

[AFL in the Cloud](https://github.com/abhisek/afl-in-the-cloud) is a PoC implementation of running parallel fuzzing in AWS cloud with automated provisioning.