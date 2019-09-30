# Taking AFL for a Ride

> All the activities in this document are performed within the Fuzzer VM

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
afl-fuzz \
  -i /tmp/hello-vulnerable-workspace/input \
  -o /tmp/hello-vulnerable-workspace/output \
  -- ./bin/hello-vulnerable-world
```