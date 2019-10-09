# Environment Setup

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

<!--
## Change Core Pattern for AFL

```
sudo -i
echo core >/proc/sys/kernel/core_pattern
```
-->