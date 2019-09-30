# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"
  config.vm.network "private_network", ip: "192.168.33.9"
  # config.vm.network "public_network"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
  end

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update && apt-get install -y build-essential wget gdb clang cmake openssl libssl-dev
    mkdir /tmp/afl-install && cd /tmp/afl-install
    wget -O afl-latest.tgz http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
    tar xzvf afl-latest.tgz
    rm -rf afl-latest.tgz
    cd afl-*
    make
    cd llvm_mode
    LLVM_CONFIG=/usr/bin/llvm-config-3.8 make
    cd .. && make install
  SHELL
end
