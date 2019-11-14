# dysco-us
Dynamic Service Chaining with Dysco in User Space

## Setting up the Environment
The Dysco protocol needs some standard packages to create the testing environment. We can download and install the required packages using apt and pip, which are the standard package managers for Ubuntu and Python, respectively. We show how to get these packages for a fresh virtual machine running Ubuntu 18.04.2 LTS on VirtualBox.

Make sure that `PKG_CONFIG_PATH` has at least `/usr/lib/pkgconfig` and `/usr/lib/x86_64-linux-gnu/pkgconfig` paths.

## Installing Linux Packages
```
~$ sudo apt update
~$ sudo apt upgrade
~$ sudo apt install expect make apt-transport-https \
      ca-certificates g++ pkg-config libunwind8-dev \
      liblzma-dev zlib1g-dev libpcap-dev libssl-dev \
      libnuma-dev git python python-pip python-scapy \
      libgflags-dev libgoogle-glog-dev libgraph-easy-perl \
      libgtest-dev libgrpc++-dev libprotobuf-dev libc-ares-dev \
      libbenchmark-dev protobuf-compiler-grpc lua5.3 \
      liblua5.3-dev libmnl-dev libsparsehash-dev iperf
```
## Installing Python Packages
```
~$ sudo pip install protobuf grpcio
```

#### For Mellanox NICs
```
apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev
```

### Installing BESS
To install BESS, you need to download the source files from the git repository with the following commands:
```
~$ git clone https://github.com/dysco/dysco-us
~$ cd dysco-us
~$ sudo ./build.py
```
You should see the following messages:

```
Downloading https://fast.dpdk.org/rel/dpdk-18.08.tar.gz ... 
Configuring DPDK... 
 - “Mellanox OFED” is not available. Disabling MLX4 and MLX5 PMDs... 
Building DPDK... 
Generating protobuf codes for pybess... 
Building BESS daemon... 
Building BESS kernel module (4.15.0-52-generic - running kernel) ... 
Done.
```

BESS and DPDK use hugepages for allocating a large memory pool for packet buffers. The default hugepage size is 2MB per page. We do not need to change the page size, but we recommend at least 2048 pages, i.e. 4GB of RAM.

To reserve the hugepages, you need to run the following steps:

```
~$ sudo ./deps/dpdk-18.08/usertools/dpdk-setup.sh
```
```diff
- [Type 21 for non-NUMA or 22 for NUMA]
- [Type 2048]
- [Type ‘ENTER’]
- [Type 35 to exit]
```
You should see the following messages (in non-NUMA case):
```
... 
Option: 21

Removing currently reserved hugepages
Unmounting /mnt/huge and removing directory

  Input the number of 2048kB hugepages
  Example: to have 128MB of hugepages available in a 2MB huge page system,
  Enter ‘64’ to reserve 64 * 2MB pages
Number of pages: 2048
Reserving hugepages
Creating /mnt/huge and mounting as hugetlbfs

Press enter to continue ... 
...

Option: 35

~$
```
### Running BESS
```
~$ sudo ./bessctl/bessctl
Type "help" for more information.
Connection to localhost:10514 failed
Perhaps bessd daemon is not running locally? Try "daemon start".
<disconnected> $
```
```diff
- [Type ‘daemon start’]
```
```
localhost:10514 $ 
```
