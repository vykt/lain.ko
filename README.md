# lain.ko

<p align="center">
    <img src="lain.ko.png" width="150" height="150">
</p>

### ABOUT:

The lain kernel module (<b>lain.ko</b>) provides an alternative kernel interface for accessing the memory and memory maps of processes on Linux. Unlike existing interfaces like procfs or ptrace, accesses through <b>lain.ko</b> can't be detected through system APIs. Detection from userspace is still possible but is no longer trivial. <b>lain.ko</b> is designed for use with [liblain](https://github.com/vykt/liblain).


### INSTALLATION:

Install the kernel headers for your running kernel:
```
# apt install linux-headers-$(uname -r)
```

Build the module:
```
$ cd src
$ ./build.sh
```


### LOADING:

Load the module:
```
# modprobe /path/to/module/lain.ko
```

Unload the module:
```
# rmmod lain
```


### INTERNALS:

The remainder of this document covers the raw interface to the <b>lain.ko</b> module. If you're interested in using <b>lain.ko</b> with [liblain](https://github.com/vykt/liblain), you can ignore the rest of this document. If you're writing your own userspace interface, read on.


#### [introduction]

The <b>lain.ko</b> module creates a character device `/dev/lainmemu` and a sysfs class `/sys/class/lain.ko`. The major number identifying the <b>lainmemu</b> device is generated dynamically. To find it's value, read the attribute file `/sys/class/lain.ko/lainmemu_major`.


#### [the lainmemu device]

The <b>lainmemu</b> character device defines the following file operations:

| Operation | Description                            |
| --------- | -------------------------------------- |
| `open()`  | Open device file                       |
| `close()` | Close device file                      |
| `seek()`  | Seek in the memory of a target process |
| `read()`  | Read memory                            |
| `write()` | Write memory                           |
| `ioctl()` | Miscellaneous operations               |

The following ioctl calls are defined:

| Ioctl call    | Description                               |
| ------------- | ----------------------------------------- |
| `OPEN_TGT`    | Open a target                             |
| `RELEASE_TGT` | Close a target                            |
| `GET_MAP`     | Fill buffer with memory map               |
| `GET_MAP_SZ`  | Retrieve required size of transfer buffer |


#### [lainmemu file operations]

The <b>lainmemu</b> device does not have to be shared. Each open call allocates private storage tied to that file descriptor. This means multiple processes can make use of the <b>lainmemu</b> device simultaneously. This also means a single process may open the device multiple times to operate on multiple targets.

The `seek()`, `read()`, and `write()` operations act on the memory of a target process. They should behave identically to operations performed on the `/proc/[pid]/mem` file.


#### [lainmemu ioctl calls]

All ioctl calls take as their argument a userspace pointer to an instance of `struct ioct_arg` defined in <b>lainko.h</b>.

Before any operations on memory can be performed, a target process must be set. This is done by providing ioctl call `OPEN_TGT` with the pid of the target inside `struct ioct_arg`. If the target exits, it will become a zombie until it is closed. A target process can be explicitly closed with ioctl call `RELEASE_TGT`, or by simply closing the <b>lainmemu</b> file descriptor.

<b>lainmemu</b> can also produce a memory map of the target process. This is a two step process:

1) Call ioctl `GET_MAP_SZ`, which returns the current number of virtual memory areas in the target process. Due to concurrency, this number may grow immediately.

2) Allocate a buffer to hold the memory map, store a pointer to it in `struct ioctl_arg`, and call ioctl `GET_MAP`. On return, your buffer will contain an array of `struct vm_entry`, also defined in <b>lainko.h</b>. Each `struct vm_entry` instance represents one virtual memory area. If your buffer is too small due to memory map growth between the `GET_MAP_SZ` and `GET_MAP` ioctl calls, you will receive an incomplete map. <b>lainmemu</b> will typically request a buffer 10% larger than required to compensate for this.
