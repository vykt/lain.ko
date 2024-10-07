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

The <b>lain.ko</b> module creates a character device <b>/dev/lainmemu</b> and a sysfs class <b>/sys/class/lain.ko</b>. The major number identifying the <b>lainmemu</b> device is generated dynamically. To find out it's value, the attribute file <b>/sys/class/lain.ko/lainmemu_major</b> exposes <b>lainmemu</b>'s major number.

In the future, additional devices may be added to lain.ko to provide other features.


#### [the lainmemu device]

The <b>lainmemu</b> character device defines the following file operations:
```
- open()  : Generic open.
- close() : Generic close.
- seek()  : Seek in the memory of a target process.
- read()  : Read memory.
- write() : Write memory.
- ioctl() : Miscellaneous operations.
```
The following ioctl calls are defined:
```
- 1 : Open the target process.
- 2 : Close the target process.
- 3 : Get the number of vmas.
- 4 : Get the memory map.
```

#### [lainmemu file operations]

The <b>lainmemu</b> device does not have to be shared. Each open call allocates private storage tied to that file descriptor. This means multiple 
processes can make use of the lainmemu device simultaneously. This also means a single process may open the device multiple times to operate on multiple devices simultaneously.

The <b>seek()</b>, <b>read()</b>, and <b>write()</b> operations act on the memory of a target process. They should behave identically to operations performed on the <b>/proc/[pid]/mem</b> file.


#### [lainmemu ioctl calls]

All ioctl calls take as their argument a userspace pointer to an instance of <b>struct ioct_arg</b> defined in <b>lain.ko.h</b>.

Before any operations on memory can be performed, a target process must be set. This is done by providing ioctl call #1 with the pid of the 
target inside <b>struct ioct_arg</b>. An opened process will become a zombie until it is closed. A target process can be explicitly closed with ioctl call #2, or by simply closing the <b>lainmemu</b> file descriptor.

<b>Lainmemu</b> can also produce a memory map of the target process. This is a two step process:

1) Call ioctl #3, which will return the current number of virtual memory
   areas in the target process, N. Due to concurrency, this number may 
   grow immediately.

2) Allocate a buffer to hold the memory map, store a pointer to it in 
   <b>struct ioctl_arg</b>, and call ioctl #4. On return, your buffer will 
   contain an array of <b>struct vm_entry</b>, one for each virtual memory 
   area. If your buffer is too small to hold the map, you will receive an 
   incomplete map. As such, consider allocating a buffer that can hold 
   N + 10% <b>vm_entry</b> structures.
