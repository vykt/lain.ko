# lainko
Kernel interface for foreign process memory manipulation.

### NOTICE:

This is the raw interface to the <i>lainko</i> module. You probably want to use the interface provided by [liblain](https://github.com/vykt/liblain). If you intend to use the <i>liblain</i> interface, you can ignore this document.


### INTERFACE:

#### Introduction:

The <i>lainko</i> module creates a character device <i>/dev/lainmemu</i> and a sysfs class <i>/sys/class/lainko</i>. The major number identifying the <i>lainmemu</i> device is generated dynamically. To find out it's value, the attribute file <i>/sys/class/lainko/lainmemu_major</i> exposes <i>lainmemu</i>'s major number.

In the future, additional devices may be added to lainko to provide other features.


#### the lainmemu device:

The <i>lainmemu</i> character device defines the following file operations:
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

#### lainmemu file operations:

The <i>lainmemu</i> device does not have to be shared. Each open call allocates private storage tied to that file descriptor. This means multiple 
processes can make use of the lainmemu device simultaneously. This also means a single process may open the device multiple times to operate on multiple devices simultaneously.

The <i>seek()</i>, <i>read()</i>, and <i>write()</i> operations act on the memory of a target process. They should behave identically to operations performed on the <i>/proc/[pid]/mem</i> file.


#### lainmemu ioctl calls:

All ioctl calls take as their argument a userspace pointer to an instance of <i>struct ioct_arg</i> defined in <i>lainko.h</i>.

Before any operations on memory can be performed, a target process must be set. This is done by providing ioctl call #1 with the pid of the 
target inside <i>struct ioct_arg</i>. An opened process will become a zombie until it is closed. A target process can be explicitly closed with ioctl call #2, or by simply closing the <i>lainmemu</i> file descriptor.

<i>Lainmemu</i> can also produce a memory map of the target process. This is a two step process:

1) Call ioctl #3, which will return the current number of virtual memory
   areas in the target process, N. Due to concurrency, this number may 
   grow immediately.

2) Allocate a buffer to hold the memory map, store a pointer to it in 
   <i>struct ioctl_arg</i>, and call ioctl #4. On return, your buffer will 
   contain an array of <i>struct vm_entry</i>, one for each virtual memory 
   area. If your buffer is too small to hold the map, you will receive an 
   incomplete map. As such, consider allocating a buffer that can hold 
   N + 10% <i>vm_entry</i> structures.
