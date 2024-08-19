/*
 *  TODO TODO TODO TODO
 *
 *  1) Make userspace determine themselves how much extra space they want to add
 *     to the buffer, AND get rid of using count in the while loop, its pointless 
 *     if userspace determines the size.
 *
 *  2) Make get_map_sz return the number of VMAs, not the size of them in bytes.
 */

#include <linux/kernel.h>
#include <linux/types.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kobject.h>

#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/mm_types.h>
#include <linux/mempolicy.h>
#include <linux/ptrace.h>

#include <linux/slab.h>
#include <linux/gfp.h>

#include <linux/compiler.h>
#include <linux/compiler_types.h>

#include <linux/minmax.h>

#include <asm-generic/page.h>

#include <uapi/asm-generic/ioctl.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/fs.h>

#include "lainko.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("vykt");
MODULE_DESCRIPTION("Kernel interface for foreign process memory manipulation.");
MODULE_VERSION("1.0");



#define MEMU_DEVICE_NAME "lainmemu"   //device will appear as /dev/lainmemu
#define CLASS_NAME "lainko"           //class will appear as  /sys/class/lainko


typedef char lain_byte;
typedef unsigned char lain_ubyte;


//globals
static char dev_major;
static struct device * lainmemu_device = NULL;
static struct class * lain_class = NULL;

//ioctl call numbers
static int lainmemu_ioctl_open_tgt;
static int lainmemu_ioctl_release_tgt;
static int lainmemu_ioctl_get_map;
static int lainmemu_ioctl_get_map_sz;


//device operations function prototypes
static loff_t memu_llseek(struct file *, loff_t, int);
static int memu_open(struct inode *, struct file *);
static int memu_release(struct inode *, struct file *);
static long memu_ioctl(struct file *, unsigned int, unsigned long);
static ssize_t memu_read(struct file *, char *, size_t, loff_t *);
static ssize_t memu_write(struct file *, const char *, size_t, loff_t *);

//device file operations
static struct file_operations file_ops = {

    .owner = THIS_MODULE,
    .llseek = memu_llseek,
    .open = memu_open,
    .release = memu_release,
    .unlocked_ioctl = memu_ioctl,
    .read = memu_read,
    .write = memu_write
}



//attribute related structures
static struct kobj_attribute memu_major_attr = {0};


static struct attribute_group memu_attrs_arr = {
    &memu_major_attr,
    NULL
};


static struct attribute_group memu_attr_group = {
    .name = NULL,
    .attrs = memu_attrs_arr,
    .bin_attrs = NULL,
    .is_visible = NULL,
    .is_bin_visible = NULL
}


//local memu data
struct local_data = {

    struct task_struct * target_task;
    struct mm_struct * target_mm;
    struct mempolicy * target_mpol;

    struct vm_entry * vm_map;
    int vm_map_sz; //in # of vm_entry

    lain_byte * tx_buf;
    ssize_t tx_buf_sz; //in bytes
}



// --- INIT ---

//get a dynamic major number
static long register_major() {
 
    //errno technically goes up to 133 as of today, but we won't receive an errno > 127
    dev_major = (char) register_chrdev(0, MEMU_DEVICE_NAME, &file_ops);
    if (unlikely(dev_major < 0)) {
        
        printk(KERN_ALERT 
          "[lainmemu][ERR] failed to register with a dynamic major device number.\n");
        return (long) dev_major;
    }

    printk(KERN_INFO 
      "[lainmemu][OK] registered with major device number %d.\n", dev_major);

    return 0;
}

//create new lain class
static long register_class() {

    lain_class = class_create(THIS_MODULE, CLASS_NAME);
    if (unlikely(IS_ERR(lain_class))) {
        
        unregister_chrdev(dev_major, MEMU_DEVICE_NAME);
        printk(KERN_ALERT "[lainmemu][ERR] failed to register a device class.\n");
        return PTR_ERR(lain_class);
    }

    printk(KERN_INFO "[lainmemu][OK] created 'lain' class in sysfs.\n");

    return 0;
}


//create a new lainmemu device
static long register_device() {

    lain_device =
        device_create(lain_class, NULL, MKDEV(dev_major, 0), NULL, MEMU_DEVICE_NAME); 
    if (unlikely(IS_ERR(lain_device))) {
        
        class_destroy(lain_class);
        unregister_chrdev(dev_major, MEMU_DEVICE_NAME);
        printk(KERN_ALERT "[lainmemu][ERR] failed to create a device.\n");
        return PTR_ERR(lainmemu_device);   
    }

    printk(KERN_INFO "[lainmemu][OK] created 'lainmemu' device.\n");

    return 0;
}


//fill lainmemu ioctl numbers
static long fill_lainmemu_ioctl_nums() {

    lainmemu_ioctl_open_tgt    = _IOR((char) dev_major, LAINMEMU_IOCTL_OPEN_TGT, 
                                      struct ioctl_arg);
    lainmemu_ioctl_release_tgt = _IOR((char) dev_major, LAINMEMU_IOCTL_RELESE_TGT,
                                      struct ioctl_arg);
    lainmemu_ioctl_get_map     = _IOW((char) dev_major, LAINMEMU_IOCTL_GET_MAP,
                                      struct ioctl_arg);
    lainmemu_ioctl_get_map_sz  = _IOW((char) dev_major, LAINMEMU_IOCTL_GET_MAP_SZ,
                                      struct ioctl_arg);
    return 0;
}


//create an attribute in lainmemu to expose major number
static long register_major_attr() {

    long ret;

    memu_major_attr = __ATTR_RO(memu_major);

    ret = (long) sysfs_create_group(&lainmemu_device.kobj, &memu_attr_group);
    if (unlikely(ret)) {
        device_destroy(lainmemu_device, MKDEV(dev_major, 0));
        class_destroy(lain_class);
        unregister_chrdev(dev_major, MEMU_DEVICE_NAME);
        printk(KERN_ALERT 
          "[lainmemu][ERR] failed to expose the major number attribute of lainmemu.\n");
        return PTR_ERR(lainmemu_device);
    }

    printk(KERN_INFO "[lainmemu][OK] exposed major number as an attribute of lainmemu");

    return 0;
}



static long (*init_fn[])()
                = {register_major, register_class, register_device,
                   fill_lainmemu_ioctl_nums, register_major_attr};
#define INIT_FN_LEN (sizeof(init_fn) / sizeof(init_fn[0]))


// --- LOAD & UNLOAD

//on lkm load
static int __init lain_init(void) {

    long ret;

    printk(KERN_INFO "[lain][OK] initialising...\n");

    //initialiser function monad
    for (int i = 0; i < INIT_FN_LEN; ++i) {
    
        ret = init_fn[i]();
        if (unlikely(ret)) {
            
            printk("[lain][ERR] returned errno: %ld.\n", ret);
            return ret;
        }
    } //end for

    return 0;
}


//on lkm unload
static int __fini lain_fini(void) {
    
    device_destroy(lainmemu_device, MKDEV(dev_major, 0));
    class_unregister(lain_class);
    class_destroy(lain_class);
    unregister_chrdev(dev_major, MEMU_DEVICE_NAME);
    printk(KERN_INFO "[lain][OK] module successfully unloaded.\n");

    return 0;
}


// -- IOCTL INTERNALS

//get the argument passed from userspace
static int get_ioctl_arg(struct ioctl_arg * arg, struct ioctl_arg __user * arg_uptr) {

    unsigned long r_bytes;

    //check the passed userspace ptr is valid
    if (!access_ok(arg_uptr, sizeof(ioctl_arg))) return -EFAULT;

    //get argument struct from userspace
    r_bytes = copy_from_user((void *) arg, 
                             (const void __user *) arg_uptr, sizeof(struct ioctl_arg));
        
    if (rd_wr != 0) return -EFAULT;
    return 0;
}


//find task of pid & increment its refcount
static struct task_struct * task_by_pid(pid_t pid) {

    struct task_struct * iter;

    //for each task in task list
    for_each_process(iter) {

        //if this is the target
        if (iter->pid == pid) {

            get_task_struct(iter);
            l_data_ptr->target_task = iter;
            return iter;
        }
    } //end for

    return ERR_PTR(-ESRCH);
}


//get memory of a task & increment its refcount
static struct mm_struct * get_mm(task_struct * task) {

    struct mm_struct * mm;
    
    mm = mm_access(task, PTRACE_MODE_ATTACH | PTRACE_MODE_FSCREDS
                         | PTRACE_MODE_READ | PTRACE_MODE_WRITE);
    if (IS_ERR_OR_NULL(mm)) {

        if (mm == NULL) return ERR_PTR(-EFAULT);
        return mm;
    }

    //prevent mm_struct from being free'd
    mmgrab(mm);

    //do not prevent the corresponding VA space from being free'd
    mmput(mm);

    return mm;
}


//release target's task and mm counters if a target is present
static void release_task_mm(struct local_data * l_data_ptr) {

    //decrement mm counter
    if (l_data_ptr->target_mm != NULL) {
        mmdrop(l_data_ptr->target_mm);
        l_data_ptr->target_mm = NULL;
    }

    //decrement task counter
    if (l_data_ptr->target_task != NULL) {
        put_task_struct(l_data_ptr->target_task);
        l_data_ptr->target_mm = NULL;
    }
}


//check structure validity & acquire map operation locks
static int prepare_map_operations(struct local_data * l_data_ptr,
                                  struct vma_iterator vma_iter) {

    //check target is set
    if (l_data_ptr->target_task == NULL) return -ESRCH;

    //increment users of mm_struct, unless its 0
    if (!mmget_not_zero(l_data_ptr->target_mm)) return -ESRCH;

    //set write lock on mm
    if (mmap_read_lock_killable(l_data_ptr->target_mm)) {

        mmput(l_data_ptr->target_mm);
        return -EINTR;
    }

    //get an iterator on vmas
    vma_iter_init(vma_iter, l_data_ptr->target_mm, 0);

    //fetch and lock mempolicy of target task 
    task_lock(l_data_ptr->target_task);

    l_data_ptr->target_mpol = get_task_policy(l_data_ptr->target_task);
    mpol_get(l_data_ptr->target_mpol);

    task_unlock(l_data_ptr->target_task);

    return 0;
}


//release map operation related locks
static void cleanup_map_operations(struct local_data * l_data_ptr) {

    mmput(l_data_ptr->target_mm);
    mpol_put(l_data_ptr->target_mpol);
}


//fill vm_entry with relevant parts of vm_area_struct
static int build_vm_entry(struct vm_entry * vm_ent, struct vm_area_struct * vma) {

    char path_buf[PATH_MAX];
    char * path_str;


    //build vm_entry
    vm_ent.vm_start = vma->vm_start;
    vm_ent.vm_end   = vma->vm_end;
    vm_ent.file_off = vma->vm_pgoff;
    vm_ent.prog     = vma->vm_page_prot;
   
    //if no backing file, make path empty
    if (vma->vm_file == NULL) {
        vm_ent->file_path[0] = '\0';
    
    //otherwise get path string & set path buffer
    } else {
        path_str = d_path(vma->vm_file->f_path, path_buf, PATH_MAX);
        if (IS_ERR_OR_NULL(path_str)) {
            return (int) path_str;
        }

        strncpy(vm_ent.file_path, path_str, PATH_MAX);
    } //end if

    return 0;
}


// --- IOCTL CALLS

//open references to PID's task and mm structures
static int memu_open_tgt(struct local_data * l_data_ptr, struct ioctl_arg * arg) {

    struct task_struct * task_ret;
    struct mm_struct * mm_ret;

    //release any previous target
    release_task_mm(l_data_ptr);
   
    //open new target
    task_ret = task_by_pid(arg->target_pid);
    if (IS_ERR(task_ret)) {
        return (int) task_ret;
    }

    //become user of target's virtual memory
    mm_ret = get_mm(task_ret);
    if (IS_ERR(mm_ret)) {
        return (int) mm_ret;
    }

    return 0;
}


//release references to PID's task and mm structures
static int memu_release_tgt(struct local_data * l_data_ptr) {

    //release any previous target
    release_task_mm(l_data_ptr);

    return 0;
}


//provide caller with size of map for target
static int memu_get_map(struct local_data * l_data_ptr, struct ioctl_arg * arg) {

    int ret;
    unsigned long bytes_not_copied;
    int count = 0;

    loff_t buf_off = 0; 

    struct vm_area_struct * vma;
    struct vma_iterator vma_iter;
    struct vm_entry vm_ent;


    //allocate buffer for the map
    l_data_ptr->tx_buf = __vmalloc(l_data_ptr->tx_buf_sz, 
                                   GFP_KERNEL | GFP_RETRY_MAYFAIL);
    if (l_data_ptr->tx_buf == NULL) return -ENOMEM;

    //acquire locks & vma iterator
    ret = prepare_map_operations(l_data_ptr, &vma_iter);
    if (ret) return ret;

    
    //while there are VMAs left and there is space in the buffer
    while ( (vma = vma_next(&vma_iter) != NULL) && (count < l_data_ptr->vm_map_sz) ) {

        //build vm_entry
        ret = build_vm_entry(&vm_ent, vma);
        if (ret) {
            cleanup_map_operations(l_data_ptr);
            vfree(l_data_ptr->tx_buf);
            return ret;
        }

        //copy vm_entry into transmission buffer
        memcpy(l_data_ptr->tx_buf + buf_off, &vm_ent, sizeof(vm_ent));
        buf_off += sizeof(vm_ent);
        ++count;

    } //end while
    

    //get gate vma    
    vma = get_gate_vma(l_data_ptr->target_mm);

    //if no gate vma present (rare arch?)
    if (vma == NULL) {
        --count;
    
    //add gate vma to buffer
    } else {
        ret = build_vm_entry(&vm_ent, vma);
        if (ret) {
            cleanup_map_operations(l_data_ptr);
            vfree(l_data_ptr->tx_buf);
            return ret;
        }

        //copy gate vma into transmission buffer
        memcpy(l_data_ptr->tx_buf + buf_off, &vm_ent, sizeof(vm_ent));
        buf_off += sizeof(vm_ent);
        ++count;

    } //end if
    
    //copy buffer to user
    bytes_not_copied = copy_to_user((void __user *) arg->u_buf, 
                                    (const void *) l_data_ptr->tx_buf,
                                    count * sizeof(struct vm_entry));

    cleanup_map_operations(l_data_ptr);
    vfree(l_data_ptr->tx_buf);

    if (bytes_not_copied) return -EFAULT;
    return 0;

}


//provide caller with map for target
static int memu_get_map_sz(struct local_data * l_data_ptr) {

    int ret;
    int count = 1; //include gate_vma from the start

    struct vm_area_struct * vma;
    struct vma_iterator vma_iter;

    //acquire locks & vma iterator
    ret = prepare_map_operations(l_data_ptr, &vma_iter);
    if (ret) return ret;


    //while there are VMAs left in this address space
    while (vma = vma_next(&vma_iter)) {
        
        ++count;
        if (count < 0) {
            cleanup_map_operations(l_data_ptr);
            return -EFBIG;
        }

    } //end while
    
    //release locks
    cleanup_map_operations(l_data_ptr);

    //add buffer for map growth 
    count += (count / MEMU_MAP_SZ_XTRA_PCNT);
    if (count < 0) return -EFBIG;

    //store map size in local storage
    l_data_ptr->vm_map_sz = count;    
    l_data_ptr->tx_buf_sz = count * sizeof(struct vm_entry);

    return count;
}


// --- MEMU FILE OPERATION INTERNALS

#define MEMU_READ 0
#define MEMU_WRITE 1

//get & convert struct file's generic private_data to struct local_data
#define GET_LOCAL_DATA(file) ((struct local_data *)(file)->private_data)


//read & write function (adapted from /fs/proc/base.c:837 mem_rw() v6.6.30)
static ssize_t mem_rw(struct mm_struct * mm, char __user * u_buf, 
                      size_t count, loff_t * ppos, bool write) {

    lain_byte * page;

    unsigned int flags = FOLL_FORCE | (write == MEMU_WRITE ? FOLL_WRITE : 0);
    unsigned long remote_addr = *ppos;
    ssize_t copied = 0;

    if (!mm) return 0;

    //get a temp buffer page
    page = (lain_byte *) __get_free_page(GFP_KERNEL);
    if (!page) return -ENOMEM;

    //increment mm's refcount unless it is already 0
    if (!mmget_not_zero(mm)) goto free;

    //while there is data to read/write
    while (count > 0) {

        //clamp single operation length between a QWORD and a page
        size_t this_len = min_t(size_t, count, PAGE_SIZE);

        /*
         *  calling copy_from_user() seems completely unnecessary in case of a 
         *  read, but procfs does it(?)
         */
        if (write == MEMU_WRITE && copy_from_user(page, u_buf, this_len)) {
            copied = -EFAULT;
            break;
        }

        //perform the read/write operation into another vma space
        this_len = access_remote_vm(mm, addr, remote_addr, page, this_len, flags);
        if (!this_len) {
            if (!copied) copied = -EIO;
        }

        if (!write && copy_to_user(buf, page, this_len)) {
            copied = -EFAULT;
            break;
        }

        buf += this_len;
        remote_addr += this_len;
        copied += this_len;
        count -= this_len;

    } //end while

    //update file position
    *ppos = addr;

    //decrease refcount of mm
    mmput(mm);

free:

    free_page((unsigned long) page);
    
    return copied;
}


// --- MEMU FILE OPERATIONS

//on lainmemu device seek
static loff_t memu_llseek(struct file * file_ptr, loff_t off, int whence) {

    switch (whence) {

        case SEEK_SET:
            file->f_pos = off;
            break;
        case SEEK_CUR:
            file->f_pos += off;
            break;
        default:
            return -EINVAL;
        
    } //end switch

    force_successful_syscall_return();
    return file->f_pos;
}


//on lainmemu device open
static int memu_open(struct inode * inode_ptr, struct file * file_ptr) {

    file_ptr->private_data = kzalloc(sizeof(struct local_data), GFP_KERNEL);
    if (unlikely(file_ptr->private_data == NULL)) {

        printk(KERN_ALERT 
          "[lainmemu][ERR] failed to allocate private data for open file.\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "[lainmemu][OK] device successfully opened.\n");

    return 0;
}


//on lainmemu device close
static int memu_release(struct inode * inode_ptr, struct file * file_ptr) {

    struct local_data * l_data_ptr = GET_LOCAL_DATA(file_ptr);

    //get rid of refcounts on target task and mm
    release_task_mm(l_data_ptr);

    //free private data
    kfree(file->private_data);

    return 0;
}


//on ioctl
static long memu_ioctl(struct file * file_ptr, 
                       unsigned int ioctl_index, unsigned long ioctl_arg_uptr) {

    int ret;
    struct local_data * l_data_ptr;
    struct ioctl_arg arg;

    //get local memu data
    l_data_ptr = GET_LOCAL_DATA(file_ptr);

    //get ioctl arg from userspace
    ret = get_ioctl_arg(&arg, (struct ioctl_arg __user *) ioctl_arg_uptr);
    if (ret) return ret;


    switch(ioctl_index) {

        case LAINMEMU_IOCTL_OPEN_TGT:            
            ret = memu_set_tgt(l_data_ptr, &arg);
            break;

        case LAINMEMU_IOCTL_RELEASE_TGT:
            ret = memu_release_tgt(l_data_ptr);
            break;

        case LAINMEMU_IOCTL_GET_MAP:
            ret = memu_get_map(l_data_ptr, &arg);
            break;

        case LAINMEMU_IOCTL_GET_MAP_SZ:
            ret = memu_get_map_sz(l_data_ptr);
            break;

        default:
            ret = -ENOTTY;

    } //end switch
    
    return ret;
}



//read from memory at offset
static ssize_t memu_read(struct file * file_ptr, 
                         char * u_buf, size_t count, loff_t * off_ptr) {

    ssize_t read_bytes;
    struct local_data * l_data_ptr;

    l_data_ptr = GET_LOCAL_DATA(file_ptr);

    //carry out the read
    read_bytes = mem_rw(l_data_ptr->target_mm, 
                        (char __user *) u_buf, count, ppos, MEMU_READ);
    if(IS_ERR(read_bytes)) {
        return read_bytes;
    }

    return 0;
}


//write to memory at offset
static ssize_t memu_write(struct file * file_ptr, 
                          const char * u_buf, size_t count, loff_t * off_ptr) {

    ssize_t write_bytes;
    struct local_data * l_data_ptr;

    l_data_ptr = GET_LOCAL_DATA(file_ptr);

    //carry out the write
    write_bytes = mem_rw(l_data_ptr->target_mm, 
                         (char __user *) u_buf, count, ppos, MEMU_WRITE); 
    if (IS_ERR(read_bytes)) {
        return read_bytes;
    }

    return 0;
}
