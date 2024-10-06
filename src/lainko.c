#include <linux/kernel.h>
#include <linux/types.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/device/class.h>

#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mempolicy.h>
#include <linux/ptrace.h>

#include <linux/kprobes.h>

#include <linux/slab.h>
#include <linux/gfp.h>

#include <linux/compiler.h>
#include <linux/compiler_types.h>

#include <linux/minmax.h>

//#include <asm-generic/page.h>
#include <asm/page.h>

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

#define MEMU_MAP_SZ_XTRA_PCNT 10      //determines extra % in map buf (see design.txt)


//globals
static char lainmemu_major;
static struct device * lainmemu_device = NULL;
static struct class * lainko_class = NULL;

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
};



//procfs vma name format strings
static const char * lainko_procfs_shmem = "[shmem:%s]";
static const char * lainko_procfs_anon = "[anon:%s]";
static const char * lainko_procfs_stack = "[stack]";
static const char * lainko_procfs_heap = "[heap]";
static const char * lainko_procfs_vdso = "[vdso]";



//sysfs attributes
static ssize_t lainmemu_major_show(const struct class * class, 
                                   const struct class_attribute * attr, char * buf);

static struct class_attribute lainmemu_major_attr = __ATTR_RO(lainmemu_major);


//un-exported symbols 
static char * symbols[] = {
    "kallsyms_lookup_name",
    "access_remote_vm",
    "get_task_policy",
    "get_gate_vma",
    "mm_access",
    "arch_vma_name"
};

#define SYMBOLS_LEN 6

#define SYM_KALLSYMS_LOOKUP_NAME 0
#define SYM_ACCESS_REMOTE_VM     1
#define SYM_GET_TASK_POLICY      2
#define SYM_GET_GATE_VMA         3
#define SYM_MM_ACCESS            4
#define SYM_ARCH_VMA_NAME        5


struct resolved_symbols{

    unsigned long (*kallsyms_lookup_name)(const char *);
    
    int (*access_remote_vm)(struct mm_struct *, unsigned long, 
                            void *, int, unsigned int);
    struct mempolicy * (*get_task_policy)(struct task_struct *);
    struct vm_area_struct * (*get_gate_vma)(struct mm_struct *);
    struct mm_struct * (*mm_access)(struct task_struct *, unsigned int);
    const char * (*arch_vma_name)(struct vm_area_struct *);
};
static struct resolved_symbols r_symbols;


//local memu data
struct local_data {

    struct task_struct * target_task;
    struct mm_struct * target_mm;
    struct mempolicy * target_mpol;

    struct vm_entry * vm_map;
    int vm_map_sz; //in # of vm_entry

    lainko_byte * tx_buf;
    ssize_t tx_buf_sz; //in bytes
};



// --- SYSFS
static ssize_t lainmemu_major_show(const struct class * class, 
                                   const struct class_attribute * attr, char * buf) {

    return sprintf(buf, "%d\n", (unsigned char) lainmemu_major);
}



// --- INIT INTERNALS

//empty kprobe
static int kallsyms_kprobe(struct kprobe * kp, struct pt_regs * regs) { 

    return 0;
}


//print symbol address to dmesg
static inline void print_symbol(int symbol_index) {

    printk(KERN_INFO "[lainko][OK] symbol resolved: %s : 0x%lx\n", 
	   symbols[symbol_index],
	   *(((unsigned long *) &r_symbols) + symbol_index));
    return;
}


//get the address of kallsyms_lookup_name
static long get_kallsyms_lookup_name(void) {

    int ret;

    struct kprobe kallsyms_kp;

    //insert kprobe
    kallsyms_kp.symbol_name = symbols[SYM_KALLSYMS_LOOKUP_NAME];
    kallsyms_kp.pre_handler = kallsyms_kprobe;

    ret = register_kprobe(&kallsyms_kp);
    if (ret < 0) {
        printk(KERN_ALERT "[lainko][ERR] failed to register kallsyms kprobe.\n");
        return -1;
    }

    //extract address of kallsyms_lookup_name from kprobe
    r_symbols.kallsyms_lookup_name = (unsigned long (*)(const char * name)) 
                                     kallsyms_kp.addr;
    print_symbol(SYM_KALLSYMS_LOOKUP_NAME);

    //remove kprobe
    unregister_kprobe(&kallsyms_kp);

    printk(KERN_INFO "[lainko][OK] acquired address of kallsyms_lookup_name().\n");

    return 0;
}


// --- INIT

//find un-exported symbols
static long locate_symbols(void) {

    //setup init
    long ret;
    unsigned long addr;

    //find address of function used to lookup symbols
    ret = get_kallsyms_lookup_name();
    if (ret) return -1;

    //access_remote_vm
    addr = r_symbols.kallsyms_lookup_name(symbols[SYM_ACCESS_REMOTE_VM]);
    if (addr == 0) return -1;
    r_symbols.access_remote_vm = (int (*)(struct mm_struct *, unsigned long,
                                  void *, int, unsigned int)) addr;
    print_symbol(SYM_ACCESS_REMOTE_VM);

    //get_task_policy
    addr = r_symbols.kallsyms_lookup_name(symbols[SYM_GET_TASK_POLICY]);
    if (addr == 0) return -1;
    r_symbols.get_task_policy = (struct mempolicy * (*)(struct task_struct *)) addr;
    print_symbol(SYM_GET_TASK_POLICY);

    //get_gate_vma
    addr = r_symbols.kallsyms_lookup_name(symbols[SYM_GET_GATE_VMA]);
    if (addr == 0) return -1;
    r_symbols.get_gate_vma = (struct vm_area_struct * (*)(struct mm_struct *)) addr;
    print_symbol(SYM_GET_GATE_VMA);

    //mm_access
    addr = r_symbols.kallsyms_lookup_name(symbols[SYM_MM_ACCESS]);
    if (addr == 0) return -1;
    r_symbols.mm_access = (struct mm_struct * (*)(struct task_struct *, unsigned int))
                          addr;
    print_symbol(SYM_MM_ACCESS);

    //arch_vma_struct
    addr = r_symbols.kallsyms_lookup_name(symbols[SYM_ARCH_VMA_NAME]);
    if (addr == 0) return -1;
    r_symbols.arch_vma_name = (const char * (*)(struct vm_area_struct *)) addr;
    print_symbol(SYM_ARCH_VMA_NAME);

    return 0;
}


//get a dynamic major number
static long memu_register_major(void) {
 
    //errno technically goes up to 133 as of today, but we won't receive an errno > 127
    lainmemu_major = (char) register_chrdev(0, MEMU_DEVICE_NAME, &file_ops);
    if (unlikely(lainmemu_major < 0)) {
        
        printk(KERN_ALERT 
          "[lainmemu][ERR] failed to register with a dynamic major device number.\n");
        return (long) lainmemu_major;
    }

    printk(KERN_INFO 
      "[lainmemu][OK] registered with major device number %d.\n", (unsigned char) lainmemu_major);

    return 0;
}


//create new lainko class
static long register_class(void) {

    lainko_class = class_create(CLASS_NAME);
    if (unlikely(IS_ERR(lainko_class))) {
        
        unregister_chrdev(lainmemu_major, MEMU_DEVICE_NAME);
        printk(KERN_ALERT "[lainmemu][ERR] failed to register a device class.\n");
        return PTR_ERR(lainko_class);
    }

    printk(KERN_INFO "[lainmemu][OK] created 'lainko' class in sysfs.\n");

    return 0;
}


//create a new lainmemu device
static long memu_register_device(void) {

    lainmemu_device =
        device_create(lainko_class, NULL, MKDEV(lainmemu_major, 0), 
                      NULL, MEMU_DEVICE_NAME); 
    if (unlikely(IS_ERR(lainmemu_device))) {
        
        class_destroy(lainko_class);
        unregister_chrdev(lainmemu_major, MEMU_DEVICE_NAME);
        printk(KERN_ALERT "[lainmemu][ERR] failed to create a device.\n");
        return PTR_ERR(lainmemu_device);   
    }

    printk(KERN_INFO "[lainmemu][OK] created 'lainmemu' device.\n");

    return 0;
}


//create an attribute in lainmemu to expose major number
static long memu_register_major_attr(void) {

    int ret;

    ret = class_create_file(lainko_class, &lainmemu_major_attr);
    if (unlikely(ret)) {
        device_destroy(lainko_class, MKDEV(lainmemu_major, 0));
        class_destroy(lainko_class);
        unregister_chrdev(lainmemu_major, MEMU_DEVICE_NAME);
        printk(KERN_ALERT 
          "[lainmemu][ERR] failed to expose the major number attribute of lainmemu.\n");
        return PTR_ERR(lainmemu_device);
    }

    printk(KERN_INFO 
      "[lainmemu][OK] exposed major number as an attribute of lainko sysfs class.\n");

    return 0;
}


//fill lainmemu ioctl numbers
static long memu_fill_ioctl_nums(void) {

    lainmemu_ioctl_open_tgt    = _IOW(lainmemu_major, LAINMEMU_IOCTL_OPEN_TGT, 
                                      struct ioctl_arg *);
    lainmemu_ioctl_release_tgt = _IO(lainmemu_major, LAINMEMU_IOCTL_RELEASE_TGT);
    lainmemu_ioctl_get_map     = _IOWR(lainmemu_major, LAINMEMU_IOCTL_GET_MAP,
                                       struct ioctl_arg *);
    lainmemu_ioctl_get_map_sz  = _IOW(lainmemu_major, LAINMEMU_IOCTL_GET_MAP_SZ,
                                      struct ioctl_arg *);
    
    printk(KERN_INFO "[lainmemu][OK] open_tgt: %8x, release_tgt: %8x, get_map: %8x, get_map_sz: %8x\n",
      lainmemu_ioctl_open_tgt, lainmemu_ioctl_release_tgt, lainmemu_ioctl_get_map, lainmemu_ioctl_get_map_sz);

    printk(KERN_INFO
      "[lainmemu][OK] registered lainmemu ioctl calls.\n");

    return 0;
}

static long (*init_fn[])(void)
                = {locate_symbols, memu_register_major, register_class, 
                   memu_register_device, memu_register_major_attr, 
                   memu_fill_ioctl_nums};
#define INIT_FN_LEN (sizeof(init_fn) / sizeof(init_fn[0]))


// --- LOAD & UNLOAD

//on lkm load
static int __attribute__((unused)) __init lainko_init(void) {

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
static void __attribute__((unused)) __exit lainko_exit(void) {
    
    device_destroy(lainko_class, MKDEV(lainmemu_major, 0));
    class_unregister(lainko_class);
    class_destroy(lainko_class);
    unregister_chrdev(lainmemu_major, MEMU_DEVICE_NAME);
    printk(KERN_INFO "[lain][OK] module successfully unloaded.\n");

    return;
}


//register load & unload functions
module_init(lainko_init);
module_exit(lainko_exit);


// -- IOCTL INTERNALS

//get the argument passed from userspace
static int get_ioctl_arg(struct ioctl_arg * arg, struct ioctl_arg __user * arg_uptr) {

    unsigned long r_bytes;

    //check the passed userspace ptr is valid
    if (!access_ok(arg_uptr, sizeof(struct ioctl_arg))) return -EFAULT;

    //get argument struct from userspace
    r_bytes = copy_from_user((void *) arg, 
                             (const void __user *) arg_uptr, sizeof(struct ioctl_arg));
        
    if (r_bytes != 0) return -EFAULT;
    return 0;
}


//find task of pid & increment its refcount
static struct task_struct * task_by_pid(struct local_data * l_data_ptr, pid_t pid) {

    struct task_struct * iter;

    printk(KERN_INFO "[lainmemu][OK] looking for task struct for %d.\n", pid);

    //for each task in task list
    for_each_process(iter) {

        //if this is the target
        if (iter->pid == pid) {

            printk("[lainmemu][OK] old task->usage is %d.\n", 
		   iter->usage.refs.counter);

            get_task_struct(iter);
            l_data_ptr->target_task = iter;

	    printk(KERN_INFO "[lainmemu][OK] found task struct for %d at 0x%8lx.\n", 
                   pid, (unsigned long) l_data_ptr->target_task);
            return iter;
        }
    } //end for

    return ERR_PTR(-ESRCH);
}


//get memory of a task & increment its refcount
static struct mm_struct * get_mm_struct(struct task_struct * task) {

    struct mm_struct * mm;
    
    mm = r_symbols.mm_access(task, PTRACE_MODE_ATTACH | PTRACE_MODE_FSCREDS);
    if (IS_ERR_OR_NULL(mm)) {

        if (mm == NULL) return ERR_PTR(-EFAULT);
        return mm;
    }

    printk(KERN_INFO "[lainmemu][OK] old mm->mm_count is %d.\n", 
	   mm->mm_count.counter);
    printk(KERN_INFO "[lainmemu][OK] old mm->mm_users is %d.\n",
	   mm->mm_users.counter - 1); //see mmput() comment

    //prevent mm_struct from being free'd
    mmgrab(mm);

    //mm_access() calls mmget() internally, which isn't needed
    mmput(mm);

    return mm;
}


//release target's task and mm counters if a target is present
static void release_task_mm(struct local_data * l_data_ptr) {

    //decrement mm counter
    if (l_data_ptr->target_mm != NULL) {
        mmdrop(l_data_ptr->target_mm);
        printk(KERN_INFO "[lainmemu][OK] new mm->mm_count is %d.\n", 
	       l_data_ptr->target_mm->mm_count.counter);
        printk(KERN_INFO "[lainmemu][OK] new mm->mm_users is %d.\n", 
	       l_data_ptr->target_mm->mm_users.counter);
        l_data_ptr->target_mm = NULL;
    }

    //decrement task counter
    if (l_data_ptr->target_task != NULL) {
        put_task_struct(l_data_ptr->target_task);
        printk(KERN_INFO "[lainmemu][OK] new task->usage is %d.\n", 
               l_data_ptr->target_task->usage.refs.counter);

        l_data_ptr->target_task = NULL;
    }
}


//check structure validity & acquire map operation locks
static int prepare_map_operations(struct local_data * l_data_ptr,
                                  struct vma_iterator * vma_iter) {

    printk(KERN_INFO 
      "[lainmemu][OK] preparing map operations for %d.\n", 
      l_data_ptr->target_task->pid);

    //check target is set
    if (l_data_ptr->target_task == NULL) return -ESRCH;

    //increment users of mm_struct's address space, unless its already 0
    if (!mmget_not_zero(l_data_ptr->target_mm)) return -ESRCH;

    //prevent memory map from being altered
    if (mmap_read_lock_killable(l_data_ptr->target_mm)) {

        mmput(l_data_ptr->target_mm);
	printk(KERN_INFO 
	       "[lainmemu][OK] failed to write lock mm_struct for %d.\n", 
	       l_data_ptr->target_task->pid);
	return -EINTR;
    }

    //get an iterator on vmas
    vma_iter_init(vma_iter, l_data_ptr->target_mm, 0);

    printk(KERN_INFO 
	   "[lainmemu][OK] prepared map operations for %d.\n", 
	   l_data_ptr->target_task->pid);

    return 0;
}


//release map operation related locks
static void cleanup_map_operations(struct local_data * l_data_ptr) {

    printk(KERN_INFO 
	   "[lainmemu][OK] cleaning up map operations for %d.\n", 
	   l_data_ptr->target_task->pid);
    
    //release memory map lock
    mmap_read_unlock(l_data_ptr->target_mm);

    //decrement users of mm_struct's address space
    mmput(l_data_ptr->target_mm);

    printk(KERN_INFO "[lainmemu][OK] cleaned up map operations for %d.\n", l_data_ptr->target_task->pid);
}


//get the name for this vma, exactly same way as procfs for parity
static inline void get_vma_name(struct vm_entry * vm_ent, 
                                struct vm_area_struct * vma, char * path_buf) {

    char * temp_str;

    //struct anon_vma_name * anon_name = vma->vm_mm ? vma->anon_name : NULL;
    struct anon_vma_name * anon_name = vma->vm_mm ? anon_vma_name(vma) : NULL;

    //if this is a 'regular' vma
    if (vma->vm_file) {

        //if the user is using named anonymous mappings
        if (anon_name) {
            snprintf(vm_ent->file_path, PATH_MAX, lainko_procfs_shmem, anon_name->name);
	} else {
            temp_str = d_path(&vma->vm_file->f_path, path_buf, PATH_MAX);
	    snprintf(vm_ent->file_path, PATH_MAX, temp_str);
	    return;
        }
    } //end if 'regular' vma

    //if vma has a special name
    if (vma->vm_ops && vma->vm_ops->name) {
        temp_str = (char *) vma->vm_ops->name(vma);
        if (temp_str) {
            snprintf(vm_ent->file_path, PATH_MAX, temp_str);
        }
        return;
    }

    temp_str = (char *) r_symbols.arch_vma_name(vma);
    if (temp_str) {
        snprintf(vm_ent->file_path, PATH_MAX, temp_str);
    }

    if (!vma->vm_mm) {
        snprintf(vm_ent->file_path, PATH_MAX, lainko_procfs_vdso);
        return;
    }

    if (vma_is_initial_heap(vma)) {
        snprintf(vm_ent->file_path, PATH_MAX, lainko_procfs_heap);
        return;
    }

    if (vma_is_initial_stack(vma)) {
        snprintf(vm_ent->file_path, PATH_MAX, lainko_procfs_stack);
        return;
    }

    if (anon_name) {
        snprintf(vm_ent->file_path, PATH_MAX, lainko_procfs_anon, anon_name->name);
        return;
    }
}


//fill vm_entry with relevant parts of vm_area_struct
static int build_vm_entry(struct vm_entry * vm_ent, 
                          struct vm_area_struct * vma, char * path_buf) {

    //build vm_entry
    vm_ent->vm_start = vma->vm_start;
    vm_ent->vm_end   = vma->vm_end;
    vm_ent->file_off = vma->vm_pgoff;
    vm_ent->prot     = vma->vm_flags;
  
    get_vma_name(vm_ent, vma, path_buf);

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
    task_ret = task_by_pid(l_data_ptr, arg->target_pid);
    if (IS_ERR(task_ret)) {
	printk(KERN_INFO "[lainmemu][OK] failed to find task_struct for %d.\n", arg->target_pid);
        return (int) PTR_ERR(task_ret);
    }

    //become user of target's virtual memory
    mm_ret = get_mm_struct(task_ret);
    if (IS_ERR(mm_ret)) {
	printk(KERN_INFO "[lainmemu][OK] failed to acquire mm_struct for %d.\n", arg->target_pid);
        return (int) PTR_ERR(mm_ret);
    }
    l_data_ptr->target_mm = l_data_ptr->target_task->mm;

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
    char * path_buf;

    int count = 0;

    struct vm_area_struct * vma;
    struct vma_iterator vma_iter;
    struct vm_entry * vm_ent;


    //allocate buffer for the map
    l_data_ptr->tx_buf = __vmalloc(l_data_ptr->tx_buf_sz, 
                                   GFP_KERNEL | __GFP_RETRY_MAYFAIL);
    if (l_data_ptr->tx_buf == NULL) return -ENOMEM;

    //allocate pathname buffer
    path_buf = __vmalloc(PATH_MAX, GFP_KERNEL);
    if (path_buf == NULL) {
        vfree(l_data_ptr->tx_buf);
        return -ENOMEM;
    }

    //acquire locks & vma iterator
    ret = prepare_map_operations(l_data_ptr, &vma_iter);
    if (ret) return ret;

    //initialise vm_ent pointer
    vm_ent = (struct vm_entry *) l_data_ptr->tx_buf;
    
    //while there are VMAs left and there is space in the buffer
    while ( ((vma = vma_next(&vma_iter)) != NULL) && (count < l_data_ptr->vm_map_sz) ) {

        //build vm_entry inside buffer
        ret = build_vm_entry(vm_ent, vma, path_buf);
        if (ret) {
            cleanup_map_operations(l_data_ptr);
            vfree(path_buf);
            vfree(l_data_ptr->tx_buf);
            return ret;
        }

        //advance loop state
        vm_ent = vm_ent + 1;
        ++count;

    } //end while
    

    //get gate vma    
    vma = r_symbols.get_gate_vma(l_data_ptr->target_mm);

    //add gate vma if present
    if (vma != NULL) {

	ret = build_vm_entry(vm_ent, vma, path_buf);
        if (ret) {
            cleanup_map_operations(l_data_ptr);
            vfree(path_buf);
            vfree(l_data_ptr->tx_buf);
            return ret;
        }

        //copy gate vma into transmission buffer
        vm_ent = vm_ent + 1;
        ++count;

    } //end if
    
    //copy buffer to user
    bytes_not_copied = copy_to_user((void __user *) arg->u_buf, 
                                    (const void *) l_data_ptr->tx_buf,
                                    count * sizeof(struct vm_entry));

    cleanup_map_operations(l_data_ptr);
    vfree(path_buf);
    vfree(l_data_ptr->tx_buf);

    if (bytes_not_copied) return -EFAULT;
    return count;
}


//provide caller with map for target
static int memu_get_map_sz(struct local_data * l_data_ptr) {

    int ret;
    int count = 1; //include gate_vma from the start

    struct vm_area_struct * vma;
    struct vma_iterator vma_iter;

    printk(KERN_INFO "[lainmemu][OK] acquiring map size for target.\n");

    //acquire locks & vma iterator
    ret = prepare_map_operations(l_data_ptr, &vma_iter);
    if (ret) return ret;

    //while there are VMAs left in this address space
    while ((vma = vma_next(&vma_iter)) != NULL) {
        
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
                      size_t count, loff_t * off_ptr, bool write) {

    lainko_byte * page;

    unsigned int flags = FOLL_FORCE | (write == MEMU_WRITE ? FOLL_WRITE : 0);
    unsigned long remote_addr = *off_ptr;
    ssize_t copied = 0;

    if (!mm) return 0;

    //get a temp buffer page
    page = (lainko_byte *) __get_free_page(GFP_KERNEL);
    if (!page) return -ENOMEM;

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
        this_len = r_symbols.access_remote_vm(mm, remote_addr, page, this_len, flags);
        if (!this_len) {
            if (!copied) copied = -EIO;
        }

        if (!write && copy_to_user(u_buf, page, this_len)) {
            copied = -EFAULT;
            break;
        }

        u_buf += this_len;
        remote_addr += this_len;
        copied += this_len;
        count -= this_len;

    } //end while

    //update file position
    *off_ptr = remote_addr;


    free_page((unsigned long) page); 
    return copied;
}


// --- MEMU FILE OPERATIONS

//on lainmemu device seek
static loff_t memu_llseek(struct file * file_ptr, loff_t off, int whence) {

    switch (whence) {

        case SEEK_SET:
            file_ptr->f_pos = off;
            break;
        case SEEK_CUR:
            file_ptr->f_pos += off;
            break;
        default:
            return -EINVAL;
        
    } //end switch

    force_successful_syscall_return();
    return file_ptr->f_pos;
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
    kfree(file_ptr->private_data);

    return 0;
}


//on ioctl
static long memu_ioctl(struct file * file_ptr, 
                       unsigned int ioctl_call, unsigned long ioctl_arg_uptr) {

    int ret;
    struct local_data * l_data_ptr;
    struct ioctl_arg arg;

    //get local memu data
    l_data_ptr = GET_LOCAL_DATA(file_ptr);

    //get ioctl arg from userspace
    ret = get_ioctl_arg(&arg, (struct ioctl_arg __user *) ioctl_arg_uptr);
    if (ret) return ret;
    
    //open target
    if (ioctl_call == lainmemu_ioctl_open_tgt) { 
	ret = memu_open_tgt(l_data_ptr, &arg);
    
    //release target
    } else if (ioctl_call == lainmemu_ioctl_release_tgt) { 
	ret = memu_release_tgt(l_data_ptr);
    
    //return map
    } else if (ioctl_call == lainmemu_ioctl_get_map) { 
	ret = memu_get_map(l_data_ptr, &arg);
    
    //return map size
    } else if (ioctl_call == lainmemu_ioctl_get_map_sz) {
	ret = memu_get_map_sz(l_data_ptr);
    
    //return error - not implemented
    } else {
        ret = -ENOTTY;
    }

    return ret;
}



//read from memory at offset
static ssize_t memu_read(struct file * file_ptr, 
                         char * u_buf, size_t count, loff_t * off_ptr) {

    ssize_t read_bytes;
    struct local_data * l_data_ptr;
    struct vm_area_struct * ret_vma;

    l_data_ptr = GET_LOCAL_DATA(file_ptr);

    //check if addr is NULL
    if (*off_ptr == 0) return -EFAULT;

    //increment mm's refcount unless it is already 0
    if (!mmget_not_zero(l_data_ptr->target_mm)) return -ESRCH;

    //check if address is mapped
    ret_vma = find_vma(l_data_ptr->target_mm, *off_ptr);
    if (ret_vma == NULL) {
        mmput(l_data_ptr->target_mm);
        return -EFAULT;
    }

    //carry out the read
    read_bytes = mem_rw(l_data_ptr->target_mm, 
                        (char __user *) u_buf, count, off_ptr, MEMU_READ);
    if(read_bytes < 0) {
        mmput(l_data_ptr->target_mm);
        return read_bytes;
    }

    //decrease refcount of mm
    mmput(l_data_ptr->target_mm);

    return 0;
}


//write to memory at offset
static ssize_t memu_write(struct file * file_ptr, 
                          const char * u_buf, size_t count, loff_t * off_ptr) {

    ssize_t write_bytes;
    struct local_data * l_data_ptr;
    struct vm_area_struct * ret_vma;

    l_data_ptr = GET_LOCAL_DATA(file_ptr);

    //check if addr is NULL
    if (*off_ptr == 0) return -EFAULT;

    //increment mm's refcount unless it is already 0
    if (!mmget_not_zero(l_data_ptr->target_mm)) return -ESRCH;

    //check if address is mapped
    ret_vma = find_vma(l_data_ptr->target_mm, *off_ptr);
    if (ret_vma == NULL) {
        mmput(l_data_ptr->target_mm);
        return -EFAULT;
    }

    //carry out the write
    write_bytes = mem_rw(l_data_ptr->target_mm, 
                         (char __user *) u_buf, count, off_ptr, MEMU_WRITE); 
    if (write_bytes < 0) {
        return write_bytes;
    }

    //decrease refcount of mm
    mmput(l_data_ptr->target_mm);

    return 0;
}
