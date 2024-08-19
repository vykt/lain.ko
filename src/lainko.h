#ifndef LAINKO_H
#define LAINKO_H

/*
 *  This header is shared with userspace.
 */

//lainmemu ioctl call numbers
#define LAINMEMU_IOCTL_OPEN_TGT   0
#define LAINMEMU_IOCTL_RELESE_TGT 1
#define LAINMEMU_IOCTL_GET_MAP    2
#define LAINMEMU_IOCTL_GET_MAP_SZ 3


//vma protection - taken from linux/pgtable_types.h
typedef struct pgprot { unsigned long pgprot; } pgprot_t;


//ioctl argument
struct ioctl_arg = {
    lain_byte * u_buf;
    pid_t target_pid;
}

//map entry
struct vm_entry = {

    unsigned long vm_start;
    unsigned long vm_end;
    
    unsigned long file_off;
    struct pgprot_t prot;
    char file_path[PATH_PAX];
}


#endif
