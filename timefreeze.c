#include <linux/kernel.h>
#include <linux/module.h>

#include "timefreeze.h"
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/utsname.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/fs_struct.h>
#include <linux/hash.h>

#include <linux/proc_fs.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/utime.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include <linux/dnotify.h>

//#define DEBUG_FREEZE_CASES
// #define DEBUG_ALL_SYSCALLS // Warning! Syscalls are entered very-very-very often! Use with care!

MODULE_DESCRIPTION("timefreeze - Linux Kernel Module");
MODULE_AUTHOR("Trifonenkov Andrew, (C) 2012");
#define MODULE_NAME "timefreeze"
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

void **sys_call_table;
__cacheline_aligned_in_smp DEFINE_SEQLOCK(rename_lock);


char syscall_path[PATH_MAX];
char buf[PATH_MAX];


asmlinkage long (*sys_stat_ORIG)(char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*sys_lstat_ORIG)(char __user *filename, struct __old_kernel_stat __user *statbuf);
asmlinkage long (*sys_fstat_ORIG)(unsigned int fd, struct __old_kernel_stat __user *statbuf);

asmlinkage long (*sys_newstat_ORIG)(char __user *filename, struct stat __user *statbuf);
asmlinkage long (*sys_newlstat_ORIG)(char __user *filename, struct stat __user *statbuf);
asmlinkage long (*sys_newfstat_ORIG)(unsigned int fd, struct stat __user *statbuf);

asmlinkage long (*sys_stat64_ORIG)(char __user *filename, struct stat64 __user *statbuf);
asmlinkage long (*sys_lstat64_ORIG)(char __user *filename, struct stat64 __user *statbuf);
asmlinkage long (*sys_fstat64_ORIG)(unsigned long fd, struct stat64 __user *statbuf);

asmlinkage long (*sys_time_ORIG)(time_t __user *tloc);
asmlinkage long (*sys_gettimeofday_ORIG)(struct timeval __user *tv, struct timezone __user *tz);
asmlinkage long (*sys_clock_gettime_ORIG)(clockid_t which_clock, struct timespec __user *tp);

asmlinkage long (*sys_utime_ORIG)(char __user *filename, struct utimbuf __user *times);
asmlinkage long (*sys_utimes_ORIG)(char __user *filename, struct timeval __user *utimes);
asmlinkage long (*sys_utimensat_ORIG)(int dfd, char __user *filename, struct timespec __user *utimes, int flags);
asmlinkage long (*sys_futimesat_ORIG)(int dfd, char __user *filename, struct timeval __user *utimes);


static long TF_current_time = 1367935298L;
//module_param(TF_current_time, long, 0644);

static struct timespec utimes_timespec_wrap[2];
static struct timeval utimes_timeval_wrap[2];

static void disable_page_protection(void) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (value & 0x00010000) {
            value &= ~0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static void enable_page_protection(void) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (!(value & 0x00010000)) {
            value |= 0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

int freeze(struct task_struct *cur, char *syscall_name) {
    struct fs_struct *fs = cur->fs;
    struct dentry *dentry = fs->pwd.dentry;

    strcpy(syscall_path, "");
    strcpy(buf, "");
    while (!IS_ROOT(dentry)) {
        struct dentry *parent = dentry->d_parent;
        strcpy(buf, syscall_path);
        strcpy(syscall_path, dentry->d_name.name);
        strcat(syscall_path, "/");
        strcat(syscall_path, buf);
        dentry = parent;
    }
#ifdef DEBUG_ALL_SYSCALLS
    printk(KERN_INFO "zdronz D: freeze call");
    printk(KERN_INFO "zdronz D: syscall_name = %s; syscall_path = %s\n", syscall_name, syscall_path);
#endif
    return (int)(long)strstr(syscall_path, WORKING_PATH);
}

asmlinkage long sys_stat_TF(char __user *filename, struct __old_kernel_stat __user *statbuf)
{
#ifdef DEBUG_ALL_SYSCALLS
    printk(KERN_INFO "zdronz\n");
#endif
    long ret = sys_stat_ORIG(filename, statbuf);

    if (ret)
        return ret;

    if (freeze(current, "stat")) {
        statbuf->st_atime = TF_current_time;
        statbuf->st_mtime = TF_current_time;
        statbuf->st_ctime = TF_current_time;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: stat(%s,0x%p) from <%s>\n",MODULE_NAME,
               filename, statbuf, current->comm);
#endif
    }
    return ret;
}

asmlinkage long sys_lstat_TF(char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    long ret = sys_lstat_ORIG(filename, statbuf);

    if (ret)
        return ret;

    if (freeze(current, "lstat")) {
        statbuf->st_atime = TF_current_time;
        statbuf->st_mtime = TF_current_time;
        statbuf->st_ctime = TF_current_time;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: lstat(%s,0x%p) from <%s>\n",MODULE_NAME,
               filename, statbuf, current->comm);
#endif
    }
    return ret;
}

asmlinkage long sys_fstat_TF(unsigned int fd, struct __old_kernel_stat __user *statbuf)
{
    long ret = sys_fstat_ORIG(fd, statbuf);

    if (ret)
        return ret;

    if (freeze(current, "fstat")) {
        statbuf->st_atime = TF_current_time;
        statbuf->st_mtime = TF_current_time;
        statbuf->st_ctime = TF_current_time;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: fstat(%u,0x%p) from <%s>\n",MODULE_NAME,
               fd, statbuf, current->comm);
#endif
    }

    return ret;
}

asmlinkage long sys_newstat_TF(char __user *filename, struct stat __user *statbuf)
{
    long ret = sys_newstat_ORIG(filename, statbuf);

    if (ret)
        return ret;

    if (freeze(current, "newstat")) {
        statbuf->st_atime = TF_current_time;
        statbuf->st_atime_nsec = 0L;
        statbuf->st_mtime = TF_current_time;
        statbuf->st_mtime_nsec = 0L;
        statbuf->st_ctime = TF_current_time;
        statbuf->st_ctime_nsec = 0L;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: newstat(%s,0x%p) from <%s>\n",MODULE_NAME,
               filename, statbuf, current->comm);
#endif
    }
    return ret;
}

asmlinkage long sys_newlstat_TF(char __user *filename, struct stat __user *statbuf)
{
    long ret = sys_newlstat_ORIG(filename, statbuf);

    if (ret)
        return ret;

    if (freeze(current, "newlstat")) {
        statbuf->st_atime = TF_current_time;
        statbuf->st_atime_nsec = 0L;
        statbuf->st_mtime = TF_current_time;
        statbuf->st_mtime_nsec = 0L;
        statbuf->st_ctime = TF_current_time;
        statbuf->st_ctime_nsec = 0L;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: newlstat(%s,0x%p) from <%s>\n",MODULE_NAME,
               filename, statbuf, current->comm);
#endif
    }
    return ret;
}

asmlinkage long sys_newfstat_TF(unsigned int fd, struct stat __user *statbuf) 
{
    long ret = sys_newfstat_ORIG(fd, statbuf);

    if (ret)
        return ret;

    if (freeze(current, "newfstat")) {
        statbuf->st_atime = TF_current_time;
        statbuf->st_atime_nsec = 0L;
        statbuf->st_mtime = TF_current_time;
        statbuf->st_mtime_nsec = 0L;
        statbuf->st_ctime = TF_current_time;
        statbuf->st_ctime_nsec = 0L;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: newfstat(%u,0x%p) from <%s>\n",MODULE_NAME,
               fd, statbuf, current->comm);
#endif
    }

    return ret;
}

asmlinkage long sys_stat64_TF(char __user *filename, struct stat64 __user *statbuf)
{
    long ret = sys_stat64_ORIG(filename, statbuf);

    if (ret)
        return ret;

    if (freeze(current, "stat64")) {
        statbuf->st_atime = TF_current_time;
        statbuf->st_atime_nsec = 0L;
        statbuf->st_mtime = TF_current_time;
        statbuf->st_mtime_nsec = 0L;
        statbuf->st_ctime = TF_current_time;
        statbuf->st_ctime_nsec = 0L;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: stat64(%s,0x%p) from <%s>\n",MODULE_NAME,
               filename, statbuf, current->comm);
#endif
    }
    return ret;
}

asmlinkage long sys_lstat64_TF(char __user *filename, struct stat64 __user *statbuf)
{
    long ret = sys_lstat64_ORIG(filename, statbuf);

    if (ret)
        return ret;

    if (freeze(current, "lstat64")) {
        statbuf->st_atime = TF_current_time;
        statbuf->st_atime_nsec = 0L;
        statbuf->st_mtime = TF_current_time;
        statbuf->st_mtime_nsec = 0L;
        statbuf->st_ctime = TF_current_time;
        statbuf->st_ctime_nsec = 0L;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: lstat64(%s,0x%p) from <%s>\n",MODULE_NAME,
               filename, statbuf, current->comm);
#endif
    }
    return ret;
}

asmlinkage long sys_fstat64_TF(unsigned long fd, struct stat64 __user *statbuf)
{
    long ret = sys_fstat64_ORIG(fd, statbuf);

    if (ret)
        return ret;

    if (freeze(current, "fstat64")) {
        statbuf->st_atime = TF_current_time;
        statbuf->st_atime_nsec = 0L;
        statbuf->st_mtime = TF_current_time;
        statbuf->st_mtime_nsec = 0L;
        statbuf->st_ctime = TF_current_time;
        statbuf->st_ctime_nsec = 0L;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: fstat64(%lu,0x%p) from <%s>\n",MODULE_NAME,
               fd, statbuf, current->comm);
#endif
    }

    return ret;
}

asmlinkage long sys_time_TF(time_t __user *tloc)
{
    long ret = sys_time_ORIG(tloc);

    if (freeze(current, "time")) {
        ret = TF_current_time;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: time(0x%p) from <%s>\n",MODULE_NAME,
               tloc, current->comm);
#endif
    }
    return ret;
}

asmlinkage long sys_gettimeofday_TF(struct timeval __user *tv, struct timezone __user *tz)
{
    long ret = sys_gettimeofday_ORIG(tv, tz);

    if (freeze(current, "gettimeofday")) {
        tv->tv_sec = TF_current_time;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: gettimeofday(0x%p,0x%p) from <%s>\n",MODULE_NAME,
               tv, tz, current->comm);
#endif
    }
    return ret;
}

asmlinkage long sys_clock_gettime_TF(clockid_t which_clock, struct timespec __user *tp)
{
    long ret = sys_clock_gettime_ORIG(which_clock, tp);

    if (ret)
        return ret;

    if (freeze(current, "clock_gettime")) {
        tp->tv_sec = TF_current_time;
        tp->tv_nsec = 0L;
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: clock_gettime(%d,0x%p) from <%s>\n",MODULE_NAME,
               which_clock, tp, current->comm);
#endif
    }
    return ret;
}


asmlinkage long sys_utime_TF(char __user *filename, struct utimbuf __user *times)
{
    if (freeze(current, "utime")) {
        if(times) {
            times->actime  = TF_current_time;
            times->modtime = TF_current_time;
#ifdef DEBUG_FREEZE_CASES
            printk(KERN_INFO "%s: utime(0x%p,0x%p) from <%s>\n",MODULE_NAME,
                   filename, times, current->comm);
#endif
        }
    }

    return sys_utime_ORIG(filename, times);
}

asmlinkage long sys_utimes_TF(char __user *filename, struct timeval __user *utimes)
{
    mm_segment_t old_fs;
    long result;

    utimes_timeval_wrap[0].tv_sec  = TF_current_time;
    utimes_timeval_wrap[0].tv_usec  = 0L;
    utimes_timeval_wrap[1].tv_sec  = TF_current_time;
    utimes_timeval_wrap[1].tv_usec  = 0L;

    if (freeze(current, "utimes")) {
#ifdef DEBUG_FREEZE_CASES
            printk(KERN_INFO "%s: utimes(0x%p,0x%p) from <%s>\n",MODULE_NAME,
                   filename, utimes, current->comm);
#endif
        if(utimes) {
            utimes[0].tv_sec  = TF_current_time;
            utimes[0].tv_usec  = 0L;
            utimes[1].tv_sec  = TF_current_time;
            utimes[1].tv_usec  = 0L;
        } else {
            utimes = utimes_timeval_wrap;
            printk(KERN_INFO "utimes = {{%lu, %lu}, {%lu, %lu}}\n", utimes[0].tv_sec, utimes[0].tv_usec, 
                    utimes[1].tv_sec, utimes[1].tv_usec);
        }
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    result = sys_utimes_ORIG(filename, utimes);
    set_fs(old_fs);

    return result;
}

asmlinkage long sys_utimensat_TF(int dfd, char __user *filename, struct timespec __user *utimes, int flags)
{
    mm_segment_t old_fs;
    long result;

    utimes_timespec_wrap[0].tv_sec  = TF_current_time;
    utimes_timespec_wrap[0].tv_nsec  = 0L;
    utimes_timespec_wrap[1].tv_sec  = TF_current_time;
    utimes_timespec_wrap[1].tv_nsec  = 0L;

    if (freeze(current, "utimensat")) {
#ifdef DEBUG_FREEZE_CASES
        printk(KERN_INFO "%s: utimensat(%d,0x%p,0x%p,%d) from <%s>\n",MODULE_NAME,
               dfd, filename, utimes, flags, current->comm);
#endif
        if(utimes) {
            utimes[0].tv_sec  = TF_current_time;
            utimes[0].tv_nsec  = 0L;
            utimes[1].tv_sec  = TF_current_time;
            utimes[1].tv_nsec  = 0L;
        } else {
            utimes = utimes_timespec_wrap;
            printk(KERN_INFO "utimensat = {{%lu, %lu}, {%lu, %lu}}\n", utimes[0].tv_sec, utimes[0].tv_nsec, 
                    utimes[1].tv_sec, utimes[1].tv_nsec);
        }
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    result = sys_utimensat_ORIG(dfd, filename, utimes, flags);
    set_fs(old_fs);

    return result;
}

asmlinkage long sys_futimesat_TF(int dfd, char __user *filename, struct timeval __user *utimes)
{
    mm_segment_t old_fs;
    long result;

    utimes_timeval_wrap[0].tv_sec  = TF_current_time;
    utimes_timeval_wrap[0].tv_usec  = 0L;
    utimes_timeval_wrap[1].tv_sec  = TF_current_time;
    utimes_timeval_wrap[1].tv_usec  = 0L;

    if (freeze(current, "futimesat")) {
#ifdef DEBUG_FREEZE_CASES
            printk(KERN_INFO "%s: futimesat(%d,0x%p,0x%p) from <%s>\n",MODULE_NAME,
                    dfd, filename, utimes, current->comm);
#endif
        if(utimes) {
            utimes[0].tv_sec  = TF_current_time;
            utimes[0].tv_usec  = 0L;
            utimes[1].tv_sec  = TF_current_time;
            utimes[1].tv_usec  = 0L;
        } else {
            utimes = utimes_timeval_wrap;
            printk(KERN_INFO "futimesat = {{%lu, %lu}, {%lu, %lu}}\n", utimes[0].tv_sec, utimes[0].tv_usec, 
                    utimes[1].tv_sec, utimes[1].tv_usec);
        }
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    result = sys_futimesat_ORIG(dfd, filename, utimes);
    set_fs(old_fs);

    return result;
}



static int __init TF_Init(void) {
    printk(KERN_INFO "TimeFreeze: module loaded.\n");

    sys_call_table = (void *)SYS_CALL_TABLE_HARD_ADDRESS;
#ifdef DEBUG_FREEZE_CASES
    printk(KERN_INFO "sys_call_table = %lx\n", (long unsigned int)sys_call_table);
#endif

    sys_stat_ORIG = (long (*)(char *, struct stat *))(sys_call_table[__NR_oldstat]);
    sys_lstat_ORIG = (long (*)(char *, struct stat *))(sys_call_table[__NR_oldlstat]);
    sys_fstat_ORIG = (long (*)(unsigned int, struct stat *))(sys_call_table[__NR_oldfstat]);
    sys_newstat_ORIG = (long (*)(char __user *, struct stat __user *))(sys_call_table[__NR_stat]);
    sys_newlstat_ORIG = (long (*)(char __user *, struct stat __user *))(sys_call_table[__NR_lstat]);
    sys_newfstat_ORIG = (long (*)(unsigned int, struct stat __user *))(sys_call_table[__NR_fstat]);
    sys_stat64_ORIG = (long (*)(char *, struct stat *))(sys_call_table[__NR_stat64]);
    sys_lstat64_ORIG = (long (*)(char *, struct stat *))(sys_call_table[__NR_lstat64]);
    sys_fstat64_ORIG = (long (*)(unsigned long, struct stat *))(sys_call_table[__NR_fstat64]);
    sys_time_ORIG = (long (*)(time_t __user *tloc))(sys_call_table[__NR_time]);
    sys_gettimeofday_ORIG = (long (*)(struct timeval __user *tv, struct timezone __user *tz))(sys_call_table[__NR_gettimeofday]);
    sys_clock_gettime_ORIG = (long (*)(clockid_t which_clock, struct timespec __user *tp))(sys_call_table[__NR_clock_gettime]);
    sys_utime_ORIG = (long (*)(char __user *filename, struct utimbuf __user *times))(sys_call_table[__NR_utime]);
    sys_utimes_ORIG = (long (*)(char __user *filename, struct timeval __user *utimes))(sys_call_table[__NR_utimes]);
    sys_utimensat_ORIG = (long (*)(int dfd, char __user *filename, struct timespec __user *utimes, int flags))sys_call_table[__NR_utimensat];
    sys_futimesat_ORIG = (long (*)(int dfd, char __user *filename, struct timeval __user *utimes))sys_call_table[__NR_futimesat];

    disable_page_protection();
    sys_call_table[__NR_oldstat] = sys_stat_TF;
    sys_call_table[__NR_oldlstat] = sys_lstat_TF;
    sys_call_table[__NR_oldfstat] = sys_fstat_TF;
    sys_call_table[__NR_stat] = sys_newstat_TF;
    sys_call_table[__NR_lstat] = sys_newlstat_TF;
    sys_call_table[__NR_fstat] = sys_newfstat_TF;
    sys_call_table[__NR_stat64] = sys_stat64_TF;
    sys_call_table[__NR_lstat64] = sys_lstat64_TF;
    sys_call_table[__NR_fstat64] = sys_fstat64_TF;
    sys_call_table[__NR_time] = sys_time_TF;
    sys_call_table[__NR_gettimeofday] = sys_gettimeofday_TF;
    sys_call_table[__NR_clock_gettime] = sys_clock_gettime_TF;
    sys_call_table[__NR_utime] = sys_utime_TF;
    sys_call_table[__NR_utimes] = sys_utimes_TF;
    sys_call_table[__NR_utimensat] = sys_utimensat_TF;
    sys_call_table[__NR_futimesat] = sys_futimesat_TF;
    enable_page_protection();

#ifdef DEBUG_FREEZE_CASES
    printk(KERN_INFO "get_seconds = %lu\n", get_seconds());
#endif

    return 0;
}

static void __exit TF_Exit(void) {
    disable_page_protection();
    sys_call_table[__NR_oldstat] = sys_stat_ORIG;
    sys_call_table[__NR_oldlstat] = sys_lstat_ORIG;
    sys_call_table[__NR_oldfstat] = sys_fstat_ORIG;
    sys_call_table[__NR_stat] = sys_newstat_ORIG;
    sys_call_table[__NR_lstat] = sys_newlstat_ORIG;
    sys_call_table[__NR_fstat] = sys_newfstat_ORIG;
    sys_call_table[__NR_stat64] = sys_stat64_ORIG;
    sys_call_table[__NR_lstat64] = sys_lstat64_ORIG;
    sys_call_table[__NR_fstat64] = sys_fstat64_ORIG;
    sys_call_table[__NR_time] = sys_time_ORIG;
    sys_call_table[__NR_gettimeofday] = sys_gettimeofday_ORIG;
    sys_call_table[__NR_clock_gettime] = sys_clock_gettime_ORIG;
    sys_call_table[__NR_utime] = sys_utime_ORIG;
    sys_call_table[__NR_utimes] = sys_utimes_ORIG;
    sys_call_table[__NR_utimensat] = sys_utimensat_ORIG;
    sys_call_table[__NR_futimesat] = sys_futimesat_ORIG;
    enable_page_protection();

    printk(KERN_INFO "TimeFreeze: unloaded module.\n");
}

module_init(TF_Init);
module_exit(TF_Exit);

