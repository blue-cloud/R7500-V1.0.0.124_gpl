/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 */

#include <linux/ptrace.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/magic.h>
#include <linux/hardirq.h>
#include <linux/kallsyms.h>
#include <linux/kmsg_dump.h>
#include <asm/arcregs.h>
#include <asm/traps.h>      /* defines for Reg values */
#include <asm/io.h>
#include <linux/fs_struct.h>
#include <linux/proc_fs.h>  // get_mm_exe_file
#include <linux/file.h>     // fput
#include <asm/board/mem_check.h>
#include <asm/board/kdump.h>
#include <asm/board/troubleshoot.h>
#include <asm/cacheflush.h>

static void show_ecr_verbose(struct pt_regs *regs, unsigned long address, unsigned int cause_reg);
static void show_task_ecr_verbose(struct pt_regs *regs);
void show_callee_regs(struct callee_regs *cregs);
static void try_dump_text_region(unsigned long ret);

#define MAX_GUEST_TROUBLESHOOT	1
static void (*kdump_guest_troubleshooters[MAX_GUEST_TROUBLESHOOT])(void);

static kdump_guest_troubleshooters_run(void)
{
	int i;

	for (i = 0; i < MAX_GUEST_TROUBLESHOOT; i++) {
		if (kdump_guest_troubleshooters[i]) {
			kdump_guest_troubleshooters[i]();
		}
	}
}

void kdump_add_troubleshooter(void (*fn)(void))
{
	int i;

	for (i = 0; i < MAX_GUEST_TROUBLESHOOT; i++) {
		if (kdump_guest_troubleshooters[i] == NULL ||
				kdump_guest_troubleshooters[i] == fn) {
			kdump_guest_troubleshooters[i] = fn;
			break;
		}
	}
}
EXPORT_SYMBOL(kdump_add_troubleshooter);

/* For dumping register file (r0-r12) or (r13-r25), instead of 13 printks,
 * we simply loop otherwise gcc generates 13 calls to printk each with it's
 * own arg setup
 */
void noinline print_reg_file(unsigned long *last_reg, int num)
{
    unsigned int i;

    for (i = num; i < num + 13; i++) {
        printk("r%02u: 0x%08lx\t", i, *last_reg);
        if ( ( (i+1) % 3) == 0 ) printk("\n");
        last_reg--;
    }
}


void show_callee_regs(struct callee_regs *cregs)
{
    print_reg_file(&(cregs->r13), 13);
    printk("\n");
}

void print_task_path_n_nm(struct task_struct *task, char *buf)
{
    struct path path;
    char *nm = NULL;
    struct mm_struct *mm;
    struct file *exe_file;
    int asid = -1;

    mm = get_task_mm(task);
    if (!mm) goto done;

    exe_file = get_mm_exe_file(mm);
    asid = mm->context.asid;
    mmput(mm);

    if (exe_file) {
        path = exe_file->f_path;
        path_get(&exe_file->f_path);
        fput(exe_file);
        nm = d_path(&path, buf, 255);
        path_put(&path);
    }

done:
    printk("\ntask = %s '%s', PID = %u, ASID = %d\n", nm, task->comm,
               task->pid, asid);
}

static void show_faulting_vma(unsigned long address, char *buf)
{
    struct vm_area_struct *vma;
    struct inode *inode;
    unsigned long ino = 0;
    dev_t dev = 0;
    char *nm = buf;

    vma = find_vma(current->active_mm, address);

    /* check against the find_vma( ) behaviour which returns the next VMA
     * if the container VMA is not found
     */
    if (vma && (vma->vm_start <= address)) {
        struct file *file = vma->vm_file;
        if (file) {
                struct path *path = &file->f_path;
                nm = d_path(path, buf, PAGE_SIZE -1);
                inode = vma->vm_file->f_path.dentry->d_inode;
                dev = inode->i_sb->s_dev;
                ino = inode->i_ino;
        }
        printk("@offset 0x%lx in [%s] \nVMA: start 0x%08lx end 0x%08lx\n\n",
               address - vma->vm_start, nm, vma->vm_start, vma->vm_end);
    }
    else printk("@No matching VMA found\n");
}
void show_stack_fragment(u32 sp)
{
	const u32 print_past_sp   = 512;
	const u32 print_before_sp = 512;
	const u32 min_sp = sp & ~(THREAD_SIZE - 1);
	const u32 max_sp = min_sp + THREAD_SIZE;
	int i = 0;

	/* avoid double faults on unaligned sp */
	if ((sp % 4) != 0) {
		printk(KERN_ERR"sp 0x%08x is misaligned, cannot print stack fragment\n", sp);
		return;
	}

	/* avoid double fault tlb miss */
	if (!is_linux_mem_addr(sp)) {
		printk(KERN_ERR"sp 0x%08x is out of valid range, cannot print stack fragment\n", sp);
		return;
	}

	/* check stack */
#ifdef CONFIG_DEBUG_STACK_USAGE
	printk(KERN_ERR"\nStack not used for current process: %lu\n",
			current ? stack_not_used(current) : (unsigned long)-1);
#endif
	if (!is_kernel_stack_good()) {
		printk(KERN_ERR"\nThread overran stack, or stack corrupted\n");
	}
	if (!is_sram_irq_stack_good()) {
		printk(KERN_ERR"\nIRQ overran stack, or stack corrupted\n");
	}

	/* print stack */

	u32 *begin = (u32*)max((sp - print_before_sp), min_sp);
	u32 *end = (u32*)min((sp + print_past_sp), max_sp);

	printk(KERN_ERR"\nStack: sp 0x%08x data 0x%p - 0x%p\n", sp, begin, end);

	while (begin < end) {
		if (i == 0) {
			printk(KERN_ERR"0x%08x: ", (u32)begin);
		}

		printk("0x%08x ", *begin);

		i++;
		begin++;

		if (i == 8) {
			printk("\n");
			i = 0;
		}
	}
	printk("\n");
}

void show_kernel_mode(void)
{
	printk(KERN_ERR"\nMode: in_irq=0x%lx in_softirq=0x%lx in_interrupt=0x%lx in_atomic=0x%lx\n",
		(unsigned long)in_irq(), (unsigned long)in_softirq(),
		(unsigned long)in_interrupt(), (unsigned long)in_atomic());
	printk(KERN_ERR"Preemption: preemptible=%d count=0x%lx\n",
		(int)preemptible(), (unsigned long)preempt_count());
}

static void show_ecr_verbose(struct pt_regs *regs, unsigned long address, unsigned int cause_reg)
{
    extern unsigned int ex_ic_ctrl;
    extern unsigned int ex_ic_data;

    unsigned int cause_vec = cause_reg >> 16;
    unsigned int cause_code = ( cause_reg >> 8 ) & 0xFF;

    /* For DTLB Miss or ProtV, display the memory involved too */
    if ( cause_vec == DATA_TLB_MISS)   // DTLB Miss
    {
        if (cause_code != 0x04 ) {  // Mislaigned access doesn't tell R/W/X
            printk("While (%s): 0x%08lx by instruction @ 0x%08lx\n",
                ((cause_code == 0x01)?"Read From":
                ((cause_code == 0x02)?"Write to":"Exchg")),
                address, regs->ret);
        }
	}
    else if (cause_vec == 0x21)   // ITLB Miss
    {
        printk("Insn could not be fetched\n");
    } else if (cause_vec == MACHINE_CHECK) {  /* Machine Check */
        printk("Reason: (%s)\n",
            (cause_code == DOUBLE_FAULT)?"Double Fault":"Other Fatal Err");
    }  else if (cause_vec == PROTECTION_VIOL) {
        printk("Reason : ");
        if (cause_code == 0x0)
            printk("Instruction fetch protection violation (execute from page marked non-execute)\n");
        else if (cause_code == 0x1)
            printk("Data read protection violation (read from page marked non-read)\n");
        else if (cause_code == 0x2)
            printk("Data store protection violation (write to a page marked non-write)\n");
        else if (cause_code == 0x3)
            printk("Data exchange protection violation\n");
        else if (cause_code ==0x4)
            printk("Misaligned access @ 0x%08lx\n", address);
    } else if (cause_vec == INSTRUCTION_ERROR) {
        printk("Instruction error: ");
		if (cause_code == ILLEGAL_INST)
	    	printk("Illegal instruction\n");
		else if (cause_code == ILLEGAL_INST_SEQ)
	 	   printk("Illegal instruction sequence\n");

		try_dump_text_region(regs->ret);
    } else {
        printk("Check Programmer's Manual\n");
    }

    if (ex_ic_ctrl) {
        if (ex_ic_ctrl & BIT_IC_CTRL_SB) {
            printk("\nBad instruction value got from icache: 0x%x\n", ex_ic_data);
        } else {
            printk("\nBad instruction is not in icache (replaced quickly?)\n");
        }
    }

    printk("\n[ECR]: 0x%08x\n", cause_reg);
    printk("[EFA]: 0x%08lx\n", address);
}


static void show_task_ecr_verbose(struct pt_regs *regs)
{
    if(current->thread.cause_code) {
        printk("Current task = '%s', PID = %u, ASID = %lu\n", current->comm,
            current->pid, current->active_mm->context.asid);

        show_ecr_verbose(regs,
            current->thread.fault_address,
            current->thread.cause_code);
    }
}
/************************************************************************
 *  API called by rest of kernel
 ***********************************************************************/

void show_regs(struct pt_regs *regs)
{
    struct task_struct *tsk = current;
    struct callee_regs *cregs;
    char *buf;

    buf = (char *)__get_free_page(GFP_TEMPORARY);
    if (!buf)
        return;

    print_task_path_n_nm(tsk, buf);

	show_task_ecr_verbose(regs);

    printk("[EFA]: 0x%08lx\n", current->thread.fault_address);
    printk("[ERET]: 0x%08lx (Faulting instruction)\n",regs->ret);

    show_faulting_vma(regs->ret, buf);   // VMA of faulting code, not data

    //extern void print_vma_addr(char *prefix, unsigned long ip);
    //print_vma_addr("",regs->ret);

    /* print special regs */
    printk("status32: 0x%08lx\n", regs->status32);
    printk("SP: 0x%08lx\tFP: 0x%08lx\n", regs->sp, regs->fp);
    printk("BLINK: 0x%08lx\tBTA: 0x%08lx\n",
            regs->blink, regs->bta);
    printk("LPS: 0x%08lx\tLPE: 0x%08lx\tLPC: 0x%08lx \n",
            regs->lp_start, regs->lp_end, regs->lp_count);

    /* print regs->r0 thru regs->r12
     * Sequential printing was generating horrible code
     */
    print_reg_file(&(regs->r0), 0);

    // If Callee regs were saved, display them too
    cregs = (struct callee_regs *) current->thread.callee_reg;
    if (cregs) show_callee_regs(cregs);

    free_page((unsigned long) buf);
}

/************************************************************************
 *  Verbose Display of Exception
 ***********************************************************************/

static void try_dump_text_region(unsigned long ret)
{
#define DUMP_BYTES_PRIOR 32
#define DUMP_BYTES_POST 31
	unsigned long lower_bound = ret - DUMP_BYTES_PRIOR;
	unsigned long upper_bound = ret + DUMP_BYTES_POST;
	u8 *p_instr = (u8 *)lower_bound;

	/* We look slightly before and after the current pointer, but
	 * only if they are within bounds.
	 */
	if (is_valid_mem_addr(lower_bound) && is_valid_mem_addr(upper_bound)) {
		int i;
		printk("0x%08x:", (unsigned int)lower_bound);
		for (i = lower_bound; i <= upper_bound; i++) {
			printk(" 0x%02x", *p_instr++);
			if (i && (((i - lower_bound + 1) % 16) == 0)) {
				printk("\n0x%08x:", (unsigned int)(i + 1));
			}
		}
	} else if (!is_valid_mem_addr(ret)) {
		printk("Not a valid memory address to fetch (%08X)\n", ret);
	} else {
		/* Single valid address - dump four bytes. Should be safe... */
		int i;
		p_instr = (u8 *)ret;
		printk("Instruction @ 0x%08x ->", (unsigned int)ret);
		for (i = 0; i < 4; i++) {
			printk(" 0x%02x", *p_instr++);
		}
	}
}


static void show_ruby_soc_registers()
{
	unsigned long base_addr = RUBY_SYS_CTL_BASE_ADDR;
	/* Registers up to offset 0x8C are contiguous, then from 0x94 to 0xC0 */
	unsigned int reg_ranges[2][2] = {{0x0, 0x8C}, {0x94, 0xC0}};
	int i;

	for (i = 0; i < 2; i++) {
		int j;
		printk("\n0x%08x:", (unsigned int)base_addr + reg_ranges[i][0]);
		for (j = reg_ranges[i][0]; j <= reg_ranges[i][1]; j += 4) {
			printk(" 0x%08x", readl(base_addr + j));
			if (j && (((j + 4) % 32) == 0)) {
				printk("\n0x%08x:", (unsigned int)base_addr + j + 4);
			}
		}
	}
}

static unsigned long s_sram_start = 0x0;
static unsigned long s_sram_end = 0x0;
static unsigned long s_sram_safe_size = 0;

void
arc_set_sram_safe_area(unsigned long sram_start, unsigned long sram_end)
{
	s_sram_start = sram_start;
	s_sram_end = sram_end;
	s_sram_safe_size = s_sram_end - s_sram_start;
}
EXPORT_SYMBOL(arc_set_sram_safe_area);

static arc_troubleshoot_start_hook_cbk sf_troubleshoot_start = NULL;
static void *sp_troubleshoot_ctx = NULL;

void
arc_set_troubleshoot_start_hook(arc_troubleshoot_start_hook_cbk in_troubleshoot_start, void *in_ctx)
{
	sf_troubleshoot_start = in_troubleshoot_start;
	sp_troubleshoot_ctx = in_ctx;
}
EXPORT_SYMBOL(arc_set_troubleshoot_start_hook);

void save_printk_sram(void)
{
	char *sp = (char *)s_sram_start;
	int log_start = 0;
	int log_end = 0;
	int log_size = 0;
	char *p_log = NULL;

	if (sf_troubleshoot_start) {
		sf_troubleshoot_start(sp_troubleshoot_ctx);
	}

	get_log_buf(&log_end, &log_size, &p_log);

	if (!log_size)
		return;

	if (log_end >= log_size)
		log_start = log_end - log_size;

	if ((log_end - log_start) >= s_sram_safe_size)
		log_start = log_end - s_sram_safe_size;

	while (log_start != log_end) {
		*sp++ = *(p_log + (log_start++ & (log_size - 1)));
	}

	/* Magic number goes almost at the end of the buffer */
	sp = (char *)s_sram_start + (s_sram_safe_size - 1);
	*sp = QTN_SAFE_SRAM_MAGIC;
	flush_dcache_all();
}

void show_kernel_fault_diag(const char *str, struct pt_regs *regs,
	unsigned long address, unsigned long cause_reg)
{
	if (sf_troubleshoot_start) {
		sf_troubleshoot_start(sp_troubleshoot_ctx);
	}
	current->thread.fault_address = address;
	current->thread.cause_code = cause_reg;

	// Caller and Callee regs
	show_regs(regs);

	// Show ECR
	show_ecr_verbose(regs, address, cause_reg);

	// Show kernel mode
	show_kernel_mode();

	// Show kernel stack trace if this Fatality happened in kernel mode
	if (!user_mode(regs))
		show_stacktrace(current, regs);

	kdump_take_snapshot("kernel halt");
	kdump_compare_all_snapshots();

	if (regs && regs->sp) {
		show_stack_fragment(regs->sp);
	}

	/* Dump context of the SoC */
	show_ruby_soc_registers();
	kmsg_dump(KMSG_DUMP_PANIC);

	sort_snaps(1);

	kdump_guest_troubleshooters_run();
	save_printk_sram();
}


/*
 * Monitoring a Variable every IRQ entry/exit
 * Low Level ISR can code to dump the contents of a variable
 * This can for e.g. be used to figure out the whether the @var
 * got clobbered during ISR or between ISRs (pure kernel mode)
 *
 * The macro itself can be switched on/off at runtime using a toggle
 * @irq_inspect_on
 */
int irq_inspect_on = 1;   // toggle to switch on/off at runtime

/* Function called from level ISR */
void print_var_on_irq(int irq, int in_or_out, uint addr, uint val)
{
    extern void raw_printk5(const char *str, uint n1, uint n2,
                                uint n3, uint n4);

#ifdef CONFIG_ARC_UART_CONSOLE
    raw_printk5("IRQ \n", irq, in_or_out, addr, val);
#endif
}

#ifdef CONFIG_DEBUG_FS

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/namei.h>
#include <linux/debugfs.h>


static struct dentry *test_dentry;
static struct dentry *test_dir;
static struct dentry *test_u32_dentry;

u32 clr_on_read = 1;

#ifdef CONFIG_ARC_TLB_PROFILE
u32 numitlb, numdtlb, num_pte_not_present;

static int fill_display_data(char *kbuf)
{
    size_t num = 0;
    num += sprintf(kbuf+num, "I-TLB Miss %x\n", numitlb);
    num += sprintf(kbuf+num, "D-TLB Miss %x\n", numdtlb);
    num += sprintf(kbuf+num, "PTE not present %x\n", num_pte_not_present);

    if (clr_on_read)
        numitlb = numdtlb = num_pte_not_present = 0;

    return num;
}

static int tlb_stats_open(struct inode *inode, struct file *file)
{
    file->private_data = (void *)__get_free_page(GFP_KERNEL);
    return 0;
}

/* called on user read(): display the couters */
static ssize_t tlb_stats_output(
    struct file *file,      /* file descriptor */
    char __user *user_buf,  /* user buffer */
    size_t  len,            /* length of buffer */
    loff_t *offset)         /* offset in the file */
{
    size_t num;
    char *kbuf = (char *)file->private_data;

    num = fill_display_data(kbuf);

   /* simple_read_from_buffer() is helper for copy to user space
     It copies up to @2 (num) bytes from kernel buffer @4 (kbuf) at offset
     @3 (offset) into the user space address starting at @1 (user_buf).
     @5 (len) is max size of user buffer
   */
    return simple_read_from_buffer(user_buf, num, offset, kbuf, len);
}

/* called on user write : clears the counters */
static ssize_t tlb_stats_clear(struct file *file, const char __user *user_buf,
     size_t length, loff_t *offset)
{
    numitlb = numdtlb = num_pte_not_present = 0;
    return  length;
}


static int tlb_stats_close(struct inode *inode, struct file *file)
{
    free_page((unsigned long)(file->private_data));
    return 0;
}

static struct file_operations tlb_stats_file_ops = {
    .read = tlb_stats_output,
    .write = tlb_stats_clear,
    .open = tlb_stats_open,
    .release = tlb_stats_close
};
#endif

static int __init arc_debugfs_init(void)
{
    test_dir = debugfs_create_dir("arc", NULL);

#ifdef CONFIG_ARC_TLB_PROFILE
    test_dentry = debugfs_create_file("tlb_stats", 0444, test_dir, NULL,
                            &tlb_stats_file_ops);
#endif

    test_u32_dentry = debugfs_create_u32("clr_on_read", 0444, test_dir, &clr_on_read);

    return 0;
}
module_init(arc_debugfs_init);

static void __exit arc_debugfs_exit(void)
{
    debugfs_remove(test_u32_dentry);
    debugfs_remove(test_dentry);
    debugfs_remove(test_dir);
}

#endif
