/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Vineetg: Aug 2009
 *  -"C" version of lowest level context switch asm macro called by schedular
 *   gcc doesn't generate the dward CFI info for hand written asm, hence can't
 *   backtrace out of it (e.g. tasks sleeping in kernel).
 *   So we cheat a bit by writing almost similar code in inline-asm.
 *  -This is a hacky way of doing things, but there is no other simple way.
 *   I don't want/intend to extend unwinding code to understand raw asm
 */

#include <asm/system.h>
#include <asm/asm-offsets.h>
#include <linux/sched.h>    //__sched

struct task_struct * __sched
__switch_to(struct task_struct *prev_task, struct task_struct *next_task)
{
    unsigned int tmp;
    unsigned int prev = (unsigned int)prev_task;
    unsigned int next = (unsigned int)next_task ;
    int num_words_to_skip = 1;
#ifdef CONFIG_ARCH_ARC_CURR_IN_REG
    num_words_to_skip++;
#endif

    __asm__ __volatile__(

    // The fp, blink stashing is generated by gcc as part of standard
    // function prelogue

    //--------------------------------
    "st.a    r13, [sp, -4]   \n\t"
    "st.a    r14, [sp, -4]   \n\t"
    "st.a    r15, [sp, -4]   \n\t"
    "st.a    r16, [sp, -4]   \n\t"
    "st.a    r17, [sp, -4]   \n\t"
    "st.a    r18, [sp, -4]   \n\t"
    "st.a    r19, [sp, -4]   \n\t"
    "st.a    r20, [sp, -4]   \n\t"
    "st.a    r21, [sp, -4]   \n\t"
    "st.a    r22, [sp, -4]   \n\t"
    "st.a    r23, [sp, -4]   \n\t"
    "st.a    r24, [sp, -4]   \n\t"
#ifndef CONFIG_ARCH_ARC_CURR_IN_REG
    "st.a    r25, [sp, -4]   \n\t"
#endif
    "sub     sp, sp, %4      \n\t"

    //--------------------------------
    "st.as   sp, [%3, %1]    \n\t"

    //--------------------------------
    "sync   \n\t"

    //--------------------------------
    "st  %2, [_current_task]   \n\t"
#ifdef CONFIG_ARCH_ARC_CURR_IN_REG
    "mov r25, %2   \n\t"
#endif

    //--------------------------------
    "ld.as  sp, [%2, %1]   \n\t"

    "add    sp, sp, %4     \n\t"
    //--------------------------------
#ifndef CONFIG_ARCH_ARC_CURR_IN_REG
    "ld.ab   r25, [sp, 4]   \n\t"
#endif
    "ld.ab   r24, [sp, 4]   \n\t"
    "ld.ab   r23, [sp, 4]   \n\t"
    "ld.ab   r22, [sp, 4]   \n\t"
    "ld.ab   r21, [sp, 4]   \n\t"
    "ld.ab   r20, [sp, 4]   \n\t"
    "ld.ab   r19, [sp, 4]   \n\t"
    "ld.ab   r18, [sp, 4]   \n\t"
    "ld.ab   r17, [sp, 4]   \n\t"
    "ld.ab   r16, [sp, 4]   \n\t"
    "ld.ab   r15, [sp, 4]   \n\t"
    "ld.ab   r14, [sp, 4]   \n\t"
    "ld.ab   r13, [sp, 4]   \n\t"

    //--------------------------------
    // last (return value) = prev (1st arg)
    // (although for ARC it moves r0 to r0
    "mov     %0, %3        \n\t"

    // Again fp, blink restoration is generated by gcc as part of standard
    // function epilogie

    :"=r" (tmp)
    :"n" ((TASK_THREAD + THREAD_KSP)/4),
     "r" (next),
     "r"(prev),
     "n" (num_words_to_skip * 4)
    :"blink"
    );

    return (struct task_struct *) tmp;
}
