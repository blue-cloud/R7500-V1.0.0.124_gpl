/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <asm/linkage.h>

	.section .sram.text, "ax",@progbits
ARC_ENTRY memcmp
	or	r12,r0,r1
	asl_s	r12,r12,30
	sub	r3,r2,1
	brls	r2,r12,.Lbytewise
	ld	r4,[r0,0]
	ld	r5,[r1,0]
	lsr.f	lp_count,r3,3
	lpne	.Loop_end
	ld_s	r2,[r0,4]
	ld_s	r12,[r1,4]
	brne	r4,r5,.Leven
	ld.a	r4,[r0,8]
	ld.a	r5,[r1,8]
	brne	r2,r12,.Lodd
.Loop_end:
	asl_s	r3,r3,3
	bhs_s	.Last_cmp
	brne	r4,r5,.Leven
	ld	r4,[r0,4]
	ld	r5,[r1,4]
	nop_s
	; one more load latency cycle
.Last_cmp:
	xor	r0,r4,r5
	bset	r0,r0,r3
	sub_s	r1,r0,1
	bic_s	r1,r1,r0
	norm	r1,r1
	b.d	.Leven_cmp
	and	r1,r1,24
.Leven:
	xor	r0,r4,r5
	sub_s	r1,r0,1
	bic_s	r1,r1,r0
	norm	r1,r1
	; slow track insn
	and	r1,r1,24
.Leven_cmp:
	asl	r2,r4,r1
	asl	r12,r5,r1
	lsr_s	r2,r2,1
	lsr_s	r12,r12,1
	j_s.d	[blink]
	sub	r0,r2,r12
	.balign	4
.Lodd:
	xor	r0,r2,r12
	sub_s	r1,r0,1
	bic_s	r1,r1,r0
	norm	r1,r1
	; slow track insn
	and	r1,r1,24
	asl_s	r2,r2,r1
	asl_s	r12,r12,r1
	lsr_s	r2,r2,1
	lsr_s	r12,r12,1
	j_s.d	[blink]
	sub	r0,r2,r12
	.balign	4
.Lbytewise:
	breq	r2,0,.Lnil
	ldb	r4,[r0,0]
	ldb	r5,[r1,0]
	lsr.f	lp_count,r3
	lpne	.Lbyte_end
	ldb_s	r3,[r0,1]
	ldb	r12,[r1,1]
	brne	r4,r5,.Lbyte_even
	ldb.a	r4,[r0,2]
	ldb.a	r5,[r1,2]
	brne	r3,r12,.Lbyte_odd
.Lbyte_end:
	bcc	.Lbyte_even
	brne	r4,r5,.Lbyte_even
	ldb_s	r3,[r0,1]
	ldb_s	r12,[r1,1]
.Lbyte_odd:
	j_s.d	[blink]
	sub	r0,r3,r12
.Lbyte_even:
	j_s.d	[blink]
	sub	r0,r4,r5
.Lnil:
	j_s.d	[blink]
	mov	r0,0
ARC_EXIT memcmp
