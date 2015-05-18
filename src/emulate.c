/*
 * x86 instruction emulation
 *
 * Copyright (C) 2011 - 2013 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include "emulate.h"

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "linux-errno.h"
#include "linux-defines.h"
#include "filp.h"
#include "process.h"
#include "debug.h"
#include "vm.h"

#define CARRY(regs) ((regs).EFlags & 1)

static inline PULONG getwreg(struct process *p, int reg)
{
	switch (reg & 7)
	{
	case 0: return &p->regs.Eax;
	case 1: return &p->regs.Ecx;
	case 2: return &p->regs.Edx;
	case 3: return &p->regs.Ebx;
	case 4: return &p->regs.Esp;
	case 5: return &p->regs.Ebp;
	case 6: return &p->regs.Esi;
	case 7: return &p->regs.Edi;
	default:
		abort();
	}
}

#define GETRM(process, out, modrm, instsz)				\
	do {								\
		if (((modrm) & 0xc0) == 0x40)				\
		{							\
			uint8_t disp8;					\
									\
			r = vm_memcpy_from_process(process, &disp8,	\
					 eip + instsz, sizeof disp8);	\
			if (r < 0)					\
				return -_L(EFAULT);			\
			instsz++;					\
			switch ((modrm) & 7)				\
			{						\
			case 0: out = process->regs.Eax; break;		\
			case 1: out = process->regs.Ecx; break;		\
			case 2: out = process->regs.Edx; break;		\
			case 3: out = process->regs.Ebx; break;		\
			case 4: return -_L(EFAULT);			\
			case 5: out = process->regs.Ebp; break;		\
			case 6: out = process->regs.Esi; break;		\
			case 7: out = process->regs.Edi; break;		\
			}						\
			out += disp8;					\
			break;						\
		}							\
		if (((modrm) & 0xc0) != 0)				\
		{							\
			fprintf(stderr,					\
				"getrm0: unhandled modrm %08x\n",	\
				 (modrm));				\
			return -_L(EFAULT);				\
		}							\
		switch ((modrm) & 7)					\
		{							\
		case 0: out = process->regs.Eax; break;			\
		case 1: out = process->regs.Ecx; break;			\
		case 2: out = process->regs.Edx; break;			\
		case 3: out = process->regs.Ebx; break;			\
		case 5: 						\
			r = vm_memcpy_from_process(process, &out,	\
					 eip + instsz, sizeof out);	\
			if (r < 0)					\
				return -_L(EFAULT);			\
			instsz += 4;					\
			break;						\
		case 6: out = process->regs.Esi; break;			\
		case 7: out = process->regs.Edi; break;			\
		default:						\
			die("getrm0: unhandled rm %08x\n",		\
				 (modrm) & 7);				\
		}							\
	} while (0)

static void handle_mov_reg_to_seg_reg(struct process *p, uint8_t modrm)
{
	if ((modrm & 0xf8) != 0xe8)
	{
		die("unhandled mov\n");
	}
	else
	{
		ULONG *reg = getwreg(p, modrm & 7);
		unsigned int x = ((*reg) >> 3) - 0x80;
		if (x >= MAX_VTLS_ENTRIES)
		{
			die("vtls out of range\n");
		}
		p->vtls_selector = x;
	}
	p->regs.Eip += 2;
}

static int handle_mov_eax_to_gs_addr(struct process *p)
{
	unsigned int offset = 0;
	int r;
	unsigned char *tls;
	char *eip = (char*) p->regs.Eip;

	r = vm_memcpy_from_process(p, &offset, eip + 2, sizeof offset);
	if (r < 0)
		return r;

	tls = (unsigned char*) p->vtls[p->vtls_selector].base_addr;
	tls += offset;
	r = vm_memcpy_to_process(p, tls, &p->regs.Eax, 4);
	if (r < 0)
		return r;

	p->regs.Eip += 6;

	return 0;
}

static int handle_mov_gs_addr_to_eax(struct process *p)
{
	unsigned int offset = 0;
	int r;
	unsigned char *tls;
	char *eip = (char*) p->regs.Eip;

	r = vm_memcpy_from_process(p, &offset, eip + 2, sizeof offset);
	if (r < 0)
		return r;

	tls = (unsigned char*) p->vtls[p->vtls_selector].base_addr;
	tls += offset;
	r = vm_memcpy_from_process(p, &p->regs.Eax, tls, 4);
	if (r < 0)
		return r;

	p->regs.Eip += 6;
	return r;
}

static int handle_movl_to_gs_reg(struct process *p)
{
	int r;
	unsigned char *tls;
	int8_t modrm;
	uint32_t value;
	char *eip = (char*) p->regs.Eip;
	uint32_t val;
	int instsz = 3;

	r = vm_memcpy_from_process(p, &modrm, eip + 2, sizeof modrm);
	if (r < 0)
		return r;

	if (modrm & 0x38)
		return -_L(EFAULT);

	tls = (unsigned char*) p->vtls[p->vtls_selector].base_addr;
	GETRM(p, val, modrm, instsz);
	tls += val;

	r = vm_memcpy_from_process(p, &value, eip + instsz, sizeof value);
	if (r < 0)
		return r;
	instsz += 4;

	r = vm_memcpy_to_process(p, tls, &value, sizeof value);
	if (r < 0)
		return r;

	p->regs.Eip += instsz;
	return r;
}

static int handle_compare_imm8_to_gs_address(struct process *p)
{
	int r;
	unsigned char *tls;
	uint8_t modrm;
	uint8_t imm8;
	uint32_t value;
	uint32_t val;
	char *eip = (char*) p->regs.Eip;
	int instsz = 3;

	r = vm_memcpy_from_process(p, &modrm, eip + 2, sizeof modrm);
	if (r < 0)
		return r;

	if ((modrm & 0x38) != 0x38)
	{
		fprintf(stderr, "emulate: unhandled instruction "
			"%02x %02x %02x ...\n", 0x65, 0x83, modrm);
		return -1;
	}

	tls = (unsigned char*) p->vtls[p->vtls_selector].base_addr;
	GETRM(p, val, modrm, instsz);
	tls += val;

	r = vm_memcpy_from_process(p, &imm8, eip + instsz, sizeof imm8);
	if (r < 0)
		return r;
	instsz++;

	r = vm_memcpy_from_process(p, &value, tls, sizeof value);
	if (r < 0)
		return r;

	/* set the flags */
	__asm__ __volatile__ (
		"\txor %%eax, %%eax\n"
		"\tcmpl %0, %1\n"
		"\tlahf\n"
		"\tmovb %%ah, (%2)\n"
	: : "r"((uint32_t)imm8), "r"(value), "r"(&p->regs.EFlags) : "eax");

	p->regs.Eip += instsz;

	return r;
}

static int handle_reg_indirect_to_read(struct process *p)
{
	int r;
	unsigned char *tls;
	struct {
		uint8_t modrm;
	} __attribute__((__packed__)) buf;
	unsigned long *preg;
	char *eip = (char*) p->regs.Eip;
	int val;
	int instsz = 3;

	r = vm_memcpy_from_process(p, &buf, eip + 2, sizeof buf);
	if (r < 0)
		return r;

	// 65 8b 38			mov    %gs:(%eax),%edi
	tls = (unsigned char*) p->vtls[p->vtls_selector].base_addr;

	preg = getwreg(p, buf.modrm >> 3);

	GETRM(p, val, buf.modrm, instsz);

	tls += val;
	r = vm_memcpy_from_process(p, preg, tls, sizeof *preg);
	if (r < 0)
		return r;

	p->regs.Eip += instsz;

	return 0;
}

static int handle_reg_indirect_to_write(struct process *p)
{
	int r;
	unsigned char *tls;
	struct {
		uint8_t modrm;
	} __attribute__((__packed__)) buf;
	unsigned long *preg;
	char *eip = (char*) p->regs.Eip;
	int val;
	int instsz = 3;

	r = vm_memcpy_from_process(p, &buf, eip + 2, sizeof buf);
	if (r < 0)
		return r;

	tls = (unsigned char*) p->vtls[p->vtls_selector].base_addr;

	preg = getwreg(p, buf.modrm >> 3);

	GETRM(p, val, buf.modrm, instsz);
	tls += val;
	r = vm_memcpy_to_process(p, tls, preg, sizeof *preg);
	if (r < 0)
		return r;

	p->regs.Eip += instsz;

	return 0;
}

static int handle_mem_to_reg_intop(struct process *p, unsigned char op)
{
	int r;
	unsigned char *tls;
	struct {
		uint8_t modrm;
	} __attribute__((__packed__)) buf;
	unsigned long *preg;
	char *eip = (char*) p->regs.Eip;
	int val;
	int instsz = 3;
	unsigned long *source;
	void *ptr;
	size_t max_size = 0;

	r = vm_memcpy_from_process(p, &buf, eip + 2, sizeof buf);
	if (r < 0)
		return r;

	tls = (unsigned char*) p->vtls[p->vtls_selector].base_addr;

	preg = getwreg(p, buf.modrm >> 3);

	GETRM(p, val, buf.modrm, instsz);
	tls += val;
	r = vm_get_pointer(p, tls, &ptr, &max_size);
	if (r < 0)
		return r;
	if (max_size < 4)
		return -_L(EFAULT);

	source = ptr;
	switch (op)
	{
#define ASMOP(op) __asm__ ("\t" #op "l %1, %0; lahf; movb %%ah, (%2)\n" \
			: "+r"(*preg) \
			: "r"(*source), "r"(&p->regs.EFlags) \
			: "eax")

	case 0: ASMOP(add); break;
	case 1: ASMOP(or);  break;
	case 2: ASMOP(adc); break;
	case 3: ASMOP(adc); break;
	case 4: ASMOP(and); break;
	case 5: ASMOP(sbb); break;
	case 6: ASMOP(xor); break;

#undef ASMOP
	case 7:
		die("unhandled integer op at %d\n", __LINE__);
	}

	p->regs.Eip += instsz;

	return 0;
}

static int handle_ff_op(struct process *p)
{
	struct {
		uint8_t x;
		uint32_t offset;
	} __attribute__((__packed__)) buf;
	unsigned char *tls;
	char *eip = (char*) p->regs.Eip;
	int r;
	int instsz = 7;

	r = vm_memcpy_from_process(p, &buf, eip + 2, sizeof buf);
	if (r < 0)
		return r;

	if (buf.x == 0x15)
	{
		uint32_t val;
		uint32_t retaddr;
		uint32_t stack;

		tls = (unsigned char*) p->vtls[p->vtls_selector].base_addr;
		tls += buf.offset;
		r = vm_memcpy_from_process(p, &val, tls, sizeof val);
		if (r < 0)
			return r;

		retaddr = p->regs.Eip + instsz;
		stack = p->regs.Esp - 4;

		// push Eip
		r = vm_memcpy_to_process(p, (void*)stack,
					 &retaddr, sizeof retaddr);
		if (r < 0)
			return r;

		p->regs.Esp = stack;
		p->regs.Eip = val;
	}
	else
		die("unhandled op: 0x65 0xff 0x%02x\n", buf.x);

	return 0;
}

int emulate_instruction(struct process *p, unsigned char *buffer)
{
	int r;

	// 8e e8			mov    %eax,%gs
	if (buffer[0] == 0x8e)
	{
		handle_mov_reg_to_seg_reg(p, buffer[1]);
		return 1;
	}
	// 65 a3 14 00 00 00		mov    %eax,%gs:0x14
	else if (buffer[0] == 0x65 && buffer[1] == 0xa3)
	{
		r = handle_mov_eax_to_gs_addr(p);
		if (r < 0)
			return 0;
	}
	else if (buffer[0] == 0x65 && buffer[1] == 0xa1)
	{
		r = handle_mov_gs_addr_to_eax(p);
		if (r < 0)
			return 0;
	}
	// 65 c7 02 ff ff ff ff		movl   $0xffffffff,%gs:(%edx)
	// 65 c7 00 80 c4 1b 08		movl   $0x81bc480,%gs:(%eax)
	else if (buffer[0] == 0x65 && buffer[1] == 0xc7)
	{
		r = handle_movl_to_gs_reg(p);
		if (r < 0)
			return 0;
	}
	// 65 83 3d 0c 00 00 00 00	cmpl   $0x0,%gs:0xc
	// 65 83 38 16			cmpl   $0x16,%gs:(%eax)
	else if (buffer[0] == 0x65 && buffer[1] == 0x83)
	{
		r = handle_compare_imm8_to_gs_address(p);
		if (r < 0)
			return 0;
	}
	// 65 89 0b			mov    %ecx,%gs:(%ebx)
	else if (buffer[0] == 0x65 && buffer[1] == 0x89)
	{
		r = handle_reg_indirect_to_write(p);
		if (r < 0)
			return 0;
	}
	// 65 8b 03			mov    %gs:(%ebx),%eax
	// 65 8b 38			mov    %gs:(%eax),%edi
	// 65 8b 45 00			mov    %gs:0x0(%ebp),%eax
	else if (buffer[0] == 0x65 && buffer[1] == 0x8b)
	{
		r = handle_reg_indirect_to_read(p);
		if (r < 0)
			return 0;
	}
	// 65 33 15 18 00 00 00		xor    %gs:0x18,%edx
	else if (buffer[0] == 0x65 && (buffer[1] & 0xc7) == 3)
	{
		r = handle_mem_to_reg_intop(p, (buffer[1] & 0x38) >> 3);
		if (r < 0)
			return 0;
	}
	// 65 ff 15 10 00 00 00    call   *%gs:0x10
	else if (buffer[0] == 0x65 && buffer[1] == 0xff)
	{
		r = handle_ff_op(p);
		if (r < 0)
			return 0;
	}
	else
		return 0;

	return 1;
}
