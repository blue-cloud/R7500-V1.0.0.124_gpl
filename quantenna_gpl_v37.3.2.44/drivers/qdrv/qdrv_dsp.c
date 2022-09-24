/**
  Copyright (c) 2008 - 2013 Quantenna Communications Inc
  All Rights Reserved

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

 **/

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>

#include <linux/device.h>
#include <linux/firmware.h>
#include <asm/io.h>
#include "qdrv_features.h"
#include "qdrv_debug.h"
#include "qdrv_mac.h"
#include "qdrv_soc.h"
#include "qdrv_dsp.h"
#include "qdrv_hal.h"
#include <qtn/registers.h>


static inline unsigned long
dsp_to_host_addr(unsigned long dsp_addr)
{
	void *ret = bus_to_virt(dsp_addr);
	if (RUBY_BAD_VIRT_ADDR == ret) {
		panic("Converting out of range DSP address 0x%lx to host address\n", dsp_addr);
	}
	return virt_to_phys(ret);
}

static int dsp_install_firmware(char *data, int size,
	u32 *dsp_start_addr)
{
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	u8* vaddr;
	int i;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter");

	ehdr = (Elf32_Ehdr *) data;
	data += sizeof(Elf32_Ehdr);

	phdr = (Elf32_Phdr *) data;
	data += ehdr->e_phnum * sizeof(Elf32_Phdr);

	for(i = 0; i < ehdr->e_phnum; i++, phdr++)
	{
		/* Skip blocks for DSP X/Y memory */
		if ((phdr->p_vaddr >= RUBY_DSP_XYMEM_BEGIN) && (phdr->p_vaddr <= RUBY_DSP_XYMEM_END)) {
			data += phdr->p_filesz;
			continue;
		}
		unsigned long p_muc = dsp_to_host_addr(phdr->p_vaddr);
		DBGPRINTF(DBG_LL_INFO, QDRV_LF_TRACE,
				"p_vaddr in ELF header is %p, "
				"remapping to 0x%lx\n", (void *)phdr->p_vaddr, p_muc);
		/* Copy segment to right location */
		vaddr = ioremap_nocache(p_muc, phdr->p_memsz);

		/* Copy data */
		memcpy(vaddr, data, phdr->p_filesz);
		/* Clear BSS */
		memset(vaddr + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);

		iounmap(vaddr);

		/* Jump to next */
		data += phdr->p_filesz;
	}

	*dsp_start_addr = ehdr->e_entry;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return(0);
}

static int dsp_load_firmware(struct device *dev, char *firmware,
	u32 *dsp_start_addr)
{
	const struct firmware *fw;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter");

	if(request_firmware(&fw, firmware, dev) < 0)
	{
		DBGPRINTF_E("Failed to load firmware \"%s\"\n", firmware);
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return(-1);
	}

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_DSP, "Firmware size is %d\n", fw->size);

	if(dsp_install_firmware((char *)fw->data, fw->size, dsp_start_addr) < 0)
	{
		DBGPRINTF_E("Failed to install firmware \"%s\"\n", firmware);
		release_firmware(fw);
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return(-1);
	}

	release_firmware(fw);

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return(0);
}

int qdrv_dsp_init(struct qdrv_cb *qcb)
{
	u32 dsp_start_addr = 0;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter");

	if(dsp_load_firmware(qcb->dev, qcb->dsp_firmware, &dsp_start_addr) < 0)
	{
		DBGPRINTF_E("dsp load firmware failed\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return(-1);
	}

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_DSP, "Firmware start address is %x\n", dsp_start_addr);

	hal_dsp_start(dsp_start_addr);
	hal_enable_dsp();

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return(0);
}

int qdrv_dsp_exit(struct qdrv_cb *qcb)
{
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter");

	hal_disable_dsp();

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return(0);
}
