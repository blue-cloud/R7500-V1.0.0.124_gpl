/**
 * Copyright (c) 2008 - 2013 Quantenna Communications Inc
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/device.h>
#include <linux/version.h>

#include <asm/io.h>
#include <asm/board/soc.h>

#include "qdrv_mac.h"
#include "qdrv_soc.h"
#include "qdrv_debug.h"
#include "qdrv_auc.h"
#include "qdrv_hal.h"
#include "qdrv_wlan.h"
#include "qdrv_vap.h"
#include <qtn/topaz_tqe.h>

#ifndef TOPAZ_PLATFORM

int qdrv_auc_init(struct qdrv_cb *qcb)
{
	return 0;
}

int qdrv_auc_exit(struct qdrv_cb *qcb)
{
	return 0;
}

#else

static qtn_shared_node_stats_t *s_per_node_stats_ptr = NULL;
static qtn_shared_vap_stats_t *s_per_vap_stats_ptr = NULL;

static inline unsigned long
auc_to_host_addr(unsigned long auc_addr)
{
	void *ret = bus_to_virt(auc_addr);
	if (RUBY_BAD_VIRT_ADDR == ret) {
		panic("Converting out of range AuC address 0x%lx to host address\n", auc_addr);
	}
	return virt_to_phys(ret);
}

static int
auc_is_ccm_addr(unsigned long addr)
{
	return
		__in_mem_range(addr, TOPAZ_AUC_IMEM_ADDR, TOPAZ_AUC_IMEM_SIZE) ||
		__in_mem_range(addr, TOPAZ_AUC_DMEM_ADDR, TOPAZ_AUC_DMEM_SIZE);
}

static void
auc_write_ccm_uint8(void *dst, uint8_t val)
{
	unsigned long addr = (unsigned long)dst;
	unsigned long addr_align = addr & ~0x3;
	unsigned long val_shift = (addr & 0x3) << 3;
	unsigned mem_val = readl(addr_align);

	mem_val = mem_val & ~(0xFF << val_shift);
	mem_val = mem_val | (val << val_shift);

	writel(mem_val, addr_align);
}

static void auc_memzero_ccm(void *dst, unsigned long size)
{
	while (size > 0) {
		auc_write_ccm_uint8(dst, 0);
		--size;
		++dst;
	}
}

static void auc_memcpy_ccm(void *dst, void *src, unsigned long size)
{
	while (size > 0) {
		auc_write_ccm_uint8(dst, readb(src));
		--size;
		++dst;
		++src;
	}
}

static void auc_memzero(void *dst, unsigned long size, unsigned long dst_phys_addr)
{
	if (auc_is_ccm_addr(dst_phys_addr)) {
		auc_memzero_ccm(dst, size);
	} else {
		memset(dst, 0, size);
	}
}

static void auc_memcpy(void *dst, void *src, unsigned long size, unsigned long dst_phys_addr)
{
	if (auc_is_ccm_addr(dst_phys_addr)) {
		auc_memcpy_ccm(dst, src, size);
	} else {
		memcpy(dst, src, size);
	}
}

static void auc_clear_addr_range(unsigned long physaddr, unsigned long size)
{
	void *vaddr = ioremap_nocache(physaddr, size);

	if (!vaddr) {
		DBGPRINTF_E("0x%lx, 0x%lx cannot be mapped\n", physaddr, size);
	} else {
		auc_memzero(vaddr, size, physaddr);
		iounmap(vaddr);
	}
}

static void auc_clear_mem(void)
{
	auc_clear_addr_range(TOPAZ_AUC_IMEM_ADDR, TOPAZ_AUC_IMEM_SIZE);
	auc_clear_addr_range(TOPAZ_AUC_DMEM_ADDR, TOPAZ_AUC_DMEM_SIZE);
	auc_clear_addr_range(RUBY_DRAM_BEGIN + CONFIG_ARC_AUC_BASE, CONFIG_ARC_AUC_SIZE);
	auc_clear_addr_range(RUBY_SRAM_BEGIN + CONFIG_ARC_AUC_SRAM_BASE, CONFIG_ARC_AUC_SRAM_SIZE);
}

static int auc_install_firmware(char *data, int size,
	u32 *auc_start_addr)
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

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		unsigned long p_auc = phdr->p_paddr;
		if (!p_auc) {
			p_auc = phdr->p_vaddr;
		}
		p_auc = auc_to_host_addr(p_auc);

		DBGPRINTF(DBG_LL_INFO, QDRV_LF_TRACE,
				"p_paddr p_vaddr in ELF header are %p %p, "
				"remapping to 0x%lx\n",
				(void *)phdr->p_paddr, (void *)phdr->p_vaddr, p_auc);

		/* Copy segment to right location */
		vaddr = ioremap_nocache(p_auc, phdr->p_memsz);

		/* Copy data */
		auc_memcpy(vaddr, data, phdr->p_filesz, p_auc);
		/* Clear BSS */
		auc_memzero(vaddr + phdr->p_filesz, phdr->p_memsz - phdr->p_filesz, p_auc);

		iounmap(vaddr);

		/* Jump to next */
		data += phdr->p_filesz;
	}

	*auc_start_addr = ehdr->e_entry;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return 0;
}

static int auc_load_firmware(struct device *dev, char *firmware,
	u32 * auc_start_addr)
{
	const struct firmware *fw;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter");

	if (request_firmware(&fw, firmware, dev) < 0) {
		DBGPRINTF_E("Failed to load firmware \"%s\"\n", firmware);
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_AUC, "Firmware size is %d\n", fw->size);

	auc_clear_mem();

	if (auc_install_firmware((char *)fw->data, fw->size, auc_start_addr) < 0) {
		DBGPRINTF_E("Failed to install firmware \"%s\"\n", firmware);
		release_firmware(fw);
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	release_firmware(fw);

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return 0;
}

void qdrv_auc_stats_setup(void)
{
	unsigned long phyaddr;
	struct shared_params *sp = qtn_mproc_sync_shared_params_get();

	if (unlikely(!sp || !sp->auc.node_stats || !sp->auc.vap_stats)) {
		DBGPRINTF(DBG_LL_ERR, QDRV_LF_TRACE, "Stats setup: failed\n");
		return;
	}

	if (!s_per_node_stats_ptr) {
		phyaddr = auc_to_host_addr((unsigned long)sp->auc.node_stats);
		s_per_node_stats_ptr = ioremap_nocache(phyaddr, QTN_NCIDX_MAX * sizeof(qtn_shared_node_stats_t));
	}

	if (!s_per_vap_stats_ptr) {
		phyaddr = auc_to_host_addr((unsigned long)sp->auc.vap_stats);
		s_per_vap_stats_ptr = ioremap_nocache(phyaddr, QTN_MAX_VAPS * sizeof(qtn_shared_vap_stats_t));
	}

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_TRACE, "Stats setup: Node : %p - %p\n"
			"             Vap  : %p - %p\n",
			sp->auc.node_stats,
			s_per_node_stats_ptr,
			sp->auc.vap_stats,
			s_per_vap_stats_ptr);
}

void qdrv_auc_stats_unmap(void)
{
	if (s_per_node_stats_ptr)
		iounmap(s_per_node_stats_ptr);
	if (s_per_vap_stats_ptr)
		iounmap(s_per_vap_stats_ptr);
}

qtn_shared_node_stats_t* qdrv_auc_get_node_stats(uint8_t node)
{
	return (s_per_node_stats_ptr) ? (s_per_node_stats_ptr + node) : NULL;
}

qtn_shared_vap_stats_t* qdrv_auc_get_vap_stats(uint8_t vapid)
{
	return (s_per_vap_stats_ptr) ? (s_per_vap_stats_ptr + vapid) : NULL;
}

void qdrv_auc_update_multicast_stats(void *ctx, uint8_t nid)
{
	uint8_t vapid;
	struct ieee80211com *ic = (struct ieee80211com *)ctx;
	struct ieee80211_node *node;
	struct ieee80211vap *vap;
	struct qdrv_vap * qv;
	qtn_shared_node_stats_t *nstats;
	qtn_shared_vap_stats_t *vstats;

	if (!ctx)
		return;

	node = ic->ic_node_idx_ni[nid];
	if (unlikely(!node))
		return;

	vap = node->ni_vap;
	qv = container_of(vap, struct qdrv_vap, iv);
	vapid = QDRV_WLANID_FROM_DEVID(qv->devid);
	nstats = qdrv_auc_get_node_stats(nid);
	vstats = qdrv_auc_get_vap_stats(vapid);

	if (unlikely(!nstats || !vstats))
		return;

	nstats->qtn_tx_mcast++;
	vstats->qtn_tx_mcast++;
}

int qdrv_auc_init(struct qdrv_cb *qcb)
{
	u32 auc_start_addr = 0;
	struct qdrv_wlan *qw = qcb->macs[0].data;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter");

	qtn_mproc_sync_shared_params_get()->auc.auc_config = global_auc_config;

	if (auc_load_firmware(qcb->dev, qcb->auc_firmware, &auc_start_addr) < 0) {
		DBGPRINTF_E("AuC load firmware failed\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return -1;
	}

	DBGPRINTF(DBG_LL_INFO, QDRV_LF_DSP, "Firmware start address is %x\n", auc_start_addr);

	hal_enable_auc();

	tqe_reg_multicast_tx_stats(qdrv_auc_update_multicast_stats, &qw->ic);

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return 0;
}

int qdrv_auc_exit(struct qdrv_cb *qcb)
{
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter");

	qdrv_auc_stats_unmap();
	hal_disable_auc();

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return 0;
}

#endif // #ifndef TOPAZ_PLATFORM
