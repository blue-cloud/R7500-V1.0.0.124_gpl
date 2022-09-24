/*
 * (C) Copyright 2011 Quantenna Communications Inc.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

/*
 * Header file which describes Ruby PCI Express specific functions.
 */


#include <common.h>
#include <command.h>
#include <asm/arch/platform.h>
#include <environment.h>
#include "ruby.h"
#include "ruby_pcie_bda.h"
#include "pcie.h"
#include "ddr.h"
#include "malloc.h"

/*
 * for End Point mode
 * Allocate and setup BAR mapping for shared memory
 */
static int32_t setup_atu_shmem(void)
{
	uint32_t val = 0x0;

	/* Select shared mem region */
	writel(PCIE_SHMEM_REGION, RUBY_PCIE_ATU_VIEW);

	/* Bar mapped area in EP */
	writel(PCIE_BAR_SHMEM_LO, RUBY_PCIE_ATU_TARGET_LO);
	writel(PCIE_BAR_SHMEM_HI, RUBY_PCIE_ATU_TARGET_HI);

	/* Set BAR size to EP memory */
	writel(PCIE_BAR_SHMEM_LEN, RUBY_PCIE_ATU_BASE_LIMIT);

	/* Define region of type memory */
	writel(PCIE_ATU_MEMREGION, RUBY_PCIE_ATU_CTL1);

	/* Enable BAR mapped region */
	writel(PCIE_SHMEM_ENABLE, RUBY_PCIE_ATU_CTL2);
	val = readl(RUBY_PCIE_ATU_CTL2);
	printf("PCIe Shmem BAR%u=0x%x Len:%uk\n", PCIE_BAR_SHMEM,
		(unsigned int)PCIE_BAR_SHMEM_LO, (PCIE_BAR_SHMEM_LEN >> 10) + 1);

	return 0;
}

/*
 * for End Point mode
 * Allocate and setup BAR mapping for syscontrol
 */
static int32_t setup_atu_sysctl(void)
{
	uint32_t val = 0x0;

	/* Select shared mem region */
	writel(PCIE_SYSCTL_REGION, RUBY_PCIE_ATU_VIEW);

	/* Bar mapped area in EP */
	writel(PCIE_BAR_SYSCTL_LO, RUBY_PCIE_ATU_TARGET_LO);
	writel(PCIE_BAR_SYSCTL_HI, RUBY_PCIE_ATU_TARGET_HI);

	/* Set size */
	writel(PCIE_BAR_SYSCTL_LEN, RUBY_PCIE_ATU_BASE_LIMIT);

	/* Define region of type memory */
	writel(PCIE_ATU_MEMREGION, RUBY_PCIE_ATU_CTL1);

	/* Enable BAR mapped region */
	writel(PCIE_SYSCTL_ENABLE, RUBY_PCIE_ATU_CTL2);
	val = readl(RUBY_PCIE_ATU_CTL2);

	printf("PCIe Sysctl BAR%u=0x%x Len:%uk\n", PCIE_BAR_SYSCTL,
		PCIE_BAR_SYSCTL_LO, ( PCIE_BAR_SYSCTL_LEN >> 10) + 1);

	return 0;
}

/*
 * for End Point mode
 * Allocate and setup BAR mapping for PCIe DMA registers
 */
#ifdef TOPAZ_PLATFORM
static int32_t setup_atu_dma(void)
{
	uint32_t val = 0x0;

	/* Select dma register region */
	writel(PCIE_DMAREG_REGION, RUBY_PCIE_ATU_VIEW);

	/* Bar mapped area in EP */
	writel(PCIE_BAR_DMAREG_LO, RUBY_PCIE_ATU_TARGET_LO);
	writel(PCIE_BAR_DMAREG_HI, RUBY_PCIE_ATU_TARGET_HI);

	/* Set size */
	writel(PCIE_BAR_DMAREG_LEN, RUBY_PCIE_ATU_BASE_LIMIT);

	/* Define region of type memory */
	writel(PCIE_ATU_MEMREGION, RUBY_PCIE_ATU_CTL1);

	/* Enable BAR mapped region */
	writel(PCIE_DMAREG_ENABLE, RUBY_PCIE_ATU_CTL2);
	val = readl(RUBY_PCIE_ATU_CTL2);

	printf("PCIe DMA BAR%u=0x%x Len:%uk\n", PCIE_BAR_DMAREG,
		PCIE_BAR_DMAREG_LO, ( PCIE_BAR_DMAREG_LEN >> 10) + 1);

	return 0;
}
#endif

#ifndef TOPAZ_PLATFORM
/*
 * for End Point mode
 * Get the low 32 bits start address of PCIe host memory
 */
static uint32_t get_pcie_host_mem_start_addr_lo(void)
{
	uint32_t host_mem_start = PCIE_HOSTMEM_START_LO;
	char *host_mem_str = NULL;

	/* Check to see if host memory start address has been
	 *  overridden to uboot env */
	host_mem_str = getenv("pcie_host_mem_start");
	if (host_mem_str) {
		host_mem_start = simple_strtoul (host_mem_str, NULL, 16);
		if (host_mem_start & (~PCIE_HOSTMEM_ADDR_ALIGN_MASK)) {
			host_mem_start = host_mem_start & PCIE_HOSTMEM_ADDR_ALIGN_MASK;
			printf("PCIe host memory address must be 64k aligned,"
				" aligned address: 0x%08x\n", host_mem_start);
		}
	}

	return host_mem_start;
}
#endif

/*
 * for End Point mode *
 * map the host memory to target
 */
#ifdef TOPAZ_PLATFORM
static int32_t setup_atu_host(volatile qdpc_pcie_bda_t *bda)
{
	uint32_t host_mem_start = PCIE_HOSTMEM_EP_START_LO - readl(&bda->bda_dma_offset);
#else
static int32_t setup_atu_host(uint32_t addr_mask)
{
	uint32_t host_mem_start = get_pcie_host_mem_start_addr_lo();
#endif
	uint32_t val = 0x0;

	/* Select shared mem region */
	writel(PCIE_HOSTMEM_REGION, RUBY_PCIE_ATU_VIEW);

	/* Memory mapped area in EP )*/
	writel(PCIE_HOSTMEM_EP_START_LO, RUBY_PCIE_ATU_BASE_LO);
	writel(PCIE_HOSTMEM_EP_START_HI, RUBY_PCIE_ATU_BASE_HI);

	/* Memory mapped area in Host*/
	writel(host_mem_start, RUBY_PCIE_ATU_TARGET_LO);
	writel(PCIE_HOSTMEM_START_HI, RUBY_PCIE_ATU_TARGET_HI);

	/* Set size */
#ifdef TOPAZ_PLATFORM
	writel(PCIE_HOSTMEM_EP_END, RUBY_PCIE_ATU_BASE_LIMIT);
#else
	writel(PCIE_HOSTMEM_EP_START_LO + addr_mask, RUBY_PCIE_ATU_BASE_LIMIT);
#endif

	/* Define region of type memory */
	writel(PCIE_ATU_MEMREGION, RUBY_PCIE_ATU_CTL1);

	/* Enable BAR mapped region */
	writel(PCIE_HOSTMEM_REGION_ENABLE, RUBY_PCIE_ATU_CTL2);
	val = readl(RUBY_PCIE_ATU_CTL2);
#ifdef TOPAZ_PLATFORM
	printf("%u:Mem: EP(0x%x->0x%x) Host(0x%x->0x%x)\n", PCIE_HOSTMEM_REGION,
		PCIE_HOSTMEM_EP_START, PCIE_HOSTMEM_EP_END,
		host_mem_start, host_mem_start + PCIE_HOSTMEM_DMA_MASK);
#else
	printf("%u:Mem: EP(0x%x->0x%x) Host(0x%x->0x%x)\n", PCIE_HOSTMEM_REGION,
		PCIE_HOSTMEM_EP_START_LO, PCIE_HOSTMEM_EP_START_LO + addr_mask,
		host_mem_start, host_mem_start + addr_mask);
#endif

	return 0;
}

#ifdef TOPAZ_PLATFORM
/*
 * for End Point mode *
 * map the host buffer descriptor to target
 * need to finish the mapping after linux bootup
 */
static int32_t setup_atu_hostbd_early(void)
{
	/* Select shared mem region */
	writel(PCIE_HOSTBD_REGION, RUBY_PCIE_ATU_VIEW);

	/* Memory mapped area in EP )*/
	writel(PCIE_HOSTBD_EP_START_LO, RUBY_PCIE_ATU_BASE_LO);
	writel(PCIE_HOSTBD_EP_START_HI, RUBY_PCIE_ATU_BASE_HI);

	/* Set size */
	writel(PCIE_HOSTBD_EP_END, RUBY_PCIE_ATU_BASE_LIMIT);

	/* Define region of type memory */
	writel(PCIE_ATU_MEMREGION, RUBY_PCIE_ATU_CTL1);

	printf("%u:BD: EP(0x%x->0x%x) Host(dynamic alloc in RC)\n", PCIE_HOSTBD_REGION,
		PCIE_HOSTBD_EP_START_LO,PCIE_HOSTBD_EP_END);

	return 0;
}
#endif

/*
 * for End Point mode
 * Setup 64KB region ATU for target to access host msi register
 */
#ifdef TOPAZ_PLATFORM
static int setup_atu_msi(volatile qdpc_pcie_bda_t *bda)
#else
static int setup_atu_msi(volatile qdpc_pcie_bda_t *bda, uint32_t end_addr)
#endif
{
	uint16_t flag = 0;
	uint32_t msi_addr = 0x0;
	uint32_t msi_addr_up = 0x0;
	uint32_t val = 0x0;
	uint32_t msi64 = 0;

	flag = readl(PCIE_MSI_CAP) >> 16;
	msi_addr = readl(PCIE_MSI_LOW_ADDR);
	msi64 = (flag & MSI_64_EN);

	/* Exit if MSI is not enabled */
	if (!(flag & MSI_EN)) {
		printf("PCIe Legacy Interrupt Support\n");
		return 1;
	}

	printf("PCIe MSI Interrupt Support\n");
	printf("%s: msi_addr=%08x\n", __func__, msi_addr);

	arc_write_uncached_32(&bda->bda_flags,PCIE_BDA_MSI| arc_read_uncached_32(&bda->bda_flags));

#ifndef TOPAZ_PLATFORM
	/* If address range of of MSI data area is within primary ATU region, we can use one ATU for both  */
	if ((msi_addr + 2) <= end_addr)
	{
		printf("%s: msi_addr less than end_addr\n", __func__);

		/* Setup EP MSI address */
		arc_write_uncached_32(&bda->bda_msi_addr, PCIE_REGION_BASE + (msi_addr & 0x1fffffff));
		return 1;
	}
#endif
	/* Enable ATU viewport */
	writel(PCIE_MSI_REGION, RUBY_PCIE_ATU_VIEW);

	/* mapped region area in EP */
	writel(PCIE_MSI_EP_START_LO, RUBY_PCIE_ATU_BASE_LO);
	writel(PCIE_MSI_EP_START_HI, RUBY_PCIE_ATU_BASE_HI);

	writel(PCIE_MSI_EP_END, RUBY_PCIE_ATU_BASE_LIMIT);

	/* Set host side msi addr */
	writel(PCIE_MSI_ADDR_ALIGN(msi_addr), RUBY_PCIE_ATU_TARGET_LO);
	if (msi64) {
		msi_addr_up = readl(PCIE_MSI_HIG_ADDR);
		writel(msi_addr_up, RUBY_PCIE_ATU_TARGET_HI);
	} else {
		writel(0x00000000, RUBY_PCIE_ATU_TARGET_HI);
	}

	/* Setup EP MSI address */
	arc_write_uncached_32(&bda->bda_msi_addr,PCIE_MSI_EP_START_LO + PCIE_MSI_ADDR_OFFSET(msi_addr));

	/* Define region of type memory */
	writel(PCIE_ATU_MEMREGION, RUBY_PCIE_ATU_CTL1);

	/* Enable region */
	writel(PCIE_MSI_REGION_ENABLE, RUBY_PCIE_ATU_CTL2);
	val = readl(RUBY_PCIE_ATU_CTL2);

	printf("%u:MSI%s: Host:0x%x%x EP:0x%x\n",PCIE_MSI_REGION, (msi64) ? "64" : "",
		msi_addr_up, msi_addr, bda->bda_msi_addr);

	return 0;
}

/*
 * for End Point mode
 */
#ifdef TOPAZ_PLATFORM
void setup_atu_outbound(volatile qdpc_pcie_bda_t *bda)
{
	setup_atu_msi(bda);
	setup_atu_host(bda);
	setup_atu_hostbd_early();

	arc_write_uncached_32(&bda->bda_dma_mask, PCIE_HOSTMEM_DMA_MASK);
}
#else
void setup_atu_outbound(volatile qdpc_pcie_bda_t *bda)
{
	uint32_t dma_mask = 0;
	uint32_t region_size_mask = (PCIE_REGION_END - PCIE_REGION_BASE);
	if (setup_atu_msi(bda, region_size_mask)){
		dma_mask = region_size_mask ;
	} else {
		dma_mask = region_size_mask - PCIE_MSIMEM_SIZE;
	}
	setup_atu_host(dma_mask);
	arc_write_uncached_32(&bda->bda_dma_mask, dma_mask);
}
#endif

/*
 * for End Point mode
 */
static void setup_atu_inbound(void)
{
	setup_atu_shmem();
	setup_atu_sysctl();
#ifdef TOPAZ_PLATFORM
	setup_atu_dma();
#endif
}

static void setup_pcie_capability(void)
{
	uint32_t *prev_cap = (uint32_t *)PCIE_CAP_PTR;
	uint32_t *curr_cap = NULL;
	uint32_t prev_val, curr_val;
	uint8_t prev_shift = 0, curr_shift;
	uint8_t prev_cap_offset;
	uint8_t curr_cap_offset;
	uint8_t curr_cap_id;
	const char *val;

	val = getenv("msi");
	if ( val == NULL || val[0] != '0')
		return;

	do {
		prev_val = readl(prev_cap);
		prev_cap_offset = ((prev_val >> prev_shift) & 0xff);

		curr_shift = 8;
		curr_cap = (uint32_t *)(PCIE_BASE_ADDRESS + prev_cap_offset);
		curr_val = readl(curr_cap);
		curr_cap_id = (uint8_t)(curr_val & 0xff);
		curr_cap_offset = (uint8_t)((curr_val >> curr_shift) & 0xff);

		if (curr_cap_id == 0x05) {
			writel((curr_cap_offset << prev_shift), prev_cap);
			printf("PCIe disabling MSI capability\n");
			break;
		}

		prev_cap = curr_cap;
		prev_shift = curr_shift;
	} while (curr_cap_offset != 0);
}

static int bootpoll(volatile qdpc_pcie_bda_t *bda, uint32_t state)
{
	while (arc_read_uncached_32(&bda->bda_bootstate) != state)
	{
		if (arc_read_uncached_32(&bda->bda_flags) & PCIE_BDA_ERROR_MASK)
			return -1;
		udelay(1000);
	}
	return 0;
}

static void set_bootstate(volatile qdpc_pcie_bda_t *bda, uint32_t state)
{
	arc_write_uncached_32(&bda->bda_bootstate, state);
}

static void booterror(volatile qdpc_pcie_bda_t *bda)
{
	if (PCIE_BDA_HOST_NOFW_ERR & arc_read_uncached_32(&bda->bda_flags))
		printf("There is no firmware in host file system!\n");
	else if (PCIE_BDA_HOST_MEMALLOC_ERR & arc_read_uncached_32(&bda->bda_flags))
		printf("Host alloc memory block for firmware download failed!\n");
	else if (PCIE_BDA_HOST_MEMMAP_ERR & arc_read_uncached_32(&bda->bda_flags))
		printf("Host do dma map for share memory block failed!\n");
	else
		printf("Other error found in host side , bda flag: 0x%x!\n", bda->bda_flags);
}

#ifndef TOPAZ_EP_MINI_UBOOT
/*
 * for End Point mode
 */
int do_flash_boot (volatile qdpc_pcie_bda_t *bda)
{
	unsigned long live_addr = 0;
	unsigned long live_size = 0;
	const unsigned long mem_addr = QTNBOOT_COPY_DRAM_ADDR;
	char *live_addr_str = getenv (LIVE_IMG_ADDR_ARG);
	char *live_size_str = getenv (LIVE_IMG_SIZE_ARG);


	printf("do flash boot\n");
	set_bootstate(bda, QDPC_BDA_FW_FLASH_BOOT);
	if (live_addr_str && live_size_str) {
		live_addr = simple_strtoul(live_addr_str, NULL, 0);
		live_size = simple_strtoul(live_size_str, NULL, 0);
	} else {
		printf("Variables: %s %s must be set\n",
		       LIVE_IMG_ADDR_ARG,
		       LIVE_IMG_SIZE_ARG);
		arc_write_uncached_32(&bda->bda_flags, PCIE_BDA_TARGET_FBOOT_ERR | arc_read_uncached_32(&bda->bda_flags));
		return 1;
	}

	/* attempt to load the live image into memory and boot it. */
	RUN("spi_flash read 0x%08lx 0x%08lx 0x%08lx", live_addr, mem_addr, live_size);
	RUN("bootm 0x%08lx", mem_addr);

	/* never gets to here */
	arc_write_uncached_32(&bda->bda_flags, PCIE_BDA_TARGET_FBOOT_ERR | arc_read_uncached_32(&bda->bda_flags));
	printf("flash boot error!\n");
	return 0;
}
#endif

/*
 * for End Point mode
 */

static int pci_endian_detect(volatile qdpc_pcie_bda_t *bda)
{
	uint32_t pci_endian;

	while (readl(&bda->bda_pci_pre_status) != QDPC_PCI_ENDIAN_VALID_STATUS)
		udelay(1000);

	pci_endian = readl(&bda->bda_pci_endian);
	if (pci_endian == QDPC_PCI_ENDIAN_DETECT_DATA) {
		printf("PCI memory region is little endian\n");
		writel(QDPC_PCI_LITTLE_ENDIAN, &bda->bda_pci_endian);
	} else if (pci_endian == QDPC_PCI_ENDIAN_REVERSE_DATA) {
		printf("PCI memory region is big endian\n");
		writel(QDPC_PCI_BIG_ENDIAN, &bda->bda_pci_endian);
	} else {
		printf("PCI memory endian value:%08x is invalid - using little endian\n", pci_endian);
		writel(QDPC_PCI_LITTLE_ENDIAN, &bda->bda_pci_endian);
	}
	writel(QDPC_PCI_ENDIAN_VALID_STATUS, &bda->bda_pci_post_status);

	return 0;
}

#ifdef TOPAZ_PLATFORM
static int host_mem_start_address_detect(volatile qdpc_pcie_bda_t *bda)
{
	while ((readl(&bda->bda_dma_offset) & PCIE_DMA_OFFSET_ERROR_MASK) == PCIE_DMA_OFFSET_ERROR)
		udelay(1000);

	printf("Host memory start address is 0x%08x\n",
		PCIE_HOSTMEM_EP_START_LO - readl(&bda->bda_dma_offset));

	return 0;
}

static void pcie_dma_read(void *dar, void *sar, u32 size, u8 ch)
{
#define EDMA_TIMEOUT	100000
	uint32_t tmp = 0;
	int i;

	writel(0x00000001, PCIE_DMA_RD_ENABLE);
	writel(0x00000000, PCIE_DMA_RD_INTMASK);
	writel(0x80000000, PCIE_DMA_CHNL_CONTEXT);
	writel(0x04000008, PCIE_DMA_CHNL_CNTRL);
	writel(size, PCIE_DMA_XFR_SIZE);
	writel(sar, PCIE_DMA_SAR_LOW);
	writel(0x00000000, PCIE_DMA_SAR_HIGH);
	writel(dar, PCIE_DMA_DAR_LOW);
	writel(0x00000000, PCIE_DMA_DAR_HIGH);
	writel(0x00000000, PCIE_DMA_RD_DOORBELL);

	for (i = 0; i < EDMA_TIMEOUT; i++) {
		udelay(1);
		tmp = readl(PCIE_DMA_RD_INTSTS);
		if (tmp & PCIE_DMA_RD_DONE_STS(ch)) {
			printf("done\n");
			break;
		}

		if (tmp & PCIE_DMA_RD_ABORT_STS(ch)) {
			printf("Error: eDMA abort\n");
			break;
		}

	}

	if (i == EDMA_TIMEOUT)
		printf("Error: eDMA timeout\n");

	writel(PCIE_DMA_RD_DONE_STS_CLR(ch), PCIE_DMA_RD_INTCLER);
}
#endif

int do_pcieboot(cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	volatile qdpc_pcie_bda_t *bda = (qdpc_pcie_bda_t *)(RUBY_PCIE_BDA_ADDR);
	uint32_t size, i=0;
	void  *srcaddr;
#ifdef TOPAZ_EP_MINI_UBOOT
	extern unsigned long load_addr;
	void *start = (void *)load_addr;
#else
	void *start = (void *)PCIE_FW_LZMA_LOAD;
	char *s = NULL;
	char *local_args[2];
	char load_addr[16];
#endif
	void *dstaddr = start;
	unsigned int tmp;
#ifdef TOPAZ_PLATFORM
	uint8_t ch = 0;
#endif

	extern int do_bootm (cmd_tbl_t *, int, int, char *[]);

	printf("Polling for PCIe Link up\n");
	while (1) {
#ifdef TOPAZ_PLATFORM
		if ((readl(TOPAZ_PCIE_STAT) & TOPAZ_PCIE_LINKUP) == TOPAZ_PCIE_LINKUP)
#else
		if (readl(RUBY_SYS_CTL_CSR) & PCIE_LINKUP)
#endif
			break;
		udelay(10); /* Delay. */
	}
	set_bootstate(bda, QDPC_BDA_PCIE_RDY);

	printf("Waiting for handshake start\n");
	if (pci_endian_detect(bda)) {
		printf("PCI memory endian detect failed\n");
	}

	/*
	 * workaround to fix tag clock issue by switching from Gen1 to Gen2
	 *  two dummy read
	 */
#ifdef TOPAZ_PLATFORM
	tmp = readl(0xcfff0000);
	tmp = readl(0xcfff0000);
#endif

#ifdef TOPAZ_PLATFORM
	if (host_mem_start_address_detect(bda)) {
		printf("Host memory start address detect failed\n");
	}
#endif

#ifdef TOPAZ_EP_MINI_UBOOT
	tmp = arc_read_uncached_32(&bda->bda_flags);
	arc_write_uncached_32(&bda->bda_flags, PCIE_BDA_XMIT_UBOOT | tmp);
#else
	/* set the flash_present flag if env indicate we have firmware in flash */
	s = getenv("flash_img");
	if (s && (*s == '1')) {
		tmp = arc_read_uncached_32(&bda->bda_flags);
		arc_write_uncached_32(&bda->bda_flags, PCIE_BDA_FLASH_PRESENT | tmp);
	}

	/*
	 * workaround to fix tag clock issue by switching from Gen1 to Gen2
	 * switch Gen2 from Gen1 here in full u-boot.bin for revB
	 */
#ifdef TOPAZ_PLATFORM
	writel(PCIE_LINK_GEN2, PCIE_LINK_CTL2);
#endif

#endif
	/* Wait for host ready */
	bootpoll(bda, QDPC_BDA_FW_HOST_RDY);

	setup_atu_outbound(bda);
	set_bootstate(bda,QDPC_BDA_FW_TARGET_RDY);
	bootpoll(bda, QDPC_BDA_FW_TARGET_BOOT);

#ifndef TOPAZ_EP_MINI_UBOOT
	/* boot from flash */
	if (PCIE_BDA_FLASH_BOOT & arc_read_uncached_32((void *)&bda->bda_flags)) {
		do_flash_boot(bda);
		return 0;
	}
#endif
	set_bootstate(bda,QDPC_BDA_FW_LOAD_RDY);

	printf("Ready to load firmware....\n");
	if (bootpoll(bda, QDPC_BDA_FW_HOST_LOAD)) {
		booterror(bda);
		return -1;
	}
	set_bootstate(bda, QDPC_BDA_FW_EP_RDY);

	bootpoll(bda, QDPC_BDA_FW_BLOCK_RDY);

	srcaddr = (void *)arc_read_uncached_32(&bda->bda_img);
	size = arc_read_uncached_32(&bda->bda_img_size);

	dcache_disable();

	/* Keep loading until we see a zero sized block */
	while (srcaddr && size) {
		printf("PCIe Load FW[%u] 0x%x->0x%x Sz:%u...\n", i++, (uint32_t)srcaddr, (uint32_t)dstaddr, size);

#ifdef TOPAZ_PLATFORM
		pcie_dma_read((void *)virt_to_bus(dstaddr), srcaddr, size, ch);
#else
		memcpy_fromio(dstaddr, srcaddr, size);
#endif
		/* Block done, inform host */
		set_bootstate(bda, QDPC_BDA_FW_BLOCK_DONE);

		/* Wait for next block */
		bootpoll(bda, QDPC_BDA_FW_BLOCK_RDY);
		srcaddr = (void *)arc_read_uncached_32(&bda->bda_img);
		dstaddr += size;
		size = arc_read_uncached_32(&bda->bda_img_size);
	}

	printf("PCIe Gen: %x\n", PCIE_LINK_MODE(readl(PCIE_LINK_STAT)));

	/* Invalidate i-cache */
	invalidate_icache_range((int)start, (int)(dstaddr - 1));

	/* Acknowledge the last zero sized block */
	set_bootstate(bda, QDPC_BDA_FW_BLOCK_DONE);

	/* Wait for bootload end message */
	bootpoll(bda, QDPC_BDA_FW_BLOCK_END);

	/* Tell host we are done */
	set_bootstate(bda, QDPC_BDA_FW_LOAD_DONE);

#ifdef TOPAZ_EP_MINI_UBOOT
	extern char warm_boot;
	extern char _start;
	tmp = arc_read_uncached_32(&bda->bda_flags);
	tmp &= ~(PCIE_BDA_XMIT_UBOOT);
	arc_write_uncached_32(&bda->bda_flags, tmp);
	/* warm boot up the full u-boot */
	start += (&warm_boot - &_start);
	printf("Go to address %p\n", start);
	((void (*)(void))start)();
#else
	dcache_enable();
	sprintf(load_addr,"0x%08lx", (unsigned long)start);
	local_args[0] = argv[0];
	local_args[1] = load_addr;

	printf("PCIe Loadaddr:%s\n",load_addr);
	do_bootm(cmdtp, 0 , 2 ,local_args);
#endif
	/*
	 * it never reaches this pointer if boot successfully, otherwise it fails to run img
	 */
	set_bootstate(bda, QDPC_BDA_FW_LOAD_FAIL);
	tmp = arc_read_uncached_32(&bda->bda_flags);
	arc_write_uncached_32(&bda->bda_flags, PCIE_BDA_TARGET_FWLOAD_ERR | tmp);

	return 1;
}

#ifndef TOPAZ_EP_MINI_UBOOT
static int on_off (const char *s)
{
	if (strcmp(s, "on") == 0) {
		return (1);
	} else if (strcmp(s, "off") == 0) {
		return (0);
	}
	return (-1);
};

static void msi_enable(void)
{
	ulong var=0;
	var = readl(PCIE_MSI_CAP);
	writel(var|RUBY_PCIE_MSI_ENABLE, PCIE_MSI_CAP);
	printf("msi enabled\n");
}

static void msi_disable(void)
{
	ulong var=0;
	var = readl(PCIE_MSI_CAP);
	writel(var&~RUBY_PCIE_MSI_ENABLE, PCIE_MSI_CAP);
	printf("msi disabled\n");
}

/*
 * for End Point mode
 */
static int msi_config (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	switch (argc) {
	case 2:			/* on / off	*/
		switch (on_off(argv[1])) {
		case 1:
			msi_enable();
			break;
		case 0:
			msi_disable();
			break;
		default: cmd_usage(cmdtp);
			return 1;
		}
		break;
	case 1:			/* default on	*/
		msi_enable();
		break;
	default: cmd_usage(cmdtp);
		return 1;
	}
	return 0;
}


/*
 * Exported functions - visible outside of this module
 */

/* enable or disable MSI */
U_BOOT_CMD(
	msi_cfg,   2,   1,     msi_config,
	"enable or disable msi",
	"[on, off]\n"
	"    - enable or disable msi with cmd msi_cfg [on, off]\n"
);

/* pcieboot */
U_BOOT_CMD(pcieboot,CONFIG_SYS_MAXARGS, 0, do_pcieboot,
		"boot from pcie.  Waits for host to load memory and then calls bootm",
		NULL);
#endif

/*
 * maybe move this later, for now we just need to remove pcie reset and set link
 * flags will be used to do any back door init we might require
 */
void pcie_ep_init(size_t memsz, uint32_t flags)
{
	uint32_t i = 0;
	uint32_t bar64 = PCIE_CFG_BAR64;
	volatile qdpc_pcie_bda_t *bda = (qdpc_pcie_bda_t *)(RUBY_PCIE_BDA_ADDR);
	/* For topaz platform, this init has done in pcie_ep_early_init */
#ifndef TOPAZ_PLATFORM
	uint32_t host_mem_start = get_pcie_host_mem_start_addr_lo();

	/* PCIe init */
	writel(RUBY_SYS_CTL_RESET_IOSS|RUBY_SYS_CTL_RESET_PCIE,RUBY_SYS_CTL_CPU_VEC_MASK);
	writel(0,RUBY_SYS_CTL_CPU_VEC);
	udelay(10);
	writel(RUBY_SYS_CTL_RESET_IOSS|RUBY_SYS_CTL_RESET_PCIE,RUBY_SYS_CTL_CPU_VEC);

	writel(0x00010020, PCIE_PORT_LINK_CTL);
	writel(PCIE_CFG0_DEFAULT_VALUE, RUBY_SYS_CTL_PCIE_CFG0);
	writel(0x00000001, RUBY_SYS_CTL_PCIE_CFG1);
	writel(0x00000000, RUBY_SYS_CTL_PCIE_CFG2);
	writel(0x45220000, RUBY_SYS_CTL_PCIE_CFG3);
	writel(0x00100007, PCIE_CMDSTS);
#endif

	writel(0xf << 22, RUBY_SYS_CTL_PCIE_SLV_REQ_MISC_INFO);

	/* Enable DMA Read Channel */
	REG_WRITE(PCIE_DMA_RD_ENABLE, 0x00000001);
	REG_WRITE(PCIE_DMA_RD_CHWTLOW,0x000001FF);
	REG_WRITE(PCIE_DMA_RD_CHWTHIG,0x00000000);

	/* Enable DMA write channel */
	REG_WRITE(PCIE_DMA_WR_ENABLE, 0x00000001);
	REG_WRITE(PCIE_DMA_WR_CHWTLOW,0x000001FF);
	REG_WRITE(PCIE_DMA_WR_CHWTHIG,0x00000000);

	/* Zero out boot data area */
	memset((void *)bda, 0, RUBY_PCIE_BDA_SIZE);
	/*
	 * Flush BDA zero to concret memory before any
	 * update to it
	 */
	flush_and_inv_dcache_range((unsigned long)bda,
			(unsigned long)bda + RUBY_PCIE_BDA_SIZE);
	arc_write_uncached_32(&bda->bda_flags, QDPC_PCIE_BDA_VERSION << 4);

#ifdef TOPAZ_PLATFORM
	/*
	 * Set dma offset to PCIE_HOSTMEM_EP_START_LO, and mask to a invalid value.
	 * The dma offset will be reset by root complex.
	 */
	arc_write_uncached_32(&bda->bda_dma_offset, PCIE_HOSTMEM_EP_START_LO | PCIE_DMA_OFFSET_ERROR);
#else
	/*
	 * Set dma offset to bda_dma_offset
	 * Don't need add judge condition, even negative result is also right
	 */
	arc_write_uncached_32(&bda->bda_dma_offset, PCIE_HOSTMEM_EP_START_LO - host_mem_start);
#endif

	set_bootstate(bda, QDPC_BDA_PCIE_INIT);
	/* Disable all BARs */
	for (i = 0 ; i < RUBY_PCIE_BAR_NUM; i++)
	{
		writel(1, RUBY_PCIE_BAR_MASK(i));
		writel(0x0, RUBY_PCIE_BAR_MASK(i));
	}

	/* Disable expansion ROM */
	writel(1, PCIE_ROM_MASK_ADDR);
	writel(0x0, PCIE_ROM_MASK_ADDR);

	/* Setup Sysctl BAR */
	writel(1, RUBY_PCIE_BAR_MASK(PCIE_BAR_SYSCTL));
	writel(PCIE_BAR_SYSCTL_LEN, RUBY_PCIE_BAR_MASK(PCIE_BAR_SYSCTL));
	writel(PCIE_BAR_CFG(bar64), RUBY_PCIE_BAR(PCIE_BAR_SYSCTL));

	/* Setup Shared memory BAR  */
	writel(1, RUBY_PCIE_BAR_MASK(PCIE_BAR_SHMEM));
	writel(PCIE_BAR_SHMEM_LEN, RUBY_PCIE_BAR_MASK(PCIE_BAR_SHMEM));
	writel(PCIE_BAR_CFG(bar64), RUBY_PCIE_BAR(PCIE_BAR_SHMEM));

	/* Setup PCIE DMA register BAR  */
	writel(1, RUBY_PCIE_BAR_MASK(PCIE_BAR_DMAREG));
	writel(PCIE_BAR_DMAREG_LEN, RUBY_PCIE_BAR_MASK(PCIE_BAR_DMAREG));
	writel(PCIE_BAR_CFG(bar64), RUBY_PCIE_BAR(PCIE_BAR_DMAREG));

	/* Setup ATU Inbound BAR mappings*/
	setup_atu_inbound();

	/* Setup PCIe capability structures */
	setup_pcie_capability();
}

#ifdef TOPAZ_PLATFORM
void pcie_ep_early_init(uint32_t flags)
{
	char *val;

	val = getenv("disable_pcie");
	if ((val != NULL) && (val[0] != '0')) {
		return;
	}

	if (flags & PCIE_RC_MODE) {
		return;
	}

	/* PCIe init */
	writel(RUBY_SYS_CTL_RESET_IOSS|RUBY_SYS_CTL_RESET_PCIE,RUBY_SYS_CTL_CPU_VEC_MASK);
	writel(0,RUBY_SYS_CTL_CPU_VEC);
	udelay(10);
	writel(RUBY_SYS_CTL_RESET_IOSS|RUBY_SYS_CTL_RESET_PCIE,RUBY_SYS_CTL_CPU_VEC);
	/*
	 * workaround to fix tag clock issue by switching from Gen1 to Gen2
	 * Init PCIe link as Gen1 mode if the board is revB board
	 */
#ifdef TOPAZ_PLATFORM
	if ((readl(RUBY_SYS_CTL_CSR) & 0xff) == TOPAZ_BOARD_REVB)
		writel(PCIE_LINK_GEN1, PCIE_LINK_CTL2);
#endif
	writel(0x00010020, PCIE_PORT_LINK_CTL);
	writel(PCIE_CFG0_DEFAULT_VALUE, RUBY_SYS_CTL_PCIE_CFG0);
	writel(0x00000001, RUBY_SYS_CTL_PCIE_CFG1);
	writel(0x00000000, RUBY_SYS_CTL_PCIE_CFG2);
	writel(0x45220000, RUBY_SYS_CTL_PCIE_CFG3);
	writel(0x00100007, PCIE_CMDSTS);

	writel(0xf << 22, RUBY_SYS_CTL_PCIE_SLV_REQ_MISC_INFO);
}

#ifndef TOPAZ_EP_MINI_UBOOT
void pci_rc_reset_ep(void)
{
	/* Set GPIO 13 to output mode   */
	gpio_config(13, GPIO_MODE_OUTPUT);
	gpio_output(13, 1);
	udelay(10);
	/* Reset EP by write 0 to data register */
	gpio_output(13, 0);
	/* Keep Reset signal 10 ms */
	udelay(10000);
	gpio_output(13, 1);
}
#endif
#endif

#ifndef TOPAZ_EP_MINI_UBOOT
/*
 * init for root complex mode
 */
void pcie_rc_init(void)
{

#ifdef TOPAZ_PLATFORM
	pci_rc_reset_ep();
#endif

	/* set as RC mode */
	writel(SYS_RST_PCIE|SYS_RST_IOSS, RUBY_SYS_CTL_CPU_VEC_MASK);
	writel(SYS_RST_PCIE|SYS_RST_IOSS, RUBY_SYS_CTL_CPU_VEC);

	writel(0x00010020, PCIE_PORT_LINK_CTL);
	writel(PCIE_CFG0_DEFAULT_VALUE | PCIE_CFG_RC_MODE, RUBY_SYS_CTL_PCIE_CFG0);
	writel(0x00000001, RUBY_SYS_CTL_PCIE_CFG1);
	writel(0x00000000, RUBY_SYS_CTL_PCIE_CFG2);
	writel(0x45220000, RUBY_SYS_CTL_PCIE_CFG3);
	writel(0x00100007, PCIE_CMDSTS);
	writel(0xf << 22, RUBY_SYS_CTL_PCIE_SLV_REQ_MISC_INFO);

	/* Enable DMA Read Channel */
	REG_WRITE(PCIE_DMA_RD_ENABLE, 0x00000001);
	REG_WRITE(PCIE_DMA_RD_CHWTLOW, 0x000001FF);
	REG_WRITE(PCIE_DMA_RD_CHWTHIG, 0x00000000);

	/* Enable DMA write channel */
	REG_WRITE(PCIE_DMA_WR_ENABLE, 0x00000001);
	REG_WRITE(PCIE_DMA_WR_CHWTLOW, 0x000001FF);
	REG_WRITE(PCIE_DMA_WR_CHWTHIG, 0x00000000);

	/* pci config space map: Define outbound region-0 that maps PCIE slave region to PCI config space */
	writel(RUBY_PCIE_ATU_OB_REGION(0), RUBY_PCIE_ATU_VIEW);
	writel(RUBY_PCIE_CONFIG_REGION, RUBY_PCIE_ATU_BASE_LO);
	writel(0x00000000, RUBY_PCIE_ATU_BASE_HI);
	writel(RUBY_PCIE_CONFIG_REGION + (RUBY_PCI_RC_CFG_SIZE - 1), RUBY_PCIE_ATU_BASE_LIMIT );
	writel(0x00000000, RUBY_PCIE_ATU_TARGET_LO);
	writel(0, RUBY_PCIE_ATU_TARGET_HI);
	writel(4, RUBY_PCIE_ATU_CTL1);
	writel(RUBY_PCIE_ATU_OB_ENABLE|RUBY_PCIE_ATU_CFG_SHIFT, RUBY_PCIE_ATU_CTL2);

	/* pci memory space map: Define outbound region-1 that maps PCIE slave region to PCI mem space */
	writel(RUBY_PCIE_ATU_OB_REGION(1), RUBY_PCIE_ATU_VIEW);
	writel(RUBY_PCI_RC_MEM_START, RUBY_PCIE_ATU_BASE_LO);
	writel(0x00000000, RUBY_PCIE_ATU_BASE_HI);
	writel(RUBY_PCI_RC_MEM_START + (RUBY_PCI_RC_MEM_WINDOW - 1), RUBY_PCIE_ATU_BASE_LIMIT );
	writel(0xc0000000, RUBY_PCIE_ATU_TARGET_LO);
	writel(0, RUBY_PCIE_ATU_TARGET_HI);
	writel(0, RUBY_PCIE_ATU_CTL1);
	writel(RUBY_PCIE_ATU_OB_ENABLE, RUBY_PCIE_ATU_CTL2);

	/* pci access enable */
	//writel(RUBY_PCI_RC_MEM_START, RUBY_PCIE_BAR(0));
	writel(PCIE_MEM_EN | PCIE_IO_EN | PCIE_BUS_MASTER_EN, RUBY_PCIE_CMD_REG);
}
#endif /* TOPAZ_EP_MINI_UBOOT */

void board_pcie_init(size_t memsz, uint32_t flags )
{
	char *val;

	if (flags & PCIE_RC_MODE) {
#ifdef TOPAZ_EP_MINI_UBOOT
		printf("Doesn't support RC mode in mini u-boot\n");
#else
		printf("init board as PCIe Root Complex mode\n");
		pcie_rc_init();
#endif

	} else {
		val = getenv("disable_pcie");

		if (val == NULL || val[0] == '0') {
			printf("init board as PCIe End Point mode\n");
			pcie_ep_init(memsz, 0);
		}
	}
}

