/*
 * Copyright (C) 2009 Freescale Semiconductor, Inc. All rights reserved.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

/*
 * mpc8569mds board configuration file
 */
#ifndef __CONFIG_H
#define __CONFIG_H

/* High Level Configuration Options */
#define CONFIG_BOOKE		1	/* BOOKE */
#define CONFIG_E500		1	/* BOOKE e500 family */
#define CONFIG_MPC85xx		1	/* MPC8540/60/55/41/48/68 */
#define CONFIG_MPC8569		1	/* MPC8569 specific */
#define CONFIG_MPC8569MDS	1	/* MPC8569MDS board specific */

#define CONFIG_FSL_ELBC		1	/* Has Enhance localbus controller */

#define CONFIG_PCI		1	/* Disable PCI/PCIE */
#define CONFIG_PCIE1		1	/* PCIE controller */
#define CONFIG_FSL_PCI_INIT	1	/* use common fsl pci init code */
#define CONFIG_FSL_PCIE_RESET	1	/* need PCIe reset errata */
#define CONFIG_SYS_PCI_64BIT	1	/* enable 64-bit PCI resources */
#define CONFIG_QE			/* Enable QE */
#define CONFIG_ENV_OVERWRITE
#define CONFIG_FSL_LAW		1	/* Use common FSL init code */

/*
 * When initializing flash, if we cannot find the manufacturer ID,
 * assume this is the AMD flash associated with the MDS board.
 * This allows booting from a promjet.
 */
#define CONFIG_ASSUME_AMD_FLASH

#ifndef __ASSEMBLY__
extern unsigned long get_clock_freq(void);
#endif
/* Replace a call to get_clock_freq (after it is implemented)*/
#define CONFIG_SYS_CLK_FREQ	66666666
#define CONFIG_DDR_CLK_FREQ	CONFIG_SYS_CLK_FREQ

/*
 * These can be toggled for performance analysis, otherwise use default.
 */
#define CONFIG_L2_CACHE				/* toggle L2 cache	*/
#define CONFIG_BTB				/* toggle branch predition */

/*
 * Only possible on E500 Version 2 or newer cores.
 */
#define CONFIG_ENABLE_36BIT_PHYS	1

#define CONFIG_BOARD_EARLY_INIT_F	1	/* Call board_pre_init */

#define CONFIG_SYS_MEMTEST_START	0x00200000	/* memtest works on */
#define CONFIG_SYS_MEMTEST_END		0x00400000

/*
 * Base addresses -- Note these are effective addresses where the
 * actual resources get mapped (not physical addresses)
 */
#define CONFIG_SYS_CCSRBAR_DEFAULT	0xff700000	/* CCSRBAR Default */
#define CONFIG_SYS_CCSRBAR		0xe0000000	/* relocated CCSRBAR */
#define CONFIG_SYS_CCSRBAR_PHYS	CONFIG_SYS_CCSRBAR
						/* physical addr of CCSRBAR */
#define CONFIG_SYS_IMMR		CONFIG_SYS_CCSRBAR
						/* PQII uses CONFIG_SYS_IMMR */

#define CONFIG_SYS_PCI1_ADDR           (CONFIG_SYS_CCSRBAR+0x8000)
#define CONFIG_SYS_PCIE1_ADDR          (CONFIG_SYS_CCSRBAR+0xa000)

/* DDR Setup */
#define CONFIG_FSL_DDR3
#undef CONFIG_FSL_DDR_INTERACTIVE
#define CONFIG_SPD_EEPROM		/* Use SPD EEPROM for DDR setup*/
#define CONFIG_DDR_SPD
#define CONFIG_DDR_DLL			/* possible DLL fix needed */
#define CONFIG_ECC_INIT_VIA_DDRCONTROLLER	/* DDR controller or DMA? */

#define CONFIG_MEM_INIT_VALUE	0xDeadBeef

#define CONFIG_SYS_DDR_SDRAM_BASE	0x00000000
					/* DDR is system memory*/
#define CONFIG_SYS_SDRAM_BASE		CONFIG_SYS_DDR_SDRAM_BASE

#define CONFIG_NUM_DDR_CONTROLLERS	1
#define CONFIG_DIMM_SLOTS_PER_CTLR	1
#define CONFIG_CHIP_SELECTS_PER_CTRL	(2 * CONFIG_DIMM_SLOTS_PER_CTLR)

/* I2C addresses of SPD EEPROMs */
#define SPD_EEPROM_ADDRESS1    0x51    /* CTLR 0 DIMM 0 */
#define SPD_EEPROM_ADDRESS2    0x52    /* CTLR 1 DIMM 0 */

/* These are used when DDR doesn't use SPD.  */
#define CONFIG_SYS_SDRAM_SIZE           1024		/* DDR is 1024MB */
#define CONFIG_SYS_DDR_CS0_BNDS         0x0000003F
#define CONFIG_SYS_DDR_CS0_CONFIG       0x80014202
#define CONFIG_SYS_DDR_TIMING_3         0x00020000
#define CONFIG_SYS_DDR_TIMING_0         0x00330004
#define CONFIG_SYS_DDR_TIMING_1         0x6F6B4644
#define CONFIG_SYS_DDR_TIMING_2         0x002888D0
#define CONFIG_SYS_DDR_SDRAM_CFG	0x47000000
#define CONFIG_SYS_DDR_SDRAM_CFG_2	0x04401040
#define CONFIG_SYS_DDR_SDRAM_MODE	0x40401521
#define CONFIG_SYS_DDR_SDRAM_MODE_2	0x8000C000
#define CONFIG_SYS_DDR_SDRAM_INTERVAL	0x03E00000
#define CONFIG_SYS_DDR_DATA_INIT        0xdeadbeef
#define CONFIG_SYS_DDR_SDRAM_CLK_CNTL	0x01000000
#define CONFIG_SYS_DDR_TIMING_4         0x00220001
#define CONFIG_SYS_DDR_TIMING_5         0x03402400
#define CONFIG_SYS_DDR_ZQ_CNTL		0x89080600
#define CONFIG_SYS_DDR_WRLVL_CNTL	0x0655A604
#define CONFIG_SYS_DDR_CDR_1		0x80040000
#define CONFIG_SYS_DDR_CDR_2		0x00000000
#define CONFIG_SYS_DDR_OCD_CTRL         0x00000000
#define CONFIG_SYS_DDR_OCD_STATUS       0x00000000
#define CONFIG_SYS_DDR_CONTROL          0xc7000000      /* Type = DDR3 */
#define CONFIG_SYS_DDR_CONTROL2         0x24400000

#define CONFIG_SYS_DDR_ERR_INT_EN       0x0000000d
#define CONFIG_SYS_DDR_ERR_DIS          0x00000000
#define CONFIG_SYS_DDR_SBE              0x00010000

#undef CONFIG_CLOCKS_IN_MHZ

/*
 * Local Bus Definitions
 */

#define CONFIG_SYS_FLASH_BASE		0xfe000000	/* start of FLASH 32M */
#define CONFIG_SYS_FLASH_BASE_PHYS	CONFIG_SYS_FLASH_BASE

#define CONFIG_SYS_BCSR_BASE		0xf8000000
#define CONFIG_SYS_BCSR_BASE_PHYS	CONFIG_SYS_BCSR_BASE

/*Chip select 0 - Flash*/
#define CONFIG_SYS_BR0_PRELIM		0xfe000801
#define	CONFIG_SYS_OR0_PRELIM		0xfe000ff7

/*Chip select 1 - BCSR*/
#define CONFIG_SYS_BR1_PRELIM		0xf8000801
#define	CONFIG_SYS_OR1_PRELIM		0xffffe9f7

/*Chip select 4 - PIB*/
#define CONFIG_SYS_BR4_PRELIM		0xf8008801
#define CONFIG_SYS_OR4_PRELIM		0xffffe9f7

/*Chip select 5 - PIB*/
#define CONFIG_SYS_BR5_PRELIM		0xf8010801
#define CONFIG_SYS_OR5_PRELIM		0xffffe9f7

#define CONFIG_SYS_MAX_FLASH_BANKS	1	/* number of banks */
#define CONFIG_SYS_MAX_FLASH_SECT	512	/* sectors per device */
#undef	CONFIG_SYS_FLASH_CHECKSUM
#define CONFIG_SYS_FLASH_ERASE_TOUT	60000	/* Flash Erase Timeout (ms) */
#define CONFIG_SYS_FLASH_WRITE_TOUT	500	/* Flash Write Timeout (ms) */

#define CONFIG_SYS_MONITOR_BASE	TEXT_BASE	/* start of monitor */

#define CONFIG_FLASH_CFI_DRIVER
#define CONFIG_SYS_FLASH_CFI
#define CONFIG_SYS_FLASH_EMPTY_INFO


/*
 * SDRAM on the LocalBus
 */
#define CONFIG_SYS_LBC_SDRAM_BASE	0xf0000000	/* Localbus SDRAM	 */
#define CONFIG_SYS_LBC_SDRAM_SIZE	64		/* LBC SDRAM is 64MB */

#define CONFIG_SYS_LBC_LCRR	0x00000004	/* LB clock ratio reg */
#define CONFIG_SYS_LBC_LBCR	0x00040000	/* LB config reg */
#define CONFIG_SYS_LBC_LSRT	0x20000000	/* LB sdram refresh timer */
#define CONFIG_SYS_LBC_MRTPR	0x00000000	/* LB refresh timer prescal*/

#define CONFIG_SYS_INIT_RAM_LOCK	1
#define CONFIG_SYS_INIT_RAM_ADDR	0xe4010000  /* Initial RAM address */
#define CONFIG_SYS_INIT_RAM_END	0x4000	    /* End of used area in RAM */

#define CONFIG_SYS_GBL_DATA_SIZE	128	/* num bytes initial data */
#define CONFIG_SYS_GBL_DATA_OFFSET	\
			(CONFIG_SYS_INIT_RAM_END - CONFIG_SYS_GBL_DATA_SIZE)
#define CONFIG_SYS_INIT_SP_OFFSET	CONFIG_SYS_GBL_DATA_OFFSET

#define CONFIG_SYS_MONITOR_LEN	(256 * 1024)	/* Reserve 256 kB for Mon */
#define CONFIG_SYS_MALLOC_LEN	(512 * 1024)	/* Reserved for malloc */

/* Serial Port */
#define CONFIG_CONS_INDEX		1
#undef	CONFIG_SERIAL_SOFTWARE_FIFO
#define CONFIG_SYS_NS16550
#define CONFIG_SYS_NS16550_SERIAL
#define CONFIG_SYS_NS16550_REG_SIZE    1
#define CONFIG_SYS_NS16550_CLK		get_bus_freq(0)

#define CONFIG_SYS_BAUDRATE_TABLE  \
	{300, 600, 1200, 2400, 4800, 9600, 19200, 38400,115200}

#define CONFIG_SYS_NS16550_COM1        (CONFIG_SYS_CCSRBAR+0x4500)
#define CONFIG_SYS_NS16550_COM2        (CONFIG_SYS_CCSRBAR+0x4600)

/* Use the HUSH parser*/
#define CONFIG_SYS_HUSH_PARSER
#ifdef  CONFIG_SYS_HUSH_PARSER
#define CONFIG_SYS_PROMPT_HUSH_PS2 "> "
#endif

/* pass open firmware flat tree */
#define CONFIG_OF_LIBFDT		1
#define CONFIG_OF_BOARD_SETUP		1
#define CONFIG_OF_STDOUT_VIA_ALIAS	1

#define CONFIG_SYS_64BIT_VSPRINTF	1
#define CONFIG_SYS_64BIT_STRTOUL	1

/*
 * I2C
 */
#define CONFIG_FSL_I2C		/* Use FSL common I2C driver */
#define CONFIG_HARD_I2C		/* I2C with hardware support*/
#undef	CONFIG_SOFT_I2C		/* I2C bit-banged */
#define CONFIG_I2C_MULTI_BUS
#define CONFIG_I2C_CMD_TREE
#define CONFIG_SYS_I2C_SPEED	400000	/* I2C speed and slave address */
#define CONFIG_SYS_I2C_SLAVE	0x7F
#define CONFIG_SYS_I2C_NOPROBES	{{0,0x69}}	/* Don't probe these addrs */
#define CONFIG_SYS_I2C_OFFSET	0x3000
#define CONFIG_SYS_I2C2_OFFSET	0x3100

/*
 * I2C2 EEPROM
 */
#define CONFIG_ID_EEPROM
#ifdef CONFIG_ID_EEPROM
#define CONFIG_SYS_I2C_EEPROM_NXID
#endif
#define CONFIG_SYS_I2C_EEPROM_ADDR      0x52
#define CONFIG_SYS_I2C_EEPROM_ADDR_LEN	1
#define CONFIG_SYS_EEPROM_BUS_NUM       1

#define PLPPAR1_I2C_BIT_MASK		0x0000000F
#define PLPPAR1_I2C2_VAL		0x00000000
#define PLPDIR1_I2C_BIT_MASK		0x0000000F
#define PLPDIR1_I2C2_VAL		0x0000000F

/*
 * General PCI
 * Memory Addresses are mapped 1-1. I/O is mapped from 0
 */
#define CONFIG_SYS_PCIE1_MEM_VIRT	0xa0000000
#define CONFIG_SYS_PCIE1_MEM_BUS	0xa0000000
#define CONFIG_SYS_PCIE1_MEM_PHYS	0xa0000000
#define CONFIG_SYS_PCIE1_MEM_SIZE	0x20000000	/* 512M */
#define CONFIG_SYS_PCIE1_IO_VIRT	0xe2800000
#define CONFIG_SYS_PCIE1_IO_BUS		0x00000000
#define CONFIG_SYS_PCIE1_IO_PHYS	0xe2800000
#define CONFIG_SYS_PCIE1_IO_SIZE	0x00800000	/* 8M */

#define CONFIG_SYS_SRIO_MEM_VIRT	0xc0000000
#define CONFIG_SYS_SRIO_MEM_BUS		0xc0000000
#define CONFIG_SYS_SRIO_MEM_PHYS	0xc0000000

#ifdef CONFIG_QE
/*
 * QE UEC ethernet configuration
 */

#define CONFIG_MIIM_ADDRESS	(CONFIG_SYS_CCSRBAR + 0x82120)
#define CONFIG_UEC_ETH
#define CONFIG_ETHPRIME         "FSL UEC0"
#define CONFIG_PHY_MODE_NEED_CHANGE

#define CONFIG_UEC_ETH1         /* GETH1 */
#define CONFIG_HAS_ETH0

#ifdef CONFIG_UEC_ETH1
#define CONFIG_SYS_UEC1_UCC_NUM        0       /* UCC1 */
#define CONFIG_SYS_UEC1_RX_CLK         QE_CLK_NONE
#define CONFIG_SYS_UEC1_TX_CLK         QE_CLK12
#define CONFIG_SYS_UEC1_ETH_TYPE       GIGA_ETH
#define CONFIG_SYS_UEC1_PHY_ADDR       7
#define CONFIG_SYS_UEC1_INTERFACE_MODE ENET_1000_RGMII_ID
#endif

#define CONFIG_UEC_ETH2         /* GETH2 */
#define CONFIG_HAS_ETH1

#ifdef CONFIG_UEC_ETH2
#define CONFIG_SYS_UEC2_UCC_NUM        1       /* UCC2 */
#define CONFIG_SYS_UEC2_RX_CLK         QE_CLK_NONE
#define CONFIG_SYS_UEC2_TX_CLK         QE_CLK17
#define CONFIG_SYS_UEC2_ETH_TYPE       GIGA_ETH
#define CONFIG_SYS_UEC2_PHY_ADDR       1
#define CONFIG_SYS_UEC2_INTERFACE_MODE ENET_1000_RGMII_ID
#endif

#endif /* CONFIG_QE */

#if defined(CONFIG_PCI)

#define CONFIG_NET_MULTI
#define CONFIG_PCI_PNP			/* do pci plug-and-play */

#undef CONFIG_EEPRO100
#undef CONFIG_TULIP

#undef CONFIG_PCI_SCAN_SHOW		/* show pci devices on startup */

#endif	/* CONFIG_PCI */

#ifndef CONFIG_NET_MULTI
#define CONFIG_NET_MULTI	1
#endif

/*
 * Environment
 */
#define CONFIG_ENV_IS_IN_FLASH	1
#define CONFIG_ENV_ADDR		(CONFIG_SYS_MONITOR_BASE - CONFIG_ENV_SECT_SIZE)
#define CONFIG_ENV_SECT_SIZE	0x20000	/* 256K(one sector) for env */
#define CONFIG_ENV_SIZE		CONFIG_ENV_SECT_SIZE

#define CONFIG_LOADS_ECHO	1	/* echo on for serial download */
#define CONFIG_SYS_LOADS_BAUD_CHANGE	1	/* allow baudrate change */

/* QE microcode/firmware address */
#define CONFIG_SYS_QE_FW_ADDR	0xfff00000

/*
 * BOOTP options
 */
#define CONFIG_BOOTP_BOOTFILESIZE
#define CONFIG_BOOTP_BOOTPATH
#define CONFIG_BOOTP_GATEWAY
#define CONFIG_BOOTP_HOSTNAME


/*
 * Command line configuration.
 */
#include <config_cmd_default.h>

#define CONFIG_CMD_PING
#define CONFIG_CMD_I2C
#define CONFIG_CMD_MII
#define CONFIG_CMD_ELF
#define CONFIG_CMD_IRQ
#define CONFIG_CMD_SETEXPR

#if defined(CONFIG_PCI)
    #define CONFIG_CMD_PCI
#endif


#undef CONFIG_WATCHDOG			/* watchdog disabled */

/*
 * Miscellaneous configurable options
 */
#define CONFIG_SYS_LONGHELP		/* undef to save memory	*/
#define CONFIG_CMDLINE_EDITING		/* Command-line editing */
#define CONFIG_SYS_LOAD_ADDR	0x2000000	/* default load address */
#define CONFIG_SYS_PROMPT	"=> "		/* Monitor Command Prompt */
#if defined(CONFIG_CMD_KGDB)
#define CONFIG_SYS_CBSIZE	2048		/* Console I/O Buffer Size */
#else
#define CONFIG_SYS_CBSIZE	512		/* Console I/O Buffer Size */
#endif
#define CONFIG_SYS_PBSIZE (CONFIG_SYS_CBSIZE+sizeof(CONFIG_SYS_PROMPT)+16)
						/* Print Buffer Size */
#define CONFIG_SYS_MAXARGS	32		/* max number of command args */
#define CONFIG_SYS_BARGSIZE	CONFIG_SYS_CBSIZE
						/* Boot Argument Buffer Size */
#define CONFIG_SYS_HZ	1000		/* decrementer freq: 1ms ticks */

/*
 * For booting Linux, the board info and command line data
 * have to be in the first 8 MB of memory, since this is
 * the maximum mapped by the Linux kernel during initialization.
 */
#define CONFIG_SYS_BOOTMAPSZ	(8 << 20)
					/* Initial Memory map for Linux*/

/*
 * Internal Definitions
 *
 * Boot Flags
 */
#define BOOTFLAG_COLD	0x01		/* Normal Power-On: Boot from FLASH */
#define BOOTFLAG_WARM	0x02		/* Software reboot */

#if defined(CONFIG_CMD_KGDB)
#define CONFIG_KGDB_BAUDRATE	230400	/* speed to run kgdb serial port */
#define CONFIG_KGDB_SER_INDEX	2	/* which serial port to use */
#endif

/*
 * Environment Configuration
 */
#define CONFIG_HOSTNAME mpc8569mds
#define CONFIG_ROOTPATH  /nfsroot
#define CONFIG_BOOTFILE  your.uImage

#define CONFIG_SERVERIP  192.168.1.1
#define CONFIG_GATEWAYIP 192.168.1.1
#define CONFIG_NETMASK   255.255.255.0

#define CONFIG_LOADADDR  200000   /*default location for tftp and bootm*/

#define CONFIG_BOOTDELAY 10       /* -1 disables auto-boot */
#undef  CONFIG_BOOTARGS           /* the boot command will set bootargs*/

#define CONFIG_BAUDRATE	115200

#define	CONFIG_EXTRA_ENV_SETTINGS					\
	"netdev=eth0\0"							\
	"consoledev=ttyS0\0"						\
	"ramdiskaddr=600000\0"						\
	"ramdiskfile=your.ramdisk.u-boot\0"				\
	"fdtaddr=400000\0"						\
	"fdtfile=your.fdt.dtb\0"					\
	"nfsargs=setenv bootargs root=/dev/nfs rw "			\
	"nfsroot=$serverip:$rootpath "					\
	"ip=$ipaddr:$serverip:$gatewayip:$netmask:$hostname:$netdev:off " \
	"console=$consoledev,$baudrate $othbootargs\0"			\
	"ramargs=setenv bootargs root=/dev/ram rw "			\
	"console=$consoledev,$baudrate $othbootargs\0"			\

#define CONFIG_NFSBOOTCOMMAND						\
	"run nfsargs;"							\
	"tftp $loadaddr $bootfile;"					\
	"tftp $fdtaddr $fdtfile;"					\
	"bootm $loadaddr - $fdtaddr"

#define CONFIG_RAMBOOTCOMMAND						\
	"run ramargs;"							\
	"tftp $ramdiskaddr $ramdiskfile;"				\
	"tftp $loadaddr $bootfile;"					\
	"bootm $loadaddr $ramdiskaddr"

#define CONFIG_BOOTCOMMAND  CONFIG_NFSBOOTCOMMAND

#endif	/* __CONFIG_H */
