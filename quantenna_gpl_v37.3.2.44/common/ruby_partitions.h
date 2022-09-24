/*
 * (C) Copyright 2010 Quantenna Communications Inc.
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
 * Header file which describes Ruby platform.
 * Has to be used by both kernel and bootloader.
 */

#ifndef __RUBY_PARTITIONS_H
#define __RUBY_PARTITIONS_H

#define F64K_UBOOT_PIGGY_PARTITION_SIZE	0x5000
#if defined(TOPAZ_PLATFORM)
	#define F64K_ENV_PARTITION_SIZE		0x6000
#else
	#define F64K_ENV_PARTITION_SIZE         0x4000
#endif

#define UBOOT_TEXT_PARTITION_SIZE	0x20000
#define UBOOT_ENV_PARTITION_ADDR	UBOOT_TEXT_PARTITION_SIZE
#define UBOOT_ENV_PARTITION_SIZE	0x10000

/*
 * Make sure CONFIG_ENV_SIZE in file carve_env_partition.sh is the same value
 */
#if defined(TOPAZ_PLATFORM)
	#define BOOT_CFG_SIZE			(24 * 1024)
#else
	#define BOOT_CFG_SIZE			(16 * 1024)
#endif

#define BOOT_CFG_BASE_SIZE              (16 * 1024)
#define BOOT_CFG_DATA_SIZE		(BOOT_CFG_SIZE - sizeof(u32))
#define BOOT_CFG_DEF_START		(0x1000)

#define RUBY_MIN_DATA_PARTITION_SIZE	(512 * 1024)
#define IMAGES_START_ADDR		(UBOOT_ENV_PARTITION_ADDR + UBOOT_ENV_PARTITION_SIZE * 2)
#define NON_IMAGE_SIZE			(UBOOT_TEXT_PARTITION_SIZE +		\
						UBOOT_ENV_PARTITION_SIZE * 2 +	\
						RUBY_MIN_DATA_PARTITION_SIZE)
#define IMG_SIZE_8M_FLASH_2_IMG		((FLASH_8MB - NON_IMAGE_SIZE) / 2)
#define IMG_SIZE_8M_FLASH_1_IMG		((FLASH_8MB - NON_IMAGE_SIZE) / 1)
#define IMG_SIZE_16M_FLASH_2_IMG	((FLASH_16MB - NON_IMAGE_SIZE) / 2)
#define IMG_SIZE_16M_FLASH_1_IMG	((FLASH_16MB - NON_IMAGE_SIZE) / 1)

#define MTD_PARTNAME_UBOOT_BIN		"uboot"
#define MTD_PARTNAME_UBOOT_ENV		"uboot_env"
#define MTD_PARTNAME_UBOOT_ENV_BAK	"uboot_env_bak"
#define MTD_PARTNAME_LINUX_SAFETY	"linux_safety"
#define MTD_PARTNAME_LINUX_LIVE		"linux_live"
#define MTD_PARTNAME_DATA		"data"

#if defined(TOPAZ_PLATFORM)
	#define IMG_SIZE_LIMIT_PLATFORM	IMG_SIZE_16M_FLASH_2_IMG
#else
	#define IMG_SIZE_LIMIT_PLATFORM	IMG_SIZE_8M_FLASH_2_IMG
#endif

#endif // #ifndef __RUBY_PARTITIONS_H


