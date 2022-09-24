/*
 * Copyright (c) 2011 Quantenna Communications, Inc.
 * All rights reserved.
 *
 * Bootcfg store through mtd driver (flash partitions)
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

#include "bootcfg_drv.h"
#include "bootcfg_store_init.h"

#include <qtn/bootcfg.h>
#include <common/ruby_partitions.h>
#include <common/ruby_version.h>

#include <linux/mtd/mtd.h>
#include <linux/sched.h>

#define UBOOT_MTD_DEVICE	0
#define BOOTCFG_MTD_DEVICE	1

static spinlock_t g_flash_lock;

static void erase_callback(struct erase_info *done)
{
	wait_queue_head_t *wait_q = (wait_queue_head_t *) done->priv;
	wake_up(wait_q);
}

static int bootcfg_flash_write(struct bootcfg_store_ops *ops, const void* buf, const size_t bytes)
{
	int ret = 0;
	size_t bytes_written;
	struct erase_info erase;
	DECLARE_WAITQUEUE(wait, current);
	wait_queue_head_t wait_q;
	struct mtd_info *mtd = get_mtd_device(NULL, BOOTCFG_MTD_DEVICE);
	size_t erase_size;

	spin_lock(&g_flash_lock);

	if (mtd == NULL) {
		printk(KERN_ERR "Could not get flash device\n");
		ret = -ENODEV;
		goto out;
	}

	erase_size = bytes + (mtd->erasesize - 1);
	erase_size = erase_size - (erase_size % mtd->erasesize);

	if (mtd->unlock && mtd->unlock(mtd, 0, erase_size)) {
		printk("bootcfg: %s unlock failed\n", mtd->name);
		ret = -ENOLCK;
		goto out;
	}

	init_waitqueue_head(&wait_q);
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&wait_q, &wait);

	memset(&erase, 0, sizeof(struct erase_info));
	erase.mtd = mtd;
	erase.callback = erase_callback;
	erase.addr = 0;
	erase.len = erase_size;
	erase.priv = (u_long) & wait_q;

	ret = mtd->erase(mtd, &erase);
	if (ret) {
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&wait_q, &wait);
		printk(KERN_WARNING "bootcfg: erase of region [0x%x, 0x%x] "
		       "on \"%s\" failed\n",
		       (unsigned)erase.addr, (unsigned)erase.len, mtd->name);
		ret = -EIO;
		goto out;
	}

	schedule();		/* Wait for erase to finish. */
	remove_wait_queue(&wait_q, &wait);

	/* write to device */
	if (mtd->write(mtd, 0, bytes, &bytes_written, buf)) {
		printk("bootcfg: could not write device\n");
		ret = -EIO;
		goto out;
	}
	if (mtd->lock && mtd->lock(mtd, 0, erase_size)) {
		printk("bootcfg: could not lock device\n");
		ret = -ENOLCK;
		goto out;
	}
out:
	spin_unlock(&g_flash_lock);
	return ret;
}

#define VERSION_STR_SIZE 16

static int bootcfg_flash_read(struct bootcfg_store_ops *ops, void* buf, const size_t bytes)
{
	int ret = 0;
	size_t bytes_read;

	struct mtd_info *mtd;

	spin_lock(&g_flash_lock);

	mtd = get_mtd_device(NULL, BOOTCFG_MTD_DEVICE);
	if (mtd == NULL) {
		printk(KERN_ERR "Could not get flash device mtd%d\n", BOOTCFG_MTD_DEVICE);
		ret = -ENODEV;
		goto out;
	}

	ret = mtd->read(mtd, 0, bytes, &bytes_read, buf);
	if (ret) {
		goto out;
	}

	spin_unlock(&g_flash_lock);

	/* Check that read exactly size was requested */
	if (bytes_read != bytes) {
		ret = -ENODATA;
		goto out;
	}

out:
	spin_unlock(&g_flash_lock);
	return ret;

}

int __init bootcfg_flash_init(struct bootcfg_store_ops *ops, size_t *store_limit)
{
	int ret = 0;
	struct mtd_info *mtd;
	size_t version_bytes;
	uint8_t version[VERSION_STR_SIZE];

	spin_lock_init(&g_flash_lock);

	spin_lock(&g_flash_lock);

	mtd = get_mtd_device(NULL, UBOOT_MTD_DEVICE);
	if (mtd == NULL) {
		printk(KERN_ERR "%s: Could not get flash device mtd%d\n",
				__FUNCTION__, UBOOT_MTD_DEVICE);
		ret = -ENODEV;
		goto out;
	}

	if (mtd->read(mtd, 4, VERSION_STR_SIZE, &version_bytes, version)) {
		ret = -EIO;
		goto out;
	}

	/* here we need to figure out version to be backward compatible */
	/* version previous to 1.1.2 do not have U_BOOT tag at fixed location */
	/* also note this will not work for umsdl uboot, must be set to boot from flash */
	/* we only check for presense of the string to make sure we are > U-boot 1.1.1 */
	/* Hardwired the string here since the global version string was modified */
	if (memcmp(version, "U-BOOT", 6) != 0) {
		printk(KERN_WARNING "%s: warning, detected old U-BOOT.  bootcfg data size limited to 4k\n",
				__FUNCTION__);
		/* size here is 4k env, 4k data */
		*store_limit = 8192;
	}

out:
	spin_unlock(&g_flash_lock);
	return ret;
}

void __exit bootcfg_flash_exit(struct bootcfg_store_ops *ops)
{
}

static struct bootcfg_store_ops flash_store_ops = {
	.read	= bootcfg_flash_read,
	.write	= bootcfg_flash_write,
	.init	= bootcfg_flash_init,
	.exit	= __devexit_p(bootcfg_flash_exit),
};

struct bootcfg_store_ops * __init bootcfg_flash_get_ops(void)
{
	return &flash_store_ops;
}

