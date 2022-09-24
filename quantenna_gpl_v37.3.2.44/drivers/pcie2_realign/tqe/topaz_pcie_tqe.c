/**
 * Copyright (c) 2012-2013 Quantenna Communications, Inc.
 * All rights reserved.
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
#include <linux/proc_fs.h>
#include <linux/io.h>

#include <linux/timer.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <qtn/dmautil.h>
#include <drivers/ruby/dma_cache_ops.h>
#include <asm/board/board_config.h>
#include "net80211/ieee80211.h"

#include <qtn/topaz_tqe.h>
#include <qtn/topaz_hbm_cpuif.h>
#include <qtn/topaz_hbm.h>
#include "topaz_pcie_tqe.h"
#include "topaz_vnet.h"
#include <linux/if_vlan.h>
#include <qtn/qdrv_sch.h>

static struct net_device *g_tqe_pcie_ndev = NULL;

void tqe_irq_enable(void)
{
#ifdef PCIE_TQE_INTR_WORKAROUND
	__topaz_tqe_cpuif_setup_irq(TOPAZ_TQE_PCIE_REL_PORT, 1, 0);
#else
	uint32_t temp;
        temp = readl(TOPAZ_LH_IPC3_INT_MASK);
        temp |= 0x1;
        writel(temp, TOPAZ_LH_IPC3_INT_MASK);
#endif
}

static void tqe_irq_disable(void)
{
#ifndef PCIE_TQE_INTR_WORKAROUND
	uint32_t temp;
        temp = readl(TOPAZ_LH_IPC3_INT_MASK);
        temp &= ~0x1;
        writel(temp, TOPAZ_LH_IPC3_INT_MASK);
#endif
}

static union topaz_tqe_pcieif_descr * desc_bus_to_uncached(struct tqe_netdev_priv *priv, void *_bus_desc)
{
	unsigned long bus_desc = (unsigned long)_bus_desc;
	unsigned long bus_start = priv->rx.descs_dma_addr;
	unsigned long virt_start = (unsigned long)&priv->rx.descs[0];
	return (void *)(bus_desc - bus_start + virt_start);
}

#ifdef CONFIG_TOPAZ_PCIE_TARGET
static int __pcie_sram_text tqe_rx_napi_handler(struct napi_struct *napi, int budget)
{
	int processed = 0;

	struct tqe_netdev_priv *const priv = container_of(napi, struct tqe_netdev_priv, napi);
	struct net_device *const pcie_ndev = priv->pcie_ndev;
	struct vmac_priv *const vmp = netdev_priv(pcie_ndev);

	vmp->stats.tx.tqe.napi_cnt++;

	while (processed < budget) {
		union topaz_tqe_cpuif_status status;
		union topaz_tqe_pcieif_descr __iomem *bus_desc;
		union topaz_tqe_pcieif_descr *uncached_virt_desc;
		union topaz_tqe_pcieif_descr stack_desc;

		status = topaz_tqe_pcieif_get_status();
		if (status.data.empty) {
			vmp->stats.tx.tqe.no_pkt++;
			break;
		}

		bus_desc = topaz_tqe_pcieif_get_curr();
		uncached_virt_desc = desc_bus_to_uncached(priv, bus_desc);
		stack_desc = *uncached_virt_desc;

		if (likely(stack_desc.data.own)) {
			const int ret = vmac_tx(&stack_desc, pcie_ndev, PKT_TQE);
			if (ret == NETDEV_TX_OK) {
				topaz_tqe_pcieif_put_back(bus_desc);
			} else {
				break;
			}
			++processed;
		} else {
			printk("%s unowned descriptor? bus_desc 0x%p\n",
					__FUNCTION__, bus_desc);
			break;
		}
	}

	vmac_tx_enqueue(pcie_ndev);

	if (processed < budget) {
		napi_complete(napi);
		tqe_irq_enable();
		vmp->stats.tx.tqe.napi_complete++;
	}

	priv->ipcstat = 0;

	return processed;
}
#elif defined (CONFIG_TOPAZ_PCIE_HOST)
static int __pcie_sram_text tqe_rx_napi_handler(struct napi_struct *napi, int budget)
{
	int processed = 0;
	struct tqe_netdev_priv *priv = container_of(napi, struct tqe_netdev_priv, napi);

	topaz_hbm_filter_txdone_pool();

	while (processed < budget) {
		union topaz_tqe_cpuif_status status;
		union topaz_tqe_pcieif_descr __iomem *bus_desc;
		union topaz_tqe_pcieif_descr *uncached_virt_desc;

		status = topaz_tqe_pcieif_get_status();
		if (status.data.empty) {
			break;
		}

		bus_desc = topaz_tqe_pcieif_get_curr();
		uncached_virt_desc = desc_bus_to_uncached(priv, bus_desc);

		if (likely(uncached_virt_desc->data.own)) {
			if (vmac_tx(uncached_virt_desc, priv->pcie_ndev, PKT_TQE)
				== NETDEV_TX_OK)
				topaz_tqe_pcieif_put_back(bus_desc);

			++processed;
		} else {
			printk("%s unowned descriptor? bus_desc 0x%p\n",
				__FUNCTION__, bus_desc);
			break;
		}
	}

	if (processed < budget) {
		napi_complete(napi);
		tqe_irq_enable();
	}

	return processed;
}
#endif


static irqreturn_t __pcie_sram_text tqe_irqh(int irq, void *_dev)
{
	struct net_device *dev = _dev;
	struct tqe_netdev_priv *priv = netdev_priv(dev);
	uint32_t ipcstat;

	ipcstat = readl(TOPAZ_LH_IPC3_INT) & 0xffff;
	if (ipcstat) {
		writel(ipcstat << 16, TOPAZ_LH_IPC3_INT);

		if(ipcstat & 0x1) {
			priv->ipcstat = ipcstat;
			napi_schedule(&priv->napi);
			tqe_irq_disable();
		}
	}

	return IRQ_HANDLED;
}

#ifdef CONFIG_TOPAZ_PCIE_TARGET
int __pcie_sram_text tqe_rx_handler(void *_dev)
{
	struct net_device *dev = _dev;
	struct tqe_netdev_priv *priv = netdev_priv(dev);

	if (priv->ipcstat) {
		tqe_rx_napi_handler(&priv->napi, 10);
	}

	return 0;
}

int __pcie_sram_text tqe_rx_handler_congest_queue(void *vmp)
{
	struct net_device *dev = ((struct vmac_priv *)vmp)->tqe_ndev;

	return tqe_rx_handler(dev);
}
#endif

/*
 * TQE network device ops
 */
static int tqe_ndo_open(struct net_device *dev)
{
	return -ENODEV;
}

static int tqe_ndo_stop(struct net_device *dev)
{
	return -ENODEV;
}

extern int fwt_sw_get_index_from_mac_be(const uint8_t *mac_be);
fwt_db_entry *vmac_get_tqe_ent(const unsigned char *src_mac_be, const unsigned char *dst_mac_be)
{
	int index = 0;
	fwt_db_entry *fwt_ent, *fwt_ent_out;

	index = fwt_sw_get_index_from_mac_be(dst_mac_be);
	if (index < 0) {
		return NULL;
	}
	fwt_ent = fwt_db_get_table_entry(index);
	if (fwt_ent && fwt_ent->valid) {
		fwt_ent_out = fwt_ent;
	} else {
		return NULL;
	}

	index = fwt_sw_get_index_from_mac_be(src_mac_be);
	if (index < 0) {
		return NULL;
	}
	fwt_ent = fwt_db_get_table_entry(index);
	if (!fwt_ent || !fwt_ent->valid)
		return NULL;

	return fwt_ent_out;
}

void __pcie_sram_text topaz_pcie_prepare_pp_cntl(union topaz_tqe_cpuif_ppctl *pp_cntl,
		uint32_t tid, fwt_db_entry *fwt_ent, void *data_bus, int data_len)
{
	uint8_t port;
	uint8_t node;
	uint8_t portal;
	uint16_t misc_user;
	int8_t pool = topaz_hbm_payload_get_pool_bus(data_bus);
	const long buff_ptr_offset =
		topaz_hbm_payload_buff_ptr_offset_bus(data_bus, pool, NULL);
	uint8_t tqe_full_free = 1;
#ifdef CONFIG_TOPAZ_PCIE_TARGET
	tqe_full_free = 0;
#endif

	port = fwt_ent->out_port;
	node = fwt_ent->out_node;
	portal = fwt_ent->portal;
	misc_user = 0;

	topaz_tqe_cpuif_ppctl_init(pp_cntl,
			port, &node, 1, tid,
			portal, 1, 0, tqe_full_free, misc_user);

	pp_cntl->data.pkt = (void *)data_bus;
	pp_cntl->data.buff_ptr_offset = buff_ptr_offset;
	pp_cntl->data.length = data_len;
	pp_cntl->data.buff_pool_num = pool;
}

#ifdef CONFIG_TOPAZ_PCIE_HOST
__attribute__((section(".sram.text"))) int topaz_pcie_tqe_xmit(fwt_db_entry *fwt_ent,
	void *data_bus, int data_len)
{
	union topaz_tqe_cpuif_ppctl ctl;
	uint8_t tid = WME_AC_TO_TID(0);/* TODO: */
	uint8_t vlan_index;

	topaz_tqe_vlan_gettid(data_bus, &tid, &vlan_index);

	topaz_pcie_prepare_pp_cntl(&ctl, tid, fwt_ent, data_bus, data_len);

	while (topaz_tqe_pcieif_tx_nready());

	topaz_tqe_pcieif_tx_start(&ctl);

	return NET_XMIT_SUCCESS;
}
#else
static int topaz_tqe_pcieif_tx_fail(void)
{
	int num = topaz_tqe_cpuif_port_to_num(TOPAZ_TQE_PCIE_REL_PORT);
	return ((qtn_mproc_sync_mem_read(TOPAZ_TQE_CPUIF_TXSTART(num)) &
		TOPAZ_TQE_CPUIF_TX_START_NOT_SUCCESS));
}

__attribute__((section(".sram.text"))) int topaz_pcie_tqe_xmit(union topaz_tqe_cpuif_ppctl *pp_cntl)
{
	while (topaz_tqe_pcieif_tx_nready());

	topaz_tqe_pcieif_tx_start(pp_cntl);

	wmb();
	while (topaz_tqe_pcieif_tx_nready());

	if (topaz_tqe_pcieif_tx_fail())
		return NET_XMIT_CN;
	else
		return NET_XMIT_SUCCESS;
}
#endif

static int tqe_ndo_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	return NETDEV_TX_BUSY;
}

static const struct net_device_ops tqe_ndo = {
	.ndo_open = tqe_ndo_open,
	.ndo_stop = tqe_ndo_stop,
	.ndo_start_xmit = tqe_ndo_start_xmit,
	.ndo_set_mac_address = eth_mac_addr,
};

static int tqe_descs_alloc(struct tqe_netdev_priv *priv)
{
	int i;
	union topaz_tqe_pcieif_descr __iomem *bus_descs;

	if (ALIGNED_DMA_DESC_ALLOC(&priv->rx, QTN_BUFS_PCIE_TQE_RX_RING, TOPAZ_TQE_CPUIF_RXDESC_ALIGN, 0)) {
		return -ENOMEM;
	}

	bus_descs = (void *)priv->rx.descs_dma_addr;
	for (i = 0; i < QTN_BUFS_PCIE_TQE_RX_RING; i++) {
		priv->rx.descs[i].data.next = &bus_descs[(i + 1) % QTN_BUFS_PCIE_TQE_RX_RING];
	}

	printk(KERN_INFO "%s: %u tqe_rx_descriptors at kern uncached 0x%p bus 0x%p\n",
			__FUNCTION__, priv->rx.desc_count, priv->rx.descs, bus_descs);

	topaz_tqe_pcieif_setup_ring((void *)priv->rx.descs_dma_addr, priv->rx.desc_count);

	return 0;
}

static void tqe_descs_free(struct tqe_netdev_priv *priv)
{
	if (priv->rx.descs) {
		ALIGNED_DMA_DESC_FREE(&priv->rx);
	}
}

struct net_device * tqe_pcie_netdev_init( struct net_device *pcie_ndev)
{
	int rc = 0;
	struct vmac_priv *vmp = netdev_priv(pcie_ndev);
	struct net_device *dev = NULL;
	struct tqe_netdev_priv *priv;
	static const int tqe_netdev_irq = 18;
#ifdef TOPAZ_PCIE_HDP_TX_QUEUE
	struct tqe_queue *tx_queue;
#endif

	dev = alloc_netdev(sizeof(struct tqe_netdev_priv), "tqe_pcie", &ether_setup);
	if (!dev) {
		printk(KERN_ERR "%s: unable to allocate dev\n", __FUNCTION__);
		goto netdev_alloc_error;
	}
	priv = netdev_priv(dev);

	dev->base_addr = 0;
	dev->irq = tqe_netdev_irq;
	dev->watchdog_timeo = 60 * HZ;
	dev->tx_queue_len = 1;
	dev->netdev_ops = &tqe_ndo;

	/* Initialise TQE */
	topaz_tqe_pcieif_setup_reset(1);
	topaz_tqe_pcieif_setup_reset(0);

	if (tqe_descs_alloc(priv)) {
		goto desc_alloc_error;
	}

	rc = request_irq(dev->irq, &tqe_irqh, 0, dev->name, dev);
	if (rc) {
		printk(KERN_ERR "%s: unable to get %s IRQ %d\n",
				__FUNCTION__, dev->name, tqe_netdev_irq);
		goto irq_request_error;
	}

	rc = register_netdev(dev);
	if (rc) {
		printk(KERN_ERR "%s: Cannot register net device '%s', error %d\n",
				__FUNCTION__, dev->name, rc);
		goto netdev_register_error;
	}

	priv->pcie_ndev = pcie_ndev;
#ifdef CONFIG_TOPAZ_PCIE_TARGET
	priv->rx_napi_budget = TQE_RX_NAPI_BUDGET;
#elif defined (CONFIG_TOPAZ_PCIE_HOST)
	priv->rx_napi_budget = board_napi_budget();
#endif

	vmp->tqe_ndev = dev;

#ifdef TOPAZ_PCIE_HDP_TX_QUEUE
	tx_queue = &priv->tqe_tx_queue;
	tx_queue->queue_in = 0;
	tx_queue->queue_out = 0;
	tx_queue->pkt_num = 0;
	init_timer(&tx_queue->tx_timer);
	tx_queue->tx_timer.data = (unsigned long)priv;
	tx_queue->tx_timer.function = (void (*)(unsigned long))&tqe_queue_start_tx;
#endif

	qdrv_dscp2tid_map_init();

	netif_napi_add(dev, &priv->napi, &tqe_rx_napi_handler, priv->rx_napi_budget);
#ifdef CONFIG_TOPAZ_PCIE_TARGET
	tqe_port_register(TOPAZ_TQE_PCIE_REL_PORT);
#endif

	napi_enable(&priv->napi);
	tqe_irq_enable();
#ifdef PCIE_TQE_INTR_WORKAROUND
        writel(readl(TOPAZ_LH_IPC3_INT_MASK) | 0x1, TOPAZ_LH_IPC3_INT_MASK);
#endif
	g_tqe_pcie_ndev = dev;
	return dev;

netdev_register_error:
	free_irq(dev->irq, dev);
irq_request_error:
	tqe_descs_free(priv);
desc_alloc_error:
	free_netdev(dev);
netdev_alloc_error:
	return NULL;
}
EXPORT_SYMBOL(tqe_pcie_netdev_init);

void tqe_pcie_netdev_term( struct net_device *pcie_ndev)
{
#ifdef CONFIG_TOPAZ_PCIE_TARGET
	tqe_port_unregister(TOPAZ_TQE_PCIE_REL_PORT);
#endif
}
EXPORT_SYMBOL(tqe_pcie_netdev_term);

void tqe_netdev_exit(void)
{
	struct net_device *dev = g_tqe_pcie_ndev;
	struct tqe_netdev_priv *priv;

	if (dev == NULL)
		return;
	priv = netdev_priv(dev);
	unregister_netdev(dev);
	free_irq(dev->irq, dev);
	tqe_descs_free(priv);
	free_netdev(dev);

	g_tqe_pcie_ndev = NULL;
}
EXPORT_SYMBOL(tqe_netdev_exit);

