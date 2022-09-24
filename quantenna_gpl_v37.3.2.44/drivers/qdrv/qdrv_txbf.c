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
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/spinlock.h>
#include <asm/hardware.h>

#include "qdrv_features.h"
#include "qdrv_debug.h"
#include "qdrv_mac.h"
#include "qdrv_soc.h"
#include "qdrv_comm.h"
#include "qdrv_wlan.h"
#include "qdrv_vap.h"
#include "qdrv_txbf.h"
#include "qdrv_hal.h"
#include "qdrv_control.h"
#include "qdrv_soc.h"
#include <qtn/qtn_global.h>
#include <qtn/txbf_mbox.h>
#include <qtn/topaz_hbm.h>

static struct ieee80211_node * qdrv_txbf_find_txnode(struct qdrv_mac *mac,
		volatile struct txbf_ndp_info *ndp_info)
{
	struct net_device *vdev;
	struct qdrv_vap *qv;

	/* Transmit frame out the primary VAP */
	vdev = mac->vnet[0];
	if (unlikely(vdev == NULL)) {
		return NULL;
	}

	qv = netdev_priv(vdev);

	return ieee80211_find_txnode(&qv->iv, (uint8_t*)ndp_info->macaddr);
}

static size_t qdrv_txbf_act_frm_allheaders_len(void)
{
	return sizeof(struct ieee80211_frame)
		 + sizeof(struct ieee80211_action)
		 + sizeof(struct ht_mimo_ctrl);
}

static struct sk_buff *qdrv_txbf_get_skb(volatile struct txbf_pkts *pkt_info)
{
#if defined(TOPAZ_PLATFORM) && TOPAZ_HBM_SKB_ALLOCATOR_DEFAULT
	const int8_t pool = TOPAZ_HBM_BUF_WMAC_RX_POOL;
	void *buf_bus = (void *) pkt_info->buffer_start;
	struct sk_buff *skb = NULL;

	if (likely(buf_bus)) {
		skb = topaz_hbm_attach_skb_bus(buf_bus, pool);
		if (skb == NULL) {
			topaz_hbm_put_payload_aligned_bus(buf_bus, pool);
		}
	}
	return skb;
#else
	return (struct sk_buff *) pkt_info->skb;
#endif
}

static void qdrv_txbf_update_mu_grp(struct qdrv_wlan *qw, volatile struct qtn_sram_qmat *mu_qmat, int install)
{
	struct ieee80211com *ic = &qw->ic;
	struct ieee80211_node *u0 = NULL;
	struct ieee80211_node *u1 = NULL;
	struct ieee80211_node *ap = NULL;
	int i;
	int qmat_uninstalled = 0;

	if (!ieee80211_swfeat_is_supported(SWFEAT_ID_MU_MIMO, 0)) {
		goto exit;
	}

	/* When qmats are installed one firsts installs the groups for every node
	with ic_node_mu_grp_update call then a single ic_mu_grp_qmat_update call
	is made to install all the qmats. Qmats removal is done in reverse order: first all
	the matrixes are removed with a single ic_mu_grp_qmat_update call
	theneach node is removed from all groups with ic_node_mu_grp_update.
	After this loop is done one sends notification to DSP that removal has been
	completed (for removal case only). It is achieved by calling
	ic_mu_grp_qmat_update with 4th parameter set to 1 */
	for (i = 0; i < QTN_MU_QMAT_MAX_SLOTS; i++) {
		if (!mu_qmat[i].valid) continue;

		if (qw->ic.ic_mu_debug_level) {
			printk("dsp to lhost(%u): %s mu grp %d u0 %d u1 %d rank %d\n",
				i, (install) ? "install" : "delete",
				mu_qmat[i].grp_id,
				mu_qmat[i].u0_aid, mu_qmat[i].u1_aid, mu_qmat[i].rank);
		}

		/* find the nodes by their AIDs */
		u0 = ieee80211_find_node_by_aid(ic, mu_qmat[i].u0_aid);
		u1 = ieee80211_find_node_by_aid(ic, mu_qmat[i].u1_aid);

		if (install) {
			if (u0 == NULL || u1 == NULL) {
				goto exit;
			}

			ap = u0->ni_vap->iv_bss;

			/* install the mu grp to Muc */
			ic->ic_node_mu_grp_update(u0, mu_qmat[i].grp_id, 0, 0);
			ic->ic_node_mu_grp_update(u1, mu_qmat[i].grp_id, 1, 0);
		} else {
			if (u0 == NULL && u1 == NULL) {
				goto exit;
			}

			/* The order of ic_mu_grp_qmat_update and ic_mu_grp_qmat_update
			execution is reverce to what we have when group is created.
			The execution order counts */

			/* One of the nodes might not already exist due having been removed
			for example during disassociation. One has to process the other node anyway */
			if (u0 != NULL) {
				ap = u0->ni_vap->iv_bss;
				if (!qmat_uninstalled) {
					ic->ic_mu_grp_qmat_update(ap, 0, 1, 0);
					qmat_uninstalled = 1;
				}
				ic->ic_node_mu_grp_update(u0, mu_qmat[i].grp_id, 0, 1);
			}

			if (u1 != NULL) {
				ap = u1->ni_vap->iv_bss;
				if (!qmat_uninstalled) {
					ic->ic_mu_grp_qmat_update(ap, 0, 1, 0);
					qmat_uninstalled = 1;
				}

				ic->ic_node_mu_grp_update(u1, mu_qmat[i].grp_id, 1, 1);
			}
		}
	}

	if (ap != NULL) {
		/* When qmat is deleted this function is called here only to send
		feadback to DSP*/
		ic->ic_mu_grp_qmat_update(ap, 0, !install, !install);
	}

exit:
	if (u0) {
		ieee80211_free_node(u0);
	}

	if (u1) {
		ieee80211_free_node(u1);
	}

	return;
}

/*
 * Mailbox tasklet
 * The node structure must be locked before scheduling this process.
 */
static void qdrv_txbf_mbox_tasklet(unsigned long data)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan*)data;
	volatile struct txbf_state *txbf_state = qw->txbf_state;
	volatile struct qtn_txbf_mbox *txbf_mbox = qtn_txbf_mbox_get();
	struct ieee80211_node *ni;
	volatile struct txbf_pkts *pkt_info;
	struct sk_buff *skb;
	u32 pktlen,pkt_offset;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	pkt_offset = qtn_txbf_mbox_recv(qtn_mproc_sync_addr(&(txbf_mbox->dsp_to_host_mbox)));

	if (pkt_offset == QTN_TXBF_DSP_TO_HOST_INST_MU_GRP) {
		qdrv_txbf_update_mu_grp(qw, &txbf_mbox->mu_grp_qmat[0], 1);
		goto exit_no_unlock;
	} else if (pkt_offset == QTN_TXBF_DSP_TO_HOST_DELE_MU_GRP) {
		qdrv_txbf_update_mu_grp(qw, &txbf_mbox->mu_grp_qmat[0], 0);
		goto exit_no_unlock;
	}

	if ((QTN_TXBF_MBOX_BAD_IDX == pkt_offset) || pkt_offset > QTN_TXBF_MUC_DSP_MSG_RING_SIZE) {
		DBGPRINTF_E("got bad txbf index (%d).\n", pkt_offset);
		goto exit_no_unlock;
	}

	pkt_info = txbf_mbox->txbf_msg_bufs + pkt_offset;
	skb = qdrv_txbf_get_skb(pkt_info);
	if (skb == NULL) {
		qtn_txbf_mbox_free_msg_buf(pkt_info);
		goto exit_no_unlock;
	}

	/* DSP is done with a received action frame */
	if (pkt_info->msg_type == QTN_TXBF_ACT_FRM_FREE_MSG) {
		uint8_t slot = pkt_info->slot;

		if (pkt_info->success) {
			txbf_state->stvec_install_success++;
			if (slot < QTN_STATS_NUM_BF_SLOTS) {
				RXSTAT(qw, rx_bf_success[slot]);
			}
			TXSTAT_SET(qw, txbf_qmat_wait, pkt_info->txbf_qmat_install_wait);
		} else {
			txbf_state->stvec_install_fail++;
			if (slot < QTN_STATS_NUM_BF_SLOTS) {
				RXSTAT(qw, rx_bf_rejected[slot]);
			}
		}
		if (pkt_info->bf_compressed) {
			txbf_state->cmp_act_frms_rxd++;
		} else {
			txbf_state->uncmp_act_frms_rxd++;
		}
		txbf_state->qmat_offset = pkt_info->qmat_offset;
		txbf_state->bf_ver = pkt_info->bf_ver;

		pkt_info->skb = 0;
		pkt_info->act_frame_phys = 0;
		pkt_info->buffer_start = 0;
		qtn_txbf_mbox_free_msg_buf(pkt_info);

		dev_kfree_skb_irq(skb);

		if (pkt_info->ndp_info.bw_mode == QTN_BW_80M) {
			txbf_state->qmat_bandwidth = BW_HT80;
		} else if (pkt_info->ndp_info.bw_mode == QTN_BW_40M) {
			txbf_state->qmat_bandwidth = BW_HT40;
		} else {
			txbf_state->qmat_bandwidth = BW_HT20;
		}
		txbf_state->bf_tone_grp = pkt_info->bf_tone_grp;

		goto exit;
	/* Discard unexpected message types */
	} else if (pkt_info->msg_type != QTN_TXBF_ACT_FRM_TX_MSG) {
		pkt_info->skb = 0;
		pkt_info->act_frame_phys = 0;
		pkt_info->buffer_start = 0;
		qtn_txbf_mbox_free_msg_buf(pkt_info);
		dev_kfree_skb_irq(skb);
		DBGPRINTF_E("Received message not for me: %x\n", pkt_info->msg_type);

		goto exit;
	}

	/* Process a transmit action frame from the DSP */
	pktlen = pkt_info->act_frame_len;
	skb_put(skb,pktlen);

	if ( txbf_state->send_txbf_netdebug ) {
		txbf_state->send_txbf_netdebug = 0;
		qdrv_control_txbf_pkt_send(qw,
				skb->data +
				qdrv_txbf_act_frm_allheaders_len() + 2,
				pkt_info->ndp_info.bw_mode);
	}

	ni = qdrv_txbf_find_txnode(qw->mac, &pkt_info->ndp_info);

	/* Clear the packet info ready for the next NDP */
	pkt_info->act_frame_phys = 0;
	pkt_info->buffer_start = 0;
	pkt_info->skb = 0;
	qtn_txbf_mbox_free_msg_buf(pkt_info);

	if (ni == NULL) {
		dev_kfree_skb_irq(skb);
	} else {
		ni->ni_ic->ic_send_80211(ni->ni_ic, ni, skb, WME_AC_VO, 0);
		if (pkt_info->bf_compressed) {
			txbf_state->cmp_act_frms_sent++;
		} else {
			txbf_state->uncmp_act_frms_sent++;
		}
		if (pkt_info->ndp_info.bw_mode == QTN_BW_80M) {
			txbf_state->qmat_bandwidth = BW_HT80;
		} else if (pkt_info->ndp_info.bw_mode == QTN_BW_40M) {
			txbf_state->qmat_bandwidth = BW_HT40;
		} else {
			txbf_state->qmat_bandwidth = BW_HT20;
		}
		txbf_state->bf_tone_grp = pkt_info->bf_tone_grp;
	}
exit:
exit_no_unlock:
	/* Enable the mbx interrupts */
	qtn_txbf_lhost_irq_enable(qw->mac);

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
}

/* Handler for the DSP interrupt for action frame */
static void qdrv_txbf_mbox_interrupt(void *arg1, void *dev_id)
{
	struct qdrv_wlan *qw = (struct qdrv_wlan*)dev_id;
	struct txbf_state *txbf_state = qw->txbf_state;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	/* Disable mbx interrupts */
	qtn_txbf_lhost_irq_disable(qw->mac);

	if (txbf_state != NULL) {
		tasklet_schedule(&txbf_state->txbf_dsp_mbox_task);
	}

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
}

int qdrv_txbf_config_get(struct qdrv_wlan *qw, u32 *value)
{
	struct txbf_state *txbf_state = (struct txbf_state *) qw->txbf_state;
	volatile struct qtn_txbf_mbox *txbf_mbox = qtn_txbf_mbox_get();
	volatile struct txbf_ctrl *bf_ctrl = NULL;

	printk("Current TXBF Config values are:\n");
	if (txbf_mbox != NULL) {
		bf_ctrl = &txbf_mbox->bfctrl_params;

		printk("    CalcChanInv               = %d\n",
			!!(bf_ctrl->svd_mode & BIT(SVD_MODE_CHANNEL_INV)));
		printk("    CalcTwoStreams            = %d\n",
			!!(bf_ctrl->svd_mode & BIT(SVD_MODE_TWO_STREAM)));
		printk("    ApplyPerAntScaling        = %d\n",
			!!(bf_ctrl->svd_mode & BIT(SVD_MODE_PER_ANT_SCALE)));
		printk("    ApplyStreamMixing         = %d\n",
			!!(bf_ctrl->svd_mode & BIT(SVD_MODE_STREAM_MIXING)));
		printk("    SVD Bypass                = %d\n",
			!!(bf_ctrl->svd_mode & BIT(SVD_MODE_BYPASS)));
	} else {
		printk("    SVD settings not available\n");
	}
	printk("    Stvec install bypass      = %d\n", txbf_state->stmat_install_bypass);
	printk("    Reg Scale fac             = %d\n", txbf_state->st_mat_reg_scale_fac);
	printk("    Stvec install success     = %d\n", txbf_state->stvec_install_success);
	printk("    Stvec install failed      = %d\n", txbf_state->stvec_install_fail);
	printk("    Stvec overwrite           = %d\n", txbf_state->stvec_overwrite);
	printk("    Comp Action Frames Sent   = %d\n", txbf_state->cmp_act_frms_sent);
	printk("    Uncomp Action Frames Sent = %d\n", txbf_state->uncmp_act_frms_sent);
	printk("    Comp Action Frames Recv   = %d\n", txbf_state->cmp_act_frms_rxd);
	printk("    Uncomp Action Frames Recv = %d\n", txbf_state->uncmp_act_frms_rxd);
	printk("    Bandwidth                 = %d\n", txbf_state->qmat_bandwidth);
#ifdef TOPAZ_PLATFORM
	if (((txbf_state->qmat_bandwidth == 0) || (txbf_state->qmat_bandwidth == BW_HT80)) &&
			(txbf_state->bf_tone_grp == QTN_TXBF_DEFAULT_QMAT_NG)) {
		/* Assume 80 MHz 11ac node if bw is 0, as hw is providing feedback */
		printk("    1 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT80_1STRM_OFFSET(txbf_state->qmat_offset));
		printk("    2 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT80_2STRM_OFFSET(txbf_state->qmat_offset));
		printk("    3 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT80_3STRM_OFFSET(txbf_state->qmat_offset));
		printk("    4 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT80_4STRM_OFFSET(txbf_state->qmat_offset));
		printk("    1 Stream 40M Stvec offset = %u\n", QTN_TXBF_QMAT80_1STRM_40M_OFFSET(txbf_state->qmat_offset));
		printk("    2 Stream 40M Stvec offset = %u\n", QTN_TXBF_QMAT80_2STRM_40M_OFFSET(txbf_state->qmat_offset));
		printk("    1 Stream 20M Stvec offset = %u\n", QTN_TXBF_QMAT80_1STRM_20M_OFFSET(txbf_state->qmat_offset));
		printk("    2 Stream 20M Stvec offset = %u\n", QTN_TXBF_QMAT80_2STRM_20M_OFFSET(txbf_state->qmat_offset));
	} else if ((txbf_state->qmat_bandwidth == 0) || (txbf_state->qmat_bandwidth == BW_HT80)) {
		/* Assume 80 MHz 11ac node if bw is 0, as hw is providing feedback */
		printk("    1 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT80_NG2_1STRM_OFFSET(txbf_state->qmat_offset));
		printk("    2 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT80_NG2_2STRM_OFFSET(txbf_state->qmat_offset));
		printk("    3 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT80_NG2_3STRM_OFFSET(txbf_state->qmat_offset));
		printk("    4 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT80_NG2_4STRM_OFFSET(txbf_state->qmat_offset));
		printk("    1 Stream 40M Stvec offset = %u\n", QTN_TXBF_QMAT80_NG2_1STRM_40M_OFFSET(txbf_state->qmat_offset));
		printk("    2 Stream 40M Stvec offset = %u\n", QTN_TXBF_QMAT80_NG2_2STRM_40M_OFFSET(txbf_state->qmat_offset));
		printk("    1 Stream 20M Stvec offset = %u\n", QTN_TXBF_QMAT80_NG2_1STRM_20M_OFFSET(txbf_state->qmat_offset));
		printk("    2 Stream 20M Stvec offset = %u\n", QTN_TXBF_QMAT80_NG2_2STRM_20M_OFFSET(txbf_state->qmat_offset));
	} else
#endif
	{
		printk("    1 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT40_1STRM_OFFSET(txbf_state->qmat_offset));
		printk("    2 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT40_2STRM_OFFSET(txbf_state->qmat_offset));
		printk("    3 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT40_3STRM_OFFSET(txbf_state->qmat_offset));
		printk("    4 Stream Stvec offset     = %u\n", QTN_TXBF_QMAT40_4STRM_OFFSET(txbf_state->qmat_offset));
#ifdef TOPAZ_PLATFORM
		printk("    1 Stream 40M Stvec offset = %u\n", QTN_TXBF_QMAT40_1STRM_40M_OFFSET(txbf_state->qmat_offset));
		printk("    2 Stream 40M Stvec offset = %u\n", QTN_TXBF_QMAT40_2STRM_40M_OFFSET(txbf_state->qmat_offset));
#endif
		printk("    1 Stream 20M Stvec offset = %u\n", QTN_TXBF_QMAT40_1STRM_20M_OFFSET(txbf_state->qmat_offset));
		printk("    2 Stream 20M Stvec offset = %u\n", QTN_TXBF_QMAT40_2STRM_20M_OFFSET(txbf_state->qmat_offset));
	}
	printk("    BF version                = %u\n", txbf_state->bf_ver);

	*value = 0;
	if (bf_ctrl == NULL) {
		return(0);
	}
	*value |= !!(bf_ctrl->svd_mode & BIT(SVD_MODE_CHANNEL_INV)) << 16;
	*value |= !!(bf_ctrl->svd_mode & BIT(SVD_MODE_TWO_STREAM)) << 12;
	*value |= !!(bf_ctrl->svd_mode & BIT(SVD_MODE_PER_ANT_SCALE)) << 8;
	*value |= !!(bf_ctrl->svd_mode & BIT(SVD_MODE_STREAM_MIXING)) << 4;
	*value |= !!(bf_ctrl->svd_mode & BIT(SVD_MODE_BYPASS));

	return(0);
}

int qdrv_txbf_config_set(struct qdrv_wlan *qw, u32 value)
{
	struct txbf_state *txbf_state = (struct txbf_state *) qw->txbf_state;
	int par0,par1, par2, par3, par4, par5;
        volatile struct qtn_txbf_mbox *txbf_mbox = qtn_txbf_mbox_get();

    DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	txbf_state->send_txbf_netdebug = 1;

	if(value & (0xFF << 24)){
		txbf_state->st_mat_reg_scale_fac = (signed char)((int)value >>24);
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return(0);
	}

	par5 = (value >> 0) & 0xf;
	par4 = (value >> 4) & 0xf;
	par3 = (value >> 8) & 0xf;
	par2 = (value >> 12) & 0xf;
	par1 = (value >> 16) & 0xf;
	par0 = (value >> 20) & 0xf;

	if (txbf_mbox != NULL) {
		volatile struct txbf_ctrl *bf_ctrl = &txbf_mbox->bfctrl_params;

		bf_ctrl->svd_mode = par0 ? BIT(SVD_MODE_CHANNEL_INV) : 0;
		bf_ctrl->svd_mode |= par1 ? BIT(SVD_MODE_TWO_STREAM) : 0;
		bf_ctrl->svd_mode |= par2 ? BIT(SVD_MODE_PER_ANT_SCALE) : 0;
		bf_ctrl->svd_mode |= par3 ? BIT(SVD_MODE_STREAM_MIXING) : 0;
		bf_ctrl->svd_mode |= par4 ? BIT(SVD_MODE_BYPASS) : 0;
		printk("Beamforming svd mode set to 0x%x\n", bf_ctrl->svd_mode);
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return(0);
	}
	printk("Beamforming svd mode not set\n");
	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
	return (-1);
}

int qdrv_txbf_init(struct qdrv_wlan *qw)
{
	struct txbf_state *txbf_state;
	struct int_handler dsp_intr_handler;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "-->Enter\n");

	if((txbf_state = (struct txbf_state *)
		kmalloc(sizeof(struct txbf_state), GFP_KERNEL)) == NULL)
	{
		DBGPRINTF_E("Unable to allocate memory for TXBF state\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");
		return(-ENOMEM);
	}

	/* Clean the state */
	memset(txbf_state, 0, sizeof(struct txbf_state));

	txbf_state->st_mat_calc_chan_inv = 1;
	txbf_state->st_mat_calc_two_streams = 1;
	txbf_state->st_mat_apply_per_ant_scaling = 1;
	txbf_state->st_mat_apply_stream_mixing = 1;
	txbf_state->st_mat_reg_scale_fac = 10;

	tasklet_init(&txbf_state->txbf_dsp_mbox_task, qdrv_txbf_mbox_tasklet, (unsigned long)qw);

	/*
	 * Register the interrupt handler to be called when DSP pushes
	 * completion message into DSP-to-LHOST mbox
	 */
	dsp_intr_handler.handler = qdrv_txbf_mbox_interrupt;
	dsp_intr_handler.arg1 = NULL;
	dsp_intr_handler.arg2 = qw;
	if (qdrv_mac_set_host_dsp_handler(qw->mac, QTN_TXBF_DSP_TO_HOST_MBOX_INT,
			&dsp_intr_handler) != 0) {
		/* Handle error case */
		DBGPRINTF_E("Set handler error\n");
		DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

		kfree(txbf_state);

		return(-ENODEV);
	}

	/* Enable the mbx interrupts */
	qtn_txbf_lhost_irq_enable(qw->mac);

	/* We need a back pointer */
	txbf_state->owner = (void *)qw;

	/* Attach the state to the wlan once we are done with everything */
	qw->txbf_state = (void *)txbf_state;

	DBGPRINTF(DBG_LL_ALL, QDRV_LF_TRACE, "<--Exit\n");

	return(0);
}

int qdrv_txbf_exit(struct qdrv_wlan *qw)
{
	struct txbf_state *txbf_state = (struct txbf_state *) qw->txbf_state;

	/* Disable the mbox interrupts */
	qtn_txbf_lhost_irq_disable(qw->mac);

	if (txbf_state)
		tasklet_kill(&txbf_state->txbf_dsp_mbox_task);

	/* Free the memory for maintaining state */
	kfree(txbf_state);

	qw->txbf_state = NULL;

	return(0);
}

/* send the MU qmat install/delete event to Muc */
void qdrv_txbf_mu_grp_qmat_update(struct ieee80211_node *ni, uint8_t grp_id,
						int delete, int feedback)
{
	struct ieee80211com *ic = ni->ni_ic;

	if (!delete) {
		ic->ic_setparam(ni, IEEE80211_PARAM_INST_MU_GRP_QMAT, grp_id, NULL, 0);
	} else {
		ic->ic_setparam(ni, IEEE80211_PARAM_DELE_MU_GRP_QMAT, grp_id,
			(unsigned char *)&feedback, sizeof(feedback));
	}
}

