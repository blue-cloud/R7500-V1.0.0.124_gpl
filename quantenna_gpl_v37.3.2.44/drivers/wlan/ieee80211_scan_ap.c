/*-
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: ieee80211_scan_ap.c 1721 2006-09-20 08:45:13Z mentor $
 */
#ifndef EXPORT_SYMTAB
#define	EXPORT_SYMTAB
#endif

/*
 * IEEE 802.11 ap scanning support.
 */
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/random.h>

#include "net80211/if_media.h"

#include "net80211/ieee80211_var.h"
#include "net80211/ieee80211_mlme_statistics.h"

static int ap_flush(struct ieee80211_scan_state *);
static void action_tasklet(IEEE80211_TQUEUE_ARG);

static int
lock_ap_list(struct ap_state *as)
{
	int bh_disabled = !in_softirq() && !irqs_disabled();

	WARN_ON_ONCE(in_irq());

	spin_lock(&as->asl_lock);
	if (bh_disabled) {
		local_bh_disable();
	}
	return bh_disabled;
}

static void
unlock_ap_list(struct ap_state *as, int bh_disabled)
{
	if (bh_disabled) {
		local_bh_enable();
	}
	spin_unlock(&as->asl_lock);
}

static void
cleanup_se(struct ap_scan_entry *se)
{
	struct ieee80211_scan_entry *ise = &se->base;
	if (ise->se_wpa_ie) {
		FREE(ise->se_wpa_ie, M_DEVBUF);
		ise->se_wpa_ie = NULL;
	}
	if (ise->se_rsn_ie) {
		FREE(ise->se_rsn_ie, M_DEVBUF);
		ise->se_rsn_ie = NULL;
	}
	if (ise->se_wme_ie) {
		FREE(ise->se_wme_ie, M_DEVBUF);
		ise->se_wme_ie = NULL;
	}
	if (ise->se_wsc_ie) {
		FREE(ise->se_wsc_ie, M_DEVBUF);
		ise->se_wsc_ie = NULL;
	}
	if (ise->se_htcap_ie) {
		FREE(ise->se_htcap_ie, M_DEVBUF);
		ise->se_htcap_ie = NULL;
	}
	if (ise->se_htinfo_ie) {
		FREE(ise->se_htinfo_ie, M_DEVBUF);
		ise->se_htinfo_ie = NULL;
	}
	if (ise->se_vhtcap_ie) {
		FREE(ise->se_vhtcap_ie, M_DEVBUF);
		ise->se_vhtcap_ie = NULL;
	}
	if (ise->se_vhtop_ie) {
		FREE(ise->se_vhtop_ie, M_DEVBUF);
		ise->se_vhtop_ie = NULL;
	}
	if (ise->se_ath_ie) {
		FREE(ise->se_ath_ie, M_DEVBUF);
		ise->se_ath_ie = NULL;
	}
	if (ise->se_ext_bssid_ie) {
		FREE(ise->se_ext_bssid_ie, M_DEVBUF);
		ise->se_ext_bssid_ie = NULL;
	}

}

static void
free_se(struct ap_scan_entry *se)
{
	cleanup_se(se);
	FREE(se, M_80211_SCAN);
}

static void
free_se_request(struct ap_scan_entry *se)
{
	if (se->se_inuse) {
		se->se_request_to_free = 1;
	} else {
		free_se(se);
	}
}

static void
free_se_process(struct ap_scan_entry *se)
{
	if (!se->se_inuse && se->se_request_to_free) {
		free_se(se);
	}
}

static void
set_se_inuse(struct ap_scan_entry *se)
{
	se->se_inuse = 1;
}

static void
reset_se_inuse(struct ap_scan_entry *se)
{
	se->se_inuse = 0;
	free_se_process(se);
}
/*
 * Attach prior to any scanning work.
 */
static int
ap_attach(struct ieee80211_scan_state *ss)
{
	struct ap_state *as;
	int i;

	_MOD_INC_USE(THIS_MODULE, return 0);

	MALLOC(as, struct ap_state *, sizeof(struct ap_state),
		M_SCANCACHE, M_NOWAIT | M_ZERO);
	if (as == NULL) {
		if (printk_ratelimit())
			printk("failed to attach before scanning\n");
		return 0;
	}
	ss->ss_priv = as;
	IEEE80211_INIT_TQUEUE(&as->as_actiontq, action_tasklet, ss);
	spin_lock_init(&as->asl_lock);
	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		TAILQ_INIT(&as->as_scan_list[i].asl_head);
	}
	return 1;
}


static int
ap_flush_asl_table(struct ieee80211_scan_state *ss)
{
	struct ap_state *as = ss->ss_priv;
	struct ap_scan_entry *se, *next;
	int i;

	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		TAILQ_FOREACH_SAFE(se, &as->as_scan_list[i].asl_head, ase_list, next) {
			TAILQ_REMOVE(&as->as_scan_list[i].asl_head, se, ase_list);
			free_se_request(se);
			if (as->as_entry_num > 0)
				as->as_entry_num--;
		}
	}
	return 0;
}

/*
 * Cleanup any private state.
 */
static int
ap_detach(struct ieee80211_scan_state *ss)
{
	struct ap_state *as = ss->ss_priv;

	if (as != NULL) {
		ap_flush_asl_table(ss);
		FREE(as, M_SCANCACHE);
	}

	_MOD_DEC_USE(THIS_MODULE);
	return 1;
}

/*
 * Flush all per-scan state.
 */
static int
ap_flush(struct ieee80211_scan_state *ss)
{
	struct ap_state *as = ss->ss_priv;
	int bh_disabled;

	bh_disabled = lock_ap_list(as);
	ap_flush_asl_table(ss);
	unlock_ap_list(as, bh_disabled);

	memset(as->as_maxrssi, 0, sizeof(as->as_maxrssi));
	memset(as->as_numpkts, 0, sizeof(as->as_numpkts));
	memset(as->as_aci,     0, sizeof(as->as_aci));
	memset(as->as_cci,     0, sizeof(as->as_aci));
	memset(as->as_numbeacons, 0, sizeof(as->as_numbeacons));
	memset(as->as_chanmetric, 0, sizeof(as->as_chanmetric));
	ss->ss_last = 0;		/* ensure no channel will be picked */
	return 0;
}

static int
find11gchannel(struct ieee80211com *ic, int i, int freq)
{
	const struct ieee80211_channel *c;
	int j;

	/*
	 * The normal ordering in the channel list is b channel
	 * immediately followed by g so optimize the search for
	 * this.  We'll still do a full search just in case.
	 */
	for (j = i+1; j < ic->ic_nchans; j++) {
		c = &ic->ic_channels[j];
		if (c->ic_freq == freq && IEEE80211_IS_CHAN_ANYG(c))
			return 1;
	}
	for (j = 0; j < i; j++) {
		c = &ic->ic_channels[j];
		if (c->ic_freq == freq && IEEE80211_IS_CHAN_ANYG(c))
			return 1;
	}
	return 0;
}

/*
 * Start an ap scan by populating the channel list.
 */
static int
ap_start(struct ieee80211_scan_state *ss, struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_channel *c;
	int i;

	ss->ss_last = 0;
	if (ic->ic_des_mode == IEEE80211_MODE_AUTO) {
		for (i = 0; i < ic->ic_nchans; i++) {
			c = &ic->ic_channels[i];
			if (c == NULL || isclr(ic->ic_chan_active, c->ic_ieee))
				continue;
			if (IEEE80211_IS_CHAN_TURBO(c)) {
				/* XR is not supported on turbo channels */
				if (vap->iv_ath_cap & IEEE80211_ATHC_XR)
					continue;
				/* dynamic channels are scanned in base mode */
				if (!IEEE80211_IS_CHAN_ST(c))
					continue;
			} else {
				/*
				 * Use any 11g channel instead of 11b one.
				 */
				if (IEEE80211_IS_CHAN_B(c) &&
				    find11gchannel(ic, i, c->ic_freq))
					continue;
			}
			if (c->ic_flags & IEEE80211_CHAN_RADAR)
				continue;
			if (ss->ss_last >= IEEE80211_SCAN_MAX)
				break;
			/* avoid DFS channels if so configured */
			if ((ss->ss_flags & IEEE80211_SCAN_NO_DFS) && (c->ic_flags & IEEE80211_CHAN_DFS))
				continue;
			ss->ss_chans[ss->ss_last++] = c;
		}
	} else {
		u_int modeflags;

		modeflags = ieee80211_get_chanflags(ic->ic_des_mode);
		if (vap->iv_ath_cap & IEEE80211_ATHC_TURBOP && modeflags != IEEE80211_CHAN_ST) {
			if (ic->ic_des_mode == IEEE80211_MODE_11G)
				modeflags = IEEE80211_CHAN_108G;
			else
				modeflags = IEEE80211_CHAN_108A;
		}
		for (i = 0; i < ic->ic_nchans; i++) {
			c = &ic->ic_channels[i];
			if (c == NULL || isclr(ic->ic_chan_active, c->ic_ieee))
				continue;
			if ((c->ic_flags & modeflags) != modeflags)
				continue;
			/* XR is not supported on turbo channels */
			if (IEEE80211_IS_CHAN_TURBO(c) && vap->iv_ath_cap & IEEE80211_ATHC_XR)
				continue;
			if (ss->ss_last >= IEEE80211_SCAN_MAX)
				break;
			/*
			 * do not select static turbo channels if the mode is not
			 * static turbo .
			 */
			if (IEEE80211_IS_CHAN_STURBO(c) && ic->ic_des_mode != IEEE80211_MODE_MAX)
				continue;
			/* No dfs interference detected channels */
			if (c->ic_flags & IEEE80211_CHAN_RADAR)
				continue;
			/* avoid DFS channels if so configured */
			if ((ss->ss_flags & IEEE80211_SCAN_NO_DFS) && (c->ic_flags & IEEE80211_CHAN_DFS))
				continue;
			ss->ss_chans[ss->ss_last++] = c;
		}
	}
	ss->ss_next = 0;
	/* XXX tunables */
	ss->ss_mindwell = msecs_to_jiffies(ic->ic_mindwell_active);
	ss->ss_maxdwell = msecs_to_jiffies(ic->ic_maxdwell_active);
	ss->ss_maxdwell_passive = msecs_to_jiffies(ic->ic_maxdwell_passive);
	ss->ss_mindwell_passive = msecs_to_jiffies(ic->ic_mindwell_passive);

#ifdef IEEE80211_DEBUG
	if (ieee80211_msg_scan(vap)) {
		printf("%s: scan set ", vap->iv_dev->name);
		ieee80211_scan_dump_channels(ss);
		printf(" dwell min %ld max %ld\n",
			ss->ss_mindwell, ss->ss_maxdwell);
	}
#endif /* IEEE80211_DEBUG */

	return 0;
}

/*
 * Restart a bg scan.
 */
static int
ap_restart(struct ieee80211_scan_state *ss, struct ieee80211vap *vap)
{
	return 0;
}

/*
 * Cancel an ongoing scan.
 */
static int
ap_cancel(struct ieee80211_scan_state *ss, struct ieee80211vap *vap)
{
	struct ap_state *as = ss->ss_priv;

	IEEE80211_CANCEL_TQUEUE(&as->as_actiontq);
	return 0;
}

static int
ap_add(struct ieee80211_scan_state *ss, const struct ieee80211_scanparams *sp,
	const struct ieee80211_frame *wh, int subtype, int rssi, int rstamp)
{
	struct ap_state *as = ss->ss_priv;
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	int chan;
	int found = 0;
	struct ap_scan_entry *se;
	struct ieee80211_scan_entry *ise;
	const u_int8_t *macaddr = wh->i_addr2;
	int bh_disabled;

#ifdef QTN_BG_SCAN
	if ((ic->ic_flags_qtn & IEEE80211_QTN_BGSCAN) && sp->chan)
		chan = sp->chan;
	else
#endif /* QTN_BG_SCAN */
	{
		chan = ieee80211_chan2ieee(ic, ic->ic_curchan);
		if (!is_channel_valid(chan)) {
			return 1;
		}
	}
	/* XXX better quantification of channel use? */
	/* XXX count bss's? */
	/* Now we Only count beacons from different bss for better quantification of channel use */

	if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
		if (rssi > as->as_maxrssi[chan])
			as->as_maxrssi[chan] = rssi;
	}

	as->as_numpkts[chan]++;

	bh_disabled = lock_ap_list(as);
	TAILQ_FOREACH(se, &as->as_scan_list[chan].asl_head, ase_list) {
		if (IEEE80211_ADDR_EQ(se->base.se_macaddr, macaddr)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		if (as->as_entry_num >= ic->ic_scan_tbl_len_max) {
			if (printk_ratelimit())
			      printk("scan found %u scan results but the list is"
					" restricted to %u entries\n", as->as_entry_num,
					ic->ic_scan_tbl_len_max);
			unlock_ap_list(as, bh_disabled);
			return 0;
		}

		MALLOC(se, struct ap_scan_entry *, sizeof(*se), M_80211_SCAN, M_NOWAIT | M_ZERO);
		if (se == NULL) {
			if (printk_ratelimit())
				printk("failed to allocate new scan entry\n");
			unlock_ap_list(as, bh_disabled);
			return 0;
		}
		as->as_entry_num++;

		IEEE80211_ADDR_COPY(se->base.se_macaddr, macaddr);
		TAILQ_INSERT_TAIL(&as->as_scan_list[chan].asl_head, se, ase_list);

		if (subtype == IEEE80211_FC0_SUBTYPE_BEACON) {
			as->as_numbeacons[chan]++;
		}
	}
	ise = &se->base;

	ieee8011_add_scan_entry(ise, sp, wh, subtype, rssi, rstamp);

	if (se->se_lastupdate == 0) {		/* first sample */
		se->se_avgrssi = RSSI_IN(rssi);
	} else {				/* avg with previous samples */
		RSSI_LPF(se->se_avgrssi, rssi);
	}
	ise->se_rssi = RSSI_GET(se->se_avgrssi);

	unlock_ap_list(as, bh_disabled);
	se->se_lastupdate = jiffies;		/* update time */
	se->se_seen = 1;
	se->se_notseen = 0;

	return 1;
}

enum chan_sel_algorithm {
	CHAN_SEL_CLEAREST = 0,		/* Select the clearest channel */
	CHAN_SEL_DFS_REENTRY = 1,	/* Select the channel based on DFS entry/re-entry requirement */
	CHAN_SEL_MAX = 2
};


typedef struct
{
	int tx_power_factor;		/*Tx power weighting factor*/
	int aci_factor;			/*ACI weighting factor*/
	int cci_factor;			/*CCI weighting factor*/
	int dfs_factor;			/*DFS weighting factor*/
	int beacon_factor;		/*Beacon number weighting factor */
} decision_metric_factor;

/*
 * Weighting factor for TX power is 2, because we have to multiply the CCI factor by 2
 * to prevent losing precision when deriving the ACI, as the ACI is 1/2 of the CCI on
 * an adjacent channel.
 */
static const decision_metric_factor g_dm_factor[CHAN_SEL_MAX] =
{
	{2, -1, -1, 0, -1},	/* CHAN_SEL_CLEAREST */
	{2, -1, -1, 8, -1}	/* CHAN_SEL_DFS_REENTRY */
};

#define QTN_CHAN_METRIC_BASE		160	/* to make sure the channel metric not to be negative */
#define QTN_METRIC_CCI_LIMIT		16
#define QTN_METRIC_BEACON_LIMIT		4
#define QTN_AS_CCA_INTF_DIVIDER		(IEEE80211_SCS_CCA_INTF_SCALE / QTN_METRIC_CCI_LIMIT)

/* Some custom knobs for out ap scan alg */
#define QTN_APSCAN_DFS_BIAS 10  /* Positive bias added for DFS channels */
#define QTN_APSCAN_METSHIFT 16  /* Precision of the metric. 16.16 format*/

#define QTN_APSCAN_TXPOWER_RANDOM_LIMIT    4

/*
 * Pick a quiet channel to use for ap operation.
 */
static struct ieee80211_channel *
ap_pick_channel(struct ieee80211com *ic, struct ieee80211_scan_state *ss, int flags)
{
	struct ap_state *as = ss->ss_priv;
	struct ieee80211_channel * newchan = NULL;
	decision_metric_factor dm_factor;
	int i, chan=0, chan2, bestchan, bestchanix;
	char rndbuf[2];
	int txpower_random;
	int cur_bw;
	int pri_inactive;

	newchan = ss->ss_chans[0];
	/* XXX select channel more intelligently, e.g. channel spread, power */
	bestchan = -1;
	bestchanix = 0;		/* NB: silence compiler */
	/*
	 * Convert CCA interference to CCI factor
	 */
	for (i = 0; i < ss->ss_last; i++) {
		chan = ieee80211_chan2ieee(ic, ss->ss_chans[i]);
		if (!is_channel_valid(chan))
			continue;

		if (as->as_cca_intf[chan] <= IEEE80211_SCS_CCA_INTF_SCALE) {
			as->as_cci[chan] = 2 * as->as_cca_intf[chan] / QTN_AS_CCA_INTF_DIVIDER;
			as->as_cci[chan] = MIN(as->as_cci[chan], QTN_METRIC_CCI_LIMIT);
		} else {
			as->as_cci[chan] = 0;
		}

		/* Reset ACI here */
		as->as_aci[chan] = 0;
	}

	/*
	 * Derive ACI (Adjacent Channel Interference) from CCI.
	 */
	for (i = 0; i < ss->ss_last; i++) {
		chan = ieee80211_chan2ieee(ic, ss->ss_chans[i]);
		if (!is_channel_valid(chan))
			continue;

		/* Adjust adjacent channel metrics to bias against close selection */
		if (i != 0) {
			chan2 = ieee80211_chan2ieee(ic, ss->ss_chans[i-1]);
			if (!is_channel_valid(chan2))
				continue;
			if (chan2 >= (chan - 4)){
				as->as_aci[chan2] += (as->as_cci[chan] >> 1);
			}
		}

		if (i != ss->ss_last - 1) {
			chan2 = ieee80211_chan2ieee(ic, ss->ss_chans[i+1]);
			if (!is_channel_valid(chan2))
				continue;
			if (chan2 <= (chan + 4)){
				as->as_aci[chan2] += (as->as_cci[chan] >> 1);
			}
		}
	}

	/* DFS entry enabled by default */
	memcpy(&dm_factor, &g_dm_factor[CHAN_SEL_DFS_REENTRY], sizeof(dm_factor));
	if (ic->ic_dm_factor.flags) {
		if (ic->ic_dm_factor.flags & DM_FLAG_TXPOWER_FACTOR_PRESENT) {
			dm_factor.tx_power_factor = ic->ic_dm_factor.txpower_factor;
		}
		if (ic->ic_dm_factor.flags & DM_FLAG_ACI_FACTOR_PRESENT) {
			dm_factor.aci_factor = ic->ic_dm_factor.aci_factor;
		}
		if (ic->ic_dm_factor.flags & DM_FLAG_CCI_FACTOR_PRESENT) {
			dm_factor.cci_factor = ic->ic_dm_factor.cci_factor;
		}
		if (ic->ic_dm_factor.flags & DM_FLAG_DFS_FACTOR_PRESENT) {
			dm_factor.dfs_factor = ic->ic_dm_factor.dfs_factor;
		}
		if (ic->ic_dm_factor.flags & DM_FLAG_BEACON_FACTOR_PRESENT) {
			dm_factor.beacon_factor = ic->ic_dm_factor.beacon_factor;
		}
	}

	/*
	 * Compute Channel Metric (Decision Metric) based on Hossein D's formula.
	 */
	for (i = 0; i < ss->ss_last; i++) {
		struct ieee80211_channel *c = ss->ss_chans[i];

		chan = ieee80211_chan2ieee(ic, ss->ss_chans[i]);
		if (!is_channel_valid(chan))
			continue;

		/* Add noise to txpower to improve random selection within channels with small txpower difference */
		get_random_bytes(rndbuf, 1);
		txpower_random = rndbuf[0] / (0xFF / (QTN_APSCAN_TXPOWER_RANDOM_LIMIT + 1));
		as->as_chanmetric[chan] = QTN_CHAN_METRIC_BASE
			+ dm_factor.tx_power_factor * (c->ic_maxpower + txpower_random)
			+ dm_factor.cci_factor * as->as_cci[chan]
			+ dm_factor.aci_factor * as->as_aci[chan]
			+ dm_factor.dfs_factor * ((c->ic_flags & IEEE80211_CHAN_DFS) ? 1 : 0)
			+ dm_factor.beacon_factor * MIN(as->as_numbeacons[chan], QTN_METRIC_BEACON_LIMIT);

		/* Add a little noise */
		get_random_bytes(rndbuf, sizeof(rndbuf));
		as->as_chanmetric[chan] <<= QTN_APSCAN_METSHIFT;
		as->as_chanmetric[chan] += (rndbuf[0] << 8) | rndbuf[1];
	}

	cur_bw = ieee80211_get_bw(ic);

	/* NB: use scan list order to preserve channel preference */
	for (i = 0; i < ss->ss_last; i++) {

		chan = ieee80211_chan2ieee(ic, ss->ss_chans[i]);
		if (!is_channel_valid(chan))
			continue;

		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
			"%s: channel %u rssi %d numbss %d numpkts %d metric %d.%d (%d)\n",
			__func__, chan, as->as_maxrssi[chan], as->as_numbeacons[chan], as->as_numpkts[chan],
			as->as_chanmetric[chan] >> QTN_APSCAN_METSHIFT,
			as->as_chanmetric[chan] & ((1<<QTN_APSCAN_METSHIFT)-1), as->as_chanmetric[chan]);

		if ((flags & IEEE80211_SCAN_NO_DFS) && (ss->ss_chans[i]->ic_flags & IEEE80211_CHAN_DFS))
			continue;

		/*
		 * If the channel is unoccupied the max rssi
		 * should be zero; just take it.  Otherwise
		 * track the channel with the lowest rssi and
		 * use that when all channels appear occupied.
		 *
		 * Check for channel interference, and if found,
		 * skip the channel.  We assume that all channels
		 * will be checked so atleast one can be found
		 * suitable and will change.  IF this changes,
		 * then we must know when we "have to" change
		 * channels for radar and move off.
		 */

		/* Check if radar detected on this channel and related secondary channel */
		if (!ic->ic_check_channel(ic, ss->ss_chans[i], 0, 0))
			continue;
		if (flags & IEEE80211_SCAN_KEEPMODE) {
			if (ic->ic_curchan != NULL) {
				if ((ss->ss_chans[i]->ic_flags & IEEE80211_CHAN_ALLTURBO) != (ic->ic_curchan->ic_flags & IEEE80211_CHAN_ALLTURBO))
					continue;
			}
		}

		if (ic->ic_rf_chipid != CHIPID_DUAL) {
			/* hzw: temporary disable these checking for RFIC5 */
			/* FIXME: Temporarily dont select any pure 20 channels */
			if (!(ss->ss_chans[i]->ic_flags & IEEE80211_CHAN_HT40)){
				continue;
			}

			if (((ss->ss_pick_flags & IEEE80211_PICK_DOMIAN_MASK) == IEEE80211_PICK_DFS) &&
			    !(ss->ss_chans[i]->ic_flags & IEEE80211_CHAN_DFS)) {
				continue;
			} else if (((ss->ss_pick_flags & IEEE80211_PICK_DOMIAN_MASK) == IEEE80211_PICK_NONDFS) &&
				   (ss->ss_chans[i]->ic_flags & IEEE80211_CHAN_DFS)) {
				continue;
			}
		}

		pri_inactive = isset(ic->ic_chan_pri_inactive, chan) ? 1 : 0;
		if (cur_bw >= BW_HT40) {
			if (((cur_bw == BW_HT40) && !(ss->ss_chans[i]->ic_flags & IEEE80211_CHAN_HT40)) ||
					((cur_bw >= BW_HT80) && !(ss->ss_chans[i]->ic_flags & IEEE80211_CHAN_VHT80))) {
				continue;
			}

			/* use the worst chanmetric as the metric of this chan set */
			chan2 = ieee80211_find_sec_chan(ss->ss_chans[i]);
			if (chan2 == 0 || as->as_chanmetric[chan] > as->as_chanmetric[chan2]) {
				continue;
			}
			if (isclr(ic->ic_chan_pri_inactive, chan2)) {
				pri_inactive = 0;
			}

			if (cur_bw >= BW_HT80) {
				chan2 = ieee80211_find_sec40u_chan(ss->ss_chans[i]);
				if (chan2 == 0 || as->as_chanmetric[chan] > as->as_chanmetric[chan2]) {
					continue;
				}
				if (isclr(ic->ic_chan_pri_inactive, chan2)) {
					pri_inactive = 0;
				}

				chan2 = ieee80211_find_sec40l_chan(ss->ss_chans[i]);
				if (chan2 == 0 || as->as_chanmetric[chan] > as->as_chanmetric[chan2]) {
					continue;
				}
				if (isclr(ic->ic_chan_pri_inactive, chan2)) {
					pri_inactive = 0;
				}
			}
		}
		if (pri_inactive) {
			/* All the sub channel can't be primary channel */
			continue;
		}

		if (ss->ss_chans[i]->ic_flags & IEEE80211_CHAN_WEATHER) {
			/*
			 * Don't pick weather channel in auto channel mode since it need
			 * too long CAC time, and it also fix the backward compatibility
			 * issue with the stations which don't support weather channels
			 */
			continue;
		}

		if (bestchan == -1 ||
		    as->as_chanmetric[chan] > as->as_chanmetric[bestchan]) {
			bestchan = chan;
			bestchanix = i;
		}
	}

	if (bestchan != -1) {
		newchan = ss->ss_chans[bestchanix];
		newchan = ieee80211_chk_update_pri_chan(ic, newchan, 1, "BSS_scan", 0);
		IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
			"%s: bestchan %d bestchan rssi %d\n",
			__func__, bestchan, bestchan != -1 ? as->as_maxrssi[bestchan] : 0);
	}

	IEEE80211_DPRINTF(ss->ss_vap, IEEE80211_MSG_SCAN,
		"%s: algorithm %s%s, pick in %s%s%s channels\n", __func__,
		((ss->ss_pick_flags & IEEE80211_PICK_ALGORITHM_MASK) == IEEE80211_PICK_REENTRY) ? "dfs_reentry" : "",
		((ss->ss_pick_flags & IEEE80211_PICK_ALGORITHM_MASK) == IEEE80211_PICK_CLEAREST) ? "clearest" : "",
		((ss->ss_pick_flags & IEEE80211_PICK_DOMIAN_MASK) == IEEE80211_PICK_DFS) ? "dfs" : "",
		((ss->ss_pick_flags & IEEE80211_PICK_DOMIAN_MASK) == IEEE80211_PICK_NONDFS) ? "non_dfs" : "",
		((ss->ss_pick_flags & IEEE80211_PICK_DOMIAN_MASK) == IEEE80211_PICK_ALL) ? "all" : "");
	ss->ss_pick_flags = IEEE80211_PICK_DEFAULT;	/* clean the flag */
	return newchan;
}

/*
 * Pick a quiet channel to use for ap operation.
 */
static int
ap_end(struct ieee80211_scan_state *ss, struct ieee80211vap *vap,
       int (*action)(struct ieee80211vap *, const struct ieee80211_scan_entry *),
       u_int32_t flags)
{
	struct ieee80211_channel * bestchan = NULL;
	struct ap_state *as = ss->ss_priv;
	struct ieee80211com *ic = vap->iv_ic;
	struct ieee80211_scan_entry se;
	int ret;

	KASSERT(vap->iv_opmode == IEEE80211_M_HOSTAP,
		("wrong opmode %u", vap->iv_opmode));

	/* scan end, no action and return */
	if (ss->ss_flags & IEEE80211_SCAN_QTN_SEARCH_MBS)
		return 1;

	/* scan end, do DFS action and return */
	if (ss->ss_flags & IEEE80211_SCAN_DFS_ACTION) {
		ic->ic_dfs_action_scan_done();
		return 1;
	}

#ifdef QTN_BG_SCAN
	if (ss->ss_flags & IEEE80211_SCAN_QTN_BGSCAN) {
		ss->ss_pick_flags = IEEE80211_PICK_DEFAULT;	/* clean the flag */
		return 1;
	}
#endif

	memset(&se, 0, sizeof(se));

	bestchan = ap_pick_channel(ic, ss, flags);
	if (bestchan == NULL) {
		printk(KERN_ERR "%s: no suitable channel! Go back!\n", vap->iv_dev->name);
		if (ic->ic_bsschan != IEEE80211_CHAN_ANYC) {
			se.se_chan = ic->ic_bsschan;
		}
		ret =  0;			/* restart scan */
	} else {
		struct ieee80211_channel *c;
		/* XXX notify all vap's? */
		/* if this is a dynamic turbo frequency , start with normal mode first */

		c = bestchan;
		if (IEEE80211_IS_CHAN_TURBO(c) && !IEEE80211_IS_CHAN_STURBO(c)) {
			if ((c = ieee80211_find_channel(ic, c->ic_freq,
				c->ic_flags & ~IEEE80211_CHAN_TURBO)) == NULL) {
				/* should never happen ?? */
				return 0;
			}
		}

		/*
		 * If bss channel is valid and if the
		 * scan is to not pick any channel then select the
		 * bss channel, otherwise choose the best channel.
		 */
		if ((ic->ic_bsschan != IEEE80211_CHAN_ANYC) &&
		    (ss->ss_flags & IEEE80211_SCAN_NOPICK)) {
			se.se_chan = ic->ic_bsschan;
		} else {
			se.se_chan = c;
		}

		ret = 1;
	}

	ic->ic_des_chan = se.se_chan;
	as->as_action = ss->ss_ops->scan_default;
	if (action)
		as->as_action = action;
	as->as_selbss = se;

	/*
	 * Must defer action to avoid possible recursive call through 80211
	 * state machine, which would result in recursive locking.
	 */
	IEEE80211_SCHEDULE_TQUEUE(&as->as_actiontq);

	return ret;
}

static void
ap_age(struct ieee80211_scan_state *ss)
{
	struct ap_state *as = ss->ss_priv;
	struct ap_scan_entry *se, *next;
	int i;
	int bh_disabled;

	bh_disabled = lock_ap_list(as);

	for (i = 0; i < IEEE80211_CHAN_MAX; i++) {
		TAILQ_FOREACH_SAFE(se, &as->as_scan_list[i].asl_head, ase_list, next) {
			if (se->se_notseen > AP_PURGE_SCANS) {
				TAILQ_REMOVE(&as->as_scan_list[i].asl_head, se, ase_list);
				free_se_request(se);
				if (as->as_entry_num > 0)
					as->as_entry_num--;
			} else {
				if (se->se_seen) {
					se->se_seen = 0;
				} else {
					se->se_notseen++;
				}
			}
		}
	}
	unlock_ap_list(as, bh_disabled);

}

static int
ap_iterate(struct ieee80211_scan_state *ss,
	ieee80211_scan_iter_func *f, void *arg)
{
	struct ap_state *as = ss->ss_priv;
	struct ieee80211vap *vap = ss->ss_vap;
	struct ieee80211com *ic = vap->iv_ic;
	struct ap_scan_entry *se;
	int chan;
	int res = 0;
	int i;
	int bh_disabled;

	bh_disabled = lock_ap_list(as);
	for (i = 0; i < ss->ss_last; i++) {
		chan = ieee80211_chan2ieee(ic, ss->ss_chans[i]);
		if (!is_channel_valid(chan))
			continue;

		TAILQ_FOREACH(se, &as->as_scan_list[chan].asl_head, ase_list) {
			set_se_inuse(se);
			res = (*f)(arg, &se->base);
			reset_se_inuse(se);
			if (res) {
				unlock_ap_list(as, bh_disabled);
				return res;
			}
		}
	}
	unlock_ap_list(as, bh_disabled);
	return res;
}

static void
ap_assoc_success(struct ieee80211_scan_state *ss,
	const u_int8_t macaddr[IEEE80211_ADDR_LEN])
{
	/* should not be called */
}

static void
ap_assoc_fail(struct ieee80211_scan_state *ss,
	const u_int8_t macaddr[IEEE80211_ADDR_LEN], int reason)
{
	/* should not be called */
}

/*
 * Default action to execute when a scan entry is found for ap
 * mode.  Return 1 on success, 0 on failure
 */
static int
ap_default_action(struct ieee80211vap *vap,
	const struct ieee80211_scan_entry *se)
{
	struct ieee80211com *ic = vap->iv_ic;

	if (ic->ic_bsschan != IEEE80211_CHAN_ANYC &&
			ic->ic_bsschan != se->se_chan &&
			vap->iv_state == IEEE80211_S_RUN) {
		ieee80211_enter_csa(ic,
				se->se_chan,
				NULL,
				IEEE80211_CSW_REASON_SCAN,
				IEEE80211_DEFAULT_CHANCHANGE_TBTT_COUNT,
				IEEE80211_CSA_MUST_STOP_TX,
				IEEE80211_CSA_F_BEACON | IEEE80211_CSA_F_ACTION);

	} else {
		ieee80211_create_bss(vap, se->se_chan);
	}

	return 1;
}

static void
action_tasklet(IEEE80211_TQUEUE_ARG data)
{
	struct ieee80211_scan_state *ss = (struct ieee80211_scan_state *)data;
	struct ap_state *as = (struct ap_state *)ss->ss_priv;
	struct ieee80211vap *vap = ss->ss_vap;

	(*ss->ss_ops->scan_default)(vap, &as->as_selbss);
}

/*
 * Module glue.
 */
MODULE_AUTHOR("Errno Consulting, Sam Leffler");
MODULE_DESCRIPTION("802.11 wireless support: default ap scanner");
#ifdef MODULE_LICENSE
MODULE_LICENSE("Dual BSD/GPL");
#endif

static const struct ieee80211_scanner ap_default = {
	.scan_name		= "default",
	.scan_attach		= ap_attach,
	.scan_detach		= ap_detach,
	.scan_start		= ap_start,
	.scan_restart		= ap_restart,
	.scan_cancel		= ap_cancel,
	.scan_end		= ap_end,
	.scan_flush		= ap_flush,
	.scan_pickchan		= ap_pick_channel,
	.scan_add		= ap_add,
	.scan_age		= ap_age,
	.scan_iterate		= ap_iterate,
	.scan_assoc_success	= ap_assoc_success,
	.scan_assoc_fail	= ap_assoc_fail,
	.scan_default		= ap_default_action,
};

static int __init
init_scanner_ap(void)
{
	mlme_stats_init();
	ieee80211_scanner_register(IEEE80211_M_HOSTAP, &ap_default);
	return 0;
}
module_init(init_scanner_ap);

static void __exit
exit_scanner_ap(void)
{
	ieee80211_scanner_unregister_all(&ap_default);
	mlme_stats_exit();
}
module_exit(exit_scanner_ap);
