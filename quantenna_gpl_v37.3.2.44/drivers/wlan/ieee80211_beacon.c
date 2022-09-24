/*-
 * Copyright (c) 2001 Atsushi Onoe
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
 * $Id: ieee80211_beacon.c 2029 2007-01-30 04:01:29Z proski $
 */
#ifndef EXPORT_SYMTAB
#define	EXPORT_SYMTAB
#endif

/*
 * IEEE 802.11 beacon handling routines
 */
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>

#include "net80211/if_media.h"
#include "net80211/ieee80211_var.h"

/*
 * Add the Epigram IE to a frame
 */
static const u_int8_t ieee80211_epigram[] = {0x00, 0x90, 0x4c, 0x03, 0x00, 0x01};
static u_int8_t *
ieee80211_add_epigram_ie(uint8_t *frm)
{
	*frm++ = IEEE80211_ELEMID_VENDOR;
	*frm++ = sizeof(ieee80211_epigram);
	memcpy(frm, ieee80211_epigram, sizeof(ieee80211_epigram));
	frm += sizeof(ieee80211_epigram);
	return frm;
}

static u_int8_t *
ieee80211_beacon_init(struct ieee80211_node *ni, struct ieee80211_beacon_offsets *bo,
	u_int8_t *frm)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = ni->ni_ic;
	u_int16_t capinfo;
	u_int8_t add_erp = 1;
	int16_t htinfo_channel_width = 0;
	int16_t htinfo_2nd_channel_offset = 0;
	struct ieee80211_rateset *rs = &ic->ic_sup_rates[ic->ic_curmode];
	int ap_pure_tkip = 0;

	KASSERT(ic->ic_bsschan != IEEE80211_CHAN_ANYC, ("no bss chan"));

	if (vap->iv_bss)
	      ap_pure_tkip = (vap->iv_bss->ni_rsn.rsn_ucastcipherset == IEEE80211_C_TKIP);

	/* Which mode AP is operating in? 20 MHz or 20/40 Mhz. Needs to know to put correct channel no in beacon */
	if((ic->ic_htcap.cap & IEEE80211_HTCAP_C_CHWIDTH40) &&
			(ic->ic_bsschan->ic_flags & (IEEE80211_CHAN_HT40U | IEEE80211_CHAN_HT40D))){
		htinfo_2nd_channel_offset =
			(ic->ic_bsschan->ic_flags & IEEE80211_CHAN_HT40U)?1:3;
		htinfo_channel_width = 1;
	}

	/* XXX timestamp is set by hardware/driver */
	memset(frm, 0, 8);
	frm += 8;

	/* beacon interval */
	*(__le16 *)frm = htole16(ni->ni_intval);
	frm += 2;

	/* capability information */
	if (vap->iv_opmode == IEEE80211_M_IBSS)
		capinfo = IEEE80211_CAPINFO_IBSS;
	else
		capinfo = IEEE80211_CAPINFO_ESS;
	if (vap->iv_flags & IEEE80211_F_PRIVACY)
		capinfo |= IEEE80211_CAPINFO_PRIVACY;
	if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
	    IEEE80211_IS_CHAN_2GHZ(ic->ic_bsschan))
		capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
	if (ic->ic_flags & IEEE80211_F_SHSLOT)
		capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
	if (ic->ic_flags & IEEE80211_F_DOTH)
		capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;
	bo->bo_caps = (__le16 *)frm;
	*(__le16 *)frm = htole16(capinfo);
	frm += 2;

	/* ssid */
	*frm++ = IEEE80211_ELEMID_SSID;
	if ((vap->iv_flags & IEEE80211_F_HIDESSID) == 0) {
		*frm++ = ni->ni_esslen;
		memcpy(frm, ni->ni_essid, ni->ni_esslen);
		frm += ni->ni_esslen;
	} else
		*frm++ = 0;

	/* supported rates */
	frm = ieee80211_add_rates(frm, rs);


	/* XXX: better way to check this? */
	/* XXX: how about DS ? */
	if (!IEEE80211_IS_CHAN_FHSS(ic->ic_bsschan)) {
		*frm++ = IEEE80211_ELEMID_DSPARMS;
		*frm++ = 1;
		*frm++ = ieee80211_chan2ieee(ic, ic->ic_bsschan); 
	}
	bo->bo_tim = frm;

	/* IBSS/TIM */
	if (vap->iv_opmode == IEEE80211_M_IBSS) {
		*frm++ = IEEE80211_ELEMID_IBSSPARMS;
		*frm++ = 2;
		*frm++ = 0; *frm++ = 0;		/* TODO: ATIM window */
		bo->bo_tim_len = 0;
	} else {
		struct ieee80211_tim_ie *tie = (struct ieee80211_tim_ie *) frm;

		tie->tim_ie = IEEE80211_ELEMID_TIM;
		tie->tim_len = sizeof(*tie) - sizeof(tie->tim_len) - sizeof(tie->tim_ie);	/* length */
		tie->tim_count = 0;	/* DTIM count */
		tie->tim_period = vap->iv_dtim_period;	/* DTIM period */
		tie->tim_bitctl = 0;	/* bitmap control */
		memset(&tie->tim_bitmap[0], 0, sizeof(tie->tim_bitmap)); /* Partial virtual bitmap */
		frm += sizeof(struct ieee80211_tim_ie);
		bo->bo_tim_len = sizeof(tie->tim_bitmap);
	}
	bo->bo_tim_trailer = frm;

	/*
	 * Tight coupling between Country IE and Power Constraint IE
	 * Both using IEEE80211_FEXT_COUNTRYIE to optional enable them.
	 */
	/* country */
	if ((ic->ic_flags_ext & IEEE80211_FEXT_COUNTRYIE)
			|| ((ic->ic_flags & IEEE80211_F_DOTH) && (ic->ic_flags_ext & IEEE80211_FEXT_TPC))) {
		frm = ieee80211_add_country(frm, ic);
	}

	/* BSS load element */
	bo->bo_bss_load = NULL;
	if (vap->interworking) {
		bo->bo_bss_load = frm;
		frm = ieee80211_add_bss_load(frm, vap);
	}

	/* Power constraint */
	if (((ic->ic_flags & IEEE80211_F_DOTH) && (ic->ic_flags_ext & IEEE80211_FEXT_COUNTRYIE))
			|| ((ic->ic_flags & IEEE80211_F_DOTH) && (ic->ic_flags_ext & IEEE80211_FEXT_TPC))) {
		*frm++ = IEEE80211_ELEMID_PWRCNSTR;
		*frm++ = 1;
		*frm++ = IEEE80211_PWRCONSTRAINT_VAL(ic);
	}

	/* Transmit power envelope */
	if (IS_IEEE80211_VHT_ENABLED(ic) && (ic->ic_flags & IEEE80211_F_DOTH) &&
	    !(ic->ic_flags_ext & IEEE80211_FEXT_TPC)) {
		frm = ieee80211_add_vhttxpwr_envelope(frm, ic);
	}

	/*TPC Report*/
	if ((ic->ic_flags & IEEE80211_F_DOTH) && (ic->ic_flags_ext & IEEE80211_FEXT_TPC)) {
		bo->bo_tpc_rep = frm;
		*frm++ = IEEE80211_ELEMID_TPCREP;
		*frm++ = 2;
		*frm++ = 0;	/* tx power would be updated in macfw */
		*frm++ = 0;	/* link margin is always 0 in beacon*/
	}

	bo->bo_chanswitch = frm;
	if (IEEE80211_IS_CHAN_ANYG(ic->ic_bsschan) ||
		(IEEE80211_IS_CHAN_11N(ic->ic_bsschan))) {
		bo->bo_erp = frm;
		if (ic->ic_curmode == IEEE80211_MODE_11A ||
			ic->ic_curmode == IEEE80211_MODE_11B) {
			add_erp = 0;
		}
		if (add_erp) {
			frm = ieee80211_add_erp(frm, ic);
		}
	}

	bo->bo_htinfo = frm;
	if (IEEE80211_IS_CHAN_ANYN(ic->ic_bsschan) &&
		(ic->ic_curmode >= IEEE80211_MODE_11NA) && !ap_pure_tkip) {
		frm = ieee80211_add_htcap(ni, frm, &ic->ic_htcap, IEEE80211_FC0_SUBTYPE_BEACON);
		bo->bo_htinfo = frm;
		ic->ic_htinfo.ctrlchannel = ieee80211_chan2ieee(ic, ic->ic_bsschan);
		ic->ic_htinfo.byte1 = (htinfo_channel_width ?
					(ic->ic_htinfo.byte1 | IEEE80211_HTINFO_B1_REC_TXCHWIDTH_40) :
					(ic->ic_htinfo.byte1 & ~IEEE80211_HTINFO_B1_REC_TXCHWIDTH_40));
		ic->ic_htinfo.choffset = htinfo_2nd_channel_offset;
		frm = ieee80211_add_htinfo(ni, frm, &ic->ic_htinfo);
	}

	/* Ext. Supp. Rates */
	frm = ieee80211_add_xrates(frm, rs);

	/* WME */
	bo->bo_wme = frm;
	if (vap->iv_flags & IEEE80211_F_WME) {
		struct ieee80211_wme_state *wme = ieee80211_vap_get_wmestate(vap);
		frm = ieee80211_add_wme_param(frm, wme, IEEE80211_VAP_UAPSD_ENABLED(vap), 0);
	}
	vap->iv_flags &= ~IEEE80211_F_WMEUPDATE;

	/* WPA 1+2 */
	if (vap->iv_flags & IEEE80211_F_WPA)
		frm = ieee80211_add_wpa(frm, vap);

	/* Can have VHT mode with 40MHz bandwidth */
	if (IS_IEEE80211_VHT_ENABLED(ic) && !ap_pure_tkip) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG,
				"%s: VHT is Enabled in network\n", __func__);
		/* VHT capability */
		frm = ieee80211_add_vhtcap(ni, frm, &ic->ic_vhtcap, IEEE80211_FC0_SUBTYPE_BEACON);

		/* VHT Operation element */
		if ((IEEE80211_IS_VHT_40(ic)) || (IEEE80211_IS_VHT_20(ic))) {
			ic->ic_vhtop.chanwidth = IEEE80211_VHTOP_CHAN_WIDTH_20_40MHZ;
		} else if (IEEE80211_IS_VHT_80(ic)) {
			ic->ic_vhtop.chanwidth = IEEE80211_VHTOP_CHAN_WIDTH_80MHZ;
			ic->ic_vhtop.centerfreq0 = ic->ic_bsschan->ic_center_f_80MHz;
		} else {
			ic->ic_vhtop.chanwidth = IEEE80211_VHTOP_CHAN_WIDTH_160MHZ;
			ic->ic_vhtop.centerfreq0 = ic->ic_bsschan->ic_center_f_160MHz;
		}
		frm = ieee80211_add_vhtop(ni, frm, &ic->ic_vhtop);
	} else {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_DEBUG,
				"%s: VHT is disabled in network\n", __func__);
	}

	/* athAdvCaps */
	bo->bo_ath_caps = frm;
	if (vap->iv_bss && vap->iv_bss->ni_ath_flags)
		frm = ieee80211_add_athAdvCap(frm, vap->iv_bss->ni_ath_flags,
			vap->iv_bss->ni_ath_defkeyindex);

	frm = ieee80211_add_qtn_ie(frm, ic,
			(vap->iv_flags_ext & IEEE80211_FEXT_WDS ? IEEE80211_QTN_BRIDGEMODE : 0),
			(vap->iv_flags_ext & IEEE80211_FEXT_WDS ?
				(IEEE80211_QTN_BRIDGEMODE | IEEE80211_QTN_LNCB) : 0),
			0, 0, 0);
	/* Extender IE */
	if (!IEEE80211_COM_WDS_IS_NONE(ic) && (vap == TAILQ_FIRST(&ic->ic_vaps))) {
		frm = ieee80211_add_qtn_extender_role_ie(frm, ic->ic_extender_role);
		frm = ieee80211_add_qtn_extender_bssid_ie(vap, frm);
	}

#ifdef CONFIG_QVSP
	/* QTN WME IE */
	if (ic->ic_wme.wme_throt_add_qwme_ie
			&& (vap->iv_flags & IEEE80211_F_WME)) {
		frm = ieee80211_add_qtn_wme_param(vap, frm);
	}
#endif

	/* Add epigram IE to address interop issue with Gen 1 (other vendor) STB */
	if (ic->ic_vendor_fix & VENDOR_FIX_BRCM_DHCP) {
		frm = ieee80211_add_epigram_ie(frm);
	}

	/* XR */
	bo->bo_xr = frm;

	bo->bo_cca = frm; /* CCA info */
	bo->bo_appie_buf = frm;
	bo->bo_appie_buf_len = 0;

	bo->bo_tim_trailerlen = frm - bo->bo_tim_trailer;
	bo->bo_chanswitch_trailerlen = frm - bo->bo_chanswitch;

	return frm;
}

/*
 * Allocate a beacon frame and fillin the appropriate bits.
 */
struct sk_buff *
ieee80211_beacon_alloc(struct ieee80211_node *ni,
	struct ieee80211_beacon_offsets *bo)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = ni->ni_ic;
	struct ieee80211_frame *wh;
	struct sk_buff *skb;
	int pktlen;
	u_int8_t *frm;
	struct ieee80211_rateset *rs;

	/*
	 * beacon frame format
	 *	[8] time stamp
	 *	[2] beacon interval
	 *	[2] capability information
	 *	[tlv] ssid
	 *	[tlv] supported rates
	 *	[7] FH/DS parameter set
	 *	[tlv] IBSS/TIM parameter set
	 *	[tlv] country code 
	 *	[3] power constraint
	 *	[5] channel switch announcement
	 *	[4] TPC Report
	 *	[3] extended rate phy (ERP)
	 *	[tlv] extended supported rates
	 *	[tlv] WME parameters
	 *	[tlv] WPA/RSN parameters
	 *	[tlv] HT Capabilities
	 *	[tlv] HT Information
	 *	[tlv] Atheros Advanced Capabilities
	 *	[tlv] AtherosXR parameters
	 *	[tlv] Quantenna flags
	 *	[tlv] epigram
	 * NB: we allocate the max space required for the TIM bitmap.
	 */
	rs = &ni->ni_rates;
	pktlen = 8					/* time stamp */
		 + sizeof(u_int16_t)			/* beacon interval */
		 + sizeof(u_int16_t)			/* capability information */
		 + 2 + ni->ni_esslen			/* ssid */
		 + 2 + IEEE80211_RATE_SIZE		/* supported rates */
		 + 7					/* FH/DS parameters max(7,3) */
		 + 2 + 4 + vap->iv_tim_len		/* IBSS/TIM parameter set*/
		 + ic->ic_country_ie.country_len + 2	/* country code */
		 + ((vap->interworking) ? 7 : 0)	/* BSS load */
		 + 3					/* power constraint */
		 + 4					/* tpc report */
		 + 5					/* channel switch announcement */
		 + 3					/* ERP */
		 + 2 + (IEEE80211_RATE_MAXSIZE - IEEE80211_RATE_SIZE) /* Ext. Supp. Rates */
		 + sizeof(struct ieee80211_wme_param)
		 + (vap->iv_caps & IEEE80211_C_WPA ?	/* WPA 1+2 */
			2 * sizeof(struct ieee80211_ie_wpa) : 0)
		 + sizeof(struct ieee80211_ie_athAdvCap)
		 +	((ic->ic_curmode >= IEEE80211_MODE_11NA) ?
				 (sizeof(struct ieee80211_ie_htcap) +
					 sizeof(struct ieee80211_ie_htinfo)):0)
		 + sizeof(struct ieee80211_ie_qtn)
#ifdef CONFIG_QVSP
		 + ((ic->ic_wme.wme_throt_add_qwme_ie && (vap->iv_flags & IEEE80211_F_WME)) ?
				 sizeof(struct ieee80211_ie_qtn_wme) : 0)
#endif
		 + ((ic->ic_vendor_fix & VENDOR_FIX_BRCM_DHCP) ? (2 + sizeof(ieee80211_epigram)) : 0)
#if defined(CONFIG_QTN_80211K_SUPPORT)
		 + (ic->ic_flags & IEEE80211_F_CCA ? sizeof(struct ieee80211_ie_measreq) + sizeof(struct ieee80211_ie_measure_comm) : 0)
#else
		 + (ic->ic_flags & IEEE80211_F_CCA ? sizeof(struct ieee80211_ie_measreq) : 0)
#endif
		 + ((IS_IEEE80211_VHT_ENABLED(ic)) ? (sizeof(struct ieee80211_ie_vhtcap) +
					sizeof(struct ieee80211_ie_vhtop) +
					sizeof(struct ieee80211_ie_chsw_wrapper) +
					sizeof(struct ieee80211_ie_wbchansw) +
					sizeof(struct ieee80211_ie_vtxpwren)): 0)
		 + (ic->ic_extender_role ? (sizeof(struct ieee80211_qtn_ext_role) + sizeof(struct ieee80211_qtn_ext_bssid))  : 0)
		;

	skb = ieee80211_getmgtframe(&frm, pktlen);
	if (skb == NULL) {
		IEEE80211_NOTE(vap, IEEE80211_MSG_ANY, ni,
			"%s: cannot get buf; size %u", __func__, pktlen);
		vap->iv_stats.is_tx_nobuf++;
		return NULL;
	}

	frm = ieee80211_beacon_init(ni, bo, frm);

	skb_trim(skb, frm - skb->data);

	wh = (struct ieee80211_frame *)
		skb_push(skb, sizeof(struct ieee80211_frame));
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
		IEEE80211_FC0_SUBTYPE_BEACON;
	wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	wh->i_dur[0] = 0;
	wh->i_dur[1] = 0;
	IEEE80211_ADDR_COPY(wh->i_addr1, vap->iv_dev->broadcast);
	IEEE80211_ADDR_COPY(wh->i_addr2, vap->iv_myaddr);
	IEEE80211_ADDR_COPY(wh->i_addr3, ni->ni_bssid);
	*(u_int16_t *)wh->i_seq = 0;

	return skb;
}
EXPORT_SYMBOL(ieee80211_beacon_alloc);

u_int32_t
get_chansw_ie_len(struct ieee80211com *ic)
{
	u_int32_t length = IEEE80211_CHANSWITCHANN_BYTES;

	if (IS_IEEE80211_VHT_ENABLED(ic)) {
		length += sizeof(struct ieee80211_ie_chsw_wrapper);
		if (ieee80211_get_bw(ic) > BW_HT20) {
			length += sizeof(struct ieee80211_ie_wbchansw);
		}
		if ((ic->ic_flags & IEEE80211_F_DOTH) &&
		    (ic->ic_flags_ext & IEEE80211_FEXT_TPC)) {
			length += sizeof(struct ieee80211_ie_vtxpwren);
		}
	}
	return length;
}

__inline__
uint8_t ieee80211_wband_chanswitch_ie_len(uint32_t bw)
{
	return ((bw >= BW_HT80) ? IEEE80211_WBAND_CHANSWITCH_IE_LEN : 0);
}

__inline__
uint8_t ieee80211_sec_chan_off_ie_len(void)
{
	return IEEE80211_SEC_CHAN_OFF_IE_LEN;
}

/*
 * Update the dynamic parts of a beacon frame based on the current state.
 */
int
ieee80211_beacon_update(struct ieee80211_node *ni,
	struct ieee80211_beacon_offsets *bo, struct sk_buff *skb, int mcast)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = ni->ni_ic;
	uint32_t bw = ieee80211_get_bw(ic);
	uint8_t wband_chanswitch_ie_len = ieee80211_wband_chanswitch_ie_len(bw);
	int len_changed = 0;
	u_int16_t capinfo;

	IEEE80211_LOCK(ic);

	if ((ic->ic_flags & IEEE80211_F_DOTH) &&
	    (vap->iv_flags & IEEE80211_F_CHANSWITCH) &&
	    (vap->iv_chanchange_count == ic->ic_chanchange_tbtt)) {
		u_int8_t *frm;
		struct ieee80211_channel *c;

		vap->iv_chanchange_count = 0;

		IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
			"%s: reinit beacon\n", __func__);

		/* 
		 * NB: ic_bsschan is in the DSPARMS beacon IE, so must set this
		 *     prior to the beacon re-init, below.
		 */
		c = ieee80211_doth_findchan(vap, ic->ic_chanchange_chan);
		if (c == NULL) {
			IEEE80211_DPRINTF(vap, IEEE80211_MSG_DOTH,
				"%s: find channel failure\n", __func__);
			IEEE80211_UNLOCK(ic);
			return 0;
		}
		ic->ic_bsschan = c;

		skb_pull(skb, sizeof(struct ieee80211_frame));
		skb_trim(skb, 0);
		frm = skb->data;
		skb_put(skb, ieee80211_beacon_init(ni, bo, frm) - frm); 
		skb_push(skb, sizeof(struct ieee80211_frame));

		vap->iv_flags &= ~IEEE80211_F_CHANSWITCH;
		ic->ic_flags &= ~IEEE80211_F_CHANSWITCH;

		len_changed = 1;
	}

	/* XXX faster to recalculate entirely or just changes? */
	if (vap->iv_opmode == IEEE80211_M_IBSS)
		capinfo = IEEE80211_CAPINFO_IBSS;
	else
		capinfo = IEEE80211_CAPINFO_ESS;
	if (vap->iv_flags & IEEE80211_F_PRIVACY)
		capinfo |= IEEE80211_CAPINFO_PRIVACY;
	if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
	    IEEE80211_IS_CHAN_2GHZ(ic->ic_bsschan))
		capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
	if (ic->ic_flags & IEEE80211_F_SHSLOT)
		capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
	if (ic->ic_flags & IEEE80211_F_DOTH)
		capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;

	*bo->bo_caps = htole16(capinfo);

	if (vap->iv_flags & IEEE80211_F_WME) {
		struct ieee80211_wme_state *wme = ieee80211_vap_get_wmestate(vap);

		/*
		 * Check for aggressive mode change.  When there is
		 * significant high priority traffic in the BSS
		 * throttle back BE traffic by using conservative
		 * parameters.  Otherwise BE uses aggressive params
		 * to optimize performance of legacy/non-QoS traffic.
		 */
		if (wme->wme_flags & WME_F_AGGRMODE) {
			if (wme->wme_hipri_traffic >
			    wme->wme_hipri_switch_thresh) {
				IEEE80211_NOTE(vap, IEEE80211_MSG_WME, ni,
					"%s: traffic %u, disable aggressive mode",
					__func__, wme->wme_hipri_traffic);
				wme->wme_flags &= ~WME_F_AGGRMODE;
				ieee80211_wme_updateparams_locked(vap);
				wme->wme_hipri_traffic =
					wme->wme_hipri_switch_hysteresis;
			} else
				wme->wme_hipri_traffic = 0;
		} else {
			if (wme->wme_hipri_traffic <=
			    wme->wme_hipri_switch_thresh) {
				IEEE80211_NOTE(vap, IEEE80211_MSG_WME, ni,
					"%s: traffic %u, enable aggressive mode",
					__func__, wme->wme_hipri_traffic);
				wme->wme_flags |= WME_F_AGGRMODE;
				ieee80211_wme_updateparams_locked(vap);
				wme->wme_hipri_traffic = 0;
			} else
				wme->wme_hipri_traffic =
					wme->wme_hipri_switch_hysteresis;
		}
		/* XXX multi-bss */
		if (vap->iv_flags & IEEE80211_F_WMEUPDATE) {
			ieee80211_add_wme_param(bo->bo_wme, wme, IEEE80211_VAP_UAPSD_ENABLED(vap), 0);
			vap->iv_flags &= ~IEEE80211_F_WMEUPDATE;
		}
	}

	if (IEEE80211_IS_CHAN_ANYN(ic->ic_bsschan) && (ic->ic_curmode >= IEEE80211_MODE_11NA)) {
		struct ieee80211_ie_htinfo *htinfo =
			(struct ieee80211_ie_htinfo *)(void *)bo->bo_htinfo;
		if (vap->iv_ht_flags & IEEE80211_HTF_HTINFOUPDATE) {
			if (vap->iv_bss->ni_rsn.rsn_ucastcipherset != IEEE80211_C_TKIP) {
				ieee80211_add_htinfo(ni, (u_int8_t *)htinfo, &ic->ic_htinfo);
				vap->iv_ht_flags &= ~IEEE80211_HTF_HTINFOUPDATE;
			}
		}
	}

	if (vap->iv_opmode == IEEE80211_M_HOSTAP) {	/* NB: no IBSS support*/
		struct ieee80211_tim_ie *tie =
			(struct ieee80211_tim_ie *) bo->bo_tim;
		/*
		 * TIM IE is programmed in QTN FW hence code to manupulate TIM is removed
		*/
		tie->tim_bitctl = 0;

		if (vap->interworking)
			ieee80211_add_bss_load(bo->bo_bss_load, vap);

		if (ic->ic_flags & IEEE80211_F_CHANSWITCH) {

			if (ic->ic_csa_count) {
				/* offset size is 802.11h csa ie + Quantenna custom cs ie */
				size_t chansw_ie_bytes = get_chansw_ie_len(ic) +
								ieee80211_sec_chan_off_ie_len() +
								wband_chanswitch_ie_len;
				u_int8_t *frm = NULL;

				/* copy out trailer to open up a slot */
				memmove(bo->bo_chanswitch + chansw_ie_bytes,
					bo->bo_chanswitch, bo->bo_chanswitch_trailerlen);

				/* add 802.11h ie in opened slot */
				frm = &(bo->bo_chanswitch[0]);
				frm = ieee80211_add_csa(frm, ic->ic_csa_mode,
					ic->ic_csa_chan->ic_ieee, ic->ic_csa_count);
				ieee80211_add_sec_chan_off(&frm, ic, ic->ic_csa_chan->ic_ieee);

				if (wband_chanswitch_ie_len) {
					frm = ieee80211_add_wband_chanswitch(frm, ic);
				}

				if (IS_IEEE80211_VHT_ENABLED(ic)) {
					frm = ieee80211_add_chansw_wrap(frm, ic);
				}

				/* update the trailer lens */
				bo->bo_chanswitch_trailerlen += chansw_ie_bytes;
				bo->bo_tim_trailerlen += chansw_ie_bytes;
				bo->bo_wme += chansw_ie_bytes;
				bo->bo_erp += chansw_ie_bytes;
				bo->bo_ath_caps += chansw_ie_bytes;
				bo->bo_xr += chansw_ie_bytes;
				bo->bo_appie_buf += chansw_ie_bytes;
				bo->bo_cca += chansw_ie_bytes;

				/* indicate new beacon length so other layers may manage memory */
				skb_put(skb, chansw_ie_bytes);
				len_changed = 1;
			}
		}

		if (ic->ic_flags & IEEE80211_F_CCA) {
#if defined(CONFIG_QTN_80211K_SUPPORT)
			size_t chan_cca_ie_bytes = sizeof(struct ieee80211_ie_measreq) + sizeof(struct ieee80211_ie_measure_comm);
			struct ieee80211_ie_measure_comm *ie_comm = (struct ieee80211_ie_measure_comm *) bo->bo_cca;
			struct ieee80211_ie_measreq *ie = (struct ieee80211_ie_measreq *) ie_comm->data;

			ie_comm->id = IEEE80211_ELEMID_MEASREQ;
			ie_comm->len = chan_cca_ie_bytes - 2;
			ie_comm->token = ic->ic_cca_token;
			ie_comm->mode = IEEE80211_CCA_REQMODE_ENABLE | IEEE80211_CCA_REQMODE_REQUEST;
			ie_comm->type = IEEE80211_CCA_MEASTYPE_CCA;
#else
			size_t chan_cca_ie_bytes = sizeof(struct ieee80211_ie_measreq);
			struct ieee80211_ie_measreq *ie = (struct ieee80211_ie_measreq *) bo->bo_cca;

			ie->id = IEEE80211_ELEMID_MEASREQ;
			ie->len = sizeof(struct ieee80211_ie_measreq) - 2;
			ie->meas_token = ic->ic_cca_token;
			ie->req_mode = IEEE80211_CCA_REQMODE_ENABLE | IEEE80211_CCA_REQMODE_REQUEST;
			ie->meas_type = IEEE80211_CCA_MEASTYPE_CCA;
#endif
			ie->chan_num = ic->ic_cca_chan;
			ie->start_tsf = htonll(ic->ic_cca_start_tsf);
			ie->duration_tu = htons(ic->ic_cca_duration_tu);

			bo->bo_xr += chan_cca_ie_bytes;/* FIXME ADM: not used should remove them.*/
			bo->bo_appie_buf += chan_cca_ie_bytes;
			bo->bo_chanswitch_trailerlen += chan_cca_ie_bytes;
			bo->bo_tim_trailerlen += chan_cca_ie_bytes;

			skb_put(skb, chan_cca_ie_bytes);
			len_changed = 1;
		}

		if (ic->ic_flags_ext & IEEE80211_FEXT_ERPUPDATE) {
			(void) ieee80211_add_erp(bo->bo_erp, ic);
			ic->ic_flags_ext &= ~IEEE80211_FEXT_ERPUPDATE;
		}
	}
	/* if it is a mode change beacon for dynamic turbo case */
	if (((ic->ic_ath_cap & IEEE80211_ATHC_BOOST) != 0) ^
	    IEEE80211_IS_CHAN_TURBO(ic->ic_curchan))
		ieee80211_add_athAdvCap(bo->bo_ath_caps, vap->iv_bss->ni_ath_flags,
			vap->iv_bss->ni_ath_defkeyindex);

	if ((vap->app_ie[IEEE80211_APPIE_FRAME_BEACON].length != 0) &&
	    (vap->app_ie[IEEE80211_APPIE_FRAME_BEACON].ie != NULL)) {
		/* adjust the buffer size if the size is changed */
		if (vap->app_ie[IEEE80211_APPIE_FRAME_BEACON].length != bo->bo_appie_buf_len) {
			int diff_len;
			diff_len = vap->app_ie[IEEE80211_APPIE_FRAME_BEACON].length - bo->bo_appie_buf_len;

			if (diff_len > 0)
				skb_put(skb, diff_len);
			else
				skb_trim(skb, skb->len + diff_len);

			bo->bo_appie_buf_len = vap->app_ie[IEEE80211_APPIE_FRAME_BEACON].length;
			/* update the trailer lens */
			bo->bo_chanswitch_trailerlen += diff_len;
			bo->bo_tim_trailerlen += diff_len;

			len_changed = 1;
		}
		memcpy(bo->bo_appie_buf,vap->app_ie[IEEE80211_APPIE_FRAME_BEACON].ie,
			vap->app_ie[IEEE80211_APPIE_FRAME_BEACON].length);

		vap->iv_flags_ext &= ~IEEE80211_FEXT_APPIE_UPDATE;
	}

	IEEE80211_UNLOCK(ic);

	return len_changed;
}
EXPORT_SYMBOL(ieee80211_beacon_update);
