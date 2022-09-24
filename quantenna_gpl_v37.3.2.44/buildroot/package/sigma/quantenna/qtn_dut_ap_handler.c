/****************************************************************************
*
* Copyright (c) 2015  Quantenna Communications, Inc.
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
* SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
* RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
* NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
* USE OR PERFORMANCE OF THIS SOFTWARE.
*
*****************************************************************************/

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "common/qsigma_common.h"
#include "common/qsigma_log.h"
#include "common/qsigma_tags.h"
#include "common/qtn_cmd_parser.h"
#include "common/qtn_dut_common.h"
#include "wfa_types.h"
#include "wfa_tlv.h"

#include "drivers/qdrv/qdrv_bld.h"
#include "qtn/qcsapi.h"

#include <linux/wireless.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <sys/ioctl.h>

#include "qtn_dut_ap_handler.h"

#define N_ARRAY(arr)			(sizeof(arr)/sizeof(arr[0]))
#define IEEE80211_TXOP_TO_US(_txop)	(uint32_t)(_txop) << 5

static int set_keymgnt(const char *if_name, const char *keymgnt)
{
	int result;
	int i;
	static const struct {
		const char *keymgnt;
		const char *beacon;
		const char *auth;
		const char *enc;
	} keymgnt_map[] = {
		{
		.keymgnt = "NONE",.beacon = "Basic",.auth = "PSKAuthentication",.enc =
				"AESEncryption"}, {
		.keymgnt = "WPA-PSK-disabled",.beacon = "WPA",.auth =
				"PSKAuthentication",.enc = "TKIPEncryption"}, {
		.keymgnt = "WPA2-PSK",.beacon = "11i",.auth = "PSKAuthentication",.enc =
				"AESEncryption"}, {
		.keymgnt = "WPA-ENT",.beacon = "WPA",.auth = "EAPAuthentication",.enc =
				"TKIPEncryption"}, {
		.keymgnt = "WPA2-ENT",.beacon = "11i",.auth = "EAPAuthentication",.enc =
				"AESEncryption"}, {
		.keymgnt = "WPA2-PSK-Mixed",.beacon = "WPAand11i",.auth =
				"PSKAuthentication",.enc = "TKIPandAESEncryption"}, {
		.keymgnt = "WPA2-Mixed",.beacon = "WPAand11i",.auth =
				"PSKAuthentication",.enc = "TKIPandAESEncryption"}, {
		NULL}
	};

	for (i = 0; keymgnt_map[i].keymgnt != NULL; ++i) {
		if (strcasecmp(keymgnt, keymgnt_map[i].keymgnt) == 0) {
			break;
		}
	}

	if (keymgnt_map[i].keymgnt == NULL) {
		return -EINVAL;
	}

	if ((result = qcsapi_wifi_set_beacon_type(if_name, keymgnt_map[i].beacon)) < 0) {
		qtn_error("can't set beacon_type to %s, error %d", keymgnt_map[i].beacon, result);
		return result;
	}

	if ((result = qcsapi_wifi_set_WPA_authentication_mode(if_name, keymgnt_map[i].auth)) < 0) {
		qtn_error("can't set authentication to %s, error %d", keymgnt_map[i].auth, result);
		return result;
	}

	if ((result = qcsapi_wifi_set_WPA_encryption_modes(if_name, keymgnt_map[i].enc)) < 0) {
		qtn_error("can't set encryption to %s, error %d", keymgnt_map[i].enc, result);
	}

	return result;
}

static int set_ap_encryption(const char *if_name, const char *enc)
{
	int i;

	static const struct {
		const char *sigma_enc;
		const char *encryption;
	} map[] = {
		{
		.sigma_enc = "TKIP",.encryption = "TKIPEncryption"}, {
		.sigma_enc = "AES",.encryption = "AESEncryption"}, {
		NULL}
	};

	for (i = 0; map[i].sigma_enc != NULL; ++i) {
		if (strcasecmp(enc, map[i].sigma_enc) == 0) {
			break;
		}
	}

	if (map[i].sigma_enc == NULL) {
		return -EINVAL;
	}

	return qcsapi_wifi_set_WPA_encryption_modes(if_name, map[i].encryption);
}

static int set_channel(const char *ifname, int channel)
{
	int ret = 0;
	char region[16];
	char channel_str[16];

	if ((ret = qcsapi_wifi_get_regulatory_region(ifname, region)) < 0) {
		qtn_error("can't get regulatory region, error %d", ret);
		return ret;
	}

	snprintf(channel_str, sizeof(channel_str), "%d", channel);
	if (strcasecmp(region, "none") == 0) {
		ret = qcsapi_wifi_set_channel(ifname, channel);
		if (ret > 0) {
			ret = qcsapi_config_update_parameter(ifname, "channel", channel_str);
		} else {
			qtn_error("can't set channel to %d, error %d", channel, ret);
		}
		return ret;
	}

	ret = qcsapi_regulatory_set_regulatory_channel(ifname, channel, region, 0);
	if (ret == -qcsapi_region_database_not_found) {
		ret = qcsapi_wifi_set_regulatory_channel(ifname, channel, region, 0);
	}

	if (ret < 0) {
		qtn_error("can't set regulatory channel to %d, error %d", channel, ret);
	} else if ((ret = qcsapi_config_update_parameter(ifname, "channel", channel_str)) < 0) {
		qtn_error("can't update channel, error %d", ret);
	}

	return ret;
}

static int set_country_code(const char *ifname, const char *country_code)
{
	int ret;
	char region[16];

	if ((ret = qcsapi_wifi_get_regulatory_region(ifname, region)) < 0) {
		qtn_error("can't get regulatory region, error %d", ret);
		return ret;
	}

	if (strcasecmp(region, country_code) != 0 &&
		(ret = qcsapi_config_update_parameter(ifname, "region", country_code)) < 0) {
		qtn_error("can't update regulatory region, error %d", ret);
		return ret;
	}

	return 0;
}

void qtn_handle_ap_get_info(int len, unsigned char *params, int *out_len, unsigned char *out)
{
	struct qtn_dut_response rsp = { 0 };
	char if_name[QTN_INTERFACE_LIST_LEN];

	rsp.status = STATUS_COMPLETE;
	if (qcsapi_firmware_get_version(rsp.ap_info.firmware_version,
			sizeof(rsp.ap_info.firmware_version)) < 0) {
		snprintf(rsp.ap_info.firmware_version,
			sizeof(rsp.ap_info.firmware_version), "unknown");
	}

	int chipid;
	const char *band = "5G";
	if (local_wifi_get_rf_chipid(&chipid) < 0) {
		/* can't really get band, use default */
	} else if (chipid == CHIPID_DUAL) {
		band = "any";
	} else if (chipid == CHIPID_2_4_GHZ) {
		band = "24G";
	} else if (chipid == CHIPID_5_GHZ) {
		band = "5G";
	}

	for (unsigned int idx = 0;
		qcsapi_get_interface_by_index(idx, if_name, sizeof(if_name)) == 0; ++idx) {

		const size_t have = strlen(rsp.ap_info.interface_list);
		const size_t left = sizeof(rsp.ap_info.interface_list) - have;
		char *dest = rsp.ap_info.interface_list + have;
		/* should build string like: 'wifi0_5G wifi1_24G wifi2_any' */
		snprintf(dest, left, "%s%s_%s", idx == 0 ? "" : " ", if_name, band);
	}

	snprintf(rsp.ap_info.agent_version, sizeof(rsp.ap_info.agent_version), "1.0");

	wfaEncodeTLV(QSIGMA_AP_GET_INFO_TAG, sizeof(rsp), (BYTE *) & rsp, out);

	*out_len = WFA_TLV_HDR_LEN + sizeof(rsp);
}

void qtn_handle_ap_set_radius(int len, unsigned char *params, int *out_len, unsigned char *out)
{
	struct qtn_dut_response rsp = { 0 };
	struct qtn_ap_set_radius ap_radius;

	memcpy(&ap_radius, params, sizeof(ap_radius));

	/* interface is optional, so it can be empty */
	const char *if_name = ap_radius.if_name[0] == '\0' ?
		QCSAPI_PRIMARY_WIFI_IFNAME : ap_radius.if_name;

	qtn_log("try to set radius: ip %s, port %d, pwd %s, if %s/%s",
		ap_radius.ip, ap_radius.port, ap_radius.password, ap_radius.if_name, if_name);

	char port_str[16];
	snprintf(port_str, sizeof(port_str), "%d", ap_radius.port);

	int result = qcsapi_wifi_add_radius_auth_server_cfg(if_name, ap_radius.ip, port_str,
		ap_radius.password);
	if (result < 0) {
		qtn_error("can't set radius ip, error %d", result);
		goto exit;
	}

exit:
	rsp.status = result == 0 ? STATUS_COMPLETE : STATUS_ERROR;
	rsp.qcsapi_error = result;

	wfaEncodeTLV(QSIGMA_AP_SET_RADIUS_TAG, sizeof(rsp), (BYTE *) & rsp, out);

	*out_len = WFA_TLV_HDR_LEN + sizeof(rsp);
}

void qtn_handle_ap_set_wireless(int len, unsigned char *params, int *out_len, unsigned char *out)
{
	struct qtn_dut_response rsp = { 0 };
	struct qtn_ap_set_wireless cmd;
	int result = 0;
	const qcsapi_mimo_type mimo_type =
		strcasecmp(cmd.programm, "vht") == 0 ? qcsapi_mimo_vht : qcsapi_mimo_ht;

	memcpy(&cmd, params, sizeof(cmd));

	const char *if_name = cmd.if_name[0] == '\0' ? QCSAPI_PRIMARY_WIFI_IFNAME : cmd.if_name;

	if (cmd.programm[0] &&
		(result = qcsapi_wifi_set_vht(if_name, mimo_type == qcsapi_mimo_vht)) < 0) {
		qtn_error("can't set vht, error %d", result);
		goto exit;
	}

	if (cmd.ssid[0] && (result = qcsapi_wifi_set_SSID(if_name, cmd.ssid)) < 0) {
		qtn_error("can't set SSID %s, error %d", cmd.ssid, result);
		goto exit;
	}

	if (cmd.channels[0] > 0 && (result = set_channel(if_name, cmd.channels[0])) < 0) {
		qtn_error("can't set channel %d, error %d", cmd.channels[0], result);
		goto exit;
	}

	if (*cmd.mode[0] && (result = qcsapi_wifi_set_phy_mode(if_name, cmd.mode[0])) < 0) {
		qtn_error("can't set phy_mode to %s, error %d", cmd.mode[0], result);
		goto exit;
	}

	if (*cmd.mode[0] && strcasecmp(cmd.mode[0], "11ac") == 0) {
		// restore 80 MHz bandwidth unless it is configured explictly
		qtn_log("restore 80MHz mode since phy is 11ac");
		qcsapi_wifi_set_bw(if_name, 80);
	}

	if (cmd.country_code[0] && (result = set_country_code(if_name, cmd.country_code)) < 0) {
		qtn_error("can't set country code to %s, error %d", cmd.country_code, result);
		goto exit;
	}

	if (cmd.has_wmm && (result = qcsapi_wifi_set_option(if_name, qcsapi_wmm, cmd.wmm)) < 0) {
		qtn_error("can't set wmm to %d, error %d", cmd.wmm, result);
		goto exit;
	}

	if (cmd.has_apsd && (result = qcsapi_wifi_set_option(if_name, qcsapi_uapsd, cmd.apsd)) < 0) {
		qtn_error("can't set apsd to %d, error %d", cmd.apsd, result);
		goto exit;
	}

	if (cmd.has_rts_threshold
		&& (result = qcsapi_wifi_set_rts_threshold(if_name, cmd.rts_threshold)) < 0) {
		qtn_error("can't set rts_threshold to %d, error %d", cmd.rts_threshold, result);
		goto exit;
	}

	if (cmd.has_power_save &&
		(result =
			qcsapi_pm_set_mode(cmd.power_save ? QCSAPI_PM_MODE_AUTO :
				QCSAPI_PM_MODE_DISABLE)) < 0) {
		qtn_error("can't set pm to %d, error %d", cmd.has_power_save, result);
		goto exit;
	}

	if (cmd.has_beacon_interval &&
		(result = qcsapi_wifi_set_beacon_interval(if_name, cmd.beacon_interval)) < 0) {
		qtn_error("can't set beacon_interval to %d, error %d", cmd.beacon_interval, result);
		goto exit;
	}

	if (cmd.has_rf_enable && (result = qcsapi_wifi_rfenable(cmd.rf_enable)) < 0) {
		qtn_error("can't set rf_enable to %d, error %d", cmd.rf_enable, result);
		goto exit;
	}

	if (cmd.has_amsdu && (result = qcsapi_wifi_set_tx_amsdu(if_name, cmd.amsdu)) < 0) {
		qtn_error("can't set amsdu to %d, error %d", cmd.amsdu, result);
		goto exit;
	}

	qcsapi_mcs_rate mcs_rate;
	snprintf(mcs_rate, sizeof(mcs_rate), "MCS%d", cmd.has_mcs_rate);

	if (cmd.has_mcs_rate && (result = qcsapi_wifi_set_mcs_rate(if_name, mcs_rate)) < 0) {
		qtn_error("can't set mcs_rate to %s, error %d", mcs_rate, result);
		goto exit;
	}

	/* looks like we don't have API to setup NSS separatly for RX and TX */
	int nss_rx;
	int nss_tx;

	if (cmd.nss_rx[0] && cmd.nss_tx[0] && sscanf(cmd.nss_rx, "%d", &nss_rx) == 1 &&
		sscanf(cmd.nss_tx, "%d", &nss_tx) == 1) {
		if (nss_rx != nss_tx) {
			qtn_error("can't set different nss for rx %d and tx %d", nss_rx, nss_tx);
			result = -EINVAL;
			goto exit;
		} else if ((result = qcsapi_wifi_set_nss_cap(if_name, mimo_type, nss_rx)) < 0) {
			qtn_error("can't set nss to %d, mimo_type %d, error %d",
				nss_rx, mimo_type, result);
			goto exit;
		}
	}

	if (0 == cmd.bandwidth) {
		cmd.bandwidth = (mimo_type == qcsapi_mimo_vht) ? 80 : 40;
	}

	if (cmd.has_bandwidth && (result = qcsapi_wifi_set_bw(if_name, cmd.bandwidth)) < 0) {
		qtn_error("can't set bandwidth to %d, error %d", cmd.bandwidth, result);
		goto exit;
	}

	if (cmd.has_dtim && (result = qcsapi_wifi_set_dtim(if_name, cmd.dtim)) < 0) {
		qtn_error("can't set dtim to %d, error %d", cmd.dtim, result);
		goto exit;
	}

	if (cmd.has_short_gi
		&& (result = qcsapi_wifi_set_option(if_name, qcsapi_short_GI, cmd.short_gi)) < 0) {
		qtn_error("can't set short_gi to %d, error %d", cmd.short_gi, result);
		goto exit;
	}

	if (cmd.has_mu_beamformer
		&& (result = qcsapi_wifi_set_enable_mu(if_name, cmd.mu_beamformer)) < 0) {
		qtn_error("can't set enable_mu to %d, error %d", cmd.mu_beamformer, result);
		goto exit;
	}

	if (cmd.has_stbc_tx) {
		system("iwpriv wifi0 setparam 160 1");	// by default it's 0
		system("set_11ac_mcs 0x05");
	}

exit:
	rsp.status = result == 0 ? STATUS_COMPLETE : STATUS_ERROR;
	rsp.qcsapi_error = result;

	wfaEncodeTLV(QSIGMA_AP_SET_WIRELESS_TAG, sizeof(rsp), (BYTE *) & rsp, out);

	*out_len = WFA_TLV_HDR_LEN + sizeof(rsp);
}

void qtn_handle_ap_set_security(int len, unsigned char *params, int *out_len, unsigned char *out)
{
	struct qtn_dut_response rsp = { 0 };
	struct qtn_ap_set_security cmd;
	int result = 0;

	memcpy(&cmd, params, sizeof(cmd));

	const char *if_name = cmd.if_name[0] == '\0' ? QCSAPI_PRIMARY_WIFI_IFNAME : cmd.if_name;
	qtn_log("set security for %s", if_name);

	if ((result = set_keymgnt(if_name, cmd.keymgnt)) < 0) {
		qtn_error("can't set keymgnt to %s, error %d", cmd.keymgnt, result);
		goto exit;
	}

	if (cmd.passphrase[0] &&
		(result = qcsapi_wifi_set_key_passphrase(if_name, 0, cmd.passphrase)) < 0) {
		qtn_error("can't set passphrase to %s, error %d", cmd.passphrase, result);
		goto exit;
	}

	if (cmd.wepkey[0] && (result = qcsapi_wifi_set_WEP_key_passphrase(if_name, cmd.wepkey)) < 0) {
		qtn_error("can't set wepkey to %s, error %d", cmd.wepkey, result);
		result = -EINVAL;
		goto exit;
	}

	if (cmd.ssid[0] && (result = qcsapi_wifi_set_SSID(if_name, cmd.ssid)) < 0) {
		qtn_error("can't set ssid to %s, error %d", cmd.ssid, result);
		goto exit;
	}

	if (cmd.has_pmf && (result = qcsapi_wifi_set_pmf(if_name, cmd.pmf)) < 0) {
		qtn_error("can't set pmd to %d, error %d", cmd.pmf, result);
		goto exit;
	}

	if (cmd.encryption[0] && (result = set_ap_encryption(if_name, cmd.encryption)) < 0) {
		qtn_error("can't set encryption to %s, error %d", cmd.encryption, result);
		goto exit;
	}

exit:
	rsp.status = result == 0 ? STATUS_COMPLETE : STATUS_ERROR;
	rsp.qcsapi_error = result;

	wfaEncodeTLV(QSIGMA_AP_SET_SECURITY_TAG, sizeof(rsp), (BYTE *) & rsp, out);

	*out_len = WFA_TLV_HDR_LEN + sizeof(rsp);
}

void qtn_handle_unknown_command(int tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_dut_response rsp = { 0 };

	rsp.status = STATUS_COMPLETE;	// report as OK only for testing. need report error in future
	rsp.qcsapi_error = 0;

	wfaEncodeTLV(tag, sizeof(rsp), (BYTE *) & rsp, out);

	*out_len = WFA_TLV_HDR_LEN + sizeof(rsp);
}

void qtn_handle_ap_reset(int len, unsigned char *params, int *out_len, unsigned char *out)
{
	struct qtn_dut_response rsp = { 0 };

	rsp.status = STATUS_COMPLETE;
	rsp.qcsapi_error = 0;

	/* we need some time to send responce before actuall reboot */
	system("sync ; reboot -d 2&");

	wfaEncodeTLV(QSIGMA_AP_REBOOT_TAG, sizeof(rsp), (BYTE *) & rsp, out);

	*out_len = WFA_TLV_HDR_LEN + sizeof(rsp);
}

static int ap_reset_to_vht_default()
{
	const char *ifname = QCSAPI_PRIMARY_WIFI_IFNAME;
	int result = 0;

	if ((result = qcsapi_wifi_set_vht(ifname, 1)) < 0) {
		qtn_error("can't enable vht, error %d", result);
		return result;
	}

	if ((result = qcsapi_wifi_set_bw(ifname, 80)) < 0) {
		qtn_error("can't set 80 MHz bw, error %d", result);
		return result;
	}

	if ((result = qcsapi_wifi_set_beacon_type(ifname, "11i")) < 0) {
		qtn_error("can't set beacon_type to, error %d", result);
		return result;
	}

	if ((result = qcsapi_wifi_set_WPA_authentication_mode(ifname, "PSKAuthentication")) < 0) {
		qtn_error("can't set PSK authentication, error %d", result);
		return result;
	}

	if ((result = qcsapi_wifi_set_WPA_encryption_modes(ifname, "AESEncryption")) < 0) {
		qtn_error("can't set AES encryption, error %d", result);
		return result;
	}

	if ((result = qcsapi_wifi_set_option(ifname, qcsapi_autorate_fallback, 1)) < 0) {
		qtn_error("can't set autorate, error %d", result);
		return result;
	}

	system("iwpriv wifi0 setparam 160 0");	// by default it's 0

	for (int timeout = 120; timeout > 0; --timeout) {
		int cacstatus;
		if (qcsapi_wifi_get_cac_status(ifname, &cacstatus) < 0 || cacstatus == 0) {
			break;
		}

		sleep(1);
	}

	return result;
}

void qtn_handle_ap_reset_default(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int err_code = 0;
	char cert_prog[16];
	char dev_type[16];
	int ret;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		err_code = ret;
		goto respond;
	}

	*cert_prog = 0;
	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, cert_prog, sizeof(cert_prog)) > 0) {
		if (strcasecmp(cert_prog, "VHT") == 0) {
			ap_reset_to_vht_default();
		}
	}

	*dev_type = 0;
	qtn_get_value_text(&cmd_req, QTN_TOK_TYPE, dev_type, sizeof(dev_type));

	qtn_log("certification program=%s, type of the device=%s", cert_prog, dev_type);

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, err_code, out_len, out);
}

void qtn_handle_ap_set_11n_wireless(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_COMPLETE;
	char ifname[16];
	char val_str[128];
	int val_int;
	int ret = 0;
	int rx_ss = -1;
	int tx_ss = -1;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto exit;
	}

	*ifname = 0;
	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MODE, val_str, sizeof(val_str)) > 0 &&
		(ret = qcsapi_wifi_set_phy_mode(ifname, val_str)) < 0) {
		qtn_error("can't set mode to %s, error %d", val_str, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_WIDTH, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d", &val_int) == 1 &&
		(ret = qcsapi_wifi_set_bw(ifname, val_int)) < 0) {
		qtn_error("can't set bandwidth to %d, error %d", val_int, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_CHANNEL, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d", &val_int) == 1 &&
		(ret = qcsapi_wifi_set_channel(ifname, val_int)) < 0) {
		qtn_error("can't set channel to %d, error %d", val_int, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, val_str, sizeof(val_str)) > 0 &&
		(ret = qcsapi_wifi_set_SSID(ifname, val_str)) < 0) {
		qtn_error("can't set SSID to %s, error %d", val_str, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_BCNINT, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d", &val_int) == 1 &&
		(ret = qcsapi_wifi_set_beacon_interval(ifname, val_int)) < 0) {
		qtn_error("can't set beacon interval to %d, error %d", val_int, ret);
		goto exit;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SPATIAL_RX_STREAM, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d", &val_int) == 1) {
		rx_ss = val_int;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SPATIAL_TX_STREAM, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d", &val_int) == 1) {
		tx_ss = val_int;
	}

	if (rx_ss == -1 && tx_ss == -1) {
		/* ignore */
	} else if (tx_ss != rx_ss) {
		qtn_error("can't set different nss for rx %d and tx %d", rx_ss, tx_ss);
		ret = -EINVAL;
		goto exit;
	} else if ((ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, rx_ss)) < 0) {
		qtn_error("can't set nss to %d, error %d", rx_ss, ret);
		goto exit;
	}

exit:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

struct qtn_qos_desc {
	enum qtn_token arg_tok;
	int qos_stream_class;
	int qos_param_id;
};

static
const struct qtn_qos_desc qtn_qos_table[] = {
	{QTN_TOK_CWMIN_VO, WME_AC_VO, IEEE80211_WMMPARAMS_CWMIN},
	{QTN_TOK_CWMIN_VI, WME_AC_VI, IEEE80211_WMMPARAMS_CWMIN},
	{QTN_TOK_CWMIN_BE, WME_AC_BE, IEEE80211_WMMPARAMS_CWMIN},
	{QTN_TOK_CWMIN_BK, WME_AC_BK, IEEE80211_WMMPARAMS_CWMIN},
	{QTN_TOK_CWMAX_VO, WME_AC_VO, IEEE80211_WMMPARAMS_CWMAX},
	{QTN_TOK_CWMAX_VI, WME_AC_VI, IEEE80211_WMMPARAMS_CWMAX},
	{QTN_TOK_CWMAX_BE, WME_AC_BE, IEEE80211_WMMPARAMS_CWMAX},
	{QTN_TOK_CWMAX_BK, WME_AC_BK, IEEE80211_WMMPARAMS_CWMAX},
	{QTN_TOK_AIFS_VO, WME_AC_VO, IEEE80211_WMMPARAMS_AIFS},
	{QTN_TOK_AIFS_VI, WME_AC_VI, IEEE80211_WMMPARAMS_AIFS},
	{QTN_TOK_AIFS_BE, WME_AC_BE, IEEE80211_WMMPARAMS_AIFS},
	{QTN_TOK_AIFS_BK, WME_AC_BK, IEEE80211_WMMPARAMS_AIFS},
	{QTN_TOK_TxOP_VO, WME_AC_VO, IEEE80211_WMMPARAMS_TXOPLIMIT},
	{QTN_TOK_TxOP_VI, WME_AC_VI, IEEE80211_WMMPARAMS_TXOPLIMIT},
	{QTN_TOK_TxOP_BE, WME_AC_BE, IEEE80211_WMMPARAMS_TXOPLIMIT},
	{QTN_TOK_TxOP_BK, WME_AC_BK, IEEE80211_WMMPARAMS_TXOPLIMIT},
	{QTN_TOK_ACM_VO, WME_AC_VO, IEEE80211_WMMPARAMS_ACM},
	{QTN_TOK_ACM_VI, WME_AC_VI, IEEE80211_WMMPARAMS_ACM},
	{QTN_TOK_ACM_BE, WME_AC_BE, IEEE80211_WMMPARAMS_ACM},
	{QTN_TOK_ACM_BK, WME_AC_BK, IEEE80211_WMMPARAMS_ACM},
};

void qtn_handle_ap_set_qos(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int err_code = 0;
	char ifname_buf[16];
	const char *ifname;
	char param_buf[32];
	int param_val;
	int ret;
	int i;

	int bss = (cmd_tag == QSIGMA_AP_SET_STAQOS_TAG) ? 1 : 0;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		err_code = ret;
		goto respond;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : QCSAPI_PRIMARY_WIFI_IFNAME;

	if ((ret = qcsapi_wifi_set_option(ifname, qcsapi_wmm, 1)) < 0) {
		status = STATUS_ERROR;
		err_code = ret;
		goto respond;
	}

	for (i = 0; i < N_ARRAY(qtn_qos_table); i++) {
		const struct qtn_qos_desc *qos_desc = &qtn_qos_table[i];

		*param_buf = 0;
		ret = qtn_get_value_text(&cmd_req, qos_desc->arg_tok, param_buf, sizeof(param_buf));

		if (ret > 0) {
			/* workaround. we can't really set ACM for AP. */
			const int ap_bss_flag =
				qos_desc->qos_param_id == IEEE80211_WMMPARAMS_ACM ? 1 : bss;

			if (qos_desc->qos_param_id == IEEE80211_WMMPARAMS_ACM)
				param_val = (strncasecmp(param_buf, "on", 2) == 0) ? 1 : 0;
			else
				param_val = atoi(param_buf);

			if (qos_desc->qos_param_id == IEEE80211_WMMPARAMS_TXOPLIMIT) {
				param_val = IEEE80211_TXOP_TO_US(param_val);
			}

			ret = qcsapi_wifi_qos_set_param(ifname,
				qos_desc->qos_stream_class,
				qos_desc->qos_param_id, ap_bss_flag, param_val);

			if (ret < 0) {
				qtn_error("class %d, param_id %d, value %s, bss %d, error %d",
					qos_desc->qos_stream_class, qos_desc->qos_param_id,
					param_buf, ap_bss_flag, ret);
				status = STATUS_ERROR;
				err_code = ret;
				goto respond;
			}
		}
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, err_code, out_len, out);
}

void qtn_handle_ap_config_commit(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int err_code = 0;
	int ret;
	char ifname[16] = { 0 };

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		err_code = ret;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	for (int timeout = 120; timeout > 0; --timeout) {
		int cacstatus;
		if (qcsapi_wifi_get_cac_status(ifname, &cacstatus) < 0 || cacstatus == 0) {
			break;
		}

		sleep(1);
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, err_code, out_len, out);
}

void qtn_handle_ap_get_mac_address(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int err_code = 0;
	int ret;
	char ifname_buf[16];
	const char *ifname;
	unsigned char macaddr[IEEE80211_ADDR_LEN];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		err_code = ret;
		goto respond;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : QCSAPI_PRIMARY_WIFI_IFNAME;

	ret = qcsapi_interface_get_mac_addr(ifname, macaddr);

	if (ret < 0) {
		status = STATUS_ERROR;
		err_code = ret;
		goto respond;
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_macaddr(cmd_tag, status, err_code, macaddr, out_len, out);
}

void qtn_handle_ap_deauth_sta(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int err_code = 0;
	int ret;
	char ifname_buf[IFNAMSIZ];
	const char *ifname;
	char tmp_buf[32];
	unsigned char macaddr[IEEE80211_ADDR_LEN];
	int reason_code;
	int ioctl_sock = -1;
	struct iwreq iwr;
	struct ieee80211req_mlme mlme;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		err_code = ret;
		goto respond;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));
	ifname = (ret > 0) ? ifname_buf : QCSAPI_PRIMARY_WIFI_IFNAME;

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_STA_MAC_ADDRESS, tmp_buf, sizeof(tmp_buf));
	if (ret <= 0) {
		status = STATUS_ERROR;
		err_code = EINVAL;
		goto respond;
	}

	ret = qtn_parse_mac(tmp_buf, macaddr);
	if (ret < 0) {
		qtn_log("error: ap_deauth_sta, invalid macaddr");
		status = STATUS_ERROR;
		err_code = EINVAL;
		goto respond;
	}

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_MINORCODE, tmp_buf, sizeof(tmp_buf));
	if (ret <= 0) {
		status = STATUS_ERROR;
		err_code = EINVAL;
		goto respond;
	}

	reason_code = atoi(tmp_buf);
	if (reason_code <= 0) {
		qtn_log("error: ap_deauth_sta, invalid reason_code");
		status = STATUS_ERROR;
		err_code = EINVAL;
		goto respond;
	}

	ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (ioctl_sock < 0) {
		status = STATUS_ERROR;
		err_code = errno;
		goto respond;
	}

	/* send management frame */
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = IEEE80211_MLME_DEAUTH;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, macaddr, IEEE80211_ADDR_LEN);

	iwr.u.data.pointer = &mlme;
	iwr.u.data.length = sizeof(mlme);

	ret = ioctl(ioctl_sock, IEEE80211_IOCTL_SETMLME, &iwr);

	close(ioctl_sock);

	if (ret < 0) {
		status = STATUS_ERROR;
		err_code = EFAULT;
		goto respond;
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, err_code, out_len, out);
}

void
qtn_handle_ap_set_11d(int cmd_tag, int len, unsigned char *params, int *out_len, unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_COMPLETE;
	char val_str[128];
	int ret = 0;
	const char *if_name = QCSAPI_PRIMARY_WIFI_IFNAME;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_COUNTRY_CODE, val_str, sizeof(val_str)) > 0) {
		ret = qcsapi_regulatory_set_regulatory_region(if_name, val_str);
		if (ret == qcsapi_region_database_not_found) {
			ret = qcsapi_wifi_set_regulatory_region(if_name, val_str);
		}

		if (ret < 0) {
			qtn_error("can't set regulatory region to %s, error %d", val_str, ret);
			goto respond;
		}
	}

respond:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_ap_set_11h(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int err_code = 0;
	int ret;
	char tmp_buf[32];
	int dfs_enable;
	int dfs_chan;
	char regulatory_mode[32];
	const char *ifname;
	int chan_is_dfs;
	int cur_chan;
	int ioctl_sock = -1;
	struct iwreq iwr;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		err_code = ret;
		goto respond;
	}

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_DFS_MODE, tmp_buf, sizeof(tmp_buf));
	if (ret <= 0) {
		status = STATUS_ERROR;
		err_code = EINVAL;
		goto respond;
	}

	dfs_enable = (strncasecmp(tmp_buf, "Enable", 6) == 0) ? 1 : 0;

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_DFS_CHAN, tmp_buf, sizeof(tmp_buf));
	if (ret <= 0) {
		status = STATUS_ERROR;
		err_code = EINVAL;
		goto respond;
	}

	dfs_chan = atoi(tmp_buf);

	if (dfs_chan <= 0) {
		status = STATUS_ERROR;
		err_code = EINVAL;
		goto respond;
	}

	*regulatory_mode = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_REGULATORY_MODE,
		regulatory_mode, sizeof(regulatory_mode));

	/* TODO: default interface? maybe get interface name from previous settings,
	 *       for instance, with help of NAME parameter? */
	ifname = QCSAPI_PRIMARY_WIFI_IFNAME;

	const int enadle_802_11h = ret > 0 && strcasecmp(regulatory_mode, "11h") == 0;

	ret = qcsapi_wifi_set_option(ifname, qcsapi_802_11h, enadle_802_11h);
	if (ret < 0) {
		qtn_error("can't set qcsapi_802_11h to %d, error %d", enadle_802_11h, ret);
		status = STATUS_ERROR;
		err_code = ret;
		goto respond;
	}

	/* get current regulatory region */
	ret = qcsapi_wifi_get_regulatory_region(ifname, tmp_buf);
	if (ret < 0) {
		status = STATUS_ERROR;
		err_code = ret;
		goto respond;
	}

	if (strncasecmp(tmp_buf, "none", 4) == 0) {
		/* we cannot enable dfs for "none" region */
		if (dfs_enable) {
			status = STATUS_ERROR;
			err_code = EPERM;
			goto respond;
		} else {
			/* dfs is already disabled */
			status = STATUS_COMPLETE;
			goto respond;
		}
	}

	/* get dfs status of channel, and match the demanded */
	ret = qcsapi_wifi_is_channel_DFS(tmp_buf, dfs_chan, &chan_is_dfs);
	if (ret < 0) {
		status = STATUS_ERROR;
		err_code = ret;
		goto respond;
	}

	if (dfs_enable == chan_is_dfs) {
		/* no need to change */
		status = STATUS_COMPLETE;
		goto respond;
	}

	/* now we can only enable DFS for the channel */
	if (!dfs_enable) {
		status = STATUS_ERROR;
		err_code = EPERM;
		goto respond;
	}

	/* get current channel */
	ret = qcsapi_wifi_get_channel(ifname, (qcsapi_unsigned_int *) & cur_chan);
	if (ret < 0) {
		status = STATUS_ERROR;
		err_code = ret;
		goto respond;
	}

	/* enable DFS */
	ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (ioctl_sock < 0) {
		status = STATUS_ERROR;
		err_code = errno;
		goto respond;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	/* mark channel as DFS */
	iwr.u.data.flags = SIOCDEV_SUBIO_SET_MARK_DFS_CHAN;
	iwr.u.data.pointer = &dfs_chan;
	iwr.u.data.length = 1;

	ret = ioctl(ioctl_sock, IEEE80211_IOCTL_EXT, &iwr);

	if (ret < 0) {
		status = STATUS_ERROR;
		err_code = errno;
		goto respond;
	}

	/*
	 * TODO: apply new DFS setting
	 *
	 if (cur_chan == dfs_chan) {
	 memset(&iwr, 0, sizeof(iwr));
	 strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	 iwr.u.freq.e = 0;
	 iwr.u.freq.m = dfs_chan;
	 iwr.u.freq.flags = IW_FREQ_FIXED;

	 ret = ioctl(ioctl_sock, SIOCSIWFREQ, &iwr);

	 if (ret < 0) {
	 status = STATUS_ERROR;
	 err_code = errno;
	 goto respond;
	 }
	 }
	 */

	status = STATUS_COMPLETE;

respond:
	if (ioctl_sock != -1)
		close(ioctl_sock);

	qtn_dut_make_response_none(cmd_tag, status, err_code, out_len, out);
}

void
qtn_handle_ap_set_rfeature(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_COMPLETE;
	char val_str[128];
	int ret;
	int channel;
	int bandwidth;
	const char *if_name = QCSAPI_PRIMARY_WIFI_IFNAME;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_CHNUM_BAND, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d;%d", &channel, &bandwidth) == 2) {

		char region[16];
		qtn_log("switch to channel %d, bw %d", channel, bandwidth);

		if ((ret = qcsapi_wifi_set_bw(if_name, bandwidth)) < 0) {
			qtn_error("can't set bandwidth to %d, error %d", bandwidth, ret);
			goto respond;
		}

		if ((ret = qcsapi_wifi_get_regulatory_region(if_name, region)) < 0) {
			qtn_error("can't get regulatory region, error %d", ret);
			goto respond;
		}

		if (strcasecmp(region, "none") == 0) {
			qcsapi_wifi_set_channel(if_name, channel);
		} else {
			ret = qcsapi_regulatory_set_regulatory_channel(if_name, channel, region, 0);
			if (ret == -qcsapi_region_database_not_found) {
				ret = qcsapi_wifi_set_regulatory_channel(if_name, channel, region,
					0);
			}

			if (ret < 0) {
				qtn_error("can't set regulatory channel, error %d", ret);
			}
		}
	}

respond:
	status = ret < 0 ? STATUS_ERROR : STATUS_COMPLETE;
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_ca_version(int tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_dut_response rsp = { 0 };

	snprintf(rsp.ca_version.version, sizeof(rsp.ca_version.version), "%s", QDRV_BLD_NAME);

	rsp.status = STATUS_COMPLETE;
	rsp.qcsapi_error = 0;

	wfaEncodeTLV(tag, sizeof(rsp), (BYTE *) & rsp, out);

	*out_len = WFA_TLV_HDR_LEN + sizeof(rsp);
}
