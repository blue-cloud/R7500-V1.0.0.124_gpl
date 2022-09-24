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

#include "qtn_dut_sta_handler.h"
#include "common/qtn_cmd_parser.h"
#include "common/qtn_dut_common.h"

#include "common/qsigma_log.h"
#include "common/qsigma_tags.h"
#include "common/qsigma_common.h"
#include "wfa_types.h"
#include "wfa_tlv.h"
#include "wfa_tg.h"
#include "wfa_cmds.h"

#include "drivers/qdrv/qdrv_bld.h"
#include "qtn/qcsapi.h"
#include <linux/wireless.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <sys/ioctl.h>

static int set_sta_encryption(const char *ifname, const char* ssid, const char *enc)
{
	int i;

	static const struct {
		const char *sigma_enc;
		const char *encryption;
	} map[] = {
		{
		.sigma_enc = "tkip",.encryption = "TKIPEncryption"}, {
		.sigma_enc = "aes-ccmp",.encryption = "AESEncryption"}, {
		.sigma_enc = "aes-ccmp-tkip",.encryption = "TKIPandAESEncryption"}, {
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

	return qcsapi_SSID_set_encryption_modes(ifname, ssid, map[i].encryption);
}

void qnat_sta_device_list_interfaces(int tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_dut_response rsp = { 0 };

	/* can't use qcsapi_get_interface_by_index() since it works for AP only */
	snprintf(rsp.ap_info.interface_list, sizeof(rsp.ap_info.interface_list), "%s",
		QCSAPI_PRIMARY_WIFI_IFNAME);

	rsp.status = STATUS_COMPLETE;
	wfaEncodeTLV(tag, sizeof(rsp), (BYTE *) & rsp, out);

	*out_len = WFA_TLV_HDR_LEN + sizeof(rsp);
}

static int qtn_sta_reset_default_vht(const char *ifname)
{
	int res;
	int bw_cap = qcsapi_bw_80MHz;

	res = qcsapi_wifi_set_vht(ifname, 1);
	if (res < 0) {
		qtn_error("error: cannot enable vht, errcode %d", res);
		return res;
	}

	res = qcsapi_wifi_set_bw(ifname, bw_cap);
	if (res < 0) {
		qtn_error("error: cannot set bw capability %d, errcode %d", bw_cap, res);
		return res;
	}

	res = qcsapi_wifi_set_option(ifname, qcsapi_autorate_fallback, 1);
	if (res < 0) {
		qtn_error("error: cannot set autorate, errcode %d", res);
		return res;
	}

	res = qcsapi_wifi_set_option(ifname, qcsapi_stbc, 1);
	if (res < 0) {
		qtn_error("error: cannot set stbc, errcode %d", res);
		return res;
	}

	/* TODO: setup other parameters */

	return 0;
}

void qtn_handle_sta_reset_default(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	qcsapi_wifi_mode current_mode;
	char ifname[IFNAMSIZ];
	char cert_prog[16];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	if ((ret = qcsapi_wifi_get_mode(ifname, &current_mode)) < 0) {
		qtn_error("can't get mode, error %d", ret);
		status = STATUS_ERROR;
		goto respond;
	}

	if (current_mode != qcsapi_station) {
		qtn_error("mode %d is wrong, should be STA", current_mode);
		status = STATUS_ERROR;
		ret = -qcsapi_only_on_STA;
		goto respond;
	}

	/* disassociate to be sure that we start disassociated. possible error is ignored. */
	qcsapi_wifi_disassociate(ifname);

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_PROG, cert_prog, sizeof(cert_prog));

	if (ret > 0) {
		/* The values shall be: PMF, WFD, P2P or VHT */
		if (strcasecmp(cert_prog, "VHT") == 0) {
			ret = qtn_sta_reset_default_vht(ifname);
		}

		/* TODO: processing for other programs */

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_disconnect(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname[IFNAMSIZ];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	if ((ret = qcsapi_wifi_disassociate(ifname)) < 0) {
		qtn_error("can't disassociate interface %s, error %d", ifname, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_send_addba(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname[IFNAMSIZ];
	char cmd[128];
	int tid;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_TID, &tid) <= 0) {
		qtn_error("no TID in request");
		status = STATUS_INVALID;
		goto respond;
	}

	snprintf(cmd, sizeof(cmd), "iwpriv %s htba_addba %d", ifname, tid);
	ret = system(cmd);
	if (ret != 0) {
		qtn_log("can't send addba using [%s], error %d", cmd, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_preset_testparameters(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	char ifname_buf[IFNAMSIZ];
	const char *ifname;
	char val_buf[32];
	int ret;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));
	ifname = (ret > 0) ? ifname_buf : QCSAPI_PRIMARY_WIFI_IFNAME;

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_MODE, val_buf, sizeof(val_buf));
	if (ret > 0) {
		const char *phy_mode = val_buf;

		ret = qcsapi_wifi_set_phy_mode(ifname, phy_mode);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_WMM, val_buf, sizeof(val_buf));
	if (ret > 0) {
		char tmpbuf[64];
		int wmm_on = (strncasecmp(val_buf, "on", 2) == 0) ? 1 : 0;

		/* TODO: qcsapi specifies enable/disable WMM only for AP */
		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s wmm %d", ifname, wmm_on);
		system(tmpbuf);
	}

	/* TODO: RTS FRGMNT
	 *   sta_preset_testparameters,interface,rtl8192s ,supplicant,ZeroConfig,mode,11ac,RTS,500
	 *   sta_preset_testparameters,interface,eth0,supplicant,ZeroConfig,mode,11ac,FRGMNT,2346
	 */

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_get_mac_address(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname_buf[16];
	const char *ifname;
	unsigned char macaddr[IEEE80211_ADDR_LEN];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : QCSAPI_PRIMARY_WIFI_IFNAME;

	ret = qcsapi_interface_get_mac_addr(ifname, macaddr);

	if (ret < 0) {
		status = STATUS_ERROR;
		goto respond;
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_macaddr(cmd_tag, status, ret, macaddr, out_len, out);
}

void qtn_handle_sta_get_info(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname_buf[16];
	const char *ifname;
	char info_buf[128] = {0};
	int info_len = 0;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : QCSAPI_PRIMARY_WIFI_IFNAME;

	ret = snprintf(info_buf + info_len, sizeof(info_buf) - info_len,
			"vendor,%s,build_name,%s", "Quantenna", QDRV_BLD_NAME);

	if (ret < 0) {
		status = STATUS_ERROR;
		goto respond;
	}

	info_len += ret;

	/* TODO: add other information */

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_vendor_info(cmd_tag, status, ret, info_buf, out_len, out);
}

void qtn_handle_sta_set_wireless(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname_buf[16];
	const char *ifname;
	char cert_prog[8];
	int vht_prog;
	int feature_enable;
	int feature_val;
	char val_buf[32];
	int conv_err = 0;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);

	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	*ifname_buf = 0;
	ret = qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname_buf, sizeof(ifname_buf));

	ifname = (ret > 0) ? ifname_buf : QCSAPI_PRIMARY_WIFI_IFNAME;

	ret = qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, cert_prog, sizeof(cert_prog));
	if (ret <= 0) {
		/* mandatory parameter */
		status = STATUS_ERROR;
		goto respond;
	}

	vht_prog = (strcasecmp(cert_prog, "VHT") == 0) ? 1 : 0;

	/* ADDBA_REJECT, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_ADDBA_REJECT, &feature_enable, &conv_err) > 0) {
		char tmpbuf[64];
		int ba_control;

		ba_control = (feature_enable) ? 0 : 0xFFFF;

		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s ba_control %d", ifname, ba_control);
		system(tmpbuf);

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* TODO: AMPDU, (enable/disable), need additional api */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_AMPDU, &feature_enable, &conv_err) > 0) {
		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* AMSDU, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_AMSDU, &feature_enable, &conv_err) > 0) {
		ret = qcsapi_wifi_set_tx_amsdu(ifname, feature_enable);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* STBC_RX, int (0/1) */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_STBC_RX, &feature_val) > 0) {
		/* enable/disable STBC */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_stbc, feature_val);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

		if (feature_val > 0) {
			/* TODO: set number of STBC Receive Streams */
		}
	}

	/* WIDTH, int (80/40/20) */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_WIDTH, &feature_val) > 0) {
		/* channel width */
		ret = qcsapi_wifi_set_bw(ifname, (unsigned) feature_val);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* SMPS, SM Power Save Mode, NOT USED IN TESTS */

	/* TXSP_STREAM, (1SS/2SS/3SS) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_TXSP_STREAM, val_buf, sizeof(val_buf)) > 0) {
		int nss = 0;
		qcsapi_mimo_type mt = vht_prog ? qcsapi_mimo_vht : qcsapi_mimo_ht;

		ret = sscanf(val_buf, "%dSS", &nss);

		if (ret != 1) {
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		ret = qcsapi_wifi_set_nss_cap(ifname, mt, nss);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* RXSP_STREAM, (1SS/2SS/3SS) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_RXSP_STREAM, val_buf, sizeof(val_buf)) > 0) {
		int nss = 0;
		qcsapi_mimo_type mt = vht_prog ? qcsapi_mimo_vht : qcsapi_mimo_ht;

		ret = sscanf(val_buf, "%dSS", &nss);

		if (ret != 1) {
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		ret = qcsapi_wifi_set_nss_cap(ifname, mt, nss);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* Band, NOT USED IN TESTS */

	/* TODO: DYN_BW_SGNL, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_DYN_BW_SGNL, &feature_enable, &conv_err) > 0) {
		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* SGI80, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_SGI80, &feature_enable, &conv_err) > 0) {
		/* disable dynamic GI selection */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_GI_probing, 0);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

		/* TODO: it sets general capability for short GI, not only SGI80 */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_short_GI, feature_enable);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* TxBF, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_TXBF, &feature_enable, &conv_err) > 0) {
		/* TODO: check, that we enable/disable SU TxBF beamformee capability
		 * with explicit feedback */
		ret = qcsapi_wifi_set_option(ifname, qcsapi_beamforming, feature_enable);

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* LDPC, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_LDPC, &feature_enable, &conv_err) > 0) {
		char tmpbuf[64];

		snprintf(tmpbuf, sizeof(tmpbuf), "iwpriv %s set_ldpc %d", ifname, feature_enable);
		system(tmpbuf);

		/* TODO: what about IEEE80211_PARAM_LDPC_ALLOW_NON_QTN ?
		 *       Allow non QTN nodes to use LDPC */

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* Opt_md_notif_ie, (NSS=1 & BW=20Mhz => 1;20) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_OPT_MD_NOTIF_IE, val_buf, sizeof(val_buf)) > 0) {
		int nss = 0;
		int bw = 0;

		ret = sscanf(val_buf, "%d;%d", &nss, &bw);

		if (ret != 2) {
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		/* TODO: implement setting Operating Mode Notification IE as specified */
		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* nss_mcs_cap, (nss_capabilty;mcs_capability => 2;0-9) */
	if (qtn_get_value_text(&cmd_req, QTN_TOK_NSS_MCS_CAP, val_buf, sizeof(val_buf)) > 0) {
		int nss = 0;
		int mcs_high = 0;

		ret = sscanf(val_buf, "%d;0-%d", &nss, &mcs_high);

		if (ret != 2) {
			ret = -EINVAL;
			status = STATUS_ERROR;
			goto respond;
		}

		/* NSS capability */
		ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_vht, nss);

		if (ret < 0) {
			status = STATUS_ERROR;
				goto respond;
		}

		/* MCS capability */

		/* TODO: implement setting MCS capability for VHT */
		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* Tx_lgi_rate, int (0) */
	if (qtn_get_value_int(&cmd_req, QTN_TOK_TX_LGI_RATE, &feature_val) > 0) {
		/* TODO: implement setting Tx Highest Supported Long GI Data Rate
		 *
		 * static int qdrv_wlan_80211_cfg_vht(struct ieee80211com *ic)
		 *   ...
		 *   ic->ic_vhtcap.rxlgimaxrate = 0;
		 *   ic->ic_vhtcap.txlgimaxrate = 0;
		 *   ...
		 */

		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}
	}

	/* Zero_crc (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_ZERO_CRC, &feature_enable, &conv_err) > 0) {
		/* setting VHT SIGB CRC to fixed value (e.g. all "0") not supported
		 * for current hardware platform
		 * VHT SIGB CRC is always calculated
		 * tests: 4.2.26
		 */

		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* Vht_tkip (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_VHT_TKIP, &feature_enable, &conv_err) > 0) {
		/* TODO: enable TKIP in VHT mode
		 *   4.2.44
		 *   Testbed Wi-Fi CERTIFIED ac with the capability of setting TKIP and VHT
		 *   and ability to generate a probe request.
		 */

		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* Vht_wep, (enable/disable), NOT USED IN TESTS (as STA testbed) */

	/* BW_SGNL, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_BW_SGNL, &feature_enable, &conv_err) > 0) {
		/* TODO: implement, similar to dynamic BW signaling
		 *   4.2.51
		 *   STA1: Testbed Wi-Fi CERTIFIED ac STA supporting the optional feature RTS
		 *   with BW signaling
		 */

		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* MU_TxBF, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_MU_TXBF, &feature_enable, &conv_err) > 0) {
		/* TODO: enable/disable Multi User (MU) TxBF beamformee capability
		 * with explicit feedback
		 *
		 * Tests: 4.2.56
		 */

		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	/* RTS_BWS, (enable/disable) */
	if (qtn_get_value_enable(&cmd_req, QTN_TOK_RTS_BWS, &feature_enable, &conv_err) > 0) {
		/* TODO: enable RTS with Bandwidth Signaling Feature
		 *
		 * Tests: 4.2.59
		 */

		ret = -EOPNOTSUPP;

		if (ret < 0) {
			status = STATUS_ERROR;
			goto respond;
		}

	} else if (conv_err < 0) {
		ret = conv_err;
		status = STATUS_ERROR;
		goto respond;
	}

	status = STATUS_COMPLETE;

respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_rfeature(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname[IFNAMSIZ];
	char val_str[128];
	int num_ss;
	int mcs;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_NSS_MCS_OPT, val_str, sizeof(val_str)) > 0 &&
		sscanf(val_str, "%d;%d", &num_ss, &mcs) == 2) {

		snprintf(val_str, sizeof(val_str), "MCS%d0%d", num_ss, mcs);
		if ((ret = qcsapi_wifi_set_mcs_rate(ifname, val_str)) < 0) {
			qtn_error("can't set mcs rate to %s, error %d", val_str, ret);
		}
	}



	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_ip_config(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	/* empty for now */


	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_psk(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret;
	char ifname[IFNAMSIZ];
	char ssid_str[128];
	char pass_str[128];
	char key_type[128];
	char enc_type[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str, sizeof(ssid_str)) <= 0) {
		qtn_error("can't get ssid");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PASSPHRASE, pass_str, sizeof(pass_str)) <= 0) {
		qtn_error("can't get pass phrase");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_KEYMGMTTYPE, key_type, sizeof(key_type)) <= 0) {
		qtn_error("can't get pass key_type");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ENCPTYPE, enc_type, sizeof(enc_type)) <= 0) {
		qtn_error("can't get enc_type");
		goto respond;
	}

	status = STATUS_ERROR;

	if (qcsapi_SSID_verify_SSID(ifname, ssid_str) < 0 &&
			(ret = qcsapi_SSID_create_SSID(ifname, ssid_str)) < 0) {
		qtn_error("can't create SSID %s, error %d", ssid_str, ret);
		goto respond;
	}

	if ((ret = set_sta_encryption(ifname, ssid_str, enc_type)) < 0) {
		qtn_error("can't set enc to %s, error %d", enc_type, ret);
		goto respond;
	}

	if ((ret = qcsapi_SSID_set_authentication_mode(ifname, ssid_str, "PSKAuthentication")) < 0) {
		qtn_error("can't set PSK authentication, error %d", ret);
		goto respond;
	}

	/* possible values for key_type: wpa/wpa2/wpa-psk/wpa2-psk/wpa2-ft/wpa2-wpa-psk */
	const int is_psk = strcasecmp(key_type, "wpa-psk") == 0 ||
				strcasecmp(key_type, "wpa2-psk") == 0 ||
				strcasecmp(key_type, "wpa2-wpa-psk") == 0;

	if (is_psk && (ret = qcsapi_SSID_set_pre_shared_key(ifname, ssid_str, 0, pass_str)) < 0) {
		qtn_error("can't set psk: ifname %s, ssid %s, key_type %s, pass %s, error %d",
			ifname, ssid_str, key_type, pass_str, ret);
	} else if (!is_psk &&
			(ret = qcsapi_SSID_set_key_passphrase(ifname, ssid_str, 0, pass_str)) < 0) {
		qtn_error("can't set pass: ifname %s, ssid %s, key_type %s, pass %s, error %d",
			ifname, ssid_str, key_type, pass_str, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_associate(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret;
	char ifname[IFNAMSIZ];
	char ssid_str[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str, sizeof(ssid_str)) <= 0) {
		qtn_error("can't get ssid");
		status = STATUS_INVALID;
		goto respond;
	}

	if ((ret = qcsapi_wifi_associate(ifname, ssid_str)) < 0) {
		qtn_error("can't associate, ifname %s, ssid %s, error %d", ifname, ssid_str, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_encryption(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char ssid_str[128];
	char encryption[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_SSID, ssid_str, sizeof(ssid_str)) <= 0) {
		qtn_error("can't get ssid");
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ENCPTYPE, encryption, sizeof(encryption)) <= 0) {
		qtn_error("can't get encryption");
		status = STATUS_INVALID;
		goto respond;
	}

	status = STATUS_ERROR;

	if (strcasecmp(encryption, "wep") == 0) {
		qtn_log("wep is not supported");
		ret = -EINVAL;
		goto respond;
	}

	if (qcsapi_SSID_verify_SSID(ifname, ssid_str) < 0 &&
			(ret = qcsapi_SSID_create_SSID(ifname, ssid_str)) < 0) {
		qtn_error("can't create SSID %s, error %d", ssid_str, ret);
		goto respond;
	}

	if (strcasecmp(encryption, "none") == 0 &&
			(ret = qcsapi_SSID_set_authentication_mode(ifname, ssid_str, "NONE")) < 0) {
		qtn_log("can't set authentication to %s, ssid %s error %d",
				encryption, ssid_str, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_dev_send_frame(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char program[64];
	char dest_mac[32];
	char frame_name[64];
	char cmd[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		status = STATUS_INVALID;
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	status = STATUS_INVALID;

	if (qtn_get_value_text(&cmd_req, QTN_TOK_PROGRAM, program, sizeof(program)) <= 0) {
		qtn_error("can't get program");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_FRAMENAME, frame_name, sizeof(frame_name)) <= 0) {
		qtn_error("can't get frame_name");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_DEST_MAC, dest_mac, sizeof(dest_mac)) <= 0) {
		qtn_error("can't get dest_mac");
		goto respond;
	}

	qcsapi_unsigned_int bw = 80;
	if ((ret = qcsapi_wifi_get_bw(ifname, &bw)) < 0) {
		qtn_error("can't get bw, error %d", ret);
	}

	snprintf(cmd, sizeof(cmd), "iwpriv %s setparam %d %u",
			ifname, IEEE80211_PARAM_VHT_OPMODE_BW, bw);
	ret = system(cmd);

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_reassoc(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char bssid[64];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		snprintf(ifname, sizeof(ifname), "%s", QCSAPI_PRIMARY_WIFI_IFNAME);
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_BSSID, bssid, sizeof(bssid)) <= 0) {
		qtn_error("can't get bssid");
		goto respond;
	}

	if ((ret = qcsapi_wifi_reassociate(ifname)) < 0) {
		qtn_error("can't reassociate, error %d", ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_systime(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char cmd[128];
	int month;
	int date;
	int year;
	int hours;
	int minutes;
	int seconds;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_YEAR, &year) <= 0) {
		qtn_error("can't get year");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_MONTH, &month) <= 0) {
		qtn_error("can't get month");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_DATE, &date) <= 0) {
		qtn_error("can't get date");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_HOURS, &hours) <= 0) {
		qtn_error("can't get hours");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_MINUTES, &minutes) <= 0) {
		qtn_error("can't get minutes");
		goto respond;
	}

	if (qtn_get_value_int(&cmd_req, QTN_TOK_SECONDS, &seconds) <= 0) {
		qtn_error("can't get seconds");
		goto respond;
	}

	snprintf(cmd, sizeof(cmd), "date -s %2.2d%2.2d%2.2d%2.2d%4.4d.%2.2d",
		month, date, hours, minutes, year, seconds);
	ret = system(cmd);
	if (ret != 0) {
		qtn_error("can't set time. error %d, cmd %s", ret, cmd);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_radio(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char mode[64];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MODE, mode, sizeof(mode)) <= 0) {
		qtn_error("can't get mode");
		goto respond;
	}

	if ((ret = qcsapi_wifi_rfenable(strcasecmp(mode, "On") == 0 ? 1 : 0)) < 0) {
		qtn_error("can't set rf to %s, error %d", mode, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_macaddr(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char mac_str[64];
	qcsapi_mac_addr mac;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get ifname");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_MAC, mac_str, sizeof(mac_str)) <= 0) {
		qtn_error("can't get mac");
		goto respond;
	}

	if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
		qtn_error("can't parse mac_str %s", mac_str);
		goto respond;
	}

	qtn_log("try to set mac on %s to %s", ifname, mac_str);

	if ((ret = qcsapi_interface_set_mac_addr(ifname, mac)) < 0) {
		qtn_error("can't set mac to %s, error %d", mac_str, ret);
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_uapsd(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char cmd[128];
	int maxsplength = 4;
	int acbe = 1;
	int acbk = 1;
	int acvi = 1;
	int acvo = 1;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get ifname");
		goto respond;
	}

	qtn_get_value_int(&cmd_req, QTN_TOK_MAXSPLENGTH, &maxsplength);
	qtn_get_value_int(&cmd_req, QTN_TOK_ACBE, &acbe);
	qtn_get_value_int(&cmd_req, QTN_TOK_ACBK, &acbk);
	qtn_get_value_int(&cmd_req, QTN_TOK_ACVI, &acvi);
	qtn_get_value_int(&cmd_req, QTN_TOK_ACVO, &acvo);

	uint8_t uapsdinfo = WME_CAPINFO_UAPSD_EN;
	if (acbe) {
		uapsdinfo |= WME_CAPINFO_UAPSD_BE;
	}

	if (acbk) {
		uapsdinfo |= WME_CAPINFO_UAPSD_BK;
	}

	if (acvi) {
		uapsdinfo |= WME_CAPINFO_UAPSD_VI;
	}

	if (acvo) {
		uapsdinfo |= WME_CAPINFO_UAPSD_VO;
	}

	uapsdinfo |= (maxsplength & WME_CAPINFO_UAPSD_MAXSP_MASK) << WME_CAPINFO_UAPSD_MAXSP_SHIFT;

	snprintf(cmd, sizeof(cmd), "iwpriv %s setparam %d %d",
			ifname, IEEE80211_PARAM_UAPSDINFO, uapsdinfo);
	ret = system(cmd);

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_reset_parm(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	char arp[64];
	char cmd[128];

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get ifname");
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_ARP, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get arp");
		goto respond;
	}

	if (strcasecmp(arp, "all") == 0) {
		snprintf(cmd, sizeof(cmd), "for ip in `grep %s /proc/net/arp | awk '{print $1}'`; "
				"do arp -i %s -d $ip; done", ifname, ifname);
	} else {
		snprintf(cmd, sizeof(cmd), "arp -i %s -d %s", ifname, arp);
	}

	ret = system(cmd);
	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

void qtn_handle_sta_set_11n(int cmd_tag, int len, unsigned char *params, int *out_len,
	unsigned char *out)
{
	struct qtn_cmd_request cmd_req;
	int status = STATUS_INVALID;
	int ret = 0;
	char ifname[IFNAMSIZ];
	int width;

	ret = qtn_init_cmd_request(&cmd_req, cmd_tag, params, len);
	if (ret != 0) {
		goto respond;
	}

	if (qtn_get_value_text(&cmd_req, QTN_TOK_INTERFACE, ifname, sizeof(ifname)) <= 0) {
		qtn_error("can't get ifname");
		goto respond;
	}

	status = STATUS_ERROR;

	if (qtn_get_value_int(&cmd_req, QTN_TOK_WIDTH, &width) > 0 &&
			(ret = qcsapi_wifi_set_bw(ifname, width)) < 0) {
		qtn_error("can't set bw to %d, error %d", width, ret);
		goto respond;
	}

	int tx_ss = -1;
	int rx_ss = -1;

	qtn_get_value_int(&cmd_req, QTN_TOK_TXSP_STREAM, &tx_ss);
	qtn_get_value_int(&cmd_req, QTN_TOK_RXSP_STREAM, &rx_ss);

	if (tx_ss == rx_ss && tx_ss != -1) {
		/* sta_set_11n is used only for 11n, so hardcode qcsapi_mimo_ht */
		ret = qcsapi_wifi_set_nss_cap(ifname, qcsapi_mimo_ht, tx_ss);
		if (ret < 0) {
			qtn_error("can't set NSS to %d, error %d", tx_ss, ret);
		}
	} else if (tx_ss != -1 || rx_ss != -1) {
		qtn_error("can't handle number of SS separatly for RX and TX");
		ret = -EINVAL;
	}

	status = ret >= 0 ? STATUS_COMPLETE : STATUS_ERROR;
respond:
	qtn_dut_make_response_none(cmd_tag, status, ret, out_len, out);
}

