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
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <net80211/ieee80211.h>
#include "wfa_types.h"
#include "wfa_tlv.h"
#include "qtn_dut_common.h"

static
int qtn_dut_print_base_response(char *buf_ptr, int buf_size, int status, int err_code)
{
	int rsp_len;
	const char *status_str;
	int need_err_code = 0;

	switch (status) {
	case STATUS_RUNNING:
		status_str = "RUNNING";
		break;

	case STATUS_INVALID:
		status_str = "INVALID";
		need_err_code = (err_code != 0);
		break;

	case STATUS_ERROR:
		status_str = "ERROR";
		need_err_code = (err_code != 0);
		break;

	case STATUS_COMPLETE:
		status_str = "COMPLETE";
		break;

	default:
		status_str = "INVALID";
		break;
	}

	if (need_err_code)
		rsp_len = snprintf(buf_ptr, buf_size, "%s,errorCode,%d", status_str, err_code);
	else
		rsp_len = snprintf(buf_ptr, buf_size, "%s", status_str);

	return rsp_len;
}

void qtn_dut_make_response_none(int tag, int status, int err_code, int *out_len,
	unsigned char *out_buf)
{
	char rsp_buf[128];
	int rsp_len;

	rsp_len = qtn_dut_print_base_response(rsp_buf, sizeof(rsp_buf), status, err_code);

	if (rsp_len > 0) {
		wfaEncodeTLV(tag, rsp_len, (BYTE *) rsp_buf, out_buf);
		*out_len = WFA_TLV_HDR_LEN + rsp_len;
	}
}

void qtn_dut_make_response_macaddr(int tag, int status, int err_code, const unsigned char *macaddr,
	int *out_len, unsigned char *out_buf)
{
	char rsp_buf[128];
	int rsp_len;

	rsp_len = qtn_dut_print_base_response(rsp_buf, sizeof(rsp_buf), status, err_code);

	if (rsp_len > 0) {
		if (status == STATUS_COMPLETE) {
			int len = snprintf(rsp_buf + rsp_len, sizeof(rsp_buf) - rsp_len,
				",mac,%02x:%02x:%02x:%02x:%02x:%02x",
				macaddr[0], macaddr[1], macaddr[2],
				macaddr[3], macaddr[4], macaddr[5]);

			if (len > 0)
				rsp_len += len;
		}

		wfaEncodeTLV(tag, rsp_len, (BYTE *) rsp_buf, out_buf);
		*out_len = WFA_TLV_HDR_LEN + rsp_len;
	}
}

void qtn_dut_make_response_vendor_info(int tag, int status, int err_code, const char *vendor_info,
	int *out_len, unsigned char *out_buf)
{
	char rsp_buf[512];
	int rsp_len;

	rsp_len = qtn_dut_print_base_response(rsp_buf, sizeof(rsp_buf), status, err_code);

	if (rsp_len > 0) {
		if ((status == STATUS_COMPLETE) && vendor_info && *vendor_info) {
			int len = snprintf(rsp_buf + rsp_len, sizeof(rsp_buf) - rsp_len,
				",%s", vendor_info);

			if (len > 0)
				rsp_len += len;
		}

		wfaEncodeTLV(tag, rsp_len, (BYTE *) rsp_buf, out_buf);
		*out_len = WFA_TLV_HDR_LEN + rsp_len;
	}
}

int qtn_parse_mac(const char *mac_str, unsigned char *mac)
{
	unsigned int tmparray[IEEE80211_ADDR_LEN];

	if (mac_str == NULL)
		return -EINVAL;

	if (sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
			&tmparray[0],
			&tmparray[1],
			&tmparray[2],
			&tmparray[3], &tmparray[4], &tmparray[5]) != IEEE80211_ADDR_LEN) {
		return -EINVAL;
	}

	mac[0] = tmparray[0];
	mac[1] = tmparray[1];
	mac[2] = tmparray[2];
	mac[3] = tmparray[3];
	mac[4] = tmparray[4];
	mac[5] = tmparray[5];

	return 0;
}
