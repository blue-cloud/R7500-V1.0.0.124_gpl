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

#ifndef QTN_DUT_COMMON_H_
#define QTN_DUT_COMMON_H_

void qtn_dut_make_response_none(int tag, int status, int err_code, int *out_len,
	unsigned char *out_buf);

void qtn_dut_make_response_macaddr(int tag, int status, int err_code, const unsigned char *macaddr,
	int *out_len, unsigned char *out_buf);

void qtn_dut_make_response_vendor_info(int tag, int status, int err_code,
	const char *vendor_info, int *out_len, unsigned char *out_buf);

int qtn_parse_mac(const char *mac_str, unsigned char *mac);

#endif				/* QTN_DUT_COMMON_H_ */
