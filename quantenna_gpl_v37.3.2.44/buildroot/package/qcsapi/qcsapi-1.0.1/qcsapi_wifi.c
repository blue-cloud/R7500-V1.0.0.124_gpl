/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2014 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : qcsapi_wifi.c                                              **
**  Description :                                                            **
**                                                                           **
*******************************************************************************
**                                                                           **
**  Redistribution and use in source and binary forms, with or without       **
**  modification, are permitted provided that the following conditions       **
**  are met:                                                                 **
**  1. Redistributions of source code must retain the above copyright        **
**     notice, this list of conditions and the following disclaimer.         **
**  2. Redistributions in binary form must reproduce the above copyright     **
**     notice, this list of conditions and the following disclaimer in the   **
**     documentation and/or other materials provided with the distribution.  **
**  3. The name of the author may not be used to endorse or promote products **
**     derived from this software without specific prior written permission. **
**                                                                           **
**  Alternatively, this software may be distributed under the terms of the   **
**  GNU General Public License ("GPL") version 2, or (at your option) any    **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR       **
**  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES**
**  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  **
**  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,         **
**  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT **
**  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,**
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF **
**  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.        **
**                                                                           **
*******************************************************************************
EH0*/

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <math.h>
#include <assert.h>
#include <netinet/ether.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <qtn/muc_phy_stats.h>
#include <qtn/lhost_muc_comm.h>
#include <qtn/qtn_vlan.h>

#include "qcsapi.h"
#include "qcsapi_private.h"
#include "qcsapi_util.h"

#include <net80211/ieee80211_mlme_statistics.h>
#include <net80211/ieee80211.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/mii.h>

#define QDRV_ASSOC_RESP_LEN		300
#define NUMBER_ASSOC_TABLE_FIELDS	35

#define QCSAPI_MAX_IW_RANGE_SIZE (sizeof(struct iw_range) + 256)
#define QCSAPI_MAX_PRIV_IOCTLS 1000

#define IEEE80211_ADDR_NULL(_a)	(memcmp(_a, "\x00\x00\x00\x00\x00\x00", IEEE80211_ADDR_LEN) == 0)

/* Definitions in connection with list_to_string ... */

typedef enum {
	list_element_unsigned_int,
	list_element_string,
	list_element_nosuch_type
} list_element_type;

typedef enum {
	unsigned_int_formatter_start,
	unsigned_int_formatter_found_range,
	unsigned_int_formatter_no_current_range
} unsigned_int_formatter_state;

/* Definitions in connection with per-association APIs. */

#define LOCAL_RSSI_OFFSET_FROM_10THS_DBM	900

typedef enum {
	NOSUCH_ASSOCIATION_ITEM = -1,
	LINK_QUALITY_ASSOCIATION = 0,
	RX_BYTES_ASSOCIATION,
	TX_BYTES_ASSOCIATION,
	RX_PACKETS_ASSOCIATION,
	TX_PACKETS_ASSOCIATION,
	TX_ERR_PACKETS_ASSOCIATION,
	RSSI_ASSOCIATION,
	BW_ASSOCIATION,
	TIME_IN_ASSOCIATION,
	MAC_ADDR_ASSOCIATION,
	IP_ADDR_ASSOCIATION,
	SNR_ASSOCIATION,
	TX_PHY_RATE_ASSOCIATION,
	RX_PHY_RATE_ASSOCIATION,
	TX_MCS_ASSOCIATION,
	RX_MCS_ASSOCIATION,
	RX_ERROR_PACKETS_ASSOCIATION,
	TX_ERROR_PACKETS_ASSOCIATION,
	RX_DROPPED_PACKETS_ASSOCIATION,
	TX_DROPPED_PACKETS_ASSOCIATION,
	MAX_QUEUED_ASSOCIATION,
	TX_ACHIEVABLE_PHY_RATE_ASSOCIATION,
	RX_ACHIEVABLE_PHY_RATE_ASSOCIATION,
	HW_NOISE_ASSOCIATION,
	IS_QTN_NODE_ASSOCIATION,
	RX_FRAGMENTS_FRAMES,
	RX_VLAN_FRAMES
} per_association_item;

typedef struct assoc_info_report {
	u_int64_t	ai_rx_bytes;
	u_int64_t	ai_tx_bytes;
	u_int32_t	ai_rx_packets;
	u_int32_t	ai_tx_packets;
	u_int32_t	ai_rx_errors;
	u_int32_t	ai_tx_errors;
	u_int32_t	ai_rx_dropped;
	u_int32_t	ai_tx_dropped;
	u_int32_t       ai_tx_ucast;
	u_int32_t       ai_rx_ucast;
	u_int32_t       ai_tx_mcast;
	u_int32_t       ai_rx_mcast;
	u_int32_t       ai_tx_bcast;
	u_int32_t       ai_rx_bcast;
	u_int32_t	ai_tx_failed;
	u_int32_t	ai_time_associated;	/*Unit: seconds*/
	u_int16_t	ai_assoc_id;
	u_int16_t	ai_link_quality;
	u_int16_t	ai_tx_phy_rate;
	u_int16_t	ai_rx_phy_rate;
	u_int32_t	ai_achievable_tx_phy_rate;
	u_int32_t	ai_achievable_rx_phy_rate;
	u_int32_t	ai_rx_fragment_pkts;
	u_int32_t	ai_rx_vlan_pkts;
	qcsapi_mac_addr	ai_mac_addr;
	int		ai_rssi;
	int		ai_smthd_rssi;
	int		ai_snr;
	int		ai_max_queued;
	u_int8_t	ai_bw;
	u_int8_t	ai_tx_mcs;
	u_int8_t	ai_rx_mcs;
	u_int8_t	ai_auth;
	char		ai_ifname[IFNAMSIZ];
	u_int32_t	ai_ip_addr;
	int		ai_hw_noise;
	u_int32_t	ai_is_qtn_node;
} assoc_info_report;

struct assoc_info_table {
	uint16_t	unit_size;	/* Size of structure assoc_info_table */
	uint16_t	cnt;		/* Record the number of valid entries */
	struct assoc_info_report array[QTN_ASSOC_LIMIT];
};

static struct {
	qcsapi_counter_type	pact_counter_type;
	per_association_item	pact_item;
} per_association_counter_table[] = {
	{QCSAPI_TOTAL_BYTES_SENT,		TX_BYTES_ASSOCIATION},
	{QCSAPI_TOTAL_BYTES_RECEIVED,		RX_BYTES_ASSOCIATION},
	{QCSAPI_TOTAL_PACKETS_SENT,		TX_PACKETS_ASSOCIATION},
	{QCSAPI_TOTAL_PACKETS_RECEIVED,		RX_PACKETS_ASSOCIATION},
	{QCSAPI_ERROR_PACKETS_SENT,		TX_ERROR_PACKETS_ASSOCIATION},
	{QCSAPI_ERROR_PACKETS_RECEIVED,		RX_ERROR_PACKETS_ASSOCIATION},
	{QCSAPI_DISCARD_PACKETS_SENT,		TX_DROPPED_PACKETS_ASSOCIATION},
	{QCSAPI_DISCARD_PACKETS_RECEIVED,	RX_DROPPED_PACKETS_ASSOCIATION},
	{QCSAPI_FRAGMENT_FRAMES_RECEIVED,	RX_FRAGMENTS_FRAMES},
	{QCSAPI_VLAN_FRAMES_RECEIVED,		RX_VLAN_FRAMES},
};

static struct {
	qcsapi_per_assoc_param	papt_parameter;
	per_association_item	papt_item;
} per_association_parameter_table[] = {
	{QCSAPI_LINK_QUALITY,	LINK_QUALITY_ASSOCIATION},
	{QCSAPI_RSSI_DBM,	RSSI_ASSOCIATION},
	{QCSAPI_BANDWIDTH,	BW_ASSOCIATION},
	{QCSAPI_SNR,		SNR_ASSOCIATION},
	{QCSAPI_TX_PHY_RATE,	TX_PHY_RATE_ASSOCIATION},
	{QCSAPI_RX_PHY_RATE,	RX_PHY_RATE_ASSOCIATION},
	{QCSAPI_HW_NOISE,		HW_NOISE_ASSOCIATION},
};

static qcsapi_bw qcsapi_bw_list[] = { qcsapi_bw_20MHz,
					qcsapi_bw_40MHz,
					qcsapi_bw_80MHz,
					qcsapi_bw_160MHz };

/**
 * Local structure for data exchange beteween API and driver/MuC firmware
 * Some fields will be converted to float which user can see
 */
typedef struct _local_qcsapi_phy_stats
{
	u_int32_t	tstamp;

	u_int32_t	assoc;

	u_int32_t	atten;
	u_int32_t	cca_total;
	u_int32_t	cca_tx;
	u_int32_t	cca_rx;
	u_int32_t	cca_int;
	u_int32_t	cca_idle;

	u_int32_t	rx_pkts;
	u_int32_t	rx_gain;
	u_int32_t	rx_cnt_crc;
	u_int32_t	rx_noise;

	u_int32_t	tx_pkts;
	u_int32_t	tx_defers;
	u_int32_t	tx_touts;
	u_int32_t	tx_retries;

	u_int32_t	cnt_sp_fail;
	u_int32_t	cnt_lp_fail;
	u_int32_t	last_tx_scale;
	u_int32_t	last_rx_mcs;
	u_int32_t	last_tx_mcs;

	u_int32_t	last_rssi;
	u_int32_t	last_rssi_array[QCSAPI_QDRV_NUM_RF_STREAMS];

	u_int32_t	last_rcpi;

	u_int32_t	last_evm;
	u_int32_t	last_evm_array[QCSAPI_QDRV_NUM_RF_STREAMS];
} local_qcsapi_phy_stats;

/*
 * Scan state and meta-information, used to decode events in connection
 * with reporting the results of an AP scan on a STA.
 */

typedef struct iwscan_state
{
  /* State */
	int	ap_num;		/* Access Point number 1->N */
	int	val_index;	/* Value in table 0->(N-1) */
} iwscan_state;


/*
 * OUI: Organizationally Unique Identifier - NOT French for yes !!
 */
#define WSC_OUI_OFFSET	2
static const unsigned char	wsc_oui[] = {0x00, 0x50, 0xf2, 0x04};
static const unsigned char	wpa1_oui[] = {0x00, 0x50, 0xf2, 0x01};
static const unsigned char	wpa2_oui[] = {0x00, 0x0f, 0xac};

static const int		encryption_mask_table[] =
{
	-1,				/* IW_IE_CIPHER_NONE */
	-1,				/* IW_IE_CIPHER_WEP40 */
	qcsapi_ap_TKIP_encryption_mask,	/* IW_IE_CIPHER_TKIP */
	-1,				/* IW_IE_CIPHER_WRAP */
	qcsapi_ap_CCMP_encryption_mask,	/* IW_IE_CIPHER_CCMP */
	-1,				/* IW_IE_CIPHER_WEP104 */
};

static const int		authentication_table[] =
{
	-1,				/* IW_IE_KEY_MGMT_NONE */
	qcsapi_ap_EAP_authentication,	/* IW_IE_KEY_MGMT_802_1X */
	qcsapi_ap_PSK_authentication,	/* IW_IE_KEY_MGMT_PSK */
};

static const struct
{
	int			we_mode;
	qcsapi_wifi_mode	wifi_mode;
} wifi_mode_table[] =
{
	{ WE_MODE_AUTO,		qcsapi_nosuch_mode },
	{ WE_MODE_ADHOC,	qcsapi_nosuch_mode },
	{ WE_MODE_MANAGED,	qcsapi_station },
	{ WE_MODE_MASTER,	qcsapi_access_point },
	{ WE_MODE_REPEATER,	qcsapi_wds },
	{ WE_MODE_SECONDARY,	qcsapi_nosuch_mode },
	{ WE_MODE_MONITOR,	qcsapi_nosuch_mode }
};

static const int	wifi_mode_table_size = sizeof( wifi_mode_table ) / sizeof( wifi_mode_table[ 0 ] );

/*
 * Bit masks for the channel entry flags.
 */

enum
{
	m_DFS_required = 0x01,
	m_40MHz_available = 0x02
};

typedef struct
{
	int	channel;
	int	max_tx_power;
	/*
	 * EIRP or conducted tx power limit based on the spec of specific region.
	 * EIRP will be used if it is defined in specific region, or conducted tx power limit
	 * will be used.
	 * Some regions also define EIRP or conducted tx power limit for STA.
	 * If so, use the STA side value.
	 * EIRP: max_tx_power = EIRP - antenna_gain - 10log10(antenna_num)
	 * Conducted: max_tx_power = Conducted - 10log10(antenna_num)
	 */
	int regulatory_tx_power;
	int	flags;
} channel_entry;

typedef struct
{
	qcsapi_regulatory_region	 controlling_authority;
	channel_entry			*p_channel_table;
} qcsapi_regulatory_entry;

/*
 * All channel_entry tables are required to be sorted in ascending numeric order
 * and to be terminated by a negative channel value.
 * Application only gets the address of the channel table; its actual size is
 * not available.  Thus the channel = -1 to terminate the table.
 *
 * Update for FCC: channels 120 to 128 are no longer valid, October 2009.
 *
 * Entry "max_tx_power" is the EIRP TX power per chain.
 */
static channel_entry	fcc_usa_channels_default[] = {
	{ 36,	11,	17,	m_40MHz_available },
	{ 40,	11,	17,	m_40MHz_available },
	{ 44,	11,	17,	m_40MHz_available },
	{ 48,	11,	17,	m_40MHz_available },
	{ 52,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 56,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 60,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 64,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 100,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 104,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 108,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 112,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 116,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 120,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 124,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 128,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 132,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 136,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 140,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 144,	18,	24,	m_40MHz_available | m_DFS_required },
	{ 149,	24,	30,	m_40MHz_available },
	{ 153,	24,	30,	m_40MHz_available },
	{ 157,	24,	30,	m_40MHz_available },
	{ 161,	24,	30,	m_40MHz_available },
	{ 165,	24,	30,	m_40MHz_available },
	{ 169,	24,	30,	m_40MHz_available },
	{ -1,	QCSAPI_TX_POWER_NOT_CONFIGURED,	QCSAPI_TX_POWER_NOT_CONFIGURED,	0 }
};

static channel_entry	ce_channels_default[] = {
	{ 36,	17,	23,	m_40MHz_available },
	{ 40,	17,	23,	m_40MHz_available },
	{ 44,	17,	23,	m_40MHz_available },
	{ 48,	17,	23,	m_40MHz_available },
	{ 52,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 56,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 60,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 64,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 100,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 104,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 108,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 112,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 116,	24,	23,	m_DFS_required },
	{ 132,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 136,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 140,	24,	23,	m_DFS_required },
	{ -1,	QCSAPI_TX_POWER_NOT_CONFIGURED,	QCSAPI_TX_POWER_NOT_CONFIGURED,	0 }
};

static channel_entry	jp_channels_default[] = {
	{ 36,	17,	23,	m_40MHz_available },
	{ 40,	17,	23,	m_40MHz_available },
	{ 44,	17,	23,	m_40MHz_available },
	{ 48,	17,	23,	m_40MHz_available },
	{ 52,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 56,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 60,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 64,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 100,	21,	27,	m_40MHz_available | m_DFS_required },
	{ 104,	21,	27,	m_40MHz_available | m_DFS_required },
	{ 108,	21,	27,	m_40MHz_available | m_DFS_required },
	{ 112,	21,	27,	m_40MHz_available | m_DFS_required },
	{ 116,	21,	27,	m_40MHz_available | m_DFS_required },
	{ 120,	21,	27,	m_40MHz_available | m_DFS_required },
	{ 124,	21,	27,	m_40MHz_available | m_DFS_required },
	{ 128,	21,	27,	m_40MHz_available | m_DFS_required },
	{ 132,	21,	27,	m_40MHz_available | m_DFS_required },
	{ 136,	21,	27,	m_40MHz_available | m_DFS_required },
	{ 140,	21,	27,	m_DFS_required },
	{ -1,	QCSAPI_TX_POWER_NOT_CONFIGURED,	QCSAPI_TX_POWER_NOT_CONFIGURED,	0 }
};

static channel_entry	ru_channels_default[] = {
	{ 36,	14,	20,	m_40MHz_available },
	{ 40,	14,	20,	m_40MHz_available },
	{ 44,	14,	20,	m_40MHz_available },
	{ 48,	14,	20,	m_40MHz_available },
	{ 52,	14,	20,	m_40MHz_available },
	{ 56,	14,	20,	m_40MHz_available },
	{ 60,	14,	20,	m_40MHz_available },
	{ 64,	14,	20,	m_40MHz_available },
	{ 132,	24,	30,	m_40MHz_available },
	{ 136,	24,	30,	m_40MHz_available },
	{ 140,	24,	30,	0 },
	{ -1,	QCSAPI_TX_POWER_NOT_CONFIGURED,	QCSAPI_TX_POWER_NOT_CONFIGURED,	0 }
};

static channel_entry	au_channels_default[] = {
	{ 36,	17,	23,	m_40MHz_available },
	{ 40,	17,	23,	m_40MHz_available },
	{ 44,	17,	23,	m_40MHz_available },
	{ 48,	17,	23,	m_40MHz_available },
	{ 52,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 56,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 60,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 64,	17,	23,	m_40MHz_available | m_DFS_required },
	{ 100,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 104,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 108,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 112,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 116,	24,	23,	m_DFS_required },
	{ 132,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 136,	24,	23,	m_40MHz_available | m_DFS_required },
	{ 140,	24,	23,	m_DFS_required },
	{ 149,	30,	36,	m_40MHz_available },
	{ 153,	30,	36,	m_40MHz_available },
	{ 157,	30,	36,	m_40MHz_available },
	{ 161,	30,	36,	m_40MHz_available },
	{ 165,	30,	36,	0},
	{ -1,	QCSAPI_TX_POWER_NOT_CONFIGURED,	QCSAPI_TX_POWER_NOT_CONFIGURED,	0 }
};

static qcsapi_regulatory_entry	regulatory_table_default[] =
{
	{ QCSAPI_REGION_USA,		&fcc_usa_channels_default[ 0 ] },
	{ QCSAPI_REGION_JAPAN,		&jp_channels_default[ 0 ] },
	{ QCSAPI_REGION_RUSSIA,		&ru_channels_default[ 0 ] },
	{ QCSAPI_REGION_EUROPE,		&ce_channels_default[ 0 ] },
	{ QCSAPI_REGION_AUSTRALIA,	&au_channels_default[ 0 ] },
};

/* dual band channel lists */
static channel_entry	fcc_usa_channels_dual_default[] = {
	{ 1,    24,     30,	0},
	{ 2,    24,     30,	0},
	{ 3,    24,     30,	0},
	{ 4,    24,     30,	0},
	{ 5,    24,     30,	0},
	{ 6,    24,     30,	0},
	{ 7,    24,     30,	0},
	{ 8,    24,     30,	0},
	{ 9,    24,     30,	0},
	{ 10,   24,     30,	0},
	{ 11,   24,     30,	0},
	{ 36,   11,     17,     m_40MHz_available },
	{ 40,   11,     17,     m_40MHz_available },
	{ 44,   11,     17,     m_40MHz_available },
	{ 48,   11,     17,     m_40MHz_available },
	{ 52,   18,     24,     m_40MHz_available | m_DFS_required },
	{ 56,   18,     24,     m_40MHz_available | m_DFS_required },
	{ 60,   18,     24,     m_40MHz_available | m_DFS_required },
	{ 64,   18,     24,     m_40MHz_available | m_DFS_required },
	{ 100,  18,     24,     m_40MHz_available | m_DFS_required },
	{ 104,  18,     24,     m_40MHz_available | m_DFS_required },
	{ 108,  18,     24,     m_40MHz_available | m_DFS_required },
	{ 112,  18,     24,     m_40MHz_available | m_DFS_required },
	{ 116,  18,     24,     m_DFS_required },
	{ 132,  18,     24,     m_40MHz_available | m_DFS_required },
	{ 136,  18,     24,     m_40MHz_available | m_DFS_required },
	{ 140,  18,     24,     m_DFS_required },
	{ 149,  24,     30,     m_40MHz_available },
	{ 153,  24,     30,     m_40MHz_available },
	{ 157,  24,     30,     m_40MHz_available },
	{ 161,  24,     30,     m_40MHz_available },
	{ 165,  24,     30,     0 },
	{ -1,   QCSAPI_TX_POWER_NOT_CONFIGURED, QCSAPI_TX_POWER_NOT_CONFIGURED, 0 }
};

static channel_entry	ce_channels_dual_default[] = {
	{ 1,    18,     20,	0},
	{ 2,    18,     20,	0},
	{ 3,    18,     20,	0},
	{ 4,    18,     20,	0},
	{ 5,    18,     20,	0},
	{ 6,    18,     20,	0},
	{ 7,    18,     20,	0},
	{ 8,    18,     20,	0},
	{ 9,    18,     20,	0},
	{ 10,   18,     20,	0},
	{ 11,   18,     20,	0},
	{ 12,   18,     20,	0},
	{ 13,   18,     20,	0},
	{ 36,   17,     23,     m_40MHz_available },
	{ 40,   17,     23,     m_40MHz_available },
	{ 44,   17,     23,     m_40MHz_available },
	{ 48,   17,     23,     m_40MHz_available },
	{ 52,   17,     23,     m_40MHz_available | m_DFS_required },
	{ 56,   17,     23,     m_40MHz_available | m_DFS_required },
	{ 60,   17,     23,     m_40MHz_available | m_DFS_required },
	{ 64,   17,     23,     m_40MHz_available | m_DFS_required },
	{ 100,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 104,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 108,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 112,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 116,  24,     23,     m_DFS_required },
	{ 132,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 136,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 140,  24,     23,     m_DFS_required },
	{ -1,   QCSAPI_TX_POWER_NOT_CONFIGURED, QCSAPI_TX_POWER_NOT_CONFIGURED, 0 }
};

static channel_entry	jp_channels_dual_default[] = {
	{ 1,    18,     14,	0},
	{ 2,    18,     14,	0},
	{ 3,    18,     14,	0},
	{ 4,    18,     14,	0},
	{ 5,    18,     14,	0},
	{ 6,    18,     14,	0},
	{ 7,    18,     14,	0},
	{ 8,    18,     14,	0},
	{ 9,    18,     14,	0},
	{ 10,   18,     14,	0},
	{ 11,   18,     14,	0},
	{ 12,   18,     14,	0},
	{ 13,   18,     14,	0},
	{ 36,   20,     23,     m_40MHz_available },
	{ 40,   20,     23,     m_40MHz_available },
	{ 44,   20,     23,     m_40MHz_available },
	{ 48,   20,     23,     m_40MHz_available },
	{ 52,   20,     23,     m_40MHz_available | m_DFS_required },
	{ 56,   20,     23,     m_40MHz_available | m_DFS_required },
	{ 60,   20,     23,     m_40MHz_available | m_DFS_required },
	{ 64,   20,     23,     m_40MHz_available | m_DFS_required },
	{ 100,  24,     27,     m_40MHz_available | m_DFS_required },
	{ 104,  24,     27,     m_40MHz_available | m_DFS_required },
	{ 108,  24,     27,     m_40MHz_available | m_DFS_required },
	{ 112,  24,     27,     m_40MHz_available | m_DFS_required },
	{ 116,  24,     27,     m_40MHz_available | m_DFS_required },
	{ 120,  24,     27,     m_40MHz_available | m_DFS_required },
	{ 124,  24,     27,     m_40MHz_available | m_DFS_required },
	{ 128,  24,     27,     m_40MHz_available | m_DFS_required },
	{ 132,  24,     27,     m_40MHz_available | m_DFS_required },
	{ 136,  24,     27,     m_40MHz_available | m_DFS_required },
	{ 140,  24,     27,     m_DFS_required },
	{ -1,   QCSAPI_TX_POWER_NOT_CONFIGURED, QCSAPI_TX_POWER_NOT_CONFIGURED, 0 }
};

static channel_entry	ru_channels_dual_default[] = {
	/* Need to get 2.4GHz configurable TX power values for RU */
	{ 1,    18,     0,	0},
	{ 2,    18,     0,	0},
	{ 3,    18,     0,	0},
	{ 4,    18,     0,	0},
	{ 5,    18,     0,	0},
	{ 6,    18,     0,	0},
	{ 7,    18,     0,	0},
	{ 8,    18,     0,	0},
	{ 9,    18,     0,	0},
	{ 10,   18,     0,	0},
	{ 11,   18,     0,	0},
	{ 12,   18,     0,	0},
	{ 13,   18,     0,	0},
	{ 36,   14,     20,     m_40MHz_available },
	{ 40,   14,     20,     m_40MHz_available },
	{ 44,   14,     20,     m_40MHz_available },
	{ 48,   14,     20,     m_40MHz_available },
	{ 52,   14,     20,     m_40MHz_available },
	{ 56,   14,     20,     m_40MHz_available },
	{ 60,   14,     20,     m_40MHz_available },
	{ 64,   14,     20,     m_40MHz_available },
	{ 132,  24,     30,     m_40MHz_available },
	{ 136,  24,     30,     m_40MHz_available },
	{ 140,  24,     30,     0 },
	{ -1,   QCSAPI_TX_POWER_NOT_CONFIGURED, QCSAPI_TX_POWER_NOT_CONFIGURED, 0 }
};

static channel_entry	au_channels_dual_default[] = {
	{ 1,    18,     20,     0},
	{ 2,    18,     20,     0},
	{ 3,    18,     20,     0},
	{ 4,    18,     20,     0},
	{ 5,    18,     20,     0},
	{ 6,    18,     20,     0},
	{ 7,    18,     20,     0},
	{ 8,    18,     20,     0},
	{ 9,    18,     20,     0},
	{ 10,   18,     20,     0},
	{ 11,   18,     20,     0},
	{ 12,   18,     20,     0},
	{ 13,   18,     20,     0},
	{ 36,   17,     23,     m_40MHz_available },
	{ 40,   17,     23,     m_40MHz_available },
	{ 44,   17,     23,     m_40MHz_available },
	{ 48,   17,     23,     m_40MHz_available },
	{ 52,   17,     23,     m_40MHz_available | m_DFS_required },
	{ 56,   17,     23,     m_40MHz_available | m_DFS_required },
	{ 60,   17,     23,     m_40MHz_available | m_DFS_required },
	{ 64,   17,     23,     m_40MHz_available | m_DFS_required },
	{ 100,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 104,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 108,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 112,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 116,  24,     23,     m_DFS_required },
	{ 132,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 136,  24,     23,     m_40MHz_available | m_DFS_required },
	{ 140,  24,     23,     m_DFS_required },
	{ 149,  30,     36,     m_40MHz_available },
	{ 153,  30,     36,     m_40MHz_available },
	{ 157,  30,     36,     m_40MHz_available },
	{ 161,  30,     36,     m_40MHz_available },
	{ 165,  30,     36,     0},
	{ -1,   QCSAPI_TX_POWER_NOT_CONFIGURED, QCSAPI_TX_POWER_NOT_CONFIGURED, 0 }
};

static qcsapi_regulatory_entry	regulatory_table_dual_default[] =
{
	{ QCSAPI_REGION_USA,		&fcc_usa_channels_dual_default[ 0 ] },
	{ QCSAPI_REGION_JAPAN,		&jp_channels_dual_default[ 0 ] },
	{ QCSAPI_REGION_RUSSIA,		&ru_channels_dual_default[ 0 ] },
	{ QCSAPI_REGION_EUROPE,		&ce_channels_dual_default[ 0 ] },
	{ QCSAPI_REGION_AUSTRALIA,	&au_channels_dual_default[ 0 ] },
};

#define NUM_OF_REGULATORY_REGION 5

static int	regulatory_table_size = NUM_OF_REGULATORY_REGION;

static channel_entry	*fcc_usa_channels = NULL;
static channel_entry	*ce_channels = NULL;
static channel_entry	*jp_channels = NULL;
static channel_entry	*ru_channels = NULL;
static channel_entry	*au_channels = NULL;

static qcsapi_regulatory_entry	*regulatory_table = NULL;

void create_regulatory_region(int rf_chipid)
{
	if (rf_chipid == CHIPID_DUAL) {
		fcc_usa_channels = fcc_usa_channels_dual_default;
		ce_channels = ce_channels_dual_default;
		jp_channels = jp_channels_dual_default;
		ru_channels = ru_channels_dual_default;
		au_channels = au_channels_dual_default;
		regulatory_table = regulatory_table_dual_default;
	}

	fcc_usa_channels = fcc_usa_channels_default;
	ce_channels = ce_channels_default;
	jp_channels = jp_channels_default;
	ru_channels = ru_channels_default;
	au_channels = au_channels_default;
	regulatory_table = regulatory_table_default;
}

/*
 * First entry for each regulatory region is the "default" name for that region, the one used to locate
 * the TX power table for that regulatory region.
 */
static struct
{
	qcsapi_regulatory_region	 the_region;
	char				*the_name;
} regulatory_region_name[] =
{
	{ QCSAPI_REGION_USA,		"us" },
	{ QCSAPI_REGION_EUROPE,		"eu" },
	{ QCSAPI_REGION_JAPAN,		"jp" },
	{ QCSAPI_REGION_RUSSIA,		"ru" },
	{ QCSAPI_REGION_AUSTRALIA,	"au" },
	{ QCSAPI_REGION_USA,		"USA" },
	{ QCSAPI_REGION_USA,		"FCC" },
	{ QCSAPI_REGION_EUROPE,		"CE" },
	{ QCSAPI_REGION_AUSTRALIA,	"AU" },
	{ QCSAPI_REGION_EUROPE,		"Europe" },
	{ QCSAPI_REGION_RUSSIA,		"Russia" },
	{ QCSAPI_REGION_JAPAN,		"Japan" },
	{ QCSAPI_REGION_AUSTRALIA,	"Australia" },
	{ QCSAPI_REGION_USA,		"cl" },
	{ QCSAPI_REGION_USA,		"ca" },
};

static const struct
{
	unsigned int	fix_idx;
	unsigned int	enable_bits;
	unsigned int	disable_bits;
} local_vendor_fix_bitmap_table[] =
{
	{ VENDOR_FIX_IDX_BRCM_DHCP, VENDOR_FIX_BRCM_DHCP,
				VENDOR_FIX_BRCM_DHCP |
					VENDOR_FIX_BRCM_REPLACE_IGMP_SRCMAC |
					VENDOR_FIX_BRCM_DROP_STA_IGMPQUERY},
	{ VENDOR_FIX_IDX_BRCM_IGMP, VENDOR_FIX_BRCM_DHCP |
					VENDOR_FIX_BRCM_REPLACE_IGMP_SRCMAC |
					VENDOR_FIX_BRCM_DROP_STA_IGMPQUERY,
				VENDOR_FIX_BRCM_REPLACE_IGMP_SRCMAC |
					VENDOR_FIX_BRCM_DROP_STA_IGMPQUERY},
};

static const struct
{
	char *counter_name;
	int counter_type;
	int report_index;
} rftest_counter_table[] =
{
	{ "RF1_TX",	2,	0 },
	{ "RF1_RX",	1,	1 },
	{ "RF2_TX",	2,	2 },
	{ "RF2_RX",	1,	3 },
	{  NULL,	0,	-1 }
};

static const int	regulatory_region_size = ARRAY_SIZE(regulatory_region_name);

static const struct {
	uint32_t scs_err_code;
	char *scs_err_str;
} scs_err_tbl[] = {
	{IEEE80211REQ_SCS_RESULT_OK,                   "operation OK"},
	{IEEE80211REQ_SCS_RESULT_SYSCALL_ERR,          "syscall error"},
	{IEEE80211REQ_SCS_RESULT_SCS_DISABLED,         "SCS is disabled"},
	{IEEE80211REQ_SCS_RESULT_NO_VAP_RUNNING,       "no VAP is running"},
	{IEEE80211REQ_SCS_RESULT_NOT_EVALUATED,        "channel ranking is not evaluated yet"},
	{IEEE80211REQ_SCS_RESULT_TMP_UNAVAILABLE,      "result is temporarily unavaialble, try later"},
	{IEEE80211REQ_SCS_RESULT_APMODE_ONLY,          "operation is only allowed in AP mode"},
	{IEEE80211REQ_SCS_RESULT_AUTOCHAN_DISABLED,    "auto channel is disabled"},
};

static const struct {
	qcsapi_tdls_type param_type;
	uint32_t ioctl_cmd;
	int32_t min_value;
	int32_t max_value;
} qcsapi_tdls_type_map_tbl[] =
{
	{
		qcsapi_tdls_over_qhop_enabled,
		IEEE80211_PARAM_TDLS_OVER_QHOP_ENABLE,
		IEEE80211_TDLS_TIMEOUT_TIME_MIN,
		IEEE80211_TDLS_TIMEOUT_TIME_MAX
	},
	{
		qcsapi_tdls_link_timeout_time,
		IEEE80211_PARAM_TDLS_TIMEOUT_TIME,
		IEEE80211_TDLS_TIMEOUT_TIME_MIN,
		IEEE80211_TDLS_TIMEOUT_TIME_MAX
	},
	{
		qcsapi_tdls_link_weight,
		IEEE80211_PARAM_TDLS_PATH_SEL_WEIGHT,
		IEEE80211_TDLS_LINK_WEIGHT_MIN,
		IEEE80211_TDLS_LINK_WEIGHT_MAX
	},
	{
		qcsapi_tdls_training_pkt_cnt,
		IEEE80211_PARAM_TDLS_TRAINING_PKT_CNT,
		IEEE80211_TDLS_TRAINING_PKT_CNT_MIN,
		IEEE80211_TDLS_TRAINING_PKT_CNT_MAX
	},
	{
		qcsapi_tdls_discovery_interval,
		IEEE80211_PARAM_TDLS_DISC_INT,
		IEEE80211_TDLS_DISC_INTERVAL_MIN,
		IEEE80211_TDLS_DISC_INTERVAL_MAX
	},
	{
		qcsapi_tdls_path_select_pps_thrshld,
		IEEE80211_PARAM_TDLS_PATH_SEL_PPS_THRSHLD,
		IEEE80211_TDLS_PATH_SEL_PPS_THRSHLD_MIN,
		IEEE80211_TDLS_PATH_SEL_PPS_THRSHLD_MAX
	},
	{
		qcsapi_tdls_path_select_rate_thrshld,
		IEEE80211_PARAM_TDLS_PATH_SEL_RATE_THRSHLD,
		IEEE80211_TDLS_PATH_SEL_RATE_THRSHLD_MIN,
		IEEE80211_TDLS_PATH_SEL_RATE_THRSHLD_MAX
	},
	{
		qcsapi_tdls_verbose,
		IEEE80211_PARAM_TDLS_VERBOSE,
		IEEE80211_TDLS_VERBOSE_MIN,
		IEEE80211_TDLS_VERBOSE_MAX
	},
	{
		qcsapi_tdls_min_rssi,
		IEEE80211_PARAM_TDLS_MIN_RSSI,
		IEEE80211_TDLS_VALID_RSSI_MIN,
		IEEE80211_TDLS_VALID_RSSI_MAX
	},
	{
		qcsapi_tdls_switch_ints,
		IEEE80211_PARAM_TDLS_SWITCH_INTS,
		IEEE80211_TDLS_SWITCH_INTS_MIN,
		IEEE80211_TDLS_SWITCH_INTS_MAX
	},
	{
		qcsapi_tdls_rate_weight,
		IEEE80211_PARAM_TDLS_RATE_WEIGHT,
		IEEE80211_TDLS_RATE_WEIGHT_MIN,
		IEEE80211_TDLS_RATE_WEIGHT_MAX
	},
	{
		qcsapi_tdls_mode,
		IEEE80211_PARAM_TDLS_MODE,
		IEEE80211_TDLS_MODE_MIN,
		IEEE80211_TDLS_MODE_MAX
	},
	{
		qcsapi_tdls_indication_window,
		IEEE80211_PARAM_TDLS_UAPSD_INDICAT_WND,
		IEEE80211_TDLS_INDICATION_WINDOWS_MIN,
		IEEE80211_TDLS_INDICATION_WINDOWS_MAX
	},
	{
		qcsapi_tdls_chan_switch_mode,
		IEEE80211_PARAM_TDLS_CS_MODE,
		IEEE80211_TDLS_CS_PROHIBIT_MIN,
		IEEE80211_TDLS_CS_PROHIBIT_MAX
	},
	{
		qcsapi_tdls_chan_switch_off_chan,
		IEEE80211_PARAM_TDLS_OFF_CHAN,
		IEEE80211_TDLS_CS_OFFCHAN_MIN,
		IEEE80211_TDLS_CS_OFFCHAN_MAX
	},
	{
		qcsapi_tdls_chan_switch_off_chan_bw,
		IEEE80211_PARAM_TDLS_OFF_CHAN_BW,
		IEEE80211_TDLS_CS_OFFCHAN_BW_MIN,
		IEEE80211_TDLS_CS_OFFCHAN_BW_MAX
	},
	{
		qcsapi_tdls_node_life_cycle,
		IEEE80211_PARAM_TDLS_NODE_LIFE_CYCLE,
		IEEE80211_TDLS_NODE_LIFE_CYCLE_MIN,
		IEEE80211_TDLS_NODE_LIFE_CYCLE_MAX
	},
};

typedef enum {
        SS_1_STREAM_SUPPORTED = 1,
        SS_2_STREAM_SUPPORTED,
        SS_3_STREAM_SUPPORTED,
        SS_4_STREAM_SUPPORTED
} qcsapi_ss;

static const struct {
	qcsapi_tdls_oper oper;
	const char *oper_descrpt;
} qcsapi_tdls_oper_map_tbl[] =
{
	{qcsapi_tdls_oper_discover,	"TDLS_DISCOVER "},
	{qcsapi_tdls_oper_setup,	"TDLS_SETUP "},
	{qcsapi_tdls_oper_teardown,	"TDLS_TEARDOWN "},
	{qcsapi_tdls_oper_switch_chan,	"TDLS_SWITCH_CHAN "},
};

static const struct {
	qcsapi_extender_type param_type;
	uint32_t ioctl_cmd;
	int32_t min_value;
	int32_t max_value;
} qcsapi_extender_type_map_tbl[] =
{
	{
		qcsapi_extender_role,
		IEEE80211_PARAM_EXTENDER_ROLE,
		IEEE80211_EXTENDER_ROLE_MIN,
		IEEE80211_EXTENDER_ROLE_MAX
	},
	{
		qcsapi_extender_mbs_best_rssi,
		IEEE80211_PARAM_EXTENDER_MBS_BEST_RSSI,
		IEEE80211_EXTENDER_MIN_RSSI,
		IEEE80211_EXTENDER_MAX_RSSI
	},
	{
		qcsapi_extender_rbs_best_rssi,
		IEEE80211_PARAM_EXTENDER_RBS_BEST_RSSI,
		IEEE80211_EXTENDER_MIN_RSSI,
		IEEE80211_EXTENDER_MAX_RSSI
	},
	{
		qcsapi_extender_mbs_wgt,
		IEEE80211_PARAM_EXTENDER_MBS_WGT,
		IEEE80211_EXTENDER_MIN_WGT,
		IEEE80211_EXTENDER_MAX_WGT
	},
	{
		qcsapi_extender_rbs_wgt,
		IEEE80211_PARAM_EXTENDER_RBS_WGT,
		IEEE80211_EXTENDER_MIN_WGT,
		IEEE80211_EXTENDER_MAX_WGT
	},
	{
		qcsapi_extender_verbose,
		IEEE80211_PARAM_EXTENDER_VERBOSE,
		IEEE80211_EXTENDER_MIN_VERBOSE,
		IEEE80211_EXTENDER_MAX_VERBOSE
	},
	{
		qcsapi_extender_roaming,
		IEEE80211_PARAM_SCAN_OPCHAN,
		IEEE80211_EXTENDER_MIN_ROAMING,
		IEEE80211_EXTENDER_MAX_ROAMING,
	},
	{
		qcsapi_extender_bgscan_interval,
		IEEE80211_PARAM_BGSCAN_INTERVAL,
		IEEE80211_EXTENDER_MIN_INTERVAL,
		IEEE80211_EXTENDER_MAX_INTERVAL
	},
};

static channel_entry *locate_regulatory_channel_entry(const qcsapi_regulatory_region the_region);
#if defined(CONFIG_QTN_80211K_SUPPORT)
static int
local_get_association_record_rmt(
		int skfd,
		const char *ifname,
		const qcsapi_unsigned_int association_index,
		uint32_t flags,
		struct ieee80211req_qtn_rmt_sta_stats *req_rmt_sta_stats
);

static int
local_get_node_param_rmt(qcsapi_per_assoc_param param_type,
		struct ieee80211req_qtn_rmt_sta_stats *req_rmt_sta_stats,
		int *param);
#endif

static int local_is_channel_dfs_channel(int channel, qcsapi_regulatory_region region)
{
	int		 iter;
	channel_entry	*p_regulatory_entry = locate_regulatory_channel_entry(region);

	if (p_regulatory_entry == NULL) {
		return 0;
	}

	for (iter = 0; p_regulatory_entry[ iter ].channel > 0; iter++) {
		if (p_regulatory_entry[iter].channel == channel) {
			if ((p_regulatory_entry[ iter ].flags & m_DFS_required) == m_DFS_required) {
				return 1;
			} else {
				return 0;
			}
		}
	}

	return 0;
}

static inline int
local_priv_ioctl(int skfd, const char *ifname, int cmd, struct iwreq *wrq)
{
	strncpy(wrq->ifr_name, ifname, IFNAMSIZ - 1);
	return ioctl(skfd, cmd, wrq);
}

static inline int
local_priv_netdev_ioctl(int skfd, const char *ifname, int cmd, struct ifreq *ifr)
{
	strncpy(ifr->ifr_name, ifname, IFNAMSIZ - 1);
	return ioctl(skfd, cmd, ifr);
}

int
local_get_priv_ioctls(int sock_fd,
		const char *p_ifname,
		int *p_num_priv_ioctls,
		struct iw_priv_args **pp_priv_ioctls)
{
	struct iwreq	iw_req;
	struct iwreq	*p_iw_req = &iw_req;
	static struct iw_priv_args *sp_priv_ioctls = NULL;
	static int	s_num_priv_ioctls = 0;
	int		rv = -EINVAL;
	static struct iw_priv_args *p_dyn_privs;

	assert(p_num_priv_ioctls != NULL);
	assert(pp_priv_ioctls != NULL);
	assert(p_ifname != NULL);

	/* Cached results - return them.
	 * We can do this safely as the private IOCTLs won't change during runtime.
	 */
	if (sp_priv_ioctls != NULL) {
		*pp_priv_ioctls = sp_priv_ioctls;
		*p_num_priv_ioctls = s_num_priv_ioctls;
		return 0;
	}

	p_dyn_privs = malloc(QCSAPI_MAX_PRIV_IOCTLS * sizeof(*p_dyn_privs));
	if (p_dyn_privs == NULL) {
		local_generic_syslog("local_get_priv_ioctls",
			   LOG_ERR,
			   "ENOMEM");
		return -ENOMEM;
	}

	assert(strnlen(p_ifname, IFNAMSIZ) <= IFNAMSIZ);

	memset(p_iw_req, 0, sizeof(*p_iw_req));

	strcpy(p_iw_req->ifr_name, p_ifname);
	p_iw_req->u.data.pointer = p_dyn_privs;
	p_iw_req->u.data.length = QCSAPI_MAX_PRIV_IOCTLS;

	rv = ioctl(sock_fd, SIOCGIWPRIV, p_iw_req);
	if (rv == -1)
		rv = -errno;

	if (rv < 0) {
		if (rv == -E2BIG) {
			local_generic_syslog("local_get_priv_ioctls",
				LOG_ERR,
				"Array too small - allocate larger buffer");
		}
		return rv;
	}
	sp_priv_ioctls = p_dyn_privs;
	s_num_priv_ioctls = p_iw_req->u.data.length;

	*pp_priv_ioctls = sp_priv_ioctls;
	*p_num_priv_ioctls = s_num_priv_ioctls;

	return 0;
}

int
local_get_we_range_data(int sock_fd, const char *p_ifname, struct iw_range *p_range)
{
	struct iwreq	iw_request;
	struct iwreq	*p_iw_request = &iw_request;
	uint8_t		iw_req_data_buff[QCSAPI_MAX_IW_RANGE_SIZE];
	int		ioctl_ret;

	assert(sock_fd != -1);
	assert(p_ifname != NULL);
	assert(QCSAPI_MAX_IW_RANGE_SIZE > sizeof(struct iw_range));

	memset(&iw_req_data_buff[0], 0, sizeof(iw_req_data_buff));
	memset(p_iw_request, 0, sizeof(*p_iw_request));

	p_iw_request->u.data.pointer = &iw_req_data_buff[0];
	p_iw_request->u.data.length = QCSAPI_MAX_IW_RANGE_SIZE;

	/* Catch silliness */
	assert(strnlen(p_ifname, sizeof(p_iw_request->ifr_name)) < sizeof(p_iw_request->ifr_name));
	strcpy(p_iw_request->ifr_name, p_ifname);

	ioctl_ret = ioctl(sock_fd, SIOCGIWRANGE, p_iw_request);

	if (ioctl_ret < 0) {
		/* FIXME: this error must be logged, as it may cause
		 * odd system behaviour.
		 */
		return ioctl_ret;
	}

	memcpy(p_range, &iw_req_data_buff[0], sizeof(*p_range));

	return 0;
}

int
local_get_we_version(void)
{
	return QTN_WE_VERSION;
}

int
local_open_iw_sockets(void)
{
	int ret_fd = socket(AF_INET, SOCK_DGRAM, 0);
	return ret_fd;
}

int
local_close_iw_sockets(int sock_fd)
{
	return close(sock_fd);
}

int
local_open_iw_socket_with_error( int *p_skfd )
{
	int	retval = 0;
	int	skfd = -1;

	if (p_skfd == NULL)
	 retval = -EFAULT;
	else
	{
		skfd = local_open_iw_sockets();

		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
		else
		  *p_skfd = skfd;
	}

	return( retval );
}


int
local_wifi_sub_ioctl_submit(
        const char	*ifname,
        int16_t		sub_cmd,
        void		*param,
        uint16_t	len
)
{
	struct iwreq	wrq;
	int		retval = 0;
	int		skfd = -1;

	retval = local_open_iw_socket_with_error( &skfd );

	if (retval < 0)
		return retval;

	memset(&wrq, 0, sizeof(wrq));

	wrq.u.data.flags   = sub_cmd;
	wrq.u.data.pointer = param;
	wrq.u.data.length  = len;

	retval = local_priv_ioctl(skfd, ifname, IEEE80211_IOCTL_EXT, &wrq);
	if (retval == -1)
		retval = -errno;

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	return retval;
}

static uint8_t qcsapi_swfeat_map[SWFEAT_MAP_SIZE] = { 0 };

int
local_swfeat_map_init(void)
{
	int retval = 0;
        char ifname[IFNAMSIZ] = "";
	static int swfeat_map_is_set = 0;

	if (swfeat_map_is_set)
		return 0;

        retval = local_get_primary_interface(ifname, sizeof(ifname) - 1);
	if (retval < 0)
		return retval;

	retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_GET_SWFEAT_MAP,
						qcsapi_swfeat_map, sizeof(qcsapi_swfeat_map));
	if (retval < 0)
		printf("Failed to get software feature map\n");
	else
		swfeat_map_is_set = 1;

	return retval;
}

int32_t
local_external_mcs_rate_to_internal(const qcsapi_mcs_rate external_mcs_rate,
		int32_t *p_internal_mcs_rate)
{
	int retval = 0;
	const char *p_mcs_rate = (const char *)external_mcs_rate;
	int mcs_rate;

	if (strncasecmp(external_mcs_rate, "MCS", 3) != 0)
		return -EINVAL;

	p_mcs_rate += 3;
	/*
	 * Eliminate "MCS00", "MCS01", etc.
	 */
	if ((*p_mcs_rate == '0' && *(p_mcs_rate + 1) != '\0') || isdigit(*p_mcs_rate) == 0)
		return -EINVAL;

	retval = local_swfeat_map_init();
        if (retval < 0)
		return retval;

	mcs_rate = atoi(p_mcs_rate);

	if (mcs_rate >= IEEE80211_HT_EQUAL_MCS_START && mcs_rate <= IEEE80211_UNEQUAL_MCS_MAX &&
		mcs_rate != IEEE80211_EQUAL_MCS_32) {
		if (isset(qcsapi_swfeat_map, SWFEAT_ID_2X2) ||
			isset(qcsapi_swfeat_map, SWFEAT_ID_2X4)) {
                        if (((mcs_rate > IEEE80211_HT_EQUAL_MCS_2SS_MAX) &&
				(mcs_rate < IEEE80211_EQUAL_MCS_32)) ||
				(mcs_rate > IEEE80211_HT_UNEQUAL_MCS_2SS_MAX)) {
				return -EINVAL;
                        }
                }
		*p_internal_mcs_rate = IEEE80211_N_RATE_PREFIX | ((mcs_rate << 16) & 0xff0000) |
					 ((mcs_rate << 8) & 0xff00) | (mcs_rate & 0xff);
#ifdef TOPAZ_PLATFORM
	} else if (mcs_rate >= 100) {
		int nss = mcs_rate / 100;
		int mcs = mcs_rate - 100 * nss;

		if ((nss >= IEEE80211_VHT_NSS1 && nss <= IEEE80211_AC_MCS_NSS_MAX &&
				mcs < IEEE80211_AC_MCS_MAX)) {
			if (isset(qcsapi_swfeat_map, SWFEAT_ID_2X2) ||
					isset(qcsapi_swfeat_map, SWFEAT_ID_2X4)) {
				if (nss > IEEE80211_VHT_NSS2) {
					return -EINVAL;
				}
			}
			*p_internal_mcs_rate = IEEE80211_AC_RATE_PREFIX |
					((((nss - 1) << 4) + mcs) & 0xff);
		} else {
			return -EINVAL;
		}
#endif
	} else {
		return -EINVAL;
	}

	return retval;
}

int
local_wifi_write_to_driver_cmdif ( const char *cmdif, const char *command )
{
	int	fd = -1;
	ssize_t	count;

	fd = open(cmdif, O_WRONLY);
	if (fd < 0) {
		return -qcsapi_system_not_started;
	}

	count = write(fd, command, strlen(command) + 1);

	close(fd);

	if (count <= 0) {
		if (errno > 0)
			return -errno;
		else
			return -EIO;
	}

	return 0;
}

int
local_wifi_write_to_qdrv( const char *command )
{
	return local_wifi_write_to_driver_cmdif(QDRV_CONTROL, command);
}

int
local_wifi_write_to_fwt( const char *command )
{
	return local_wifi_write_to_driver_cmdif(FWT_CONTROL, command);
}

/*
 * Do not use "index" as a variable name, it conflicts with a C-library entry point.
 */
int
local_get_we_device_by_index( unsigned int we_index, char *ifname, size_t maxlen)
{
#define NUMBER_HEADER_LINES_PROC_NET_WIRELESS	2
	int	retval = 0;
	char	internal_buffer[IFNAMSIZ] = {'\0'};
	FILE	*wireless_fh = fopen(PROC_NET_WIRELESS, "r");
	int	iter;
	int	complete = 0;

	if (wireless_fh == NULL) {
		retval = -errno;
		if (retval >= 0) {
			retval = -ENOENT;
		}

		return retval;
	}

	for (iter = 0; iter < NUMBER_HEADER_LINES_PROC_NET_WIRELESS && retval >= 0; iter++) {
		if (read_to_eol(&internal_buffer[0], sizeof(internal_buffer), wireless_fh) == NULL) {
			retval = -EIO;		/* something bad happened */
		}
	}

	for (iter = 0; iter <= we_index; iter++) {
		if (read_to_eol(&internal_buffer[0], sizeof(internal_buffer), wireless_fh) == NULL) {
			retval = -ERANGE;
			complete = 1;
		} else  if (iter == we_index) {
			char	local_ifname[IFNAMSIZ];

			local_interface_get_name(&local_ifname[0], &internal_buffer[0]);
			strncpy( ifname, &local_ifname[0], maxlen);
		}
	}

	fclose(wireless_fh);

	return(retval);
}

static int
append_unsigned_int_with_prefix( unsigned int the_value, char *prefix, char *output_str, const unsigned int max_output_len )
{
	int			retval = 0;
	unsigned int		formatted_length;
	const unsigned int	prefix_length = strlen( prefix );
	char			formatted_buffer[ 12 ];

	sprintf( &formatted_buffer[ 0 ], "%u", the_value );
	formatted_length = strlen( &formatted_buffer[ 0 ] );

	if (max_output_len >= formatted_length + prefix_length)
	{
		strcpy( output_str, prefix );
		output_str += prefix_length;
		strcpy( output_str, &formatted_buffer[ 0 ] );
		output_str += formatted_length;

		retval += (formatted_length + prefix_length);
	}
	else
	  retval = -1;

	return( retval );
}

/*
 * Special note: max_output_len is the count of non-NULL chars in the output string.
 *               So if the output string has dimension 64, max_output_len should be 63 (or less).
 *
 * Special note: retval is the count of characters in the resulting string.
 */

static int
list_unsigned_int_to_string(
	unsigned int *input_list,
	const unsigned int input_len,
	char *starting_output_str,
	const unsigned int max_output_len
)
{
	int				 retval = 0;
	int				 found_error = 0;
	unsigned int	 		 iter, last_value = 0;
	unsigned int		 	 current_output_len = max_output_len;
	char				*current_output_str = starting_output_str;
	int				 ival = append_unsigned_int_with_prefix(  input_list[ 0 ], "", current_output_str, current_output_len );
	unsigned_int_formatter_state	 formatter_state = unsigned_int_formatter_start;

	if (ival >= 0)
	{
		last_value = input_list[ 0 ];
		formatter_state = unsigned_int_formatter_no_current_range;
		current_output_str += ival;
		current_output_len = current_output_len - ival;
		retval = (int) ival;
	}
	else
	  found_error = 1;

	if (input_len > 1 && found_error == 0)
	{
		for (iter = 1; iter < input_len && found_error == 0; iter++)
		{
			unsigned int	current_value = input_list[ iter ];

			switch (formatter_state)
			{
			  case unsigned_int_formatter_no_current_range:
				if (current_value == last_value + 1)
				  formatter_state = unsigned_int_formatter_found_range;
				else
				{
					ival = append_unsigned_int_with_prefix( current_value, ",", current_output_str, current_output_len );
					if (ival >= 0)
					{
						current_output_str += ival;
						current_output_len = current_output_len - ival;
						retval += ival;
					}
					else
					  found_error = 1;
				}
				break;

			  case unsigned_int_formatter_found_range:
				if (current_value != last_value + 1)
				{
				  /* complete current range */

					ival = append_unsigned_int_with_prefix( last_value, "-", current_output_str, current_output_len );

					if (ival >= 0)
					{
						current_output_str += ival;
						current_output_len = current_output_len - ival;

						retval += ival;
					}
					else
						found_error = 1;

					if (found_error == 0)
					{
					  /* Append current value.  It may start a new range; it may not. */

						ival = append_unsigned_int_with_prefix( current_value, ",", current_output_str, current_output_len );
						if (ival >= 0)
						{
							current_output_str += ival;
							current_output_len = current_output_len - ival;

							retval += ival;
						}
						else
						  found_error = 1;
					}

					formatter_state = unsigned_int_formatter_no_current_range;
				}
				break;

			  default:
				printf( "programming error, unexpected unsigned int formatting state %d\n", formatter_state );
				break;
			}

			last_value = current_value;
		}

		if (formatter_state == unsigned_int_formatter_found_range)
		{
		  /* complete final range */

			ival = append_unsigned_int_with_prefix( last_value, "-", current_output_str, current_output_len );

			if (ival >= 0)
			{
				current_output_str += ival;
				current_output_len = current_output_len - ival;
				retval += ival;
			}
		}
	}

	return( retval );
}

static int
list_to_string(
	void *input_list[],
	const unsigned int input_len,
	list_element_type element_type,
	char *output_str,
	const unsigned int max_output_len
)
{
	int	retval = 0;

	switch (element_type)
	{
	  case list_element_unsigned_int:
		retval = list_unsigned_int_to_string( (unsigned int *) input_list, input_len, output_str, max_output_len );
		break;

	  case list_element_string:
		break;

	  default:
		retval = -1;
		break;
	}

	return( retval );
}

/* end of programs relating to list_to_string */

/* verify argument ifname is a WE (wireless extended) device */

int
verify_we_device( int skfd, const char *ifname, char *wename, const unsigned int wesize )
{
	int		retval = 0;
	struct iwreq	wrq;

	memset( &wrq, 0, sizeof( wrq ) );
	retval = local_priv_ioctl( skfd, ifname, SIOCGIWNAME, &wrq );
	if (retval < 0)
	  retval = -errno;
	else
	{
		if (wename != NULL)
		{
			strncpy( wename, &wrq.u.name[ 0 ], wesize - 1 );
			wename[ wesize - 1 ] = '\0';
		}
	}

	return( retval );
}

/*
 * The prefix of Ethernet interface name MUST be "eth".
 */
static int
local_check_ether_name(const char *ifname) {
	if (strncmp(ifname, "eth", 3) == 0)
		return 0;

	return -qcsapi_invalid_ifname;
}

/* Ether addr of the form XX:XX:XX:XX:XX:XX - 17 bytes max. */
#define QCSAPI_SIZE_ETHER_ADDR 17

/* VERY simple validation routine, just don't accept non-hex digits
 * as uClibc has bugs in ether_aton
 */
struct ether_addr *
local_ether_aton(char *eth_macaddr)
{
	int i;
	char *cp = eth_macaddr;
	int colons_found = 0;

	/* Sanity - don't allow something larger than 6 bytes + colons */
	if (strnlen(eth_macaddr, QCSAPI_SIZE_ETHER_ADDR + 1) > QCSAPI_SIZE_ETHER_ADDR) {
		return NULL;
	}
	for (i = 0; i < QCSAPI_SIZE_ETHER_ADDR - 1; i++) {
		if (*cp == ':') {
			colons_found++;
			cp++;
		} else if (*cp == '\0') {
			/* Let ether_aton deal with the string */
			break;
		}
		if (!isxdigit(*cp)) {
			return NULL;
		}
		cp++;
	}
	if (colons_found == 5) {
		return ether_aton(eth_macaddr);
	}
	return NULL;
}

static int
local_locate_iwpriv_cmd(const char		*cmd,
			struct iw_priv_args	*priv,
			int			 priv_num,
			int			*subcmd,
			int			*offset
)
{
	int i, j;

	for (i = 0; i < priv_num; i++)
		if (strcmp(priv[i].name, cmd) == 0) break;

	if (i == priv_num) {
		return(-EOPNOTSUPP);
	}

	/* Special case - private ioctls, need to find the full ioctl number */
	if (priv[i].cmd < SIOCDEVPRIVATE) {
		for (j = 0; j < priv_num; j++)
			if ((priv[j].name[0] == '\0') &&
			    (priv[j].set_args == priv[i].set_args) &&
			    (priv[j].get_args == priv[i].get_args))
				break;

		if (j == priv_num) {
			return( -EOPNOTSUPP );
		}

		*subcmd = priv[i].cmd;
		*offset = sizeof(__u32);
		i = j;
	}

	return i;
}

static int
local_prepare_iwpriv_wrq(int skfd,
			const char *ifname,
			struct iw_priv_args *priv,
			char *argv[],
			int argc,
			struct iwreq *wrq,
			u_char *buffer,
			int buffer_size
)
{
	int temp;
	int i = -1;
	int args_size = priv->set_args & IW_PRIV_SIZE_MASK;

	if (argc > args_size)
		argc = args_size;

	if ((priv->set_args & IW_PRIV_TYPE_MASK) == IW_PRIV_TYPE_CHAR) {
		if (argc > 0) {
			wrq->u.data.length = strlen(argv[0]) + 1;
			if (wrq->u.data.length > args_size )
				wrq->u.data.length = args_size;
			if (wrq->u.data.length >= buffer_size - 1)
				wrq->u.data.length = buffer_size - 1;
		} else
			wrq->u.data.length = 1;
	} else {
		wrq->u.data.length = argc;
	}


	if ((priv->set_args & IW_PRIV_SIZE_FIXED) &&
	    (wrq->u.data.length != args_size)) {
		local_generic_syslog(QCSAPI_WIFI_IWPRIV_SYSLOG_FACILITY,
				     LOG_ERR,
				    "Needs exactly %d argument(s)...\n",
				     priv->set_args & IW_PRIV_SIZE_MASK);
		return( -EOPNOTSUPP );
	}

	switch (priv->set_args & IW_PRIV_TYPE_MASK)
	{
	case IW_PRIV_TYPE_BYTE:
		while (++i < argc) {
			sscanf(argv[i], "%i", &temp);
			buffer[i] = (char) temp;
		}
		break;

	case IW_PRIV_TYPE_INT:
		while (++i < argc )
			sscanf(argv[i], "%i", (__s32*)buffer + i);
		break;

	case IW_PRIV_TYPE_CHAR:
		if (argc > 0) {
			memcpy(buffer, argv[0], wrq->u.data.length);
			buffer[wrq->u.data.length] = '\0';
		} else {
			buffer[0] = '\0';
		}
		break;

	case IW_PRIV_TYPE_FLOAT:
		printf("Unsupported float type for iwpriv\n");
		local_generic_syslog(QCSAPI_WIFI_IWPRIV_SYSLOG_FACILITY,
				     LOG_ERR,
				    "Float type is not supported...\n");
		return( -EOPNOTSUPP );
		break;

	case IW_PRIV_TYPE_ADDR:
		while (++i < argc) {
			struct ether_addr *aton_ret;
			aton_ret = local_ether_aton(argv[i]);
			struct sockaddr *csa = ((struct sockaddr *)buffer) + i;

			if (aton_ret == NULL) {
				local_generic_syslog(QCSAPI_WIFI_IWPRIV_SYSLOG_FACILITY,
						LOG_ERR,
						"Invalid address [%s]...\n", argv[i]);
				return -EPERM;
			}
			csa->sa_family = AF_INET;
			memcpy(csa->sa_data, aton_ret, 6);
		}
		break;

	default:
		local_generic_syslog(QCSAPI_WIFI_IWPRIV_SYSLOG_FACILITY,
				     LOG_ERR,
				    "Args [0x%x] not implemented...\n", priv->set_args);
		return( -EOPNOTSUPP );
	}

	return 0;
}

static int
local_get_priv_args_size(int	args)
{
	int num = args & IW_PRIV_SIZE_MASK;

	switch (args & IW_PRIV_TYPE_MASK)
	{
	case IW_PRIV_TYPE_BYTE:
	case IW_PRIV_TYPE_CHAR:
		return num;
		break;
	case IW_PRIV_TYPE_INT:
		return num * sizeof(__u32);
		break;
	case IW_PRIV_TYPE_ADDR:
		return num * sizeof(struct sockaddr);
		break;
	case IW_PRIV_TYPE_FLOAT:
		return num * sizeof(struct iw_freq);
	default:
		return 0;
		break;
	}
}
static int
local_parse_iwpriv_result(struct iw_priv_args *priv,
			struct iwreq *wrq,
			u_char *data,
			void* result,
			__u32 size
)
{
	int	c = 0;

	/* get number of the returned data */
	if ((priv->get_args & IW_PRIV_SIZE_FIXED) &&
	    (local_get_priv_args_size(priv->get_args) <= IFNAMSIZ)) {
		memcpy(data, wrq->u.name, IFNAMSIZ);
		c = priv->get_args & IW_PRIV_SIZE_MASK;
	} else {
		c = wrq->u.data.length;
	}

	switch (priv->get_args & IW_PRIV_TYPE_MASK)
	{
	case IW_PRIV_TYPE_CHAR:
		if (size > c) {
			data[c] = '\0';
			strcpy(result, (char*)data);
		} else {
			return( -ENOMEM );
		}
		break;

	case IW_PRIV_TYPE_INT:
		c *= sizeof(__s32);
		/* continue copying data */
	case IW_PRIV_TYPE_BYTE:
		if (size >= c) {
			memcpy(result, (void*)data, c);
		} else {
			return( -ENOMEM );
		}
		break;

	default:
		local_generic_syslog(QCSAPI_WIFI_IWPRIV_SYSLOG_FACILITY,
				     LOG_ERR,
				    "Not yet implemented...\n");
		return( -EOPNOTSUPP );
	}

	return 0;
}

int
local_wifi_option_getparam( const int skfd, const char *ifname, const int param, int *p_value )
{
       int              retval = 0;
       char             getparam_index[4];
       char            *argv[] = { &getparam_index[0] };
       const int        argc = sizeof( argv ) / sizeof( argv[ 0 ] );
       __s32            value;

       snprintf( &getparam_index[ 0 ], sizeof(getparam_index), "%d", param);
       retval = call_private_ioctl(
         skfd,
         argv, argc,
         ifname,
        "getparam",
        &value,
         sizeof( __s32 )
       );

       if (retval >= 0)
       {
               *p_value= (int) value;
       }

       return( retval );
}

static int local_is_emac_rgmii(uint32_t emac_flags)
{
	return ((emac_flags & EMAC_IN_USE) != 0) &&
		((emac_flags & EMAC_PHY_NOT_IN_USE) != 0) &&
		((emac_flags & EMAC_PHY_MII) == 0);
}

static int local_get_interface_types(string_64 p_buffer)
{
	char tmp_value[20] = {'\0'};
	int ival, have_eth = 0, have_rgmii = 0;

	ival = local_boardparam_get_parameter(
		"emac0",
		&tmp_value[0],
		sizeof(tmp_value));

	if (ival >= 0) {
		ival = atoi(&tmp_value[0]);
		if (local_is_emac_rgmii(ival)) {
			have_rgmii = 1;
		} else if ((ival & EMAC_IN_USE) != 0) {
			have_eth = 1;
		}
	}

	ival = local_boardparam_get_parameter(
		"emac1",
		&tmp_value[0],
		sizeof(tmp_value));

	if (ival >= 0) {
		ival = atoi(&tmp_value[0]);
		if (local_is_emac_rgmii(ival)) {
			have_rgmii = 1;
		} else if ((ival & EMAC_IN_USE) != 0) {
			have_eth = 1;
		}
	}

	ival = local_boardparam_get_parameter(
		"bd_pcie",
		&tmp_value[0],
		sizeof(tmp_value));

	if ((ival >= 0) && (atoi(&tmp_value[0]) != PCIE_NOT_IN_USE)) {
		strcat(p_buffer, "PCIe,");
	}

	if (have_rgmii) {
		strcat(p_buffer, "RGMII,");
	}

	if (have_eth) {
		strcat(p_buffer, "ETH,");
	}

	ival = strlen(p_buffer);

	if (ival > 0) {
		p_buffer[ival - 1] = '\0';
	}

	return 0;
}

int
call_private_ioctl(int		skfd,
		char *		argv[],
		int		argc,
		const char *	ifname,
		const char *	cmd,
		void *		result_addr,
		unsigned int	result_size
)
{
	enum {
		iwpriv_buffer_size = 4096
	};
	struct iwreq	 wrq;
	u_char		*buffer = NULL;
	int		 subcmd = 0;	/* sub-ioctl index */
	int		 offset = 0;	/* Space for sub-ioctl index */
	int		 ret = 0;
	struct iw_priv_args	*priv_args;
	struct iw_priv_args	*priv = NULL;
	int		 priv_num;
	int		 index;

	ret = local_get_priv_ioctls(skfd, ifname, &priv_num, &priv);
	if (ret < 0)
		goto ready_to_return;

	if (priv_num <= 0 || priv == NULL) {
		ret = -EOPNOTSUPP;
		goto ready_to_return;
	}

	if((argc >= 1) && (sscanf(argv[0], "[%i]", &subcmd) == 1)) {
		argv++;
		argc--;
	}

	index = local_locate_iwpriv_cmd(cmd, priv, priv_num, &subcmd, &offset);
	if (index < 0) {
		local_generic_syslog(QCSAPI_WIFI_IWPRIV_SYSLOG_FACILITY,
				     LOG_ERR,
				    "Invalid command: %s.\n",
				     cmd);
		ret = -EOPNOTSUPP;
		goto ready_to_return;
	}
	priv_args = &priv[index];

	if ((buffer = (u_char *) malloc( iwpriv_buffer_size )) == NULL) {
		ret = -ENOMEM;
		goto ready_to_return;
	}
	memset(buffer, 0, iwpriv_buffer_size);

	memset((u_char*)&wrq, 0, sizeof(wrq));
	if ((priv_args->set_args & IW_PRIV_TYPE_MASK) &&
	    (priv_args->set_args & IW_PRIV_SIZE_MASK)) {
		if (local_prepare_iwpriv_wrq(skfd, ifname, priv_args, argv, argc,
				&wrq, buffer, iwpriv_buffer_size) != 0) {
			ret = -EPERM;
			goto ready_to_return;
		}
	}

	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

	if ((priv_args->set_args & IW_PRIV_SIZE_FIXED) &&
	   ((local_get_priv_args_size(priv_args->set_args) + offset) <= IFNAMSIZ)) {
		/* all SET args fit within wrq */
		if (offset) wrq.u.mode = subcmd;
		memcpy(wrq.u.name + offset, buffer, IFNAMSIZ - offset);
	} else if ((priv_args->set_args == 0) &&
		    (priv_args->get_args & IW_PRIV_SIZE_FIXED) &&
		    (local_get_priv_args_size(priv_args->get_args) <= IFNAMSIZ)) {
		/* no SET args, GET args fit within wrq */
		if (offset) wrq.u.mode = subcmd;
	} else {
		/* argv won't fit in wrq, or variable number of argv */
		wrq.u.data.pointer = (caddr_t) buffer;
		wrq.u.data.flags = subcmd;
	}

	if (ioctl(skfd, priv_args->cmd, &wrq) < 0) {
		local_generic_syslog(QCSAPI_WIFI_IWPRIV_SYSLOG_FACILITY,
				     LOG_ERR,
				    "Interface %s doesn't accept private ioctl...\n", ifname);
		local_generic_syslog(QCSAPI_WIFI_IWPRIV_SYSLOG_FACILITY,
				     LOG_ERR,
				    "%s (%X): %s\n",
				     cmd, priv_args->cmd, strerror(errno));
		ret = -EOPNOTSUPP;
		goto ready_to_return;
	}

	if ((priv_args->get_args & IW_PRIV_TYPE_MASK) &&
	    (priv_args->get_args & IW_PRIV_SIZE_MASK)) {
		ret = local_parse_iwpriv_result(priv_args, &wrq, buffer,
						result_addr, result_size);
	}

  ready_to_return:
	if (buffer != NULL)
		free(buffer);

	return ret;
}

/* Keep in sync with enum qcsapi_wifi_mode */
const char *qcsapi_wifi_mode_str(const qcsapi_wifi_mode mode)
{
	switch (mode) {
	case qcsapi_mode_not_defined:
		return "undefined";
	case qcsapi_access_point:
		return "ap";
	case qcsapi_station:
		return "sta";
	case qcsapi_wds:
		return "wds";
	case qcsapi_repeater:
		return "repeater";
	case qcsapi_nosuch_mode:
	default:
		return "invalid";
		break;
	}
}

static int
local_swfeat_is_supported(const uint16_t feat)
{
	if (local_swfeat_map_init() < 0)
		return 0;

	if (feat >= SWFEAT_ID_MAX)
		return 0;

	if (!isset(qcsapi_swfeat_map, feat))
		return 0;

	return 1;
}

int
local_swfeat_check_supported(const uint16_t feat)
{
	if (!local_swfeat_is_supported(feat))
		return -qcsapi_not_supported;

	return 0;
}

int
local_print_swfeat_map(char *buf, const int len)
{
	int retval = 0;
        char ifname[IFNAMSIZ] = "";

        retval = local_get_primary_interface(ifname, sizeof(ifname) - 1);
	if (retval < 0)
		return retval;

	retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_PRINT_SWFEAT_MAP, buf, len);
	if (retval < 0)
		printf("Failed to get software feature map\n");

	return retval;
}

int
qcsapi_get_swfeat_list(string_4096 buf)
{
	int retval;

	enter_qcsapi();

	retval = local_print_swfeat_map(buf, sizeof(string_4096));

	leave_qcsapi();

	return retval;
}

int local_get_supported_spatial_streams(int *num_tx_ss, int *num_rx_ss)
{
	int retval = 0;

	retval = local_swfeat_map_init();
	if (retval < 0)
		return retval;

	if (isset(qcsapi_swfeat_map, SWFEAT_ID_4X4)) {
                *num_tx_ss = SS_4_STREAM_SUPPORTED;
                *num_rx_ss = SS_4_STREAM_SUPPORTED;
	} else if (isset(qcsapi_swfeat_map, SWFEAT_ID_2X4)) {
                *num_tx_ss = SS_2_STREAM_SUPPORTED;
                *num_rx_ss = SS_4_STREAM_SUPPORTED;
	} else if (isset(qcsapi_swfeat_map, SWFEAT_ID_2X2)) {
                *num_tx_ss = SS_2_STREAM_SUPPORTED;
                *num_rx_ss = SS_2_STREAM_SUPPORTED;
	} else {
                *num_tx_ss = SS_1_STREAM_SUPPORTED;
                *num_rx_ss = SS_1_STREAM_SUPPORTED;
	}

	return retval;
}

int local_wifi_get_chan_power_table(const char *ifname,
			struct ieee80211_chan_power_table *p_table)
{
	int retval = 0;

	if (ifname == NULL || p_table == NULL) {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		retval = local_interface_verify_net_device(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_sub_ioctl_submit(ifname,
				SIOCDEV_SUBIO_GET_CHANNEL_POWER_TABLE,
				p_table, sizeof(*p_table));
	}

	return retval;
}

int local_wifi_set_chan_power_table(const char *ifname,
			struct ieee80211_chan_power_table *p_table)
{
	int retval = 0;
	struct ieee80211_chan_power_table power_table;

	if (ifname == NULL || p_table == NULL) {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		retval = local_interface_verify_net_device(ifname);
	}

	if (retval >= 0) {
		memcpy(&power_table, p_table, sizeof(power_table));
		retval = local_wifi_sub_ioctl_submit(ifname,
				SIOCDEV_SUBIO_SET_CHANNEL_POWER_TABLE,
				&power_table, sizeof(power_table));
	}

	return retval;
}

static int local_get_max_bw(void)
{
	int max_bw = qcsapi_bw_80MHz;	/* all current boards */
	int i;

	for (i = 0; i < ARRAY_SIZE(qcsapi_bw_list); i++) {
		if (qcsapi_bw_list[i] >= max_bw)
			break;
	}

	return i;
}

static int local_get_bond_opt_info( string_64 p_buffer )
{
	int i;
	int j = 0;
	int retval;
	int len;
	int vht = 0;
	int max_bw_ent = local_get_max_bw();
	int tx_ss;
	int rx_ss;
	int first = 1;

	retval = local_swfeat_map_init();
	if (retval < 0)
		return retval;

	if (isset(qcsapi_swfeat_map, SWFEAT_ID_VHT))
		vht = 1;

	retval = local_get_supported_spatial_streams(&tx_ss, &rx_ss);
	if (retval < 0)
		return retval;

	len = sprintf(&p_buffer[j], "VHT:%d TX_SS:%d RX_SS:%d BW:",
		vht, tx_ss, rx_ss);
	 j += len;

	for (i = 0; i <= max_bw_ent; i++, j += len) {
		len = sprintf(&p_buffer[j], "%s%d",
			first ? "" : ",",
			qcsapi_bw_list[i]);
		if (len <= 0)
			 break;
		first = 0;
	}

        return 0;
}

/*
 * Assumes ifname has been verified as a WiFi (Wireless Extensions) device
 */
static int
local_wifi_set_private_int_param_by_name(const int skfd,
					 const char *ifname,
					 const char *param_name,
					 const int param_val)
{
	int		retval = 0;
	char		setparam_value[ 12 ];
	char		*argv[] = { &setparam_value[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );

	snprintf(&setparam_value[ 0 ], sizeof( setparam_value ), "%d", param_val );

	retval = call_private_ioctl(
	  skfd,
	  argv, argc,
	  ifname,
	  param_name,
	  NULL,
	  0
	);

	return( retval );
}

static int
local_wifi_get_private_int_param_by_name(const int skfd,
					 const char *ifname,
					 const char *param_name,
					 int *p_value)
{
	int	 retval = 0;
	char	**argv = NULL;
	int	 argc = 0;
	__s32	 local_value;

	retval = call_private_ioctl(
		  skfd,
		  argv, argc,
		  ifname,
		  param_name,
	(void *) &local_value,
		  sizeof( __s32 )
	);

	if (retval >= 0) {
		*p_value = (int) local_value;
	}

	return( retval );
}

static int
local_wifi_get_mu_use_precode(int skfd, const char *ifname,
	const qcsapi_unsigned_int grp, int *mu_precode)
{
	int		 retval = 0;
	char		 getparam_str[ 12 ];
	char		*argv[] = { &getparam_str[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );
	u_int32_t	 getparam_int = IEEE80211_PARAM_GET_MU_GRP_QMAT + (grp << 16);
	__s32		 local_mu_precode;

	snprintf( &getparam_str[ 0 ], sizeof( getparam_str ), "%u", getparam_int );

	retval = call_private_ioctl(skfd,
				 argv, argc,
				 ifname,
				"getparam",
				&local_mu_precode,
				 sizeof( local_mu_precode ));

	if (retval >= 0) {
		*mu_precode = (int) local_mu_precode;
	}

	return( retval );
}

int
local_wifi_get_bandwidth( const int skfd, const char *ifname, qcsapi_bw *p_bw )
{
	int	 retval = 0;
	char	 getparam_index[ 8 ];
	char	*argv[] = { &getparam_index[ 0 ] };
	int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );
	__s32	 bandwidth;

	snprintf( &getparam_index[ 0 ], sizeof(getparam_index), "%d", IEEE80211_PARAM_BW_SEL_MUC);
	retval = call_private_ioctl(
		  skfd,
		  argv, argc,
		  ifname,
		 "getparam",
	(void *) &bandwidth,
		  sizeof( __s32 )
	);

	if (retval >= 0)
	{
		*p_bw = bandwidth;
	}

	return( retval );
}

int
local_wifi_get_hw_options(int *hw_options)
{
	int retval = 0;
	char hw_options_from_qdrv[12];

	retval = local_wifi_write_to_qdrv("get 0 hw_options");
	if (retval < 0) {
		return retval;
	}

	retval = local_read_string_from_file(QDRV_RESULTS, hw_options_from_qdrv,
			sizeof(hw_options_from_qdrv));

	if (retval >= 0 && strlen(hw_options_from_qdrv) > 0) {
		*hw_options = atoi(hw_options_from_qdrv);
	}

	return retval;
}

int
local_wifi_get_power_table_checksum(char *fname, char *checksum_buf, int bufsize)
{
	int retval = 0;
	char cmd_buf[128];

	snprintf(&cmd_buf[0], sizeof(cmd_buf), "get 0 power_table_checksum %s", fname);

	retval = local_wifi_write_to_qdrv(cmd_buf);
	if (retval < 0) {
		return retval;
	}

	retval = local_read_string_from_file(QDRV_RESULTS, checksum_buf, bufsize);

	return retval;
}

int
local_wifi_get_rf_chipid(int *chipid)
{
	int retval = 0;
	char hw_chipid_str[12];

	retval = local_wifi_write_to_qdrv("get 0 rf_chipid");
	if (retval < 0) {
		return retval;
	}

	retval = local_read_string_from_file(QDRV_RESULTS, hw_chipid_str,
			sizeof(hw_chipid_str));

	if (retval >= 0 && strlen(hw_chipid_str) > 0) {
		*chipid = atoi(hw_chipid_str);
	}

	return retval;
}

static int
local_wifi_option_get_802_11h( const int skfd, const char *ifname, int *p_config_802_11h )
{
	int		 retval = 0;
	__s32		 local_802_11h;
	char		*argv[] = { NULL };
	int		 argc = 0;
	char curr_region_name[QCSAPI_MIN_LENGTH_REGULATORY_REGION];

	retval = local_get_internal_regulatory_region(skfd, ifname, curr_region_name);

	if (retval >= 0 && strcmp(curr_region_name,"none") == 0) {
		//11h is not supported
		retval = -qcsapi_option_not_supported;
	}

	if (retval >= 0) {
		retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"get_doth",
			(void *) &local_802_11h,
			sizeof( __s32 )
		);
	}

	if (retval >= 0)
		*p_config_802_11h = (int) local_802_11h;

	return( retval );
}

static int
local_wifi_option_set_802_11h( const int skfd, const char *ifname, const int config_802_11h )
{
	int		 retval = 0;
	char		 setparam_value[ 4 ];
	char		*argv[] = { &setparam_value[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );

	char curr_region_name[QCSAPI_MIN_LENGTH_REGULATORY_REGION];

	retval = local_get_internal_regulatory_region(skfd, ifname, curr_region_name);

	if (retval >= 0 && strcmp(curr_region_name,"none") == 0) {
		//11h is not supported
		retval = -qcsapi_option_not_supported;
	}

	if (retval >= 0) {
		if (config_802_11h)
			strcpy( &setparam_value[ 0 ], "1" );
		else
			strcpy( &setparam_value[ 0 ], "0" );

		retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"doth",
			NULL,
			0
		);
	}
	return( retval );
}

static int
local_wifi_option_set_sta_dfs(const int skfd, const char *ifname, const int config_sta_dfs)
{
	int retval = 0;
	char setparam_value[4];
	char *argv[] = { &setparam_value[ 0 ] };
	const int argc = sizeof( argv ) / sizeof( argv[ 0 ] );

	if (config_sta_dfs) {
		strcpy(&setparam_value[0], "1");
	} else {
		strcpy(&setparam_value[0], "0");
	}
	retval = call_private_ioctl (
		skfd,
		argv, argc,
		ifname,
		"sta_dfs",
		NULL,
		0
	);

	return retval;
}

static int
local_wifi_option_get_tpc_query( const int skfd, const char *ifname, int *p_config_tpc_query )
{
	int	 retval = 0;
	__s32	 local_802_tpc_query;
	char	*argv[] = { NULL };
	int	 argc = 0;

	retval = call_private_ioctl(
		  skfd,
		  argv, argc,
		  ifname,
		 "get_tpc_query",
	(void *) &local_802_tpc_query,
		  sizeof( __s32 )
	);

	if (retval >= 0)
		*p_config_tpc_query = (int) local_802_tpc_query;

	return( retval );
}

static int
local_wifi_option_set_tpc_query( const int skfd, const char *ifname, const int config_tpc_query )
{
	int		 retval = 0;
	char		 setparam_value[ 4 ];
	char		*argv[] = { &setparam_value[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );

	if (config_tpc_query)
		strcpy( &setparam_value[ 0 ], "1" );
	else
		strcpy( &setparam_value[ 0 ], "0" );

	retval = call_private_ioctl(
	  skfd,
	  argv, argc,
	  ifname,
	 "tpc_query",
	  NULL,
	  0
	);

	return( retval );
}

static int
local_wifi_option_get_dfs_fast_switch( const int skfd, const char *ifname, int *p_dfs_fast_switch )
{
	int		 retval = 0;
	__s32		 local_dfs_fast_switch;
	char		*argv[] = { NULL };
	int		 argc = 0;

	retval = call_private_ioctl(
		  skfd,
		  argv, argc,
		  ifname,
		 "get_dfs_switch",
	(void *) &local_dfs_fast_switch,
		  sizeof( __s32 )
	);

	if (retval >= 0)
	  *p_dfs_fast_switch = (int) local_dfs_fast_switch;

	return( retval );
}

static int
local_wifi_option_set_dfs_fast_switch( const int skfd, const char *ifname, const int dfs_fast_switch )
{
	int		 retval = 0;
	char		 setparam_value[ 4 ];
	char		*argv[] = { &setparam_value[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );

	if (dfs_fast_switch)
	  strcpy( &setparam_value[ 0 ], "1" );
	else
	  strcpy( &setparam_value[ 0 ], "0" );

	retval = call_private_ioctl(
	  skfd,
	  argv, argc,
	  ifname,
	 "dfs_fast_switch",
	  NULL,
	  0
	);

	return( retval );
}

static int
local_wifi_option_get_avoid_dfs_scan( const int skfd, const char *ifname, int *p_avoid_dfs_scan )
{
	int		 retval = 0;
	__s32		 local_avoid_dfs_scan;
	char		*argv[] = { NULL };
	int		 argc = 0;

	retval = call_private_ioctl(
		  skfd,
		  argv, argc,
		  ifname,
		 "get_scan_dfs",
	(void *) &local_avoid_dfs_scan,
		  sizeof( __s32 )
	);

	if (retval >= 0)
	  *p_avoid_dfs_scan = (int) local_avoid_dfs_scan;

	return( retval );
}

static int
local_wifi_option_set_avoid_dfs_scan( const int skfd, const char *ifname, const int avoid_dfs_scan )
{
	int		 retval = 0;
	char		 setparam_value[ 4 ];
	char		*argv[] = { &setparam_value[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );

	if (avoid_dfs_scan)
	  strcpy( &setparam_value[ 0 ], "1" );
	else
	  strcpy( &setparam_value[ 0 ], "0" );

	retval = call_private_ioctl(
	  skfd,
	  argv, argc,
	  ifname,
	 "scan_no_dfs",
	  NULL,
	  0
	);

	return( retval );
}

static int
local_wifi_get_802_11_mode( const int skfd, const char *ifname, char *wifi_802_11_mode )
{
	int			retval = 0;
	char		*argv[] = { NULL };
	int			argc = 0;
	string_64	phy_mode;

	retval = call_private_ioctl(
					skfd,
					argv, argc,
					ifname,
					"get_mode",
					(void *) phy_mode,
					sizeof(string_64));

	if (retval >= 0)
	{
		sprintf(wifi_802_11_mode, "%s", phy_mode);
	}

	return( retval );
}

static int
local_wifi_set_802_11_mode( const int skfd, const char *ifname, const char *wifi_802_11_mode )
{
	int	 retval = 0;
	char	*argv[] = { (char *)wifi_802_11_mode };
	int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );

	retval = call_private_ioctl(
		  skfd,
		  argv, argc,
		  ifname,
		 "mode",
		  NULL,
		  0
	);

	return( retval );
}

static int
local_wifi_option_set_iwpriv_bw( const int skfd, const char *ifname, const qcsapi_bw the_bw )
{
	int retval = 0;
	char setparam_index[4];
	char setparam_value[4];
	char *argv[] = { &setparam_index[0], &setparam_value[0] };
	const int argc = ARRAY_SIZE(argv);

	if ((the_bw > qcsapi_bw_40MHz) && !local_swfeat_is_supported(SWFEAT_ID_VHT))
		return -EOPNOTSUPP;

	switch (the_bw) {
	case qcsapi_bw_20MHz:
		strcpy(setparam_value, "20");
		break;
	case qcsapi_bw_40MHz:
		strcpy(setparam_value, "40");
		break;
	case qcsapi_bw_80MHz:
		strcpy(setparam_value, "80");
		break;
	case qcsapi_bw_160MHz:
		strcpy(setparam_value, "160");
		break;
	default:
		return -EOPNOTSUPP;
	}

	snprintf(setparam_index, sizeof(setparam_index), "%d", IEEE80211_PARAM_BW_SEL_MUC);

	retval = call_private_ioctl(skfd, argv, argc, ifname, "setparam", NULL, 0);

	return retval;
}

static int
local_wifi_option_set_iwpriv_wmm( const int skfd, const char *ifname, int wmm_on)
{
	int		 retval = 0;
	char		 setparam_index[ 4 ], setparam_value[ 4 ];
	char		*argv[] = { &setparam_index[ 0 ],  &setparam_value[ 0 ] };
	const int	 argc = ARRAY_SIZE(argv);
	int		 ival;

	if (wmm_on) {
		strcpy( &setparam_value[0], "1");
	} else {
		strcpy( &setparam_value[0], "0");
	}

	snprintf( &setparam_index[ 0 ], sizeof(setparam_index), "%d", IEEE80211_PARAM_WMM);

	ival = call_private_ioctl(
				skfd,
				argv, argc,
				ifname,
				"setparam",
				NULL,
				0);

	if (ival < 0)
		retval = ival;

	return( retval );
}

static int
local_wifi_get_mcs_rate( const int skfd, const char *ifname, int *p_internal_mcs )
{
	int		 retval = 0;
	__s32		 internal_mcs;
	char		*argv[] = { NULL };
	int		 argc = 0;

	retval = call_private_ioctl(
		  skfd,
		  argv, argc,
		  ifname,
		 "get_fixedtxrate",
	(void *) &internal_mcs,
		  sizeof( __s32 )
	);

	if (retval >= 0)
	  *p_internal_mcs = (int) internal_mcs;

	return( retval );
}

static int
local_wifi_set_mcs_rate(const int skfd, const char *ifname,
		const int32_t internal_mcs)
{
	int retval = 0;
	char local_mcs_string[12];
	char setparam_index[4];
	char *argv[] = {&setparam_index[0], &local_mcs_string[0]};
	const int argc = sizeof(argv) / sizeof(argv[0]);

	snprintf(&setparam_index[0], sizeof(setparam_index), "%d", IEEE80211_PARAM_FIXED_TX_RATE);
	snprintf(&local_mcs_string[0], sizeof(local_mcs_string), "0x%x", internal_mcs);

	retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"setparam",
			NULL,
			0);

	return retval;
}

static int
get_wifi_base_frequency( int skfd, const char *ifname, qcsapi_base_frequency *p_base_frequency )
{
	int		 retval = 0;

	retval = verify_we_device( skfd, ifname, NULL, 0 );

	if (retval >= 0)
	{
		char	 getparam_index[ 4 ];
		char	*argv[] = { &getparam_index[ 0 ] };
		int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );
		int32_t	 basefreq_flag;

		snprintf( &getparam_index[ 0 ], sizeof(getparam_index), "%d", IEEE80211_PARAM_GET_RFCHIP_ID);
		retval = call_private_ioctl(
			  skfd,
			  argv, argc,
			  ifname,
			 "getparam",
		(void *) &basefreq_flag,
			  sizeof(int32_t)
		);

		if (retval >= 0)
	        {
		  /*
		   * follow the model in wireless.php
		   */
			if (basefreq_flag == CHIPID_2_4_GHZ)
				*p_base_frequency = qcsapi_2_4_GHz;
			else if (basefreq_flag == CHIPID_5_GHZ)
				*p_base_frequency = qcsapi_5_GHz;
			else if (basefreq_flag == CHIPID_DUAL)
				*p_base_frequency = qcsapi_dual;
			else
				*p_base_frequency = qcsapi_5_GHz;
                }
	}

	return( retval );
}

const char *
get_default_region_name( qcsapi_regulatory_region the_region )
{
	const char	*retaddr = NULL;
	unsigned int	 iter;

	for (iter = 0; iter < regulatory_region_size && retaddr == NULL; iter++)
	{
		if (the_region == regulatory_region_name[ iter ].the_region)
		  retaddr = regulatory_region_name[ iter ].the_name;
	}

	return( retaddr );
}

int
local_verify_wifi_mode(
	const int skfd,
	const char *ifname,
	qcsapi_wifi_mode required_wifi_mode,
	qcsapi_wifi_mode *p_wifi_mode)
{
	qcsapi_wifi_mode	current_mode = qcsapi_mode_not_defined;
	int			retval = local_wifi_get_mode(skfd, ifname, &current_mode);

	if (retval < 0) {
		return retval;
	}

	if (current_mode != required_wifi_mode) {
		if (required_wifi_mode == qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
		} else if (required_wifi_mode == qcsapi_station) {
			retval = -qcsapi_only_on_STA;
		} else if (required_wifi_mode == qcsapi_wds) {
			retval = -qcsapi_only_on_wds;
		} else {
			retval = -qcsapi_programming_error;
		}
	}

	if (p_wifi_mode != NULL) {
		*p_wifi_mode = current_mode;
	}

	return retval;
}

int
local_verify_repeater_mode(const int skfd, qcsapi_wifi_mode *wifi_mode)
{
	int retval = 0;
	char getparam_index[4] = {0};
	char *argv[] = {&getparam_index[0]};
	const int argc = ARRAY_SIZE(argv);
	int ioctl_result = 0;
	char primary_ifname[IFNAMSIZ] = {0};

	*wifi_mode = qcsapi_nosuch_mode;

	retval = local_get_primary_interface(primary_ifname, sizeof(primary_ifname) - 1);
	if (retval < 0) {
		return retval;
	}

	snprintf(&getparam_index[0], sizeof(getparam_index), "%d", IEEE80211_PARAM_REPEATER);

	retval = call_private_ioctl(
			skfd,
			argv, argc,
			primary_ifname,
			"getparam",
			&ioctl_result,
			sizeof(ioctl_result));
	if (retval < 0) {
		return retval;
	}

	if (ioctl_result == 1) {
		*wifi_mode = qcsapi_repeater;
	}

	return 0;
}

int
local_set_internal_regulatory_region(int skfd,
		const char *ifname,
		const char *default_regulatory_region,
		int board_provision_enabled)
{
	int		 retval = 0;

	retval = verify_we_device( skfd, ifname, NULL, 0 );

	if (retval >= 0) {
		char		 setparam_str[ 12 ];
		char		*argv[] = { &setparam_str[ 0 ] };
		const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );
		union {
			u_int32_t	as_u32;
			char		as_chars[ 4 ];
		} setparam_value;

		strncpy( &setparam_value.as_chars[ 0 ], default_regulatory_region, sizeof( setparam_value ) );
		setparam_value.as_chars[ sizeof( setparam_value ) - 1 ] = '\0';

		sprintf( &setparam_str[ 0 ], "%d", (int) setparam_value.as_u32 );

		retval = call_private_ioctl(
		    skfd,
		    argv, argc,
		    ifname,
		    "region",
		    NULL,
		    0
		    );

		/*
		 * ONLY enable 802.11d for board provisioning
		 */
		if (retval >= 0 && local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL) >= 0) {
			if (board_provision_enabled) {
				const char *eu_region = NULL;
				eu_region = get_default_region_name(QCSAPI_REGION_EUROPE);

				/* Prevent to use wrong region(For board provision, region name should be country name) */
				if (strcasecmp(eu_region, default_regulatory_region) == 0) {
					strcpy(setparam_str, "0");
					local_generic_syslog( "802.11d Set country code", LOG_NOTICE,
						"Region %s, Disable country IE support. Region name should be a country name.",
						default_regulatory_region);
				} else {
					strcpy(setparam_str, "1");
					local_generic_syslog( "802.11d Set country code", LOG_NOTICE,
						"country code set to %s",
						default_regulatory_region);
				}
			} else {
				strcpy(setparam_str, "0");
			}

			/* Enable/disable country IE */
			retval = call_private_ioctl(
			  skfd,
			  argv, argc,
			  ifname,
			 "countryie",
			  NULL,
			  0
			);
		}
	}

	return( retval );
}

int
local_get_internal_regulatory_region( int skfd, const char *ifname, char *region_by_name )
{
	int		 retval = verify_we_device( skfd, ifname, NULL, 0 );
	union {
		u_int32_t	as_u32;
		char		as_chars[ 4 ];
	} getparam_value;

	if (retval >= 0) {
		char	*argv[] = { NULL };
		int	 argc = 0;

		retval = call_private_ioctl(
			  skfd,
			  argv, argc,
			  ifname,
			 "get_region",
		(void *) &(getparam_value.as_u32),
			  sizeof( u_int32_t )
		);

	}
  /*
   * WLAN driver reports the regulatory region in UPPER CASE ...
   */
	if (retval >= 0) {
		if (strcmp( &(getparam_value.as_chars[ 0 ]), "NA" ) == 0 || getparam_value.as_u32 == 0) {
			strcpy(region_by_name, "none");
		}
		else {
			int	iter;

			for (iter = 0; iter < 4 && getparam_value.as_chars[ iter ] != '\0'; iter++) {
				getparam_value.as_chars[ iter ] = tolower( getparam_value.as_chars[ iter ] );
			}

			strncpy( region_by_name, &(getparam_value.as_chars[ 0 ]), 4 );
		}
	}

	return( retval );
}

int
local_get_tx_power( int skfd, const char *ifname, const qcsapi_unsigned_int the_channel, int *p_tx_power)
{
	int		 retval = 0;
	char		 getparam_str[ 12 ];
	char		*argv[] = { &getparam_str[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );
	u_int32_t	 getparam_int = IEEE80211_PARAM_CONFIG_TXPOWER + (the_channel << 16);
	__s32		 local_tx_power;

	snprintf( &getparam_str[ 0 ], sizeof( getparam_str ), "%u", getparam_int );

	retval = call_private_ioctl(skfd,
				 argv, argc,
				 ifname,
				"getparam",
				&local_tx_power,
				 sizeof( __s32 ));

	if (retval >= 0) {
		*p_tx_power = (int) local_tx_power;
	}

	return( retval );
}

static int
local_get_assoc_records(int skfd, const char *ifname, struct qcsapi_assoc_records *assoc_record)
{
	int				retval=0;
	struct ieee80211_assoc_history	from_driver;

	retval = call_private_ioctl(skfd,
				 NULL, 0,
				 ifname,
				"assoc_history",
				&from_driver,
				 sizeof(from_driver));

	if (retval >= 0) {
		memcpy(&assoc_record->addr[0][0],
		       &from_driver.ah_macaddr_table[0][0],
			sizeof(assoc_record->addr));
		memcpy(&assoc_record->timestamp[0],
		       &from_driver.ah_timestamp[0],
			sizeof(assoc_record->timestamp));
	}

	return retval;
}

static int
local_reset_assoc_records(int skfd, const char *ifname)
{
	int retval=0;
	char *argv[]={"notused"};

	retval = call_private_ioctl(skfd,
				 argv, 1,
				 ifname,
				"reset_assoc_his",
				 NULL,
				 0);

	return retval;
}

static int
local_wifi_option_get_vht ( const int skfd, const char *ifname, qcsapi_11nac_stat *pvht)
{
	int		 retval = 0;
	char	*argv[] = { "2" };
	int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );
	__s32	phymode;

	retval = call_private_ioctl(
	  skfd,
	  argv, argc,
	  ifname,
	 "getparam",
	  (void *) &phymode,
	  sizeof( __s32 )
	);

	if (retval >= 0) {
		*pvht = phymode;
	}

	return( retval );
}


static int
local_wifi_option_set_vht ( const int skfd, const char *ifname, const qcsapi_11nac_stat the_vht)
{
	int		 retval = 0;
	char		 setparam_index[ 4 ], setparam_value[ 4 ];
	char		*argv[] = { &setparam_index[ 0 ],  &setparam_value[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );

	if (the_vht == qcsapi_11nac_enable)
		strcpy( &setparam_value[ 0 ], "1" );
	else if (the_vht == qcsapi_11nac_disable)
                strcpy( &setparam_value[ 0 ], "0" );
	else {
		printf("!! ERROR: Invalid Entry\n");
		printf(" Please enter 1 for 11ac mode and 0 for 11n mode\n");
		return retval;
	}
	strcpy( &setparam_index[ 0 ], "2" );

	retval = call_private_ioctl(
	  skfd,
	  argv, argc,
	  ifname,
	 "setparam",
	  NULL,
	  0
	);

	return retval;
}

static int
local_wifi_option_get_disassoc_reason ( const int skfd, const char *ifname, qcsapi_unsigned_int *reason)
{
        int              retval = 0;
        char    *argv[] = { NULL };
        int      argc = 0;
        __s32   reason_code;

        retval = call_private_ioctl(
          skfd,
          argv, argc,
          ifname,
         "disassoc_reason",
          (void *) &reason_code,
          sizeof( __s32 )
        );

        if (retval >= 0) {
                *reason = reason_code;
        }

        return( retval );
}

int
qcsapi_wifi_reassociate(const char *ifname)
{
	int retval = 0;
	int skfd = -1;
	int argc = 1;
	char *argv[] = { "1" };

	enter_qcsapi();

	if (!ifname) {
		retval = -EFAULT;
	}

	if (retval >= 0) {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = call_private_ioctl(skfd,
					argv, argc,
					ifname,
					"cl_remove",
					NULL,
					0);
	}

	if (skfd >= 0) {
		close(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_assoc_records(const char *ifname,
			      int reset,
			      qcsapi_assoc_records *records)
{
	int			retval = 0;
	int			skfd = -1;


	enter_qcsapi();

	if (ifname == NULL || records == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0) {
			retval = skfd;
		}

		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_get_assoc_records(skfd, ifname, records);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (reset) {
		retval = local_reset_assoc_records(skfd, ifname);
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

static int
local_get_csw_records(int skfd, const char *ifname, qcsapi_csw_record * csw_record)
{
	int retval=0;
	retval = call_private_ioctl(skfd,
				 NULL, 0,
				 ifname,
				 "get_csw_record",
				 csw_record,
				 sizeof( qcsapi_csw_record ));

	return retval;
}

static int
local_clean_csw_records(int skfd, const char *ifname)
{
	int retval=0;
	char *argv[]={"notused"};

	retval = call_private_ioctl(skfd,
				 argv, 1,
				 ifname,
				 "clean_csw",
				 NULL,
				 0);

	return retval;
}

int
local_wifi_enable_country_ie( const int skfd, const char *ifname, const int32_t enable )
{
	int retval = 0;
	char setparam_str[12] = {0};
	char *argv[] = {&setparam_str[0]};
	const int argc = sizeof(argv) / sizeof(argv[0]);

	sprintf(setparam_str, "%d", enable);
	retval = call_private_ioctl(
				skfd,
				argv, argc,
				ifname,
				"countryie",
				NULL,
				0
	);

	return retval;
}

int
local_wifi_set_country_code( const int skfd, const char *ifname, const char *country_name )
{
	int retval = 0;
	char setparam_str[12] = {0};
	char *argv[] = {&setparam_str[0]};
	const int argc = sizeof(argv) / sizeof(argv[0]);
	union {
		uint32_t as_u32;
		char as_chars[4];
	} setparam_value;

	strncpy(&setparam_value.as_chars[0], country_name, sizeof(setparam_value) );
	setparam_value.as_chars[sizeof(setparam_value) - 1] = '\0';
	sprintf(&setparam_str[0], "%d", (int)setparam_value.as_u32);

	retval = call_private_ioctl(
				skfd,
				argv, argc,
				ifname,
				"country_code",
				NULL,
				0
	);

	return retval;
}

int
qcsapi_wifi_get_csw_records( const char *ifname, int reset, qcsapi_csw_record * record)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || record == NULL)
	      retval = -EFAULT;

	if (retval >= 0) {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	}

	if (retval >= 0) {
		if (wifi_mode == qcsapi_station) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = local_get_csw_records(skfd, ifname, record);
		if (reset) {
			retval = local_clean_csw_records(skfd, ifname);
		}
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return(retval);
}

int
qcsapi_wifi_get_radar_status(const char *ifname, qcsapi_radar_status *rdstatus)
{
	int	retval = 0;

	enter_qcsapi();

	if (ifname == NULL || rdstatus == NULL)
	      retval = -EFAULT;

	if (retval >= 0)
		retval = local_interface_verify_net_device(ifname);

	if (retval >= 0) {
		retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_RADAR_STATUS,
					(void *)rdstatus, sizeof(rdstatus));

		if (retval < 0)
			retval = -qcsapi_invalid_dfs_channel;
	}

	leave_qcsapi();

	return(retval);
}
/*
 */

#define FREQUENCY_OFFSET_PER_CHANNEL	5		/* MHz */
#define BASE_FREQUENCY_5_GHZ		5000		/* MHz, for "channel 0" */
#define FIRST_REGULAR_CHANNEL_5_GHZ	5180		/* Channel 36 */
#define LAST_REGULAR_CHANNEL_5_GHZ	169
#define FIRST_ROLLOVER_CHANNEL_5_GHZ	184
#define ROLLOVER_FREQUENCY_5_GHZ	4920		/* MHz, for channel 184 */
#define LAST_FREQUENCY_24_GHZ		2472		/* Channel 13. We ignore Japan channel 14 as it's non-standard and 11b only. */
#define FIRST_FREQUENCY_24_GHZ		2412		/* Channel 1 */

static int
local_freq2chan( const struct iw_freq *freq, const struct iw_range *range, qcsapi_base_frequency base_frequency, qcsapi_unsigned_int *p_channel )
{
	int	retval = 0;

	if ((base_frequency == qcsapi_5_GHz)
					|| (base_frequency == qcsapi_2_4_GHz)
					|| (base_frequency == qcsapi_dual)) {

		unsigned int		freq_in_MHz, divisor = 1000000;
		qcsapi_unsigned_int	local_channel = 0;

		/* Exclude values outside our calculation range capabilities */
		if (freq->e > 6 || freq->e < 0) {
			retval = -EOPNOTSUPP;
		} else if (freq->e > 0) {
			int	iter = freq->e;

			/* Calculate how many zeros we need to chop off with the divisor */
			while (iter > 0) {
				iter--;
				divisor = divisor / 10;
			}
		}

		if (retval == 0) {
			/* Frequency normalised to MHz, which we can then convert to a channel number */
			freq_in_MHz = freq->m / divisor;

			/* Case 1 - 5GHz channel outsize our supported range */
			if (((freq_in_MHz % FREQUENCY_OFFSET_PER_CHANNEL != 0) && (base_frequency == qcsapi_5_GHz)) ||
				freq_in_MHz > BASE_FREQUENCY_5_GHZ + LAST_REGULAR_CHANNEL_5_GHZ * FREQUENCY_OFFSET_PER_CHANNEL) {
				retval = -ERANGE;
			/* Case 2 - 2.4GHz channel */
			} else if (freq_in_MHz <= LAST_FREQUENCY_24_GHZ) {
				/* We don't support < channel 1 */
				if (freq_in_MHz < FIRST_FREQUENCY_24_GHZ) {
					retval = -ERANGE;
				} else {
					/* Channel is calculated based on first channel, add 1 to get the integer channel number */
					local_channel = ((freq_in_MHz - FIRST_FREQUENCY_24_GHZ) / FREQUENCY_OFFSET_PER_CHANNEL) + 1;
					if (local_channel > QCSAPI_MAX_CHANNEL) {
						retval = -ERANGE;
					}
				}
			/* Case 2 - the 4.9GHz channels */
			} else if (freq_in_MHz < BASE_FREQUENCY_5_GHZ) {
				local_channel = (freq_in_MHz - ROLLOVER_FREQUENCY_5_GHZ) / FREQUENCY_OFFSET_PER_CHANNEL + FIRST_ROLLOVER_CHANNEL_5_GHZ;
				if (local_channel > QCSAPI_MAX_CHANNEL) {
					retval = -ERANGE;
				}
			/* Case 3 - the 5GHz channels */
			} else {
				if (freq_in_MHz < FIRST_REGULAR_CHANNEL_5_GHZ) {
					retval = -ERANGE;
				} else {
					local_channel = (freq_in_MHz - BASE_FREQUENCY_5_GHZ) / FREQUENCY_OFFSET_PER_CHANNEL;
					if (local_channel > LAST_REGULAR_CHANNEL_5_GHZ) {
						retval = -ERANGE;
					}
				}
			}
			/* FIXME: Japan has some oddness in channels - this code doesn't account for that oddness. */
		}

		if (retval == 0) {
			*p_channel = local_channel;
		}
	} else {
		retval = -EOPNOTSUPP;
	}

	return  retval;
}

int
local_wifi_get_channel( int skfd, const char *ifname, unsigned int *p_new_channel )
{
	int			retval = 0;
	qcsapi_base_frequency	base_frequency;
	struct iwreq		wrq;
	struct iw_range		range;

	if (retval >= 0) {
		retval = local_get_we_range_data(skfd, ifname, &range);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = get_wifi_base_frequency( skfd, ifname, &base_frequency );
	}

	if (retval >= 0) {
		retval = local_priv_ioctl(skfd, ifname, SIOCGIWFREQ, &wrq);
	}

	if (retval >= 0) {
		qcsapi_unsigned_int	local_channel;

		retval = local_freq2chan( &(wrq.u.freq), &range, base_frequency, &local_channel );
		if (retval >= 0)
		  *p_new_channel = local_channel;
	}

	return( retval );
}

int
local_wifi_set_channel( int skfd, const char *ifname, const unsigned int new_channel )
{
	int		retval = 0;
	struct iwreq	wrq;
	//double		freq = (double) new_channel;
	unsigned int	old_channel;
	int scan_status = 0;
	qcsapi_interface_status_code status_code = qcsapi_interface_status_error;

	retval = local_interface_get_status(skfd, ifname, &status_code);
	if (retval < 0) {
		return retval;
	}

	retval = local_wifi_get_private_int_param_by_name(skfd, ifname, "get_scanstatus", &scan_status);
	if (retval < 0) {
		return retval;
	}

	/*
	 * Only check if new channel is same as old channel
	 * when interface is up and scan is not on going.
	 */
	if (scan_status == 0 && status_code == qcsapi_interface_status_running) {
		retval = local_wifi_get_channel(skfd, ifname, &old_channel);
		if (retval < 0) {
			return retval;
		}

		if (new_channel == old_channel)
			return 0;
	}

	memset( &wrq, 0, sizeof( wrq ) );

	wrq.u.freq.e = 0;
	wrq.u.freq.m = new_channel;

	local_generic_syslog( "Set Channel", LOG_NOTICE, "freq %d, wrq.u.freq.e %d, wrq.u.freq.m %d\n",
				new_channel, wrq.u.freq.e, wrq.u.freq.m);
	wrq.u.freq.flags = IW_FREQ_FIXED;

	retval = local_priv_ioctl(skfd, ifname, SIOCSIWFREQ, &wrq);
	if (retval < 0) {
		int	local_retval = -errno;

		if (local_retval < 0)
		  retval = local_retval;
	}

	return( retval );
}

int
local_wifi_set_chan_pri_inactive( int skfd, const char *ifname, unsigned int channel, unsigned int inactive, unsigned int flags)
{
	int retval = 0;
	char setparam_value[32];
	char id[8];
	char *argv[] = {id,  &setparam_value[0]};
	const int argc = ARRAY_SIZE(argv);
	uint32_t param_value;

	param_value = channel | ((!inactive) << 16) | ((flags & 0xff) << 24)  ;
	snprintf(id, sizeof(id), "%d", IEEE80211_PARAM_DEACTIVE_CHAN_PRI);

	snprintf(&setparam_value[0], sizeof(setparam_value), "0x%x", param_value);
	retval = call_private_ioctl(
	  skfd,
	  argv, argc,
	  ifname,
	 "setparam",
	  NULL,
	  0
	);

	return( retval );
}

static int
local_wifi_scs_set_iwpriv( const int skfd, const char *ifname, uint32_t param_value )
{
	int retval = 0;
	char setparam_value[12];
	char param_id[6];
	char *argv[] = {param_id,  &setparam_value[0]};
	const int argc = ARRAY_SIZE(argv);

	sprintf(param_id, "%d", IEEE80211_PARAM_SCS);
	snprintf(&setparam_value[0], sizeof(setparam_value), "0x%x", param_value);
	retval = call_private_ioctl(
	  skfd,
	  argv, argc,
	  ifname,
	 "setparam",
	  NULL,
	  0
	);

	return( retval );
}

static int
local_wifi_scs_get_iwpriv( const int skfd, const char *ifname, uint32_t *p_value )
{
	int retval = 0;
	char param_id[6];
	char *argv[] = {param_id};
	int argc = sizeof(argv)/sizeof(argv[0]);
	uint32_t value = 0;

	sprintf(param_id, "%d", IEEE80211_PARAM_SCS);
	retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"getparam",
			(void *) &value,
			sizeof(uint32_t)
	);
	if (retval >= 0) {
		*p_value = value;
	}

	return( retval );
}

static int
local_wifi_scs_get_dfs_reentry_request_iwpriv(const int skfd, const char *ifname, uint32_t *p_value)
{
	int retval = 0;
	char param_id[6];
	char *argv[] = {param_id};
	uint32_t value = 0;

	sprintf(param_id, "%d", IEEE80211_PARAM_SCS_DFS_REENTRY_REQUEST);
	retval = call_private_ioctl(
			skfd,
			argv, 1,
			ifname,
			"getparam",
			(void *) &value,
			sizeof(uint32_t)
	);
	if (retval >= 0) {
		*p_value = value;
	}

	return(retval);
}

int
qcsapi_wifi_get_bw( const char *ifname, qcsapi_unsigned_int *p_bw )
{
	qcsapi_bw	band_width = qcsapi_nosuch_bw;
	int		skfd = -1;
	int		retval = 0;

	enter_qcsapi();

	if (p_bw == NULL || ifname == NULL) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = verify_we_device( skfd, ifname, NULL, 0 );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_bandwidth( skfd, ifname, &band_width );
	}

	if (retval >= 0) {
		*p_bw = band_width;
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return (retval );
}

static int
local_validate_802_11_mode_string( const char *phy_mode )
{
	if (phy_mode == NULL)
		return -EFAULT;

	if ((strcasecmp(phy_mode, "11b") != 0)
			&& (strcasecmp(phy_mode, "11a") != 0)
			&& (strcasecmp(phy_mode, "11g") != 0)
			&& (strcasecmp(phy_mode, "11ng") != 0)
			&& (strcasecmp(phy_mode, "11na") != 0)
			&& (strcasecmp(phy_mode, "11ac") != 0)
			&& (strcasecmp(phy_mode, "11acEdge+") != 0)
			&& (strcasecmp(phy_mode, "11acEdge-") != 0)
			&& (strcasecmp(phy_mode, "11acCntr+") != 0)
			&& (strcasecmp(phy_mode, "11acCntr-") != 0))
	{
		return -EINVAL;
	}

	return 0;
}

static int
local_validate_bandwidth(const qcsapi_bw the_bw)
{
        int i;
	int max_bw_ent = local_get_max_bw();

	for (i = 0; i <= max_bw_ent; i++) {
		if (the_bw == qcsapi_bw_list[i])
                        return 0;
	}

        return -EOPNOTSUPP;
}

int
qcsapi_wifi_set_bw( const char *ifname, const qcsapi_unsigned_int the_bw )
{
	int		skfd = -1;
	int		retval = 0;
	string_64	phy_mode;
	char		current_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION];

	enter_qcsapi();

	/* Validate if board supports the_bw  */
	retval = local_validate_bandwidth(the_bw);
	if (retval >= 0)
	{
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = verify_we_device( skfd, ifname, NULL, 0 );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	/* Validate with the current mode */
	if (retval >= 0)
	{
		memset(phy_mode, 0, sizeof(phy_mode));
		retval = local_wifi_get_802_11_mode( skfd, ifname, phy_mode );
		if (retval >= 0)
		{
			/* Allow bandwidth 80 only in 11ac and auto modes.
			Check the mode substring 11ac for 11ac modes.
			11ac modes could be 11acEdge+, 11acCtrn+ etc */
			if ((the_bw == 80)
				&& (strncasecmp(phy_mode, "11ac", strlen("11ac"))
					&& strncasecmp(phy_mode, "auto", strlen("auto"))))
			{
				retval = -EOPNOTSUPP;
			}
		}
	}
	if (retval >= 0) {
		int	ival;
		ival = local_wifi_option_set_iwpriv_bw( skfd, ifname, the_bw );
		if (ival < 0)
			retval = ival;
	}

	if (retval >= 0) {
		retval = local_get_internal_regulatory_region(skfd, ifname, &current_region[0]);
	}

	if (retval >= 0 && strcmp(&current_region[0], "none")) {
		/* Reset region since bandwidth was changed */
		retval = local_regulatory_set_regulatory_region(ifname, current_region);

		if (retval == -qcsapi_region_database_not_found) {
			retval = local_wifi_set_regulatory_region(ifname, current_region);
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return (retval );
}

static int
is_in_list_5Ghz_channels(qcsapi_unsigned_int channel)
{
	int i;
	qcsapi_unsigned_int qcsapi_channels_5ghz[] = QCSAPI_CHANNELS_5GHZ_LIST;
	const unsigned int count_channels = TABLE_SIZE(qcsapi_channels_5ghz);

	for (i = 0; i < count_channels; i++) {
		if (channel == qcsapi_channels_5ghz[i])
			return 1;
	}
	return 0;
}

static int
is_in_list_2_4Ghz_channels(qcsapi_unsigned_int channel)
{
	int i;
	qcsapi_unsigned_int qcsapi_channels_2_4ghz[] = QCSAPI_CHANNELS_2_4GHZ_LIST;
	const unsigned int count_channels = TABLE_SIZE(qcsapi_channels_2_4ghz);

	for (i = 0; i < count_channels; i++) {
		if (channel == qcsapi_channels_2_4ghz[i])
			return 1;
	}
	return 0;
}
static int
get_list_2_4Ghz_channels(string_1024 list_of_channels)
{
	int retval = 0;
	qcsapi_unsigned_int qcsapi_channels_2_4ghz[] = QCSAPI_CHANNELS_2_4GHZ_LIST;
	const unsigned int count_channels = TABLE_SIZE(qcsapi_channels_2_4ghz);

	list_to_string((void *)&qcsapi_channels_2_4ghz[0], count_channels,
			list_element_unsigned_int, list_of_channels, 1024
			);

	return(retval);
}

static int
get_list_5Ghz_channels(const qcsapi_bw local_bandwidth, string_1024 list_of_channels)
{
	int retval = 0;
	qcsapi_unsigned_int qcsapi_channels_5ghz[] = QCSAPI_CHANNELS_5GHZ_LIST;
	const unsigned int count_channels_20MHz = TABLE_SIZE(qcsapi_channels_5ghz);

	list_of_channels[0] = '\0';

	list_to_string((void *)&qcsapi_channels_5ghz[0],
			count_channels_20MHz,
			list_element_unsigned_int,
			list_of_channels, 1024
			);

	return(retval);
}

int
qcsapi_wifi_get_list_channels( const char *ifname, string_1024 list_of_channels )
{
	int		skfd = -1;
	qcsapi_bw	local_bandwidth = qcsapi_nosuch_bw;
	int		retval = 0;

	enter_qcsapi();

	if (list_of_channels == NULL)
	  retval = -EFAULT;
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0)
	{
		qcsapi_base_frequency	base_frequency;

		if ((retval = get_wifi_base_frequency( skfd, ifname, &base_frequency )) >= 0)
		{
			if (base_frequency == qcsapi_5_GHz)
			{
				if ((retval = local_wifi_get_bandwidth( skfd, ifname, &local_bandwidth )) >= 0)
				{
					retval = get_list_5Ghz_channels( local_bandwidth, list_of_channels );
				}
			}
			else
			{
				retval = get_list_2_4Ghz_channels( list_of_channels );
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

/*
 * QBOX710 3-way switch button GPIO pin 12, 13
 * QHS840 2-way switch button GPIO pin 12
 */

#define MODE_SWITCH_LOW_ORDER_PIN	12
#define MODE_SWITCH_HIGH_ORDER_PIN	13

#define MODE_SWITCH_AUTO			2

int
qcsapi_wifi_get_mode_switch( uint8_t *p_wifi_mode_switch_setting )
{
	int	retval = 0;
	qcsapi_gpio_config gpio_config;

	enter_qcsapi();
	if (p_wifi_mode_switch_setting == NULL) {
		retval = -EFAULT;
	} else {
		/* GPIO12 is used on both 2way and 3way switches */
		if ((retval = local_lookup_gpio_config(MODE_SWITCH_LOW_ORDER_PIN, &gpio_config)) >= 0 &&
				gpio_config != qcsapi_gpio_input_only) {
			retval = -qcsapi_configuration_error;
		}

		if (retval >= 0) {
			retval = local_led_get(MODE_SWITCH_LOW_ORDER_PIN, p_wifi_mode_switch_setting);
		}

#ifndef TOPAZ_PLATFORM
		/* GPIO13 is used on 3way switch only */
		if (retval >= 0 && (retval = local_lookup_gpio_config(MODE_SWITCH_HIGH_ORDER_PIN, &gpio_config)) >= 0 &&
				gpio_config != qcsapi_gpio_input_only) {
			retval = -qcsapi_configuration_error;
		}

		if (retval >= 0) {
			if (*p_wifi_mode_switch_setting == 0) {
				/* if GPIO12 equals 0 than this is auto mode */
				*p_wifi_mode_switch_setting = MODE_SWITCH_AUTO;
			} else {
				/* if GPIO12 is 1 that GPIO13 tells whether mode is AP or STA */
				retval = local_led_get(MODE_SWITCH_HIGH_ORDER_PIN, p_wifi_mode_switch_setting);
			}
		}
#endif /* !TOPAZ_PLATFORM */
	}
	leave_qcsapi();

	return( retval );
}
/*
 * Mode is Access Point (server) or Station (client)
 * Other modes TBD
 *
 * This entry point allows p_wifi_mode to be NULL so an application can verfiy ifname is a WiFi VAP.
 */

int
local_wifi_get_mode( const int skfd, const char *ifname, qcsapi_wifi_mode *p_wifi_mode )
{
	struct iwreq		wrq;
	int			retval = local_priv_ioctl( skfd, ifname, SIOCGIWMODE, &wrq );

	if (retval >= 0)
	{
		unsigned int		iter;
		int			found_mode = 0;
		qcsapi_wifi_mode	local_wifi_mode = qcsapi_nosuch_mode;

		for (iter = 0; iter < wifi_mode_table_size && found_mode == 0; iter++)
		{
			if (wrq.u.mode == wifi_mode_table[ iter ].we_mode)
			{
				found_mode = 1;
				local_wifi_mode = wifi_mode_table[ iter ].wifi_mode;
			}
		}

		if (p_wifi_mode != NULL) {
			*p_wifi_mode = local_wifi_mode;
		}
	}
	else
	{
		if (errno > 0)
		  retval = -errno;
	}

	return( retval );
}


int
qcsapi_wifi_get_mode( const char *ifname, qcsapi_wifi_mode *p_wifi_mode )
{
	int			retval = 0;
	int			skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || p_wifi_mode == NULL)
	  retval = -EFAULT;
	else
	{
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	if (retval >= 0)
	{
		retval = local_wifi_get_mode( skfd, ifname, p_wifi_mode );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_phy_mode( const char *ifname, char *p_wifi_phy_mode )
{
	int	retval = 0;
	int	skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || p_wifi_phy_mode == NULL)
	{
		retval = -EFAULT;
	}
	else
	{
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0)
	{
		retval = local_wifi_get_802_11_mode( skfd, ifname, p_wifi_phy_mode );
	}

	if (skfd >= 0)
	{
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_phy_mode( const char *ifname, const char *new_phy_mode )
{
	int	retval = 0;
	int	skfd = -1;

	enter_qcsapi();

	if (ifname == NULL)
		retval = -EFAULT;

	/* Validate the phy mode string */
	retval = local_validate_802_11_mode_string(new_phy_mode);
	if (retval >= 0)
	{
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0)
	{
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0)
	{
		retval = local_wifi_set_802_11_mode(skfd, ifname, new_phy_mode);
	}

	if (skfd >= 0)
	{
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return( retval );
}

static int
do_wifi_reload_in_mode(const char *ifname, const char *wifi_mode_str)
{
	int retval;
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE];

	retval = system("/scripts/netdebug off > /dev/null");
	if (retval)
		goto out;

	retval = system("/scripts/radardebug off > /dev/null");
	if (retval)
		goto out;

	retval = system("/scripts/memdebug off > /dev/null");
	if (retval)
		goto out;

	retval = system("/scripts/ratedebug off > /dev/null");
	if (retval)
		goto out;

	retval = system("/scripts/offline_dump off > /dev/null");
	if (retval)
		goto out;

	/* waiting for pktlogger timer firing */
	sleep(0.2);

	retval = system("/scripts/unload > /dev/null");
	if (retval) {
		goto out;
	}

	sleep(1);

	snprintf(cmd, QCSAPI_WIFI_CMD_BUFSIZE, "/scripts/start-vap %s > /dev/null", wifi_mode_str);

	retval = system(cmd);

out:
	if (retval >= 0) {
		retval = 0;
	}
	return retval;
}

static int
local_verify_mode(const qcsapi_wifi_mode new_wifi_mode)
{
	int retval = 0;

	switch (new_wifi_mode) {
	case qcsapi_access_point:
	case qcsapi_wds:
		retval = local_swfeat_check_supported(SWFEAT_ID_MODE_AP);
		break;
	case qcsapi_repeater:
		retval = local_swfeat_check_supported(SWFEAT_ID_MODE_REPEATER);
		break;
	case qcsapi_station:
		retval = local_swfeat_check_supported(SWFEAT_ID_MODE_STA);
		break;
	default:
		retval = -qcsapi_not_supported;
		break;
	}

	if (retval < 0) {
		printf("%s mode is not supported on this device\n",
			qcsapi_wifi_mode_str(new_wifi_mode));
		return retval;
	}

	return 0;
}

static int
local_verify_mbss_configured()
{
	int retval;
	char configuration_file[122] = {0};
	char grep_mbss_config_str[128] = {0};

	retval = locate_configuration_file(qcsapi_access_point,
				&configuration_file[0],
				sizeof(configuration_file));
	if (retval < 0)
		return retval;

	snprintf(grep_mbss_config_str,
				sizeof(grep_mbss_config_str),
				"if [ -n \"$(grep ^bss= %s)\" ];then exit 1; fi",
				configuration_file);

	retval = system(grep_mbss_config_str);
	if (retval < 0)
		return retval;

	if (WEXITSTATUS(retval) == 1)
		return 1;

	return 0;
}

int
qcsapi_wifi_reload_in_mode(const char *ifname, const qcsapi_wifi_mode new_wifi_mode)
{
	int retval = 0;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto out;
	}

	if ((new_wifi_mode != qcsapi_access_point)
			&& (new_wifi_mode != qcsapi_station)
			&& (new_wifi_mode != qcsapi_repeater)) {
		retval = -EINVAL;
		goto out;
	}

	if (new_wifi_mode == qcsapi_repeater) {
		retval = local_verify_mbss_configured();
		if (retval == 1) {
			retval = -EOPNOTSUPP;
			goto out;
		}
	}

	retval = local_verify_mode(new_wifi_mode);
	if (retval < 0)
		goto out;

	if (local_verify_interface_is_primary(ifname) < 0) {
		retval = -EBADR;
		goto out;
	}

	/* Interface should exist */
	if (local_interface_verify_net_device(ifname) < 0) {
		retval = -ENOENT;
		goto out;
	}

	retval = do_wifi_reload_in_mode(ifname, qcsapi_wifi_mode_str(new_wifi_mode));
out:
	leave_qcsapi();

	return retval;
}

/*
 * Check whether a new interface can be created with special mode.
 * The rules:
 *   1. If the primary interface is not exist, the new interface can be created.
 *   2. The new interface mode should be same as the primary interface.
 *   3. If the primary interface is 'STA' mode, no more interface can be created.
 * Return:
 *  >=0 : The new interface can be created.
 *   <0 : Don't create it.
 */
static int
local_set_mode_check(const qcsapi_wifi_mode new_wifi_mode)
{
	int retval;
	int skfd = -1;
	qcsapi_wifi_mode primary_wifi_mode = qcsapi_nosuch_mode;
	char primary_ifname[IFNAMSIZ];

	retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1);
	if (retval == -ERANGE) {
		return 0; /* Rule 1 */
	}

	if (retval >= 0) {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, primary_ifname, &primary_wifi_mode);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	if (retval >= 0) {
		if (primary_wifi_mode == qcsapi_station) {
			return -EPERM;
		}

		if (new_wifi_mode != primary_wifi_mode) {
			return -EPERM;
		}
	}

	return retval;
}

int
qcsapi_wifi_set_mode( const char *ifname, const qcsapi_wifi_mode new_wifi_mode )
{
	int	retval = 0;

	enter_qcsapi();

	if (ifname == NULL)
	  retval = -EFAULT;
	else if (new_wifi_mode != qcsapi_access_point && new_wifi_mode != qcsapi_station)
	  retval = -EINVAL;
	else
	{
		int	ival = local_interface_verify_net_device( ifname );
	  /*
	   * proposed VAP (ifname) must not be present as a network interface
	   */
		if (ival >= 0)
		  retval = -EEXIST;
		else if (ival != -ENODEV)
		  retval = ival;
	}

	if (retval >= 0)
		retval = local_set_mode_check(new_wifi_mode);

	if (retval >= 0) {
		char		 enable_vap_message[ IFNAMSIZ + 14 ];

		sprintf( &enable_vap_message[ 0 ], "start 0 %s %s",
			qcsapi_wifi_mode_str(new_wifi_mode), ifname );
		retval = local_wifi_write_to_qdrv( &enable_vap_message[ 0 ] );
	}

	if (retval >= 0) {
		char	qdrv_result[ 8 ];

		retval = local_read_string_from_file( QDRV_CONTROL, &qdrv_result[ 0 ], sizeof( qdrv_result ) );
		if (retval >= 0)
		{
			if (strncmp( &qdrv_result[ 0 ], EXPECTED_QDRV_RESULT, strlen( EXPECTED_QDRV_RESULT ) ) != 0)
			  retval = -EIO;
		}
	}

	if (retval >= 0) {
		int	ival = local_interface_verify_net_device( ifname );

		if (ival < 0)
		  retval = -ENODEV;
	}

	/* This check can't be done until the vap has been created */
	if (retval >= 0)
		retval = local_verify_mode(new_wifi_mode);

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_rfenable(const qcsapi_unsigned_int onoff)
{
	int retval;

	enter_qcsapi();

	char cmd[QCSAPI_WIFI_CMD_BUFSIZE];
	snprintf(cmd, QCSAPI_WIFI_CMD_BUFSIZE - 1, "/scripts/rfenable %d", onoff);

	retval = system(cmd);

	leave_qcsapi();
	return retval;
}

int
qcsapi_wifi_startprod( void )
{
	int retval;
        char buf[8]={0};
        FILE *fd = NULL;

        fd = fopen(TMP_FILE_IS_STARTPROD_DONE,"r");
        if(fd)
        {
                fgets(buf, 8, fd);
                fclose(fd);
                if( 1 == atoi(&buf[0]) )
                        return 0;
        }

	enter_qcsapi();

	retval = system("/scripts/start-prod &");

	leave_qcsapi();
	return retval;
}

int qcsapi_is_startprod_done(int *p_status)
{
        char buf[8]={0};
        FILE *fd;
        int retval = 0;

        if( !p_status )
                return -EFAULT;

        enter_qcsapi();

        fd = fopen(TMP_FILE_IS_STARTPROD_DONE,"r");
        if (!fd) {
                *p_status = 0;
        } else {
                fgets(buf, 8, fd);
                fclose(fd);
                *p_status = atoi(&buf[0]);
        }

        leave_qcsapi();

        return retval;
}

int
qcsapi_wifi_rfstatus( qcsapi_unsigned_int *rfstatus)
{
	int retval = 0;
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE];

	enter_qcsapi();

	if (rfstatus == NULL) {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		snprintf(cmd, QCSAPI_WIFI_CMD_BUFSIZE - 1, "/scripts/rfstatus");
		*rfstatus = !!(system(cmd) >> 8);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_noise( const char *ifname, int *p_noise )
{
	int	retval = 0;
	int	skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || p_noise == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, NULL );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_write_to_qdrv( "get 0 noise" );
	}

	if (retval >= 0) {
		char	noise_from_qdrv[ 10 ];

		retval = local_read_string_from_file( QDRV_RESULTS, &noise_from_qdrv[ 0 ], sizeof( noise_from_qdrv ) );

		if (retval >= 0) {
			int	noise_in_10ths_dbm = atoi( &noise_from_qdrv[ 0 ] );

			if (noise_in_10ths_dbm < 0) {
				*p_noise = (noise_in_10ths_dbm - 5) / 10;
			} else {
				*p_noise = (noise_in_10ths_dbm + 5) / 10;
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_rssi_by_chain( const char *ifname, int rf_chain, int *p_rssi )
{
	int		retval = 0;
	int		skfd = -1;
	int			rssi_stats_fd = -1;
	struct qtn_stats	stats_with_rssi;
	int			rssi_in_10ths_dbm;

	enter_qcsapi();

	if (ifname == NULL || p_rssi == NULL) {
		retval = -EFAULT;
	} else if (rf_chain < 0 || rf_chain >= NUM_RF_CHAINS) {
		retval = -EINVAL;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	if ((retval = local_wifi_get_mode(skfd, ifname, NULL)) < 0) {
		goto ready_to_return;
	}

	if ((retval = local_verify_interface_is_primary(ifname)) < 0) {
		goto ready_to_return;
	}

	if ((rssi_stats_fd = open(QDRV_RSSI_PHY_STATS, O_RDONLY)) < 0) {
		retval = -qcsapi_system_not_started;
		goto ready_to_return;
	}

	if (read(rssi_stats_fd, (char *)&stats_with_rssi, sizeof(stats_with_rssi)) != sizeof(stats_with_rssi)) {
		retval = -qcsapi_programming_error;
		goto ready_to_return;
	}

	rssi_in_10ths_dbm = stats_with_rssi.rx_phy_stats.last_rssi_evm[rf_chain];

	if (rssi_in_10ths_dbm == QDRV_REPORTS_CONFIG_ERR) {
		retval = -qcsapi_configuration_error;
	} else if (rssi_in_10ths_dbm < 0) {
		*p_rssi = (rssi_in_10ths_dbm - 5) / 10;
	} else {
		*p_rssi = (rssi_in_10ths_dbm + 5) / 10;
	}

ready_to_return:
	if (rssi_stats_fd >= 0) {
		close(rssi_stats_fd);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_avg_snr( const char *ifname, int *p_snr )
{
	int	retval = 0;
	int	skfd = -1;
	int	iter;
	char	qdrv_phy_stat_msg[40];

	enter_qcsapi();

	if (ifname == NULL || p_snr == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	if ((retval = local_wifi_get_mode(skfd, ifname, NULL)) < 0) {
		goto ready_to_return;
	}

	if ((retval = local_verify_interface_is_primary(ifname)) < 0) {
		goto ready_to_return;
	}

	snprintf(&qdrv_phy_stat_msg[0],
		  sizeof(qdrv_phy_stat_msg),
		 "get 0 phy_stat %s",
		  QTN_PHY_AVG_ERROR_SUM_NSYM_NAME);

	/*
	 * Try multiple times to circumvent possible collisions with other processes
	 * contacting the Q driver.
	 */
	for (iter = 0; iter < 5; iter++) {
		char	snr_from_qdrv[12] = "";

		retval = local_wifi_write_to_qdrv(&qdrv_phy_stat_msg[0]);
		if (retval < 0) {
			goto ready_to_return;
		}

		retval = local_read_string_from_file(QDRV_RESULTS,
						    &snr_from_qdrv[0],
						     sizeof(snr_from_qdrv));

		if (strlen(&snr_from_qdrv[0]) > 0) {
			*p_snr = atoi(&snr_from_qdrv[0]);

			goto ready_to_return;
		}
	}

	retval = -qcsapi_measurement_not_available;

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
local_wifi_create_regulatory_region_table(void)
{
	int retval = 0;
	int rf_chipid = 0;

	retval = local_wifi_get_rf_chipid(&rf_chipid);
	if (retval >= 0) {
		create_regulatory_region(rf_chipid);
	}

	return retval;
}

int
qcsapi_wifi_get_list_regulatory_regions( string_256 list_regulatory_regions )
{
	int		retval = 0;
	unsigned int	current_list_length = 0;

	enter_qcsapi();

	if (list_regulatory_regions == NULL)
	  retval = -EFAULT;
	else
	{
		unsigned int	iter;
		int		get_out_now = 0;
	  /*
	   * get_out_now is a guard against overrunning the string_128 buffer.
	   * Not at all likely (the list of regulatory regions exceeds 128 chars?),
	   * but buffer overruns must be avoided.
	   */
		list_regulatory_regions[ 0 ] = '\0';

		local_wifi_create_regulatory_region_table();
		for (iter = 0; iter < regulatory_table_size && get_out_now == 0; iter++) {
			int				complete = 0;
			unsigned int			iter_2;
			qcsapi_regulatory_region	this_region =
				regulatory_table[ iter ].controlling_authority;

			for (iter_2 = 0; iter_2 < regulatory_region_size && complete == 0; iter_2++) {
				if (this_region == regulatory_region_name[ iter_2 ].the_region) {
					unsigned int	incremental_length =
						strlen( regulatory_region_name[ iter_2 ].the_name );

					complete = 1;
					if (iter > 0)
					  incremental_length++;

					if (incremental_length + current_list_length > sizeof( string_256 ) - 1) {
						get_out_now = 1;
					} else {
						if (iter > 0)
						  strcat( list_regulatory_regions, "," );
						strcat( list_regulatory_regions, regulatory_region_name[ iter_2 ].the_name );

						current_list_length += incremental_length;
					}
				}
			}
		}
	}

	leave_qcsapi();

	return( retval );
}

static channel_entry *
locate_regulatory_channel_entry( const qcsapi_regulatory_region the_region )
{
	channel_entry	*ret_addr = NULL;
	unsigned int	 iter;

	local_wifi_create_regulatory_region_table();

	for (iter = 0; iter < regulatory_table_size && ret_addr == NULL; iter++)
	{
		if (regulatory_table[ iter ].controlling_authority == the_region)
		{
			ret_addr = regulatory_table[ iter ].p_channel_table;
		}
	}

	return( ret_addr );
}

static qcsapi_regulatory_entry *
locate_regulatory_entry( const qcsapi_regulatory_region the_region )
{
	qcsapi_regulatory_entry	*ret_addr = NULL;
	unsigned int		 iter;

	local_wifi_create_regulatory_region_table();

	for (iter = 0; iter < regulatory_table_size && ret_addr == NULL; iter++)
	{
		if (regulatory_table[ iter ].controlling_authority == the_region)
		{
			ret_addr = &regulatory_table[ iter ];
		}
	}

	return( ret_addr );
}

static qcsapi_regulatory_region
get_regulatory_region_from_name( const char *region_by_name )
{
	qcsapi_regulatory_region	the_region = QCSAPI_NOSUCH_REGION;
	unsigned int			iter;

	for (iter = 0; iter < regulatory_region_size && the_region == QCSAPI_NOSUCH_REGION; iter++) {
		if (strcasecmp( region_by_name, regulatory_region_name[ iter ].the_name ) == 0)
		  the_region = regulatory_region_name[ iter ].the_region;
	}

	return( the_region );
}

static int
get_max_tx_power(
	const channel_entry *p_regulatory_entry,
	const qcsapi_unsigned_int the_channel,
	const qcsapi_bw bandwidth
)
{
	unsigned int	iter;

	if (p_regulatory_entry != NULL) {
		for (iter = 0; p_regulatory_entry[ iter ].channel > 0; iter++) {
			if (p_regulatory_entry[ iter ].channel == the_channel) {
				if (bandwidth == qcsapi_bw_40MHz &&
				    (p_regulatory_entry[ iter ].flags & m_40MHz_available) != m_40MHz_available) {
					return QCSAPI_TX_POWER_NOT_CONFIGURED;
				} else {
					return p_regulatory_entry[ iter ].max_tx_power;
				}
			}
		}
	}

	return QCSAPI_TX_POWER_NOT_CONFIGURED;
}

int
local_bootcfg_get_min_tx_power( void )
{
	int	retval = DEFAULT_MIN_TX_POWER;
	char	min_tx_power_value[ 8 ] = { '\0' };
	int	ival = local_bootcfg_get_parameter( "min_tx_power", &min_tx_power_value[ 0 ], sizeof( min_tx_power_value ) );

	if (ival < 0)
	{
		sprintf( &min_tx_power_value[ 0 ], "%d", DEFAULT_MIN_TX_POWER );
		local_bootcfg_set_parameter( "min_tx_power", &min_tx_power_value[ 0 ], 1);
	}
	else
	{
		retval = atoi( &min_tx_power_value[ 0 ]  );
	}

	return( retval );
}

int
local_bootcfg_get_max_sta_dfs_tx_power(int *p_max_sta_dfs_tx_power)
{
	char	max_tx_power_value[8] = {'\0'};
	int	retval = local_bootcfg_get_parameter(
			"max_sta_tx_power",
			&max_tx_power_value[ 0 ],
			sizeof( max_tx_power_value ));

	if (retval >= 0) {
		*p_max_sta_dfs_tx_power = atoi(&max_tx_power_value[0]);
	}

	return(retval);
}

/*
 * Guaranteed to return a value.  If everything fails, return default default TX power
 */
int
local_bootcfg_get_default_tx_power(void)
{
	int	retval = DEFAULT_DEFAULT_TX_POWER;
	char	max_tx_power_value[ 8 ] = { '\0' };
	int	ival = -1;

	ival = local_bootcfg_get_parameter( "max_tx_power", &max_tx_power_value[ 0 ], sizeof( max_tx_power_value ) );

	if (ival < 0) {
		sprintf( &max_tx_power_value[ 0 ], "%d", DEFAULT_DEFAULT_TX_POWER );
		local_bootcfg_set_parameter( "max_tx_power", &max_tx_power_value[ 0 ], 1);
	} else {
		retval = atoi( &max_tx_power_value[ 0 ]  );
	}

	return( retval );
}

int
local_wifi_configure_band_tx_power(
	int skfd,
	const char *ifname,
	const int start_channel,
	const int stop_channel,
	const int max_tx_power,
	const int min_tx_power
)
{
	int	retval = 0;
  /*
   *  Sanity checks - any failures are actually programming errors ...
   */
	if (start_channel > stop_channel)
	  retval = -EINVAL;
	else
	{
		int		 setparam_value = 0;
		char		 setparam_str[ 12 ] = { '\0' };
		char		*argv[] = { &setparam_str[ 0 ] };
		const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );

		setparam_value = ((start_channel & 0xff) << 24) |
				 ((stop_channel & 0xff) << 16) |
				 ((max_tx_power & 0xff) << 8) |
				   min_tx_power;
		sprintf( &setparam_str[ 0 ], "%d", setparam_value );
		retval = call_private_ioctl(
		  skfd,
		  argv, argc,
		  ifname,
		 "cfg_txpower",
		  NULL,
		  0
		);
	   // printf( "local_wifi_configure_band_tx_power: %d %d %d\n", start_channel, stop_channel, max_tx_power );
	}

	return( retval );
}

int
local_wifi_configure_bw_tx_power(
	int skfd,
	const char *ifname,
	const int channel,
	const int bf_on,
	const int number_ss,
	const int bandwidth,
	const int power
)
{
	int retval = 0;
	int setparam_value = 0;
	char setparam_str[ 12 ] = { '\0' };
	char *argv[] = { &setparam_str[ 0 ] };
	const int argc = sizeof( argv ) / sizeof( argv[ 0 ] );

	setparam_value = ((channel & 0xff) << 24) |
			 ((!!bf_on) << 20) |
			 ((number_ss & 0xf) << 16) |
			 ((bandwidth & 0xff) << 8) |
			 (power & 0xff);
	sprintf( &setparam_str[ 0 ], "%d", setparam_value );
	retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"cfg_bw_power",
			NULL,
			0);

	return( retval );
}

int
local_wifi_configure_regulatory_tx_power(
	int skfd,
	const char *ifname,
	const int start_channel,
	const int stop_channel,
	const int regulatory_tx_power
)
{
	int retval = 0;
	/*
	 *  Sanity checks - any failures are actually programming errors ...
	 */
	if (start_channel > stop_channel) {
		retval = -EINVAL;
	} else {
		int setparam_value = 0;
		char setparam_str[12] = {'\0'};
		char *argv[] = {&setparam_str[0]};
		const int argc = sizeof(argv) / sizeof(argv[0]);

		setparam_value = ((start_channel & 0xff) << 16) |
				((stop_channel & 0xff) << 8) |
				regulatory_tx_power;

		sprintf(&setparam_str[0], "%d", setparam_value);
		retval = call_private_ioctl(
				skfd,
				argv, argc,
				ifname,
				"cfg_reg_txpower",
				NULL,
				0);
	}

	return retval;
}

int
local_wifi_set_tx_power( int skfd, const char *ifname, const int start_channel, int tx_power )
{
	int		 retval = verify_we_device( skfd, ifname, NULL, 0 );
	unsigned int	 old_channel = 0;

	if (retval >= 0)
	{
		retval = local_wifi_configure_band_tx_power(
			skfd,
			ifname,
			start_channel,
			start_channel,
			tx_power,
			1
		);

		local_generic_syslog( "Set Channel", LOG_NOTICE,
		  "Configuring TX power to %d for WiFi channel %d",
		   tx_power, start_channel
		);

		/*
		 * If the channel is same as old channel, no channel switch and the tx power is not sent to Phy.
		 * So, send it to Phy separately.
		 */
		if (retval >= 0) {
			retval = local_wifi_get_channel(skfd, ifname, &old_channel);
		}
		if ((retval >= 0) && (old_channel == start_channel)) {
			char tx_power_cmd[64];

			sprintf(tx_power_cmd, "/scripts/set_tx_pow %d >/dev/null", tx_power);
			system(tx_power_cmd);
		}
	}

	return( retval );
}

#define TX_POWER_FILENAME_BASE	"/proc/bootcfg/eirp_info"
#define CONFIGURE_TX_POWER_DB	"configure_tx_power_limit"
#define TX_POWER_ALT_FILENAME_BASE "/ro/bootcfg/eirp_info"

static int
local_wifi_get_database_tx_power(
	const qcsapi_unsigned_int the_channel,
	const qcsapi_regulatory_region the_region,
	const qcsapi_bw bandwidth,
	const int default_tx_power,
	int *p_database_power
)
{
	int		 retval = 0;
	const char	*default_region_name = get_default_region_name( the_region );
	char		 tx_power_database[ 32 ] = { '\0' };
	FILE		*tx_db_fh = NULL;

	if (default_region_name == NULL)
	  retval = -EOPNOTSUPP;

	if (retval >= 0) {
		strcpy( &tx_power_database[ 0 ], TX_POWER_ALT_FILENAME_BASE );
		strcat( &tx_power_database[ 0 ], "_" );
		strcat( &tx_power_database[ 0 ], default_region_name );
		strcat( &tx_power_database[ 0 ], ".txt" );

		tx_db_fh = fopen( &tx_power_database[ 0 ], "r" );
		if (tx_db_fh == NULL)
		{
		    /*
		     * No modified power table available.
		     * Fallback to default.
		     */
		    memset(tx_power_database, 0, sizeof(tx_power_database));

		    strcpy( &tx_power_database[ 0 ], TX_POWER_FILENAME_BASE );
		    strcat( &tx_power_database[ 0 ], "_" );
		    strcat( &tx_power_database[ 0 ], default_region_name );
		    strcat( &tx_power_database[ 0 ], ".txt" );

		    tx_db_fh = fopen( &tx_power_database[ 0 ], "r" );
		}

		if (tx_db_fh == NULL)
		{
			char	create_tx_power_db[ 32 ];

			sprintf( &create_tx_power_db[ 0 ], "%s %s", CONFIGURE_TX_POWER_DB, default_region_name );
			system( &create_tx_power_db[ 0 ] );

			tx_db_fh = fopen( &tx_power_database[ 0 ], "r" );
		}
	}

	if (tx_db_fh == NULL)
	{
		*p_database_power = default_tx_power;
		retval = -ENOENT;
	}
	else
	{
		int	complete = 0;
		char	tx_power_database_entry[ 80 ];

		while ((complete == 0) &&
		       (fgets( &tx_power_database_entry[ 0 ], sizeof( tx_power_database_entry ), tx_db_fh ) != NULL))
		{
			if (tx_power_database_entry[ 0 ] != '#')
			{
				int	channel = 0, tx_power = 0, tx_pwr_20MHz = 0;
				int	ival = sscanf(
						&tx_power_database_entry[ 0 ],
						"%d%d%d",
						&channel,
						&tx_power,
						&tx_pwr_20MHz
				);

				if (ival >= 2 && channel == (int) the_channel)
				{
					complete = 1;
					if (ival == 2 || bandwidth != qcsapi_bw_20MHz)
					  *p_database_power = tx_power;
					else
					  *p_database_power = tx_pwr_20MHz;

				   // printf( "TX power database: %d %d\n", channel, *p_database_power );
				}
			}
		}

		if (complete == 0)
		{
			*p_database_power = default_tx_power;
			retval = -ENOENT;
		}
	}

	if (tx_db_fh != NULL)
	  fclose( tx_db_fh );

	return( retval );
}

static int
local_wifi_get_regulatory_tx_power(
	const qcsapi_unsigned_int the_channel,
	const qcsapi_regulatory_region the_region,
	const qcsapi_bw bandwidth,
	int *p_max_power
)
{
	int		 retval = 0;
	channel_entry	*p_regulatory_entry = NULL;

	if (p_max_power == NULL)
	  retval = -EFAULT;
	else
	{
		p_regulatory_entry = locate_regulatory_channel_entry( the_region );
		if (p_regulatory_entry == NULL)
		  retval = -EOPNOTSUPP;
	}

	if (retval >= 0)
	{
		int	local_tx_power = get_max_tx_power( p_regulatory_entry, the_channel, bandwidth );
	  /*
	   * get_max_tx_power returns QCSAPI_TX_POWER_NOT_CONFIGURED (-128) if the channel is not in
	   * the regulatory entry tables. As local_tx_power is in units of dBm, a value of -1
	   * represents a power level fractionally below 1 milliwatt, a forseeable low-power level.
	   */
		if (local_tx_power <= QCSAPI_TX_POWER_NOT_CONFIGURED)
		  retval = -EINVAL;
		else
		  *p_max_power = local_tx_power;
	}

	return( retval );
}

static int
local_wifi_get_configured_tx_power(
	const qcsapi_unsigned_int the_channel,
	const qcsapi_regulatory_region the_region,
	const qcsapi_bw bandwidth,
	const qcsapi_wifi_mode wifi_mode,
	int *p_configured_power
)
{
	int	regulatory_tx_power = 0;
	int	default_tx_power = local_bootcfg_get_default_tx_power();
	int	configured_tx_power = default_tx_power;
	int	default_sta_tx_power_dfs = default_tx_power;
	int	retval = local_wifi_get_regulatory_tx_power(the_channel,
							    the_region,
							    bandwidth,
							   &regulatory_tx_power );

	if (wifi_mode == qcsapi_station && the_region == QCSAPI_REGION_EUROPE) {
		local_bootcfg_get_max_sta_dfs_tx_power(&default_sta_tx_power_dfs);
	}

	if (retval >= 0) {
		int	database_tx_power = 0;
		int	ival = 0;

		if (wifi_mode == qcsapi_station &&
		    (local_is_channel_dfs_channel(the_channel, the_region) != 0) &&
		    default_sta_tx_power_dfs < configured_tx_power) {
			configured_tx_power = default_sta_tx_power_dfs;
		}

		if (regulatory_tx_power < configured_tx_power) {
			configured_tx_power = regulatory_tx_power;
		}

		ival = local_wifi_get_database_tx_power(
			 the_channel,
			 the_region,
			 bandwidth,
			 default_tx_power,
			&database_tx_power
		);

		if (ival >= 0)
		{
			if (database_tx_power < configured_tx_power)
			{
				configured_tx_power = database_tx_power;
			}
		}
	}

	if (retval >= 0)
	  *p_configured_power = configured_tx_power;

	return( retval );
}

static int
local_wifi_config_txpower(
	int skfd,
	const char *ifname,
	const qcsapi_bw bandwidth,
	const qcsapi_wifi_mode wifi_mode,
	qcsapi_regulatory_entry *p_regulatory_entry,
	int default_sta_tx_power_dfs
)
{
	int			 retval = 0;
	channel_entry		*p_channel_table = NULL;

	if (p_regulatory_entry == NULL)
	  retval = -EFAULT;			/* actually a programming error !! */

	if (retval >= 0)
	{
		p_channel_table = p_regulatory_entry->p_channel_table;
		if (p_channel_table == NULL)
		  retval = -EFAULT;
	}

	if (retval >= 0)
	{
		int				iter;
		int				current_max_tx_power = -1;
		int				start_channel = -1;
		int				stop_channel = -1;
		int				min_tx_power_for_wlan = 1;	/* min TX power fixed to 1 */
		int				min_tx_power = local_bootcfg_get_min_tx_power();
		int				regulatory_tx_power = -1;
		int				default_tx_power = local_bootcfg_get_default_tx_power();
		qcsapi_regulatory_region	the_region = p_regulatory_entry->controlling_authority;

		for (iter = 0; p_channel_table[ iter ].channel > 0; iter++)
		{
			int	new_tx_power = p_channel_table[ iter ].max_tx_power;
			int new_regulatory_tx_power = p_channel_table[ iter ].regulatory_tx_power;

		  /*
		   * See commentary in local_wifi_set_chanlist regarding European channels, 149 to 161.
		   */
			if (new_tx_power >= min_tx_power)
			{
				int	next_channel = p_channel_table[ iter ].channel;
				int	database_tx_power = 0, ival = 0;

				if (start_channel < 0)
				  start_channel = next_channel;
				if (stop_channel < 0)
				  stop_channel = next_channel;

				if (default_tx_power < new_tx_power)
				  new_tx_power = default_tx_power;

				ival = local_wifi_get_database_tx_power(
					 next_channel,
					 the_region,
					 bandwidth,
					 default_tx_power,
					&database_tx_power
				);
				if (ival >= 0 && database_tx_power < new_tx_power)
				  new_tx_power = database_tx_power;

				if (wifi_mode == qcsapi_station &&
				    (local_is_channel_dfs_channel(next_channel, the_region) != 0) &&
				     default_sta_tx_power_dfs < new_tx_power) {
					new_tx_power = default_sta_tx_power_dfs;
				}

				if (current_max_tx_power < 0)
				  current_max_tx_power = new_tx_power;

				if (regulatory_tx_power < 0)
					regulatory_tx_power = new_regulatory_tx_power;

				if (new_tx_power != current_max_tx_power)
				{
					retval = local_wifi_configure_band_tx_power(
						skfd,
						ifname,
						start_channel,
						stop_channel,
						current_max_tx_power,
						min_tx_power_for_wlan
					);

					local_wifi_configure_regulatory_tx_power(
							skfd,
							ifname,
							start_channel,
							stop_channel,
							regulatory_tx_power
							);

					local_generic_syslog( "Set Region", LOG_NOTICE,
				  "Configuring TX power to %d for WiFi channels %d to %d",
				   current_max_tx_power, start_channel, stop_channel
					);

					current_max_tx_power = new_tx_power;
					regulatory_tx_power = new_regulatory_tx_power;
					start_channel = next_channel;
					stop_channel = start_channel;
				}
				else
				  stop_channel = next_channel;
			}
		}
	  /*
	   * There will always be a last band to configure TX power for ...
	   */
		retval = local_wifi_configure_band_tx_power(
			skfd,
			ifname,
			start_channel,
			stop_channel,
			current_max_tx_power,
			min_tx_power
		);

		local_wifi_configure_regulatory_tx_power(
				skfd,
				ifname,
				start_channel,
				stop_channel,
				regulatory_tx_power
				);

		local_generic_syslog( "Set Region", LOG_NOTICE,
		  "Configuring TX power to %d for WiFi channels %d to %d",
		   current_max_tx_power, start_channel, stop_channel
		);
	}

	return( retval );
}

int
local_wifi_pre_deactive_DFS_channels( int skfd, const char *ifname, int scheme )
{
	struct iwreq	wrq;
	int flag_dfs_channels_deactive = scheme;
	int retval = 0;

	memset( &wrq, 0, sizeof( wrq ) );
	wrq.u.data.flags   = SIOCDEV_SUBIO_DI_DFS_CHANNELS;
	wrq.u.data.pointer = &flag_dfs_channels_deactive;
	wrq.u.data.length  = sizeof(flag_dfs_channels_deactive);

	strncpy(wrq.ifr_name, ifname, IFNAMSIZ - 1);
	retval = ioctl(skfd, IEEE80211_IOCTL_EXT, &wrq);

	if (retval == -1)
		retval = -errno;

	return retval;
}

static int
local_wifi_set_chanlist( int skfd, const char *ifname, const qcsapi_bw bandwidth, channel_entry *p_regulatory_channel )
{
	int		 retval = 0;
	enum {
		chanlist_array_size = COUNT_802_11_CHANNELS / NBBY
	};

	retval = verify_we_device( skfd, ifname, NULL, 0 );

	if (retval >= 0)
	{
		int	 	 argc = chanlist_array_size;
		u_int8_t	 chanlist_vals[ chanlist_array_size ];
		char		 chanlist_strs[ chanlist_array_size ][ 4 ];
		char		*chanlist_argv[ chanlist_array_size ];
		unsigned int	 iter;
		int		 min_tx_power = local_bootcfg_get_min_tx_power();
		int		 dfs_channel[116];
		int		 dfs_ch_cnt = 0;

		memset( &chanlist_vals[ 0 ], 0, sizeof( chanlist_vals ) );
		memset( &dfs_channel[ 0 ], 0, sizeof( dfs_channel) );

		for (iter = 0; p_regulatory_channel[ iter ].channel > 0; iter++)
		{
		  /*
		   * Special work-a-round for Europe, channels 149 - 161.  These channels are listed in
		   * the original requirements, but max TX power is only 6 dB.  Other restrictions are
		   * also present.  The corresponding script set_avail_chan disables 149 - 161 for Europe.
		   * To keep this API in sync with set_avail_chan, verify the maximum TX power is larger
		   * than 9 dBm before enabling the channel.
		   *
		   * Extended to get the minimum TX power from a boot cfg environment parameter.
		   *
		   * Note though that get_regulatory_tx_power will still work for channels 149 to 161 in Europe.
		   */
			if (p_regulatory_channel[ iter ].max_tx_power >= min_tx_power) {
			  /*
			   * One additional test based on bandwidth (20 vs 40 MHz):
			   *   All channels are available if the bandwidth is 20 MHz
			   *   If the bandwidth is 40 MHz, verify the 40 MHz flag is set for that channel.
			   */
				if ((bandwidth == qcsapi_bw_20MHz ||
					(p_regulatory_channel[ iter ].flags & m_40MHz_available)))
					setbit( chanlist_vals, p_regulatory_channel[ iter ].channel - 1 );

				if (((p_regulatory_channel[ iter ].flags & m_DFS_required) == m_DFS_required) && (dfs_ch_cnt < 116)) {
					dfs_channel[dfs_ch_cnt++] = p_regulatory_channel[ iter ].channel;
				}
			}
		  /*
		   * For some reason the WLAN driver required the user-space program to
		   * subtract 1 from bit / channel index if the phy type is T_DS.  Which
		   * it apparently is right now.  Thus subtract 1 from channel before calling
		   * setbit.
		   */
		}

		for (iter = 0; iter < chanlist_array_size; iter++)
		{
			sprintf( &chanlist_strs[ iter ][ 0 ], "%d", chanlist_vals[ iter ] );
			chanlist_argv[ iter ] = &chanlist_strs[ iter ][ 0 ];
		}

		retval = call_private_ioctl(
			  skfd,
			  chanlist_argv, argc,
			  ifname,
			  "setchanlist",
			  NULL,
			  0
		);

		if (retval >=0) {
			struct iwreq	wrq;

			memset( &wrq, 0, sizeof( wrq ) );
			wrq.u.data.flags   = SIOCDEV_SUBIO_SET_MARK_DFS_CHAN;
			wrq.u.data.pointer = dfs_channel;
			wrq.u.data.length  = dfs_ch_cnt;

			strncpy(wrq.ifr_name, ifname, IFNAMSIZ);
			ioctl(skfd, IEEE80211_IOCTL_EXT, &wrq);
		}
	}

	return( retval );
}

int
qcsapi_wifi_get_regulatory_tx_power(
	const char *ifname,
	const qcsapi_unsigned_int the_channel,
	const char *region_by_name,
	int *p_tx_power
)
{
	int				retval = 0;
	int				local_tx_power = QCSAPI_TX_POWER_NOT_CONFIGURED;
	int				skfd = -1;
	qcsapi_regulatory_region	the_region = QCSAPI_NOSUCH_REGION;

	enter_qcsapi();

	if (p_tx_power == NULL || region_by_name == NULL || ifname == NULL)
	  retval = -EFAULT;
	else
	  retval = local_open_iw_socket_with_error( &skfd );

	if (retval >= 0) {
		the_region = get_regulatory_region_from_name( region_by_name );
		if (the_region == QCSAPI_NOSUCH_REGION)
		  retval = -EOPNOTSUPP;
	}
  /*
   * Provide access to the regulatory TX power if calstate = 1.
   */
	if (retval >= 0) {
		char	calstate_value[ 4 ] = { '\0' };
		int	ival = local_bootcfg_get_parameter( "calstate", &calstate_value[ 0 ], sizeof( calstate_value ) );

		if (ival < 0 || strcmp( &calstate_value[ 0 ], "1" ) != 0) {
			retval = verify_we_device( skfd, ifname, NULL, 0 );

			if (retval >= 0) {
				retval = local_verify_interface_is_primary(ifname);
			}
		}
	}

	/*
	 * Regulatory TX power does not depend on the bandwidth; thus this API does not
	 * take bandwidth as a parameter.
	 *
	 * All channels that the regulatory authority has authorized are valid in 20 MHz mode.
	 * A few such channels (116, 140) may not be valid in 40 MHz mode.  Avoid that
	 * potential problem by calling the internal API with a bandwidth of 20 MHz.
	 */
	if (retval >= 0)
	  retval = local_wifi_get_regulatory_tx_power( the_channel, the_region, qcsapi_bw_20MHz, &local_tx_power );

	if (retval >= 0)
	  *p_tx_power = local_tx_power;

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_configured_tx_power(
	const char *ifname,
	const qcsapi_unsigned_int the_channel,
	const char *region_by_name,
	const qcsapi_unsigned_int the_bw,
	int *p_tx_power
)
{
	int				retval = 0;
	int				local_tx_power = 0;
	int				skfd = -1;
	qcsapi_wifi_mode		the_wifi_mode = qcsapi_access_point;
	qcsapi_regulatory_region	the_region = QCSAPI_NOSUCH_REGION;

	enter_qcsapi();

	if (p_tx_power == NULL || region_by_name == NULL || ifname == NULL)
	  retval = -EFAULT;
	else if (the_bw != (int) qcsapi_bw_20MHz && the_bw != qcsapi_bw_40MHz)
	  retval = -EINVAL;
	else
	  retval = local_open_iw_socket_with_error( &skfd );

	if (retval >= 0)
	{
		the_region = get_regulatory_region_from_name( region_by_name );
		if (the_region == QCSAPI_NOSUCH_REGION)
		  retval = -EOPNOTSUPP;
	}
  /*
   * Provide access to the configured TX power if calstate = 1.
   */
	if (retval >= 0)
	{
		char	calstate_value[ 4 ] = { '\0' };
		int	ival = local_bootcfg_get_parameter( "calstate", &calstate_value[ 0 ], sizeof( calstate_value ) );

		if (ival < 0 || strcmp( &calstate_value[ 0 ], "1" ) != 0) {
			retval = local_wifi_get_mode( skfd, ifname, &the_wifi_mode );

			if (retval >= 0) {
				retval = local_verify_interface_is_primary(ifname);
			}
		} else {
			/*
			 * If calstate = 1, default to AP as the WiFi mode.
			*/
			the_wifi_mode = qcsapi_access_point;
		}
	}

	if (retval >= 0)
	  retval = local_wifi_get_configured_tx_power( the_channel, the_region, the_bw, the_wifi_mode, &local_tx_power );

	if (retval >= 0)
	  *p_tx_power = local_tx_power;

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_regulatory_channel(
	const char *ifname,
	const qcsapi_unsigned_int the_channel,
	const char *region_by_name,
	const qcsapi_unsigned_int tx_power_offset
)
{
	int				retval = 0;
	int				local_tx_power = 0;
	int				min_tx_power = local_bootcfg_get_min_tx_power();
	int				max_tx_power = local_bootcfg_get_default_tx_power();
	int				regulatory_tx_power_limit;
	int				configured_tx_power;
	int				skfd = -1;
	qcsapi_bw			bandwidth = qcsapi_bw_40MHz;
	qcsapi_wifi_mode		wifi_mode = qcsapi_nosuch_mode;
	qcsapi_regulatory_region	the_region = QCSAPI_NOSUCH_REGION;
	qcsapi_regulatory_region	current_region = QCSAPI_NOSUCH_REGION;

	enter_qcsapi();

	retval = local_open_iw_socket_with_error( &skfd );

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_bandwidth( skfd, ifname, &bandwidth );
	}

	if (retval >= 0) {
		the_region = get_regulatory_region_from_name(region_by_name);
		if (the_region == QCSAPI_NOSUCH_REGION)
		  retval = -EOPNOTSUPP;
	}
	/*
	 * Get the current regulatory region and power limits of this region
	 */
	if (retval >= 0) {
		char region_name[QCSAPI_MIN_LENGTH_REGULATORY_REGION];
		retval = local_get_internal_regulatory_region( skfd, ifname, &region_name[0] );
		if (retval >= 0) {
			current_region = get_regulatory_region_from_name( region_name );
			if (current_region == QCSAPI_NOSUCH_REGION) {
				retval = -EOPNOTSUPP;
			} else if (the_region != current_region) {
				retval = -EINVAL;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_regulatory_tx_power( the_channel,
							     current_region,
							     bandwidth,
							     &regulatory_tx_power_limit );
	}

	if (retval >= 0 && regulatory_tx_power_limit < 1) {
		retval = -qcsapi_configuration_error;
	}

	if (retval >= 0) {
		retval = local_wifi_get_configured_tx_power( the_channel, current_region,
							     bandwidth, wifi_mode, &configured_tx_power );
	}

	if (retval >= 0) {
		local_tx_power = configured_tx_power - tx_power_offset;
		if (local_tx_power < min_tx_power
		    || local_tx_power > max_tx_power
		    || local_tx_power > regulatory_tx_power_limit
		    || local_tx_power > configured_tx_power)
			retval = -EINVAL;
		/*
		 * First configure TX power for the channel - then set the channel
		 */
		if (retval >= 0) {
			retval = local_wifi_set_tx_power( skfd, ifname, the_channel, local_tx_power );
		}
		if (retval >= 0) {
			retval = local_wifi_set_channel( skfd, ifname, the_channel );
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

qcsapi_regulatory_region local_wifi_get_region_by_name(const char *region_by_name)
{
	unsigned int iter;
	qcsapi_regulatory_region the_region = QCSAPI_NOSUCH_REGION;

	for (iter = 0; iter < regulatory_region_size && the_region == QCSAPI_NOSUCH_REGION; iter++) {
		if (strcasecmp( region_by_name, regulatory_region_name[ iter ].the_name ) == 0) {
		  the_region = regulatory_region_name[ iter ].the_region;
		  break;
		}
	}

	return the_region;
}

int local_wifi_check_radar_mode(const char *ifname, const char *region_by_name, int skfd)
{
	int retval = 0;
	int enable_radar = 0;
	char set_radar_mode_msg[32] = {'\0'};
	qcsapi_regulatory_region the_region;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;

	if (region_by_name == NULL || skfd < 0)
		return -EINVAL;

	the_region = local_wifi_get_region_by_name(region_by_name);

	if (the_region != QCSAPI_NOSUCH_REGION) {
		if (the_region != QCSAPI_REGION_RUSSIA) {
			retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
			if (retval < 0)
				return -EINVAL;

			if (local_wifi_mode == qcsapi_access_point) {
				enable_radar = 1;
			} else if (local_verify_repeater_mode(skfd, &local_wifi_mode) >= 0
					&& local_wifi_mode == qcsapi_repeater) {
				enable_radar = 0;
			} else {
				char sta_dfs[20] = {'\0'};
				int	ival = local_bootcfg_get_parameter("sta_dfs", &sta_dfs[0], sizeof(sta_dfs));

				if (ival >= 0 && strcmp( &sta_dfs[ 0 ], "1" ) == 0)
					enable_radar = 1;
			}
		}
	} else {
		return -EINVAL;
	}

	sprintf(&set_radar_mode_msg[0], "iwpriv %s markdfs %d", ifname, enable_radar);
	system(set_radar_mode_msg);

	return 0;
}

int
local_wifi_set_regulatory_region( const char *ifname, const char *region_by_name )
{
	int				 retval = 0;
	int				 skfd = -1;
	qcsapi_regulatory_region	 the_region = QCSAPI_NOSUCH_REGION;
	qcsapi_regulatory_entry		*p_regulatory_entry = NULL;
	channel_entry			*p_regulatory_channel = NULL;
	qcsapi_bw			 bandwidth = qcsapi_bw_40MHz;
	qcsapi_wifi_mode		 wifi_mode = qcsapi_nosuch_mode;
	int				 default_sta_tx_power_dfs = local_bootcfg_get_default_tx_power();

	if (ifname == NULL || region_by_name == NULL)
	  retval = -EFAULT;
	else
	  retval = local_open_iw_socket_with_error( &skfd );

	if (retval >= 0)
	  retval = local_wifi_get_bandwidth( skfd, ifname, &bandwidth );

	if (retval >= 0)
	  retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		char	current_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION];

		retval = local_get_internal_regulatory_region(skfd, ifname, &current_region[0]);
		if (strcasecmp(&current_region[0], "none") != 0) {
			retval = -EOPNOTSUPP;
		}
	}

	if (retval >= 0) {
		qcsapi_interface_status_code status_code = qcsapi_interface_status_error;

		retval = local_interface_get_status(skfd, ifname, &status_code);
		if (status_code != qcsapi_interface_status_disabled)
			retval = -EOPNOTSUPP;
	}

	if (retval >= 0) {
		the_region = local_wifi_get_region_by_name(region_by_name);
		if (the_region == QCSAPI_NOSUCH_REGION)
		  retval = -EINVAL;
	}

	if (wifi_mode == qcsapi_station && the_region == QCSAPI_REGION_EUROPE) {
		local_bootcfg_get_max_sta_dfs_tx_power(&default_sta_tx_power_dfs);
	}

	if (retval >= 0) {
		p_regulatory_entry = locate_regulatory_entry( the_region );
		if (p_regulatory_entry == NULL)
		  retval = -EOPNOTSUPP;
		else
		  p_regulatory_channel = p_regulatory_entry->p_channel_table;
	}

	if (retval >= 0) {
		retval = local_wifi_set_chanlist( skfd, ifname, bandwidth, p_regulatory_channel );
	}

	if (retval >= 0) {
		retval = local_wifi_config_txpower(skfd,
						   ifname,
						   bandwidth,
						   wifi_mode,
						   p_regulatory_entry,
						   default_sta_tx_power_dfs);
	}

	if (retval >= 0) {
		const char	*region_name = get_default_region_name( the_region );

		if (region_name == NULL)
		  retval = -qcsapi_programming_error;
		else {
			char	enable_radar_msg[ 32 ] = { '\0' };

			/* Initialize the radar module */
			sprintf( &enable_radar_msg[ 0 ], "radar enable %s", region_name );
			retval = local_wifi_write_to_qdrv( &enable_radar_msg[ 0 ] );

			local_set_internal_regulatory_region(skfd, ifname, region_name, 0);
		}
	}

	/* For AP mode, always enable radar detection
	 * For STA mode, enable/disable radar detection according to user config
	 * Note: here no check on retval is on purpose for supporting dynamical mode reloading
	 */
	retval = local_wifi_check_radar_mode(ifname, region_by_name, skfd);

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	return( retval );
}

int
qcsapi_wifi_set_regulatory_region( const char *ifname, const char *region_by_name )
{
	int retval;

	enter_qcsapi();
	retval = local_wifi_set_regulatory_region(ifname, region_by_name);
	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_regulatory_region(const char *ifname, char *region_by_name)
{
	int		retval = 0;
	int		skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || region_by_name == NULL) {
		retval = -EFAULT;
	}
	else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_get_internal_regulatory_region( skfd, ifname, region_by_name );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_tx_power(const char *ifname, const qcsapi_unsigned_int the_channel, int *p_tx_power)
{
	int		retval = 0;
	int		skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || p_tx_power == NULL) {
		retval = -EFAULT;
	} else if (the_channel > QCSAPI_MAX_CHANNEL || the_channel < QCSAPI_MIN_CHANNEL) {
		retval = -EINVAL;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_get_tx_power( skfd, ifname, the_channel, p_tx_power);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int qcsapi_wifi_set_tx_power(const char *ifname,
			const qcsapi_unsigned_int the_channel,
			const int tx_power)
{
	int retval = 0;
	int min_tx_power = local_bootcfg_get_min_tx_power();
	int max_tx_power = local_bootcfg_get_default_tx_power();
	int regulatory_tx_power_limit;
	int configured_tx_power;
	int skfd = -1;
	qcsapi_bw bandwidth = qcsapi_bw_40MHz;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	qcsapi_regulatory_region curr_region = QCSAPI_NOSUCH_REGION;
	char curr_region_name[QCSAPI_MIN_LENGTH_REGULATORY_REGION];

	enter_qcsapi();

	if (local_use_new_tx_power() == 1) {
		retval = local_regulatory_set_tx_power(ifname, the_channel, tx_power);
		leave_qcsapi();
		return retval;
	}

	if (the_channel > QCSAPI_MAX_CHANNEL || the_channel < QCSAPI_MIN_CHANNEL)
		retval = -EINVAL;

	if (retval >= 0)
		retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0)
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0)
		retval = local_wifi_get_bandwidth(skfd, ifname, &bandwidth);

	if (retval >= 0) {
		retval = local_get_internal_regulatory_region(skfd, ifname, curr_region_name);
		if (retval >= 0)
			curr_region = get_regulatory_region_from_name(curr_region_name);
	}

	if (retval >= 0 && curr_region != QCSAPI_NOSUCH_REGION) {
		retval = local_wifi_get_regulatory_tx_power(the_channel,
							     curr_region,
							     bandwidth,
							     &regulatory_tx_power_limit);

		if (retval >= 0 && regulatory_tx_power_limit < 1)
			retval = -qcsapi_configuration_error;

		if (retval >= 0)
			retval = local_wifi_get_configured_tx_power(the_channel,
					curr_region,
					bandwidth,
					wifi_mode,
					&configured_tx_power);
	} else if (retval >= 0 && strcasecmp(curr_region_name, "none") == 0) {
		regulatory_tx_power_limit = max_tx_power;
		configured_tx_power = max_tx_power;
	}

	if (retval >= 0) {
		if (tx_power < min_tx_power || tx_power > max_tx_power ||
				tx_power > regulatory_tx_power_limit ||
				tx_power > configured_tx_power)
			retval = -EINVAL;

		if (retval >= 0)
			retval = local_wifi_set_tx_power(skfd, ifname, the_channel, tx_power);
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

static int
local_get_bw_power( int skfd,
			const char *ifname,
			const qcsapi_unsigned_int the_channel,
			const qcsapi_unsigned_int bf_on,
			const qcsapi_unsigned_int number_ss,
			int *p_power_20M,
			int *p_power_40M,
			int *p_power_80M)
{
	int		 retval = 0;
	char		 getparam_str[ 12 ];
	char		*argv[] = { &getparam_str[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );
	u_int32_t	 getparam_int;
	__s32		 local_tx_power;

	getparam_int = (IEEE80211_PARAM_CONFIG_BW_TXPOWER & 0xffff) |
			((number_ss & 0xf) << 16) |
			((!!bf_on) << 20) |
			((the_channel & 0xff) << 24);
	snprintf( &getparam_str[ 0 ], sizeof( getparam_str ), "%u", getparam_int );

	retval = call_private_ioctl(skfd,
				 argv, argc,
				 ifname,
				"getparam",
				&local_tx_power,
				 sizeof( __s32 ));

	if (retval >= 0) {
		*p_power_20M = (int)(local_tx_power & 0xff);
		*p_power_40M = (int)((local_tx_power >> 8) & 0xff);
		*p_power_80M = (int)((local_tx_power >> 16) & 0xff);
		if (*p_power_20M == 0xff) {
			*p_power_20M = -1;
		}
		if (*p_power_40M == 0xff) {
			*p_power_40M = -1;
		}
		if (*p_power_80M == 0xff) {
			*p_power_80M = -1;
		}
	}

	return( retval );
}

static int local_wifi_get_bw_power(const char *ifname,
			const qcsapi_unsigned_int the_channel,
			const qcsapi_unsigned_int bf_on,
			const qcsapi_unsigned_int number_ss,
			int *p_power_20M,
			int *p_power_40M,
			int *p_power_80M)
{
	int retval = 0;
	int skfd = -1;

	if (ifname == NULL || p_power_20M == NULL ||
			p_power_40M == NULL || p_power_80M == NULL) {
		retval = -EFAULT;
	} else if (the_channel > QCSAPI_MAX_CHANNEL || the_channel < QCSAPI_MIN_CHANNEL) {
		retval = -EINVAL;
	} else if (number_ss <= 0 || number_ss > QCSAPI_QDRV_NUM_RF_STREAMS) {
		retval = -EINVAL;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_get_bw_power( skfd, ifname, the_channel,
				bf_on, number_ss, p_power_20M, p_power_40M, p_power_80M);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	return( retval );
}

int qcsapi_wifi_get_bw_power(const char *ifname,
			const qcsapi_unsigned_int the_channel,
			int *p_power_20M,
			int *p_power_40M,
			int *p_power_80M)
{
	int retval;

	enter_qcsapi();

	retval = local_wifi_get_bw_power(ifname,
			the_channel,
			0,
			1,
			p_power_20M,
			p_power_40M,
			p_power_80M);

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_set_bw_power(const char *ifname,
			const qcsapi_unsigned_int the_channel,
			const int power_20M,
			const int power_40M,
			const int power_80M)
{
	int pwr_idx;
	int bf_on;
	int number_ss;
	int retval = 0;
	int retval2;

	enter_qcsapi();

	for (pwr_idx = QCSAPI_POWER_INDEX_BFOFF_1SS;
			pwr_idx < QCSAPI_POWER_TOTAL; pwr_idx++) {
		bf_on = pwr_idx >= QCSAPI_POWER_INDEX_BFON_1SS;
		number_ss = pwr_idx + 1 - (bf_on ? QCSAPI_POWER_INDEX_BFON_1SS :
				QCSAPI_POWER_INDEX_BFOFF_1SS);
		retval2 = local_regulatory_set_bw_power(ifname,
				the_channel,
				bf_on,
				number_ss,
				power_20M,
				power_40M,
				power_80M);
		if (retval2 < 0) {
			retval = retval2;
		}
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_bf_power(const char *ifname,
			const qcsapi_unsigned_int the_channel,
			const qcsapi_unsigned_int number_ss,
			int *p_power_20M,
			int *p_power_40M,
			int *p_power_80M)
{
	int retval;

	enter_qcsapi();

	retval = local_wifi_get_bw_power(ifname,
			the_channel,
			1,
			number_ss,
			p_power_20M,
			p_power_40M,
			p_power_80M);

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_set_bf_power(const char *ifname,
			const qcsapi_unsigned_int the_channel,
			const qcsapi_unsigned_int number_ss,
			const int power_20M,
			const int power_40M,
			const int power_80M)
{
	int bf_on;
	int retval = 0;
	int retval2;

	enter_qcsapi();

	for (bf_on = 0; bf_on <= 1; bf_on++) {
		retval2 = local_regulatory_set_bw_power(ifname,
				the_channel,
				bf_on,
				number_ss,
				power_20M,
				power_40M,
				power_80M);
		if (retval2 < 0) {
			retval = retval2;
		}
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_tx_power_ext(const char *ifname,
			const qcsapi_unsigned_int the_channel,
			const qcsapi_unsigned_int bf_on,
			const qcsapi_unsigned_int number_ss,
			int *p_power_20M,
			int *p_power_40M,
			int *p_power_80M)
{
	int retval;

	enter_qcsapi();

	retval = local_wifi_get_bw_power(ifname,
			the_channel,
			bf_on,
			number_ss,
			p_power_20M,
			p_power_40M,
			p_power_80M);

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_set_tx_power_ext(const char *ifname,
			const qcsapi_unsigned_int the_channel,
			const qcsapi_unsigned_int bf_on,
			const qcsapi_unsigned_int number_ss,
			const int power_20M,
			const int power_40M,
			const int power_80M)
{
	int retval;

	enter_qcsapi();

	retval = local_regulatory_set_bw_power(ifname,
			the_channel,
			bf_on,
			number_ss,
			power_20M,
			power_40M,
			power_80M);

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_chan_power_table(const char *ifname,
		qcsapi_channel_power_table *chan_power_table)
{
	int retval;
	int pwr_idx;
	int bf_on;
	int num_ss;
	int idx_bf;
	int idx_ss;
	struct ieee80211_chan_power_table qdrv_table;

	enter_qcsapi();

	qdrv_table.chan_ieee = chan_power_table->channel;
	retval = local_wifi_get_chan_power_table(ifname, &qdrv_table);
	if (retval >= 0) {
		if (qdrv_table.chan_ieee == 0) {
			/* "0" means no such channel */
			retval = -1;
		}
	}

	if (retval >= 0) {
		for (pwr_idx = QCSAPI_POWER_INDEX_BFOFF_1SS;
				pwr_idx < QCSAPI_POWER_TOTAL; pwr_idx++) {
			bf_on = pwr_idx >= QCSAPI_POWER_INDEX_BFON_1SS;
			num_ss = pwr_idx + 1 - (bf_on ? QCSAPI_POWER_INDEX_BFON_1SS :
					QCSAPI_POWER_INDEX_BFOFF_1SS);
			idx_bf = PWR_IDX_BF_OFF + bf_on;
			idx_ss = PWR_IDX_1SS + num_ss - 1;
			chan_power_table->power_20M[pwr_idx] =
					qdrv_table.maxpower_table[idx_bf][idx_ss][PWR_IDX_20M];
			chan_power_table->power_40M[pwr_idx] =
					qdrv_table.maxpower_table[idx_bf][idx_ss][PWR_IDX_40M];
			chan_power_table->power_80M[pwr_idx] =
					qdrv_table.maxpower_table[idx_bf][idx_ss][PWR_IDX_80M];
		}
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_set_chan_power_table(const char *ifname,
		qcsapi_channel_power_table *chan_power_table)
{
	int retval;

	enter_qcsapi();

	retval = local_regulatory_set_chan_power_table(ifname,
			chan_power_table);

	leave_qcsapi();

	return retval;
}

int
local_wifi_get_power_recheck(qcsapi_unsigned_int *p_power_recheck)
{
	int retval;
	char power_recheck_from_qdrv[12];

	retval = local_wifi_write_to_qdrv("get 0 power_recheck");

	if (retval >= 0) {
		retval = local_read_string_from_file(QDRV_RESULTS, power_recheck_from_qdrv,
				sizeof(power_recheck_from_qdrv));
	}

	if (retval >= 0) {
		if (strlen(power_recheck_from_qdrv) > 0)
			*p_power_recheck = atoi(power_recheck_from_qdrv);
		else
			retval = -1;
	}

	return retval;
}

int
local_wifi_get_power_selection(qcsapi_unsigned_int *p_power_selection)
{
	int retval;
	char power_selection_from_qdrv[12];

	retval = local_wifi_write_to_qdrv("get 0 power_selection");

	if (retval >= 0) {
		retval = local_read_string_from_file(QDRV_RESULTS, power_selection_from_qdrv,
				sizeof(power_selection_from_qdrv));
	}

	if (retval >= 0) {
		if (strlen(power_selection_from_qdrv) > 0)
			*p_power_selection = atoi(power_selection_from_qdrv);
		else
			retval = -1;
	}

	return retval;
}

int
qcsapi_wifi_get_power_selection(qcsapi_unsigned_int *p_power_selection)
{
	int retval = 0;

	enter_qcsapi();

	if (p_power_selection == NULL) {
		retval = -EFAULT;
	}

	if (retval >= 0) {
		retval = local_wifi_get_power_selection(p_power_selection);
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_power_selection(const qcsapi_unsigned_int power_selection)
{
	int retval = 0;

	enter_qcsapi();

	if (power_selection > PWR_TABLE_SEL_MAX) {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		char qdrv_command[32];

		sprintf(&qdrv_command[0], "set power_selection %u", power_selection);
		retval = local_wifi_write_to_qdrv(&qdrv_command[0]);
	}

	leave_qcsapi();

	return( retval );
}

int qcsapi_wifi_get_carrier_interference(const char *ifname,
			int *ci)
{
	enter_qcsapi();

	/* TODO: */

	leave_qcsapi();

	return -EOPNOTSUPP;
}

int qcsapi_wifi_get_congestion_index(const char *ifname, int *ci)
{
	int retval = 0;
	int skfd = -1;
	char setparam_code[QCSAPI_IOCTL_BUFSIZE];
	char *argv[] = {&setparam_code[0]};
	int  argc = sizeof(argv) / sizeof(argv[0]);
	int value;

	enter_qcsapi();
	retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0) {
		snprintf(setparam_code, sizeof(setparam_code), "%u", IEEE80211_PARAM_CONGEST_IDX);
		retval = call_private_ioctl(
				skfd,
				argv,
				argc,
				ifname,
				"getparam",
				(void *)&value,
				sizeof(int)
		);
	}

	if (retval >= 0)
		*ci = value;

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return (retval);
}

static int
local_get_current_channel_bw_region(
	int skfd,
	const char *ifname,
	qcsapi_unsigned_int *p_channel,
	qcsapi_bw *p_bw,
	qcsapi_regulatory_region *p_current_region)
{
	int				retval = 0;
	qcsapi_unsigned_int		local_channel;
	char				local_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION];
	qcsapi_bw			local_bw = qcsapi_nosuch_bw;
	qcsapi_regulatory_region	local_enum_region = QCSAPI_NOSUCH_REGION;

	if (ifname == NULL || p_channel == NULL || p_bw == NULL || p_current_region == NULL) {
		return -EFAULT;
	}

	retval = local_wifi_get_channel(skfd, ifname, &local_channel);
	if (retval < 0) {
		return retval;
	}

	retval = local_wifi_get_bandwidth(skfd, ifname, &local_bw);
	if (retval < 0) {
		return retval;
	}

	retval = local_get_internal_regulatory_region(skfd, ifname, &local_region[0]);
	if (retval < 0) {
		return retval;
	}

	/* "none" is not a regulatory region */
	if (strcasecmp(&local_region[0], "none") == 0) {
		return -qcsapi_configuration_error;
	}

	local_enum_region = get_regulatory_region_from_name(&local_region[0]);
	if (local_enum_region == QCSAPI_NOSUCH_REGION) {
		return -qcsapi_programming_error;
	}

	*p_channel = local_channel;
	*p_bw = local_bw;
	*p_current_region = local_enum_region;

	return retval;
}

int
qcsapi_wifi_get_supported_tx_power_levels(
	const char *ifname,
	string_128 available_percentages)
{
	int				retval = 0;
	int				skfd = -1;
	qcsapi_wifi_mode		current_wifi_mode = qcsapi_mode_not_defined;
	qcsapi_unsigned_int		current_channel = 0;
	qcsapi_bw			current_bw = qcsapi_nosuch_bw;
	qcsapi_regulatory_region	local_enum_region = QCSAPI_NOSUCH_REGION;
	int				regulatory_tx_power_limit = 0;
	int				configured_tx_power = 0;
	int				min_tx_power = 0;
	int				tx_power_iter = 0;

	enter_qcsapi();

	if (local_use_new_tx_power() == 1) {
		retval = local_regulatory_get_supported_tx_power_levels(ifname,
				available_percentages);
		leave_qcsapi();
		return retval;
	}

	if (ifname == NULL || available_percentages == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_get_current_channel_bw_region(
		skfd,
		ifname,
		&current_channel,
		&current_bw,
		&local_enum_region);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_regulatory_tx_power(
		current_channel,
		local_enum_region,
		current_bw,
		&regulatory_tx_power_limit);
	if (retval >= 0 && regulatory_tx_power_limit < 1) {
		retval = -qcsapi_configuration_error;
	}
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_configured_tx_power(
		current_channel,
		local_enum_region,
		current_bw,
		current_wifi_mode,
		&configured_tx_power);
	if (retval < 0) {
		goto ready_to_return;
	}

	min_tx_power = local_bootcfg_get_min_tx_power();

	available_percentages[0] = '\0';

	for (tx_power_iter = min_tx_power; tx_power_iter <= configured_tx_power; tx_power_iter++) {
		unsigned int tx_power_percentage = POWER_PERCENTAGE(tx_power_iter, configured_tx_power);
		char	percentage_str[6];

		snprintf(&percentage_str[0], sizeof(percentage_str), "%u", tx_power_percentage);
		if (tx_power_iter > min_tx_power) {
			strcat(available_percentages, ",");
		}
		strcat(available_percentages, &percentage_str[0]);
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_current_tx_power_level(
	const char *ifname,
	uint32_t *p_current_percentage)
{
	int				retval = 0;
	int				skfd = -1;
	qcsapi_unsigned_int		current_channel;
	qcsapi_bw			current_bw;
	qcsapi_regulatory_region	local_enum_region = QCSAPI_NOSUCH_REGION;
	qcsapi_wifi_mode		current_wifi_mode = -qcsapi_nosuch_mode;
	int				local_tx_power = 0;
	int				configured_tx_power = 0;

	enter_qcsapi();

        if (local_use_new_tx_power() == 1) {
                retval = local_regulatory_get_current_tx_power_level(ifname,
                                p_current_percentage);
                leave_qcsapi();
                return retval;
        }

	if (ifname == NULL || p_current_percentage == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_get_current_channel_bw_region(
		skfd,
		ifname,
		&current_channel,
		&current_bw,
		&local_enum_region
	);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_get_tx_power(skfd, ifname, current_channel, &local_tx_power);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_configured_tx_power(
						    current_channel,
						    local_enum_region,
						    current_bw,
						    current_wifi_mode,
						    &configured_tx_power);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (local_tx_power < 1) {
		local_tx_power = 1;
	}

	*p_current_percentage = POWER_PERCENTAGE(local_tx_power, configured_tx_power);

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_power_constraint(
		const char *ifname,
		uint32_t pwr_constraint)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		retval = local_interface_verify_net_device(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);

		if (current_wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_set_private_int_param_by_name( skfd, ifname, "doth_pwrcst", (int)pwr_constraint);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_power_constraint(
		const char *ifname,
		uint32_t *p_pwr_constraint)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (p_pwr_constraint == NULL) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
	}

	if (retval >= 0) {
		retval = local_interface_verify_net_device(ifname);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_private_int_param_by_name( skfd,ifname,"get_doth_pwrcst",(int*)p_pwr_constraint);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_set_tpc_interval(
		const char *ifname,
		int tpc_interval)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		retval = local_interface_verify_net_device(ifname);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_set_private_int_param_by_name( skfd, ifname, "tpc_interval", (int)tpc_interval);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_tpc_interval(
		const char *ifname,
		uint32_t *p_tpc_interval)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (p_tpc_interval == NULL) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
	}

	if (retval >= 0) {
		retval = local_interface_verify_net_device(ifname);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_private_int_param_by_name(skfd,ifname,"get_tpc_intvl",(int*)p_tpc_interval);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

/*
 * Restriction:
 *     0: no additional restrictions beyond regulatory region and band width.
 *     1: DFS is NOT required for the channel.
 *     2: DFS IS required for the channel.
 */

static int
local_wifi_get_restricted_list_channels(
	const char *region_by_name,
	const qcsapi_unsigned_int bw,
	const int restriction,
	string_1024 list_of_channels
)
{
	int				 retval = 0;
	qcsapi_regulatory_region	 the_region = QCSAPI_NOSUCH_REGION;
	channel_entry			*p_regulatory_entry = NULL;

	if (region_by_name == NULL || list_of_channels == NULL)
	  retval = -EFAULT;
	else if (bw != qcsapi_bw_40MHz && bw != qcsapi_bw_20MHz)
	  retval = -EINVAL;
	else
	{
		unsigned int	iter;

		for (iter = 0; iter < regulatory_region_size && the_region == QCSAPI_NOSUCH_REGION; iter++) {
			if (strcasecmp( region_by_name, regulatory_region_name[ iter ].the_name ) == 0)
			  the_region = regulatory_region_name[ iter ].the_region;
		}

		if (the_region == QCSAPI_NOSUCH_REGION)
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		p_regulatory_entry = locate_regulatory_channel_entry( the_region );
		if (p_regulatory_entry == NULL)
		  retval = -EOPNOTSUPP;
	}

	if (retval >= 0 && p_regulatory_entry != NULL)
	{
		unsigned int	iter;
		char		channel_str[ 12 ];
		int		min_tx_power = local_bootcfg_get_min_tx_power();
		int		started_list = 0;

		*list_of_channels = '\0';

		for (iter = 0; p_regulatory_entry[ iter ].channel > 0; iter++)
		{
			int	channel_usable = p_regulatory_entry[ iter ].max_tx_power >= min_tx_power;
		  /*
		   * See comment above about channels 149 to 161 in Europe.  Returned list omits
		   * channels 149 to 161, as these are blocked by set_regulatory_region in Europe.
		   */
			if (channel_usable &&
			    bw == qcsapi_bw_40MHz &&
			  ((p_regulatory_entry[ iter ].flags & m_40MHz_available) != m_40MHz_available))
			  channel_usable = 0;

			if (channel_usable)
			{
				if (restriction == 1 &&
				  ((p_regulatory_entry[ iter ].flags & m_DFS_required) == m_DFS_required))
				  channel_usable = 0;
				else if (restriction == 2 &&
				       ((p_regulatory_entry[ iter ].flags & m_DFS_required) != m_DFS_required))
				  channel_usable = 0;

			}

			if (channel_usable)
			{
				sprintf( &channel_str[ 0 ], "%d", p_regulatory_entry[ iter ].channel );
				if (started_list == 0)
				  started_list = 1;
				else
				  strcat( list_of_channels, "," );
				strcat( list_of_channels, &channel_str[ 0 ] );
			}
		}
	}

	return( retval );
}


int
qcsapi_wifi_get_list_regulatory_channels(
	const char *region_by_name,
	const qcsapi_unsigned_int bw,
	string_1024 list_of_channels
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_wifi_get_restricted_list_channels( region_by_name, bw, 0, list_of_channels );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_list_DFS_channels(
	const char *region_by_name,
	const int DFS_flag,
	const qcsapi_unsigned_int bw,
	string_1024 list_of_channels
)
{
	int	retval = 0;
	int	local_restriction = 0;

	enter_qcsapi();

	if (DFS_flag == 0)
	  local_restriction = 1;
	else if (DFS_flag == 1)
	  local_restriction = 2;
	else
	  retval = -EINVAL;

	if (retval >= 0)
	  retval = local_wifi_get_restricted_list_channels( region_by_name, bw, local_restriction, list_of_channels );

	leave_qcsapi();

	return( retval );
}

/*
 * Channel is either subject to DFS restrictions or it is not.  Bandwidth does not matter.
 */
static int
local_wifi_is_channel_DFS( const char *region_by_name, const qcsapi_unsigned_int the_channel, int *p_channel_is_DFS )
{
	int				 retval = 0;
	qcsapi_regulatory_region	 the_region = QCSAPI_NOSUCH_REGION;
	channel_entry			*p_regulatory_entry = NULL;

	if (region_by_name == NULL || p_channel_is_DFS == NULL)
	  retval = -EFAULT;
	else
	{
		unsigned int	iter;

		for (iter = 0; iter < regulatory_region_size && the_region == QCSAPI_NOSUCH_REGION; iter++) {
			if (strcasecmp( region_by_name, regulatory_region_name[ iter ].the_name ) == 0)
			  the_region = regulatory_region_name[ iter ].the_region;
		}

		if (the_region == QCSAPI_NOSUCH_REGION)
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		p_regulatory_entry = locate_regulatory_channel_entry( the_region );
		if (p_regulatory_entry == NULL)
		  retval = -EOPNOTSUPP;
	}

	if (retval >= 0 && p_regulatory_entry != NULL)
	{
		unsigned int	iter;
		int		min_tx_power = local_bootcfg_get_min_tx_power();
		int		found_entry = 0;

		for (iter = 0; p_regulatory_entry[ iter ].channel > 0 && found_entry == 0; iter++)
		{
			int	channel_usable = p_regulatory_entry[ iter ].max_tx_power >= min_tx_power;
		  /*
		   * See comment above about channels 149 to 161 in Europe.  Returned list omits
		   * channels 149 to 161, as these are blocked by set_regulatory_region in Europe.
		   */
			if (channel_usable && p_regulatory_entry[ iter ].channel == the_channel)
			{
				found_entry = 1;

				if ((p_regulatory_entry[ iter ].flags & m_DFS_required) == m_DFS_required)
				  *p_channel_is_DFS = 1;
				else
				  *p_channel_is_DFS = 0;
			}
		}

		if (found_entry == 0)
		  retval = -EINVAL;
	}

	return( retval );
}

int
qcsapi_wifi_is_channel_DFS( const char *region_by_name, const qcsapi_unsigned_int the_channel, int *p_channel_is_DFS )
{
	int retval = 0;

	enter_qcsapi();

	retval = local_wifi_is_channel_DFS( region_by_name, the_channel, p_channel_is_DFS );

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_DFS_alt_channel( const char *ifname, qcsapi_unsigned_int *p_dfs_alt_chan )
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || p_dfs_alt_chan == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (current_wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_wifi_get_private_int_param_by_name(skfd, ifname,
			"get_alt_chan", (int *)p_dfs_alt_chan);

	if (retval < 0) {
		goto ready_to_return;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_wifi_set_DFS_alt_channel( const char *ifname, const qcsapi_unsigned_int dfs_alt_chan )
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (current_wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0) {
		goto ready_to_return;
	}

	/* When dfs_alt_chan set to zero, it means this function will be disabled*/
	if (dfs_alt_chan > QCSAPI_MAX_CHANNEL) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	retval = local_wifi_set_private_int_param_by_name(skfd, ifname,
			"set_alt_chan", dfs_alt_chan);

	if (retval < 0) {
		goto ready_to_return;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

int
local_wifi_get_SSID( const int skfd, const char *ifname, qcsapi_SSID SSID_str )
{
	int		retval = 0;
	struct iwreq	wrq;

	if (SSID_str == NULL)
	  retval = -EFAULT;
	else
	{
		memset( SSID_str, 0, sizeof( qcsapi_SSID ) );

		wrq.u.essid.pointer = (caddr_t) SSID_str;
		wrq.u.essid.length = IW_ESSID_MAX_SIZE + 1;
		wrq.u.essid.flags = 0;
		retval = local_priv_ioctl(skfd, ifname, SIOCGIWESSID, &wrq);

		if (retval < 0)
		{
			if (errno > 0)
				retval = -errno;
		}
	}

	return( retval );
}

/*
 * Set the SSID using the Wireless Extended interface (programming based on iwconfig)
 */
int
local_wifi_set_SSID( const int skfd, const char *ifname, const qcsapi_SSID SSID_str )
{
	int		retval = 0;
	int		we_kernel_version = local_get_we_version();
	struct iwreq	wrq;


	wrq.u.essid.pointer = (caddr_t) SSID_str;
	wrq.u.essid.length = strlen( SSID_str );
	wrq.u.essid.flags = 1;

	if(we_kernel_version < 21)
	  wrq.u.essid.length++;

	retval = local_priv_ioctl(skfd, ifname, SIOCSIWESSID, &wrq);

	if (retval < 0)
	{
		if (errno > 0)
		  retval = -errno;
	}

	return( retval );
}

/* The QCSAPIs to work with the SSID are in qcsapi_security.c */

int
qcsapi_wifi_get_channel( const char *ifname, qcsapi_unsigned_int *p_current_channel )
{
	int			retval = 0;
	int			skfd = -1;

	enter_qcsapi();

	if (p_current_channel == NULL)
	  retval = -EFAULT;
	else
	{
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = retval;
		}
	}

	if (retval >= 0)
	{
		retval = local_wifi_get_channel( skfd, ifname, p_current_channel );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_channel( const char *ifname, const qcsapi_unsigned_int new_channel )
{
	int		retval = 0;
	int		skfd = -1;

	enter_qcsapi();

	/* Do not block new_channel == 0, 0 will triger the automatic channel selection */
	if ((new_channel > QCSAPI_MAX_CHANNEL || new_channel < QCSAPI_MIN_CHANNEL) &&
			(new_channel != QCSAPI_ANY_CHANNEL)) {
		retval = -EINVAL;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_set_channel( skfd, ifname, new_channel );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_chan_pri_inactive( const char *ifname, const qcsapi_unsigned_int channel,
				const qcsapi_unsigned_int inactive)
{
	int		retval = 0;
	int		skfd = -1;

	enter_qcsapi();

	if ((channel > QCSAPI_MAX_CHANNEL || channel < QCSAPI_MIN_CHANNEL)) {
		retval = -EINVAL;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_set_chan_pri_inactive(skfd, ifname, channel, inactive,
				CHAN_PRI_INACTIVE_CFG_USER_OVERRIDE);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_beacon_interval( const char *ifname, qcsapi_unsigned_int *p_current_bintval )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (p_current_bintval == NULL)
		retval = -EFAULT;
	else
	{
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
	}

	if (retval >= 0)
		retval = local_interface_verify_net_device(ifname);

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);

		if (current_wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
		retval = local_wifi_get_private_int_param_by_name( skfd,ifname,"get_bintval",(int*)p_current_bintval);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_beacon_interval( const char *ifname, const qcsapi_unsigned_int new_bintval )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0)
		retval = -errno;

	if (retval >= 0)
		retval = local_interface_verify_net_device(ifname);

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);

		if (current_wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0)
	{
		retval = local_wifi_set_private_int_param_by_name( skfd, ifname, "bintval", (int)new_bintval);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
local_wifi_get_BSSID( const int skfd, const char *ifname, qcsapi_mac_addr BSSID_str )
{
	int	retval = 0;

	if (ifname == NULL || BSSID_str == NULL)
	  retval = -EFAULT;
	else
	{
		struct iwreq	wrq;
		int		ival = local_priv_ioctl(skfd, ifname, SIOCGIWAP, &wrq);

		if (ival >= 0)
		{
			memcpy(BSSID_str, wrq.u.ap_addr.sa_data, sizeof( qcsapi_mac_addr ) );
		}
		else
		{
			retval = -errno;
			if (retval >= 0)
			  retval = ival;
		}
	}

	return( retval );
}

int
qcsapi_wifi_get_BSSID( const char *ifname, qcsapi_mac_addr BSSID_str )
{
	int				retval = 0;
	int				skfd = -1;
	qcsapi_interface_status_code	status_code = qcsapi_interface_status_error;

	enter_qcsapi();

	if (ifname == NULL || BSSID_str == NULL)
		retval = -EFAULT;
	else
		retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0) {
		retval = local_interface_get_status(skfd, ifname, &status_code);
	}

	if (retval >= 0) {
		if (status_code == qcsapi_interface_status_disabled) {
			memset(BSSID_str, 0, sizeof(qcsapi_mac_addr));
		} else {
			retval = local_wifi_get_BSSID(skfd, ifname, BSSID_str);
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_config_BSSID(const char *ifname, qcsapi_mac_addr BSSID)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;
	char BSSID_string[MAC_ADDR_STRING_LENGTH];

	enter_qcsapi();

	if (ifname == NULL || BSSID == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
	}

	if (local_wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
	}

	if (retval >= 0) {
		if (local_verify_interface_is_primary(ifname) == 0) {
			local_interface_get_mac_addr(skfd, ifname, BSSID);
		} else {
			retval = lookup_ap_security_parameter(ifname,
					qcsapi_access_point,
					"bssid",
					BSSID_string,
					sizeof(BSSID_string));
			if (retval >= 0) {
				retval = local_parse_mac_addr(BSSID_string, BSSID);
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_ssid_get_bssid(const char *ifname, const qcsapi_SSID ssid_str,
			   qcsapi_mac_addr bssid)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;
	char bssid_string[MAC_ADDR_STRING_LENGTH];

	enter_qcsapi();

	if (ifname == NULL || bssid == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
	}

	if (local_wifi_mode != qcsapi_station) {
		retval = -qcsapi_only_on_STA;
	}

	if (retval >= 0) {
		retval = lookup_SSID_parameter(ssid_str, local_wifi_mode, "bssid", bssid_string,
			sizeof(bssid_string));
	}

	if (retval >= 0) {
		retval = local_parse_mac_addr(bssid_string, bssid);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return( retval );
}


int
qcsapi_wifi_ssid_set_bssid(const char *ifname, const qcsapi_SSID ssid_str,
			   const qcsapi_mac_addr bssid)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || bssid == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
	}

	if (local_wifi_mode != qcsapi_station) {
		retval = -qcsapi_only_on_STA;
	}

	if (retval >= 0) {
		const static qcsapi_mac_addr	all_FF = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

		if (memcmp(bssid, all_FF, sizeof(all_FF)) == 0) {
			retval = remove_security_parameter(ifname, ssid_str, "bssid",
							   local_wifi_mode,
							   security_update_complete);
		}
		else if (((retval = local_generic_verify_mac_addr_valid(bssid)) >= 0)) {
			char mac_str[32];

			snprintf(mac_str, sizeof(mac_str), MACFILTERINGMACFMT,
				 bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

			retval = update_security_parameter(ifname, ssid_str, "bssid", mac_str,
							   local_wifi_mode, QCSAPI_TRUE,
							   QCSAPI_FALSE, security_update_complete);
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return( retval );
}
static int local_wifi_get_qos_param(const int skfd,
				    const char *ifname,
				    int the_queue,
				    int the_param,
				    int ap_bss_flag,
				    int *p_value)
{
	int		 retval = 0;
	char		 qos_queue_str[4];
	char		 qos_param_str[4];
	char		 ap_bss_flag_str[4];
	char		*argv[] = {&qos_param_str[0],
				   &qos_queue_str[0],
				   &ap_bss_flag_str[0]
			 };
	const int	 argc = sizeof(argv) / sizeof(argv[0]);
	int32_t		 local_qos_param_val = 0;

	/* Value of queue to use ranges from 0 to 3. */
	if (the_queue < 0 || the_queue > 3) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	/* Value of parameter to report ranges from 1 to 6. */
	if (the_param < 1 || the_param > 6 ||
			(the_param == IEEE80211_WMMPARAMS_ACM && ap_bss_flag != 1) ||
			(the_param == IEEE80211_WMMPARAMS_NOACKPOLICY && ap_bss_flag != 0)) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	if (ap_bss_flag != 0 && ap_bss_flag != 1) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	snprintf(&qos_queue_str[0], sizeof(qos_queue_str), "%d", (int) the_queue);
	snprintf(&qos_param_str[0], sizeof(qos_param_str), "%d", the_param);
	snprintf(&ap_bss_flag_str[0], sizeof(ap_bss_flag_str), "%d", (int) ap_bss_flag);

	retval = call_private_ioctl(skfd,
				 argv,
				 argc,
				 ifname,
				"getwmmparams",
				&local_qos_param_val,
				 sizeof(local_qos_param_val));

	if (retval >= 0) {
		*p_value = (int) local_qos_param_val;
	}

ready_to_return:

	return retval;
}

static int local_wifi_set_qos_param(const int skfd,
				    const char *ifname,
				    int the_queue,
				    int the_param,
				    int ap_bss_flag,
				    int value)
{
	int		 retval = 0;
	char		 qos_queue_str[4];
	char		 qos_param_str[4];
	char		 ap_bss_flag_str[4];
	char		 qos_param_val_str[8];
	char		*argv[] = {&qos_param_str[0],
				   &qos_queue_str[0],
				   &ap_bss_flag_str[0],
				   &qos_param_val_str[0]
			 };
	const int	 argc = sizeof(argv) / sizeof(argv[0]);
	int32_t		 local_qos_param_val = value;

	if (the_queue < 0 || the_queue > 3) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	if ((the_param < 1 || the_param > 6 ||
			(the_param == IEEE80211_WMMPARAMS_ACM && ap_bss_flag != 1) ||
			(the_param == IEEE80211_WMMPARAMS_NOACKPOLICY && ap_bss_flag != 0))) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	if (ap_bss_flag != 0 && ap_bss_flag != 1) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	snprintf(&qos_queue_str[0], sizeof(qos_queue_str), "%d", (int) the_queue);
	snprintf(&qos_param_str[0], sizeof(qos_param_str), "%d", the_param);
	snprintf(&ap_bss_flag_str[0], sizeof(ap_bss_flag_str), "%d", (int) ap_bss_flag);
	snprintf(&qos_param_val_str[0], sizeof(qos_param_val_str), "%d", value);

	retval = call_private_ioctl(skfd,
				 argv,
				 argc,
				 ifname,
				"setwmmparams",
				&local_qos_param_val,
				 sizeof(local_qos_param_val));

ready_to_return:

	return retval;
}

int qcsapi_wifi_qos_get_param(const char *ifname,
			      int the_queue,
			      int the_param,
			      int ap_bss_flag,
			      int *p_value)
{
	int	skfd = -1;
	int	retval = 0;

	enter_qcsapi();

	if (ifname == NULL || p_value == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0) {
		goto ready_to_return;
	}

	if ((retval = local_interface_verify_net_device(ifname)) < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_qos_param(skfd,
					  ifname,
					  the_queue,
					  the_param,
					  ap_bss_flag,
					  p_value);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_qos_set_param(const char *ifname,
			      int the_queue,
			      int the_param,
			      int ap_bss_flag,
			      int value)
{
	int	skfd = -1;
	int	retval = 0;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0) {
		goto ready_to_return;
	}

	if ((retval = local_interface_verify_net_device(ifname)) < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_set_qos_param(skfd,
					  ifname,
					  the_queue,
					  the_param,
					  ap_bss_flag,
					  value);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_wmm_ac_map(const char *ifname, string_64 mapping_table)
{
	int i = 0;
	int	retval = 0;
	FILE *qdrv_sch_fd = NULL;
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE];
	char file_name[QCSAPI_WIFI_CMD_BUFSIZE];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -ENODEV;
		goto ready_to_return;
	}

	if (mapping_table == NULL) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0)
		goto ready_to_return;

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd) - 1, "get 0 wmm_ac_map %s", ifname);
	retval = local_wifi_write_to_qdrv(cmd);
	if (retval < 0)
		goto ready_to_return;

	memset(file_name, 0, sizeof(file_name));
	snprintf(file_name, sizeof(file_name) - 1, QDRV_RESULTS);

	qdrv_sch_fd = fopen(file_name, "r");
	if (!qdrv_sch_fd) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	fgets(mapping_table, QCSAPI_WIFI_AC_MAP_SIZE, qdrv_sch_fd);
	for (i = 0; i < IEEE8021P_PRIORITY_NUM; i++) {
		fgets(mapping_table + strlen(mapping_table),
			QCSAPI_WIFI_AC_MAP_SIZE - strlen(mapping_table), qdrv_sch_fd);
	}

ready_to_return:
	if (qdrv_sch_fd)
		fclose(qdrv_sch_fd);

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_set_wmm_ac_map(const char *ifname, int user_prio, int ac_index)
{
	int	retval = 0;
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -ENODEV;
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0)
		goto ready_to_return;

	if ((user_prio < IEEE8021P_PRIORITY_ID0) ||
			(user_prio > IEEE8021P_PRIORITY_ID7)) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	if ((ac_index < IEEE80211_WMM_AC_BE) ||
			(ac_index > IEEE80211_WMM_AC_VO)) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd) - 1, "set wmm_ac_map %s %d %d",
			ifname, user_prio, ac_index);
	retval = local_wifi_write_to_qdrv(cmd);

ready_to_return:
	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_dscp_8021p_map(const char *ifname, string_64 mapping_table)
{
	int	retval = 0;

#ifdef TOPAZ_PLATFORM
	retval = -EOPNOTSUPP;
#else
	int	dot1p_up;
	int	i = 0;
	FILE	*qdrv_sch_fd = NULL;
	char	cmd[QCSAPI_WIFI_CMD_BUFSIZE];
	char	file_name[QCSAPI_WIFI_CMD_BUFSIZE];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -ENODEV;
		goto ready_to_return;
	}

	if (mapping_table == NULL) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0)
		goto ready_to_return;

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd) - 1, "get 0 dscp_8021p_map %s", ifname);
	retval = local_wifi_write_to_qdrv(cmd);
	if (retval < 0)
		goto ready_to_return;

	memset(file_name, 0, sizeof(file_name));
	snprintf(file_name, sizeof(file_name) - 1, QDRV_RESULTS);

	qdrv_sch_fd = fopen(file_name, "r");
	if (!qdrv_sch_fd) {
		retval = -EFAULT;
		goto ready_to_return;
	}
	while(((dot1p_up = fgetc(qdrv_sch_fd)) != EOF) && (i < IP_DSCP_NUM))
		mapping_table[i++] = (uint8_t)(dot1p_up - 0x30);
ready_to_return:
	if (qdrv_sch_fd)
		fclose(qdrv_sch_fd);

	leave_qcsapi();
#endif
	return retval;
}

int qcsapi_wifi_get_dscp_ac_map(const char *ifname, struct qcsapi_data_64bytes *mapping_table)
{
	int	retval = 0;

#ifndef TOPAZ_PLATFORM
	retval = -EOPNOTSUPP;
#else
	enter_qcsapi();

	if (ifname == NULL || mapping_table == NULL)
	      retval = -EINVAL;

	if (retval >= 0)
		retval = local_interface_verify_net_device(ifname);

	if (retval >= 0)
		retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_GET_DSCP2AC_MAP,
				mapping_table->data, IP_DSCP_NUM);

	leave_qcsapi();
#endif
	return retval;
}

#ifndef TOPAZ_PLATFORM
static int translate_ip_dscp(const char *argv, uint8_t *array, uint8_t *number)
{
	char	temp[3] = {0};
	uint8_t	i = 0;
	uint8_t	ip_dscp_number = 0;
	uint8_t ip_dscp_value[IP_DSCP_NUM] = {0};
	const char	*ip_dscp_str = NULL;

	if (argv == NULL || array == NULL || number == NULL)
		return -ENODEV;

	ip_dscp_str = argv;

	while (*ip_dscp_str != 0)
	{
		if (ip_dscp_number >= IP_DSCP_NUM)
			return -EINVAL;
		if (*ip_dscp_str != ',') {
			temp[i++] = *ip_dscp_str;
			if (i >= 3) {
				return -EINVAL;
			}
		} else {
			/*
			 * IP DSCP 64 is used to revert IP DSCP to 802.1p UP mapping table to default
			 */
			if ((ip_dscp_value[ip_dscp_number] = atoi(temp)) > IP_DSCP_NUM) {
				return -EINVAL;
			}
			i = 0;
			ip_dscp_number++;
			memset(temp, 0, 3);
		}
		ip_dscp_str++;
	}

	/*No comma for last IP DSCP vaule*/
	if ((ip_dscp_number < IP_DSCP_NUM) &&
		((ip_dscp_value[ip_dscp_number++] = atoi(temp)) > IP_DSCP_NUM)) {
			return -ENODEV;
	}

	*number = ip_dscp_number;
	memcpy(array, ip_dscp_value, ip_dscp_number);

	return 0;
}
#endif

int qcsapi_wifi_set_dscp_8021p_map(const char *ifname, const char *ip_dscp_list, uint8_t dot1p_up)
{
	int	retval = 0;
#ifdef TOPAZ_PLATFORM
	retval = -EOPNOTSUPP;
#else
	char	cmd[QCSAPI_WIFI_CMD_BUFSIZE];
	uint8_t	ip_dscp_number = 0;
	uint8_t ip_dscp_value[IP_DSCP_NUM] = {0};
	int	i = 0;

	enter_qcsapi();

	if (ifname == NULL || ip_dscp_list == NULL) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0)
		goto ready_to_return;

	if ((retval = translate_ip_dscp(ip_dscp_list, ip_dscp_value, &ip_dscp_number)) < 0) {
		goto ready_to_return;
	}

	if (dot1p_up >= IEEE8021P_PRIORITY_NUM) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	for (i = 0; i < ip_dscp_number; i++) {
		memset(cmd, 0, sizeof(cmd));
		snprintf(cmd, sizeof(cmd) - 1, "set dscp_8021p_map %s %d %d",
				ifname, ip_dscp_value[i], dot1p_up);
		retval |= local_wifi_write_to_qdrv(cmd);
	}

ready_to_return:
	leave_qcsapi();
#endif
	return retval;
}

int qcsapi_wifi_set_dscp_ac_map(const char *ifname,
			const struct qcsapi_data_64bytes *dscp_list,
			uint8_t dscp_list_len,
			uint8_t ac)
{
	int	retval = 0;
#ifndef TOPAZ_PLATFORM
	retval = -EOPNOTSUPP;
#else
	qcsapi_dscp2ac_data dscp2ac;

	enter_qcsapi();

	if (ifname == NULL || dscp_list == NULL) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	retval = local_interface_verify_net_device(ifname);
	if (retval < 0)
		goto ready_to_return;

	if (ac > IEEE80211_WMM_AC_VO) {
		retval = -ERANGE;
		goto ready_to_return;
	}

	dscp2ac.ac = ac;
	dscp2ac.list_len = dscp_list_len;
	memcpy(dscp2ac.ip_dscp_list, dscp_list->data, dscp_list_len);
	retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_SET_DSCP2AC_MAP,
					&dscp2ac, sizeof(qcsapi_dscp2ac_data));

ready_to_return:
	leave_qcsapi();
#endif
	return retval;
}


int qcsapi_wifi_get_priority(const char *ifname, uint8_t *p_priority)
{
	int			retval = 0;
	int			skfd = -1;
	int			pri;
	qcsapi_wifi_mode	current_wifi_mode = qcsapi_nosuch_mode;

	if (p_priority == NULL)
		return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0)
		retval = -errno;

	if (retval >= 0)
		retval = local_interface_verify_net_device(ifname);

	/* WDS is not currently supported */
	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);
		if (current_wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_private_int_param_by_name(skfd, ifname, "get_vap_pri",
									(int *)&pri);
		if (retval >= 0)
			*p_priority = (uint8_t)pri;
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_set_priority(const char *ifname, uint8_t priority)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	current_wifi_mode = qcsapi_nosuch_mode;

	retval = local_swfeat_check_supported(SWFEAT_ID_QTM_PRIO);
	if (retval < 0)
		return retval;

	if (priority >= QTN_VAP_PRIORITY_NUM)
		return -EINVAL;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0)
		retval = -errno;

	if (retval >= 0)
		retval = local_interface_verify_net_device(ifname);

	/* WDS is not currently supported */
	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);

		if (current_wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_set_private_int_param_by_name( skfd, ifname, "vap_pri", (int)priority);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_airfair(const char *ifname, uint8_t *p_airfair)
{
#ifdef TOPAZ_PLATFORM
	int			retval = 0;
	int			skfd = -1;
	int			pri;
	qcsapi_wifi_mode	current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (p_airfair == NULL) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
	}

	if (retval >= 0)
		retval = local_interface_verify_net_device(ifname);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	/* WDS is not currently supported */
	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);

		if (current_wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
		retval = local_wifi_get_private_int_param_by_name(skfd, ifname, "get_airfair", (int*)&pri);
		if (retval >= 0)
			*p_airfair = (uint8_t)pri;
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
#else
	return -qcsapi_not_supported;
#endif
}

int qcsapi_wifi_set_airfair(const char *ifname, uint8_t airfair)
{
#ifdef TOPAZ_PLATFORM
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	current_wifi_mode = qcsapi_nosuch_mode;

	if (airfair > 1)
		return -EINVAL;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0)
		retval = -errno;

	if (retval >= 0)
		retval = local_interface_verify_net_device(ifname);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	/* WDS is not currently supported */
	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);

		if (current_wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_set_private_int_param_by_name( skfd, ifname, "airfair", (int)airfair);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
#else
	return -qcsapi_not_supported;
#endif
}

int
qcsapi_wifi_get_IEEE_802_11_standard( const char *ifname, char *IEEE_802_11_standard )
{
	int		retval = 0;
	int		skfd = -1;

	enter_qcsapi();

	if (IEEE_802_11_standard == NULL)
	  retval = -EFAULT;
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		int		ival;
		struct iwreq	wrq;

		memset( &wrq, 0, sizeof( wrq ) );
		ival = local_priv_ioctl( skfd, ifname, SIOCGIWNAME, &wrq );
		if (ival >= 0) {
			if (strstr( wrq.u.name, "802.11ac" ) != NULL)
                          strcpy( IEEE_802_11_standard, "a|n|ac" );
			else if (strstr( wrq.u.name, "802.11na" ) != NULL)
			  strcpy( IEEE_802_11_standard, "a|n" );
			else if (strstr( wrq.u.name, "802.11ng" ) != NULL)
			  strcpy( IEEE_802_11_standard, "g|n" );
			else if (strstr( wrq.u.name, "802.11g" ) != NULL)
			  strcpy( IEEE_802_11_standard, "g-only" );
			else if (strstr( wrq.u.name, "802.11a" ) != NULL)
			  strcpy( IEEE_802_11_standard, "a-only" );
			else if (strstr( wrq.u.name, "802.11b" ) != NULL)
			  strcpy( IEEE_802_11_standard, "b-only" );
			else if (strstr( wrq.u.name, "802.11n" ) != NULL)
			  strcpy( IEEE_802_11_standard, "n-only" );
			else
			  *IEEE_802_11_standard = '\0';
		} else {
			retval = -errno;
			if (retval >= 0)
			  retval = ival;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_dtim(const char *ifname, qcsapi_unsigned_int *p_dtim)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || p_dtim == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (current_wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_wifi_get_private_int_param_by_name(skfd, ifname,
			"get_dtim_period", (int *)p_dtim);

	if (retval < 0) {
		goto ready_to_return;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_wifi_set_dtim(const char *ifname, qcsapi_unsigned_int dtim)
{
	int retval = 0;
	int skfd = -1;
	char temp_str[2];
	qcsapi_wifi_mode current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (current_wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	sprintf( &temp_str[0], "%d", dtim);
	retval = update_security_parameter(
			ifname,
			NULL,
			"dtim_period",
			&temp_str[0],
			qcsapi_access_point,
			QCSAPI_TRUE,
			qcsapi_bare_string,
			security_update_complete
		);

	if (retval >= 0) {
		retval = update_security_bss_configuration(ifname);
	}

	if (retval < 0) {
		goto ready_to_return;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_wifi_get_assoc_limit(const char *ifname, qcsapi_unsigned_int *p_assoc_limit)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || p_assoc_limit == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0) {
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (current_wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_wifi_get_private_int_param_by_name(skfd, ifname,
			"get_assoc_limit", (int *)p_assoc_limit);

	if (retval < 0) {
		goto ready_to_return;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_wifi_set_assoc_limit(const char *ifname, qcsapi_unsigned_int assoc_limit)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0) {
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (current_wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_wifi_set_private_int_param_by_name(skfd, ifname,
			"assoc_limit", assoc_limit);

	if (retval < 0) {
		goto ready_to_return;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

static int
local_wifi_get_wmm_state(const int skfd, const char *ifname, int *wmm_state)
{
	int		 retval = 0;
	__s32		internal_wmm;
	char		*argv[] = { NULL };
	int		 argc = 0;

	retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);

	if (retval >= 0) {
		retval = call_private_ioctl(skfd,
					argv, argc,
					ifname,
					"get_wmm",
					(void *) &internal_wmm,
					sizeof( __s32 ));
		if (retval >= 0)
			*wmm_state = (int) internal_wmm;

	} else {
		*wmm_state  = 1;
		retval = 0;
	}

	return(retval);
}

/*
 * Disable WMM
 *
 * When WMM is disabled, the phy mode will be downgraded to 11a mode
 * and the bandwidth will be set to 20 MHz
 */
static int local_wifi_disable_wmm(int skfd, const char *ifname)
{
	int	retval;
	char	current_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION];
	qcsapi_base_frequency base_frequency;

	retval = local_wifi_option_set_iwpriv_bw(skfd,
						ifname,
						qcsapi_bw_20MHz);

	if (retval >= 0) {
		retval = local_get_internal_regulatory_region(skfd,
							ifname,
							&current_region[0]);
	}

	if (retval >= 0 && strcmp(&current_region[0], "none") != 0) {
		retval = local_regulatory_set_regulatory_region(ifname, current_region);

		if (retval == -qcsapi_region_database_not_found) {
			retval = local_wifi_set_regulatory_region(ifname, current_region);
		}
	}

	if (retval >= 0) {
		retval = get_wifi_base_frequency(skfd,
						ifname,
						&base_frequency);

		if ((retval >= 0) && (base_frequency != qcsapi_2_4_GHz)) {
			retval = local_wifi_set_802_11_mode(skfd, ifname, "11a");
		}
	}

	if (retval >= 0) {
		retval = local_wifi_option_set_iwpriv_wmm(skfd, ifname, 0);
	}

	return retval;
}

static int local_wifi_get_bw(const char *ifname, qcsapi_bw *bw, char *band_str)
{
	int	retval;
	char	bw_value_str[QCSAPI_MAX_PARAMETER_VALUE_LEN] = {0};

	retval = local_get_parameter(ifname, "bw",
				&bw_value_str[0],
				QCSAPI_MAX_PARAMETER_VALUE_LEN,
				LOCAL_GET_CONFIG_SCRIPT);

	if (retval == -qcsapi_parameter_not_found) {
		if (strncmp(band_str, "11ac", 4) == 0) {
			*bw = qcsapi_bw_80MHz;
		} else {
			*bw = qcsapi_bw_40MHz;
		}
		retval = 0;

	} else if (retval >= 0) {
		if (strcmp(bw_value_str, "20") == 0) {
			*bw = qcsapi_bw_20MHz;
		} else if (strcmp(bw_value_str, "40") == 0) {
			*bw = qcsapi_bw_40MHz;
		} else if (strcmp(bw_value_str, "80") == 0) {
			*bw = qcsapi_bw_80MHz;
		} else if (strcmp(bw_value_str, "160") == 0) {
			*bw = qcsapi_bw_160MHz;
		} else {
			retval = -EINVAL;
		}
	}

	return retval;
}

/*
 * Enable WMM
 *
 * When WMM return enabled from disabled, the phy mode and the bandwidth
 * will recover according to the "band"/"bw" parameter in config file.
 *
 * If there is no such parameters, the phy mode will be set according to the
 * chipsets: 11ac for TOPAZ and above; 11N for RUBY
 */
static int local_wifi_enable_wmm(int skfd, const char *ifname)
{
	int	retval;
	qcsapi_bw	bw;
	char	band_value_str[QCSAPI_MAX_PARAMETER_VALUE_LEN] = {0};
	char	current_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION];

	retval = local_get_parameter(ifname,
					"band",
					&band_value_str[0],
					QCSAPI_MAX_PARAMETER_VALUE_LEN,
					LOCAL_GET_CONFIG_SCRIPT);

	if (retval == -qcsapi_parameter_not_found) {
		strcpy(band_value_str, "11ac");
	}

	if (retval >= 0)
		retval = local_wifi_set_802_11_mode(skfd, ifname, band_value_str);

	if (retval >= 0) {
		retval = local_wifi_option_set_iwpriv_wmm(skfd, ifname, 1);
	}

	if (retval >= 0) {
		retval = local_wifi_get_bw(ifname, &bw, band_value_str);

		if (retval >= 0) {
			retval = local_wifi_option_set_iwpriv_bw(skfd, ifname, bw);
		}
	}

	if (retval >= 0) {
		retval = local_get_internal_regulatory_region(skfd,
							ifname,
							&current_region[0]);
	}

	if (retval >= 0 && strcmp(&current_region[0], "none") != 0) {
		retval = local_regulatory_set_regulatory_region(ifname, current_region);

		if (retval == -qcsapi_region_database_not_found) {
			retval = local_wifi_set_regulatory_region(ifname, current_region);
		}
	}

	return retval;
}

static int local_wifi_set_wmm(int skfd, const char *ifname, int enable)
{
	int	retval = 0;
	int	wmm_state;

	retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
		if (retval >= 0) {
			retval = local_wifi_get_wmm_state(skfd, ifname, &wmm_state);
			if (retval >= 0) {
				if (wmm_state != enable) {
					if (!enable) {
						retval = local_wifi_disable_wmm(skfd, ifname);
					} else {
						retval = local_wifi_enable_wmm(skfd, ifname);
					}
				}
			}
		}
	}

	return retval;
}

int
qcsapi_wifi_get_bss_assoc_limit(const char *ifname, qcsapi_unsigned_int *p_assoc_limit)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || p_assoc_limit == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (current_wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_wifi_get_private_int_param_by_name(skfd, ifname,
			"get_bss_assolmt", (int *)p_assoc_limit);

	if (retval < 0) {
		goto ready_to_return;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_wifi_set_bss_assoc_limit(const char *ifname, qcsapi_unsigned_int assoc_limit)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode current_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &current_wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (current_wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_wifi_set_private_int_param_by_name(skfd, ifname,
			"bss_assoc_limit", assoc_limit);

	if (retval < 0) {
		goto ready_to_return;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

static int
local_wifi_select_autorate_fallback( const int skfd, const char *ifname, int enable_flag )
{
	int		retval = 0;
	struct iwreq	wrq;

	if (enable_flag)
	{
		int	ival;

		memset( &wrq, 0, sizeof( wrq ) );

		wrq.u.bitrate.value = -1;
		wrq.u.bitrate.fixed = 0;

		ival = local_priv_ioctl(skfd, ifname, SIOCSIWRATE, &wrq);
		if (ival < 0)
		{
			retval = -errno;

			if (retval >= 0)
			  retval = ival;
		}
	}
	else
	{
		retval = -EOPNOTSUPP;
	}

	return( retval );
}

static int
local_wifi_option_setparam_value( const int skfd, const char *ifname, const int param, const int value)
{
	int		 retval = 0;
	char		 setparam_index[ 4 ];
	char		 setparam_value[ 4 ];
	char		*argv[] = { &setparam_index[ 0 ], &setparam_value[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );

	snprintf( &setparam_index[ 0 ], sizeof(setparam_index), "%d", param);
	snprintf( &setparam_value[ 0 ], sizeof(setparam_value), "%d", value);

	retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"setparam",
			NULL,
			0
			);

	return( retval );
}

int
local_wifi_option_setparam( const int skfd, const char *ifname, const int param, const int value)
{
	return local_wifi_option_setparam_value(skfd, ifname, param, value ? 1 : 0);
}

#define QCSAPI_DEFAULT_TXBF_PERIOD	10
#define QCSAPI_EXP_MAT_BFON		0x11
#define QCSAPI_EXP_MAT_BFOFF		0x10

int
local_wifi_set_beamforming( const int skfd, const char *ifname, int value )
{
	int retval = 0;

	if (value) {
		retval = local_wifi_option_setparam_value( skfd, ifname,
				IEEE80211_PARAM_TXBF_PERIOD,
				QCSAPI_DEFAULT_TXBF_PERIOD );
		if (retval >= 0)
			retval = local_wifi_option_setparam_value( skfd, ifname,
					IEEE80211_PARAM_EXP_MAT_SEL,
					QCSAPI_EXP_MAT_BFON);
	} else {
		retval = local_wifi_option_setparam_value( skfd, ifname,
				IEEE80211_PARAM_EXP_MAT_SEL,
				QCSAPI_EXP_MAT_BFOFF );
		if (retval >= 0)
			retval = local_wifi_option_setparam_value( skfd, ifname,
					IEEE80211_PARAM_TXBF_PERIOD,
					0);
	}

	return retval;
}

int
local_wifi_get_beamforming( const int skfd, const char *ifname, int *value )
{
	int retval = 0;
	int txbf_period = 0;

	retval = local_wifi_option_getparam( skfd, ifname,
				IEEE80211_PARAM_TXBF_PERIOD,
				&txbf_period );

	if (retval >= 0)
		*value = txbf_period > 0 ? 1 : 0;

	return retval;
}

static int local_wifi_get_uapsd_state(const int skfd, const char *ifname, int *uapsd_state)
{
	int	retval = 0;
	int	internal_uapsd;

	retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	}

	if (retval >= 0) {
		retval = local_wifi_get_private_int_param_by_name(skfd, ifname, "get_uapsd", &internal_uapsd);
		if (retval >= 0)
			*uapsd_state = internal_uapsd;
	}

	return(retval);
}

static int local_wifi_set_uapsd(int skfd, const char *ifname, int enable_flag)
{
	int	retval = 0;

	if (enable_flag > 1)
		retval = -qcsapi_param_value_invalid;

	retval = verify_we_device(skfd, ifname, NULL, 0);
	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
		if (retval >= 0) {
			retval = local_wifi_set_private_int_param_by_name(skfd, ifname, "uapsd", enable_flag);;
		}
	}

	return retval;
}

int
qcsapi_wifi_get_option( const char *ifname, qcsapi_option_type qscapi_option, int *p_current_option )
{
	int			skfd = -1;
	int			retval = 0;
	qcsapi_wifi_mode	current_wifi_mode;

	enter_qcsapi();

	if (p_current_option == NULL)
	   retval = -EFAULT;
	else
	{
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	if (retval >= 0)
	{
		retval = local_wifi_get_mode( skfd, ifname, &current_wifi_mode );
	}

	if (retval >= 0)
	{
		switch( qscapi_option )
		{
		  case qcsapi_channel_refresh:		/* access point only */
			if (current_wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			} else {
				*p_current_option = 0;
				retval = -qcsapi_option_not_supported;
			}
			break;

		  case qcsapi_DFS:			/* AP and STA */
			*p_current_option = 1;		/* DFS is enabled */
			break;
		  case qcsapi_uapsd:
			{
				int uapsd;
				*p_current_option = 0;
				retval = local_wifi_get_uapsd_state(skfd, ifname, &uapsd);
				if (retval >= 0) {
					*p_current_option = uapsd;
				}
				break;
			}

	  /*
	   * Thus WMM is ALWAYS enabled at STA side.
	   */
		  case qcsapi_wmm:
			{
				int wmm_state;
				retval = local_wifi_get_wmm_state(skfd, ifname, &wmm_state);
				if (retval >= 0) {
					*p_current_option = wmm_state;
				}
				break;
			}

		  case qcsapi_beacon_advertise:		/* access point only */
			if (current_wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
			else
			  *p_current_option = 1;	/* beacon always on */
			break;

		  case qcsapi_wifi_radio:
			*p_current_option = 1;		/* radio always on */
			break;

		  case qcsapi_autorate_fallback:
			{
				int	internal_mcs = 0;

				retval = local_wifi_get_mcs_rate( skfd, ifname, &internal_mcs );
				if (retval >= 0)
				{
					*p_current_option = (internal_mcs == -1);
				}
			}
			break;

		  case qcsapi_security:
			{
				qcsapi_security_setting	current_setting = qcsapi_security_not_defined;

				retval = local_security_get_security_setting( skfd, ifname, &current_setting );
				if (retval >= 0)
				{
					if (current_setting != qcsapi_security_on &&
					    current_setting != qcsapi_security_off)
					{
						retval = -ENODATA;
					}
					else
					{
						if (current_setting == qcsapi_security_on)
						  *p_current_option = 1;
						else
						  *p_current_option = 0;
					}
				}
			}
			break;

		  case qcsapi_SSID_broadcast:
			if (current_wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
			else
			{
				retval = local_security_get_broadcast_SSID( ifname, p_current_option );
			}
			break;

		  case qcsapi_802_11d:
		  case qcsapi_wireless_isolation:
			retval = -EOPNOTSUPP;
			break;

		  case qcsapi_short_GI:
			{
				int	short_gi = 0;

				retval = local_verify_interface_is_primary(ifname);
				if (retval == 0) {
					retval = local_wifi_option_getparam( skfd, ifname,
							IEEE80211_PARAM_SHORT_GI, &short_gi );
					if (retval >= 0)
					      *p_current_option = (short_gi) ? 1 : 0;
				}
			}
			break;

		  case qcsapi_802_11h:
			{
				int	config_802_11h = 0;

				retval = local_wifi_option_get_802_11h( skfd, ifname, &config_802_11h );
				if (retval >= 0)
				  *p_current_option = (config_802_11h) ? 1 : 0;
			}
			break;

		  case qcsapi_tpc_query:
			{
				int	config_802_tpc_query = 0;

				retval = local_wifi_option_get_tpc_query( skfd, ifname, &config_802_tpc_query );
				if (retval >= 0)
				  *p_current_option = (config_802_tpc_query) ? 1 : 0;
			}
			break;

		  case qcsapi_dfs_fast_channel_switch:
			if (current_wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
			else
			{
				int	dfs_fast_switch = 0;

				retval = local_wifi_option_get_dfs_fast_switch( skfd, ifname, &dfs_fast_switch );
				if (retval >= 0)
				  *p_current_option = (dfs_fast_switch) ? 1 : 0;
			}
			break;

		  case qcsapi_dfs_avoid_dfs_scan:
			if (current_wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
			else
			{
				int	dfs_fast_switch = 0;

				retval = local_wifi_option_get_avoid_dfs_scan( skfd, ifname, &dfs_fast_switch );
				if (retval >= 0)
				  *p_current_option = (dfs_fast_switch) ? 1 : 0;
			}
			break;

		  case qcsapi_specific_scan:
			if (current_wifi_mode != qcsapi_station)
				retval = -qcsapi_only_on_STA;
			else
			{
				int specific_scan = 0;

				retval = local_wifi_option_get_specific_scan( ifname, &specific_scan );
				if (retval >= 0)
					*p_current_option = (specific_scan) ? 1 : 0;
			}
			break;

		  case qcsapi_GI_probing:
			{
				int	GI_probing= 0;

				retval = local_wifi_option_getparam( skfd, ifname, IEEE80211_PARAM_GI_SELECT, &GI_probing);
				if (retval >= 0)
					*p_current_option = (GI_probing) ? 1 : 0;
			}
			break;

		  case qcsapi_GI_fixed:
			{
				int	GI_fixed= 0;

				retval = local_wifi_option_getparam( skfd, ifname, IEEE80211_PARAM_FIXED_SGI, &GI_fixed);
				if (retval >= 0)
					*p_current_option = (GI_fixed) ? 1 : 0;
			}
			break;

		  case qcsapi_stbc:
			{
				int	stbc = 0;
				retval = local_verify_interface_is_primary(ifname);
				if (retval == 0) {
					retval = local_wifi_option_getparam( skfd, ifname, IEEE80211_PARAM_STBC, &stbc);
					if (retval >= 0)
					      *p_current_option = (stbc) ? 1: 0;
				}
			}
			break;

		  case qcsapi_beamforming:
			{
				int beamforming = 0;
				retval = local_wifi_get_beamforming( skfd, ifname, &beamforming);
				if (retval >= 0)
					*p_current_option = (beamforming) ? 1 : 0;
			}
			break;

		  case qcsapi_nosuch_option:
		  default:
			retval = -EINVAL;
			break;

		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_option( const char *ifname, qcsapi_option_type qscapi_option, int new_option )
{
	int			skfd = -1;
	int			retval = 0, local_error_retval = 0;
	qcsapi_wifi_mode	current_wifi_mode;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0)
	{
		local_error_retval = -errno;
		if (local_error_retval >= 0)
		  local_error_retval = skfd;
	}

	if (local_error_retval >= 0)
	{
		local_error_retval = local_wifi_get_mode( skfd, ifname, &current_wifi_mode );
	}

	if (local_error_retval >= 0)
	{
		switch( qscapi_option )
		{
		  case qcsapi_channel_refresh:		/* access point only */
			if (current_wifi_mode != qcsapi_access_point) {
				local_error_retval = -qcsapi_only_on_AP;
			} else {
				local_error_retval = -qcsapi_option_not_supported;
			}
			break;

		  case qcsapi_DFS:			/* DFS cannot be configured */
			local_error_retval = -EOPNOTSUPP;
			break;

		  case qcsapi_uapsd:
			local_error_retval = local_wifi_set_uapsd(skfd, ifname, new_option);
			break;
	  /*
	   * Currently, we just support disabling the WMM in AP mode. And when the WMM is disabled,
	   * the AP will be set 11a phy mode.
	   */
		  case qcsapi_wmm:
			local_error_retval = local_wifi_set_wmm(skfd, ifname, new_option);
			break;

		  case qcsapi_beacon_advertise:		/* access point only */
			if (current_wifi_mode != qcsapi_access_point || new_option == 0)
			  local_error_retval = -EOPNOTSUPP;
			break;

		  case qcsapi_wifi_radio:
			local_error_retval = -EOPNOTSUPP;
			break;

		  case qcsapi_autorate_fallback:
			local_error_retval = local_wifi_select_autorate_fallback( skfd, ifname, new_option );
			break;

		  case qcsapi_security:
			local_error_retval = -EOPNOTSUPP;
			break;

		  case qcsapi_SSID_broadcast:
			if (current_wifi_mode != qcsapi_access_point) {
				local_error_retval = -qcsapi_only_on_AP;
			} else {
				local_error_retval = local_security_set_broadcast_SSID( ifname, new_option );
			}
			break;

		  case qcsapi_802_11d:
		  case qcsapi_wireless_isolation:
			local_error_retval = -EOPNOTSUPP;
			break;

		  case qcsapi_802_11h:
			local_error_retval = local_wifi_option_set_802_11h( skfd, ifname, new_option );
			break;

		  case qcsapi_sta_dfs:
			if (current_wifi_mode != qcsapi_station) {
				local_error_retval = -qcsapi_only_on_STA;
			} else {
				local_error_retval = local_wifi_option_set_sta_dfs( skfd, ifname, new_option );
			}
			break;

		  case qcsapi_tpc_query:
			local_error_retval = local_wifi_option_set_tpc_query( skfd, ifname, new_option );
			break;

		  case qcsapi_dfs_fast_channel_switch:
			if (current_wifi_mode != qcsapi_access_point) {
				local_error_retval = -qcsapi_only_on_AP;
			} else {
				local_error_retval = local_wifi_option_set_dfs_fast_switch( skfd, ifname, new_option );
			}
			break;

		  case qcsapi_dfs_avoid_dfs_scan:
			if (current_wifi_mode != qcsapi_access_point) {
				local_error_retval = -qcsapi_only_on_AP;
			} else {
				local_error_retval = local_wifi_option_set_avoid_dfs_scan( skfd, ifname, new_option );
			}
			break;

		  case qcsapi_short_GI:
			local_error_retval = local_verify_interface_is_primary(ifname);
			if (local_error_retval == 0) {
				local_error_retval = local_wifi_option_setparam( skfd, ifname, IEEE80211_PARAM_SHORT_GI, new_option );
			}
			break;

		  case qcsapi_specific_scan:
			if (current_wifi_mode != qcsapi_station) {
				local_error_retval = -qcsapi_only_on_STA;
			} else {
				local_error_retval = local_wifi_option_set_specific_scan( skfd, ifname, new_option );
			}
			break;

		  case qcsapi_GI_probing:
			local_error_retval = local_wifi_option_setparam( skfd, ifname, IEEE80211_PARAM_GI_SELECT, new_option );
			break;

		  case qcsapi_GI_fixed:
			local_error_retval = local_wifi_option_setparam( skfd, ifname, IEEE80211_PARAM_FIXED_SGI, new_option );
			break;

		  case qcsapi_stbc:
			local_error_retval = local_verify_interface_is_primary(ifname);
			if (local_error_retval == 0) {
				local_error_retval = local_wifi_option_setparam( skfd, ifname, IEEE80211_PARAM_STBC, new_option );
			}
			break;

		  case qcsapi_beamforming:
			local_error_retval = local_wifi_set_beamforming( skfd, ifname, new_option );
			break;

		  case qcsapi_nosuch_option:
		  default:
			local_error_retval = -EINVAL;
			break;

		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	if (local_error_retval < 0)
	 retval = local_error_retval;

	leave_qcsapi();

	return( retval );
}

#define HW_REVISION_FILE	"/proc/hw_revision"

int
local_get_hw_desc(char *pbuffer, const int len)
{
	int retval;

	retval = local_wifi_write_to_qdrv("get 0 hw_desc");
	if (retval < 0)
		return retval;

	retval = local_read_string_from_file(QDRV_RESULTS, pbuffer, len);

	return retval;
}

static int local_get_hw_id(string_64 p_buffer)
{
	int retval;
	string_64 hw_desc;
	char *hw_id;

	retval = local_get_hw_desc(hw_desc, sizeof(hw_desc));
	if (retval < 0)
		return retval;

	hw_id = strrchr(hw_desc, ' ');

	if (!hw_id)
		return -EINVAL;

	++hw_id;

	strcpy(p_buffer, hw_id);

	return 0;
}

int
qcsapi_get_board_parameter(qcsapi_board_parameter_type board_param, string_64 p_buffer)
{
	int retval = 0;
	int len = 0;
	int max_bw_ent = 0;
	int v1 = 0;
	int v2 = 0;
	int i;
	int j;
	int first = 1;

	enter_qcsapi();

	if (p_buffer == NULL) {
		leave_qcsapi();
		return -EFAULT;
	}

	switch (board_param) {
	case qcsapi_hw_revision:
		retval = local_read_string_from_file(HW_REVISION_FILE, p_buffer, sizeof(string_64));
		break;
	case qcsapi_hw_id:
		retval = local_get_hw_id(p_buffer);
		break;
	case qcsapi_hw_desc:
		retval = local_get_hw_desc(p_buffer, sizeof(string_64));
		break;
	case qcsapi_rf_chipid:
		retval = local_wifi_get_rf_chipid(&v1);
		sprintf(p_buffer, "%d", v1);
		break;
	case qcsapi_vht:
		if (local_swfeat_is_supported(SWFEAT_ID_VHT))
			v1 = 1;
		sprintf(p_buffer, "%d", v1);
		break;
	case qcsapi_bandwidth:
                max_bw_ent = local_get_max_bw();
		for (i = 0, j = 0; i <= max_bw_ent; i++, j += len) {
			len = sprintf(&p_buffer[j], "%s%d",
				first ? "" : ",",
				qcsapi_bw_list[i]);
			if (len <= 0)
			      break;
		      first = 0;
		}
		break;
	case qcsapi_spatial_stream:
		retval = local_get_supported_spatial_streams(&v1, &v2);
		if (retval >= 0)
			sprintf(p_buffer, "TX_SS:%d RX_SS:%d", v1, v2);
		break;
	case qcsapi_bond_opt:
		retval = local_get_bond_opt_info(p_buffer);
		break;
	case qcsapi_interface_types:
		retval = local_get_interface_types(p_buffer);
		break;
	case qcsapi_nosuch_parameter:
	default:
		retval = -EINVAL;
		break;
	}

	leave_qcsapi();

	return retval;
}

static unsigned int
cvt_rate_mbps_to_string( unsigned int current_rate, char *rate_in_mbps )
{
	unsigned int	integer_rate_mbps = current_rate / 1000000;
	unsigned int	fractional_rate_mbps = current_rate % 1000000;
	unsigned int	length_current_rate;

	if (fractional_rate_mbps == 0)
	{
		sprintf( rate_in_mbps, "%u", integer_rate_mbps );
		length_current_rate = strlen( rate_in_mbps );
	}
	else
	{
		unsigned int	local_length;

		sprintf( rate_in_mbps, "%u.%06u", integer_rate_mbps, fractional_rate_mbps );
		local_length = strlen( rate_in_mbps );
		if (local_length > 0)
		{
		  /* trim trailing 0's.
		   * Since the fractional rate in MBPS is not 0, at least one digi
		   * to the right of the decimal point will NOT be 0.
		   *
		   * Thus possibility of 1.000000  ==>  1. will not occur
		   */
			int	complete = 0;

			while (local_length > 1 && complete == 0)
			{
				if (rate_in_mbps[ local_length - 1 ] == '0')
				{
					rate_in_mbps[ local_length - 1 ] = '\0';
					local_length--;
				}
				else
				  complete = 1;
			}
		}

		length_current_rate = local_length;
	}

	return( length_current_rate );
}

/*
 * Special note: max_output_len is the count of non-NULL chars in the output string.
 *               So if the output string has dimension 64, max_output_len should be 63 (or less).
 * Special note: retval is the count of characters in the resulting string.
 */

static int
list_rates_to_string(
	int32_t *list_of_rates,				/* match type of 'bitrate' array in iw_range struct */
	const unsigned int list_length,
	char *output_str,
	const unsigned int max_output_len
)
{
	int		retval = 0;
	int		found_error = 0;
	char		rate_in_mbps[ 12 ];
	unsigned int	iter, current_output_len = max_output_len;
	unsigned int	current_rate = (unsigned int) list_of_rates[ 0 ];
	unsigned int	length_current_rate = cvt_rate_mbps_to_string( current_rate, &rate_in_mbps[ 0 ] );

	if (length_current_rate <= current_output_len)
	{
		strcpy( output_str, &rate_in_mbps[ 0 ] );
		output_str += length_current_rate;
		current_output_len = current_output_len - length_current_rate;

		retval = (int) length_current_rate;
	}
	else
	  found_error = 1;

	for (iter = 1; iter < list_length && found_error == 0; iter++)
	{
		current_rate = (unsigned int) list_of_rates[ iter ];
		length_current_rate = cvt_rate_mbps_to_string( current_rate, &rate_in_mbps[ 0 ] );

		if (length_current_rate + 1 <= current_output_len)
		{
			*(output_str++) = ',';
			strcpy( output_str, &rate_in_mbps[ 0 ] );
			output_str += length_current_rate;
			current_output_len = current_output_len - length_current_rate;

			retval += (int) length_current_rate;
		}
		else
		  found_error = 1;
	}

	return( retval );
}

int
qcsapi_wifi_get_rates( const char *ifname, qcsapi_rate_type rate_type, string_1024 supported_rates )
{
	int	skfd = -1;
	int	retval = 0;
	int32_t	rates[128];
	int32_t num_rates = 0;

	enter_qcsapi();

	if (supported_rates == NULL) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval >= 0) {
		struct iwreq	wrq;
		int		ival;

		memset(&wrq, 0, sizeof(struct iwreq));
		wrq.u.data.pointer = rates;
		wrq.u.data.length  = sizeof(rates);
		wrq.u.data.flags = rate_type;

		ival = local_priv_ioctl(skfd, ifname, IEEE80211_IOCTL_GET_RATES, &wrq);

		if (ival >= 0) {
			num_rates = wrq.u.data.length / sizeof(int32_t);
		} else {
			retval = -errno;
			if (retval >= 0) {
				retval = ival;
			}
		}
	}

	if (retval >= 0) {
		list_rates_to_string( &rates[0], num_rates, supported_rates, sizeof(string_1024) - 1 );
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

/**
 * qcsapi_wifi_set_rates - function used to set Basic and Operational rates in the driver.
 */
int
qcsapi_wifi_set_rates( const char *ifname, qcsapi_rate_type rate_type, const string_256 current_rates, int num_rates )
{
	int skfd = -1;
	int retval = 0;

	(void)rate_type;

	enter_qcsapi();

	if (current_rates == NULL) {
		retval = -EFAULT;
	} else {
		retval = skfd = local_open_iw_sockets();
	}

	if (retval >= 0) {
		int ival;

		struct iwreq wrq;

		memset(&wrq, 0, sizeof(wrq));
		wrq.u.data.pointer = (char *)current_rates;
		wrq.u.data.length = num_rates;
		wrq.u.data.flags = rate_type;

		ival = local_priv_ioctl(skfd, ifname, IEEE80211_IOCTL_SET_RATES, &wrq);
		if (ival < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = ival;
			}
		} else {
			retval = ival;
		}
	}

	if (retval > 0) {
		retval = -EOPNOTSUPP;
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

#define MIN_MAX_DWELL_TIME	50

enum {
	LOCAL_STA_SET_MAX_DWELL_TIME_ACTIVE = 0,
	LOCAL_STA_SET_MIN_DWELL_TIME_ACTIVE = 1,
	LOCAL_STA_SET_MAX_DWELL_TIME_PASSIVE = 2,
	LOCAL_STA_SET_MIN_DWELL_TIME_PASSIVE = 3,
};

int
qcsapi_wifi_set_dwell_times(
	const char *ifname,
	const unsigned int max_dwell_time_active_chan,
	const unsigned int min_dwell_time_active_chan,
	const unsigned int max_dwell_time_passive_chan,
	const unsigned int min_dwell_time_passive_chan
)
{
	int			skfd = -1;
	int			retval = 0;
	int			iter;
	qcsapi_wifi_mode	current_wifi_mode = qcsapi_nosuch_mode;
	struct {
		const char *param_name;
		int param_value;
	} iwpriv_op_table[] = {
		{ "max_dt_act", 0 },		/* LOCAL_STA_SET_MAX_DWELL_TIME_ACTIVE */
		{ "min_dt_act", 0 },		/* LOCAL_STA_SET_MIN_DWELL_TIME_ACTIVE */
		{ "max_dt_pas", 0 },		/* LOCAL_STA_SET_MAX_DWELL_TIME_PASSIVE */
		{ "min_dt_pas", 0 },		/* LOCAL_STA_SET_MIN_DWELL_TIME_PASSIVE */
	};

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode( skfd, ifname, &current_wifi_mode );
	if (retval < 0) {
		goto ready_to_return;
	}

	if (max_dwell_time_active_chan < MIN_MAX_DWELL_TIME ||
	    max_dwell_time_passive_chan < MIN_MAX_DWELL_TIME ||
	    min_dwell_time_active_chan < (max_dwell_time_active_chan / 2) ||
	    min_dwell_time_passive_chan < (max_dwell_time_passive_chan / 2)) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	iwpriv_op_table[LOCAL_STA_SET_MAX_DWELL_TIME_ACTIVE].param_value = max_dwell_time_active_chan;
	iwpriv_op_table[LOCAL_STA_SET_MIN_DWELL_TIME_ACTIVE].param_value = min_dwell_time_active_chan;
	iwpriv_op_table[LOCAL_STA_SET_MAX_DWELL_TIME_PASSIVE].param_value = max_dwell_time_passive_chan;
	iwpriv_op_table[LOCAL_STA_SET_MIN_DWELL_TIME_PASSIVE].param_value = min_dwell_time_passive_chan;

	for (iter = 0;
	     iter < ARRAY_SIZE(iwpriv_op_table);
	     iter++) {
		retval = local_wifi_set_private_int_param_by_name(skfd, ifname,
					iwpriv_op_table[iter].param_name,
					iwpriv_op_table[iter].param_value);
		if (retval < 0) {
			goto ready_to_return;
		}
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_dwell_times(
	const char *ifname,
	unsigned int *p_max_dwell_time_active_chan,
	unsigned int *p_min_dwell_time_active_chan,
	unsigned int *p_max_dwell_time_passive_chan,
	unsigned int *p_min_dwell_time_passive_chan
)
{
	int			skfd = -1;
	int			retval = 0;
	int			iter;
	qcsapi_wifi_mode	current_wifi_mode = qcsapi_nosuch_mode;
	struct {
		const char *param_name;
		int param_value;
	} iwpriv_op_table[] = {
		{ "get_max_dt_act", 0 },		/* LOCAL_STA_SET_MAX_DWELL_TIME_ACTIVE */
		{ "get_min_dt_act", 0 },		/* LOCAL_STA_SET_MIN_DWELL_TIME_ACTIVE */
		{ "get_max_dt_pas", 0 },		/* LOCAL_STA_SET_MAX_DWELL_TIME_PASSIVE */
		{ "get_min_dt_pas", 0 },		/* LOCAL_STA_SET_MIN_DWELL_TIME_PASSIVE */
	};

	enter_qcsapi();

	if (ifname == NULL ||
	    p_max_dwell_time_active_chan == NULL ||
	    p_min_dwell_time_active_chan == NULL ||
	    p_max_dwell_time_passive_chan == NULL ||
	    p_min_dwell_time_passive_chan == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode( skfd, ifname, &current_wifi_mode );
	if (retval < 0) {
		goto ready_to_return;
	}

	for (iter = 0;
	     iter < ARRAY_SIZE(iwpriv_op_table);
	     iter++) {
		retval = local_wifi_get_private_int_param_by_name(skfd, ifname,
					iwpriv_op_table[iter].param_name,
					&(iwpriv_op_table[iter].param_value));
		if (retval < 0) {
			goto ready_to_return;
		}
	}

	*p_max_dwell_time_active_chan = iwpriv_op_table[LOCAL_STA_SET_MAX_DWELL_TIME_ACTIVE].param_value;
	*p_min_dwell_time_active_chan = iwpriv_op_table[LOCAL_STA_SET_MIN_DWELL_TIME_ACTIVE].param_value;
	*p_max_dwell_time_passive_chan = iwpriv_op_table[LOCAL_STA_SET_MAX_DWELL_TIME_PASSIVE].param_value;
	*p_min_dwell_time_passive_chan = iwpriv_op_table[LOCAL_STA_SET_MIN_DWELL_TIME_PASSIVE].param_value;

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

#define MIN_BGSCAN_DWELL_TIME	10
#define MAX_BGSCAN_DWELL_TIME	20
enum {
	LOCAL_STA_SET_DWELL_TIME_ACTIVE = 0,
	LOCAL_STA_SET_DWELL_TIME_PASSIVE = 1
};

int
qcsapi_wifi_set_bgscan_dwell_times(
	const char *ifname,
	const unsigned int dwell_time_active_chan,
	const unsigned int dwell_time_passive_chan
)
{
	int			skfd = -1;
	int			retval = 0;
	int			iter;
	qcsapi_wifi_mode	current_wifi_mode = qcsapi_nosuch_mode;
	struct {
		const char *param_name;
		int param_value;
	} iwpriv_op_table[] = {
		{ "bg_dt_act", 0 },		/* LOCAL_STA_SET_BGSCAN_DWELL_TIME_ACTIVE */
		{ "bg_dt_pas", 0 },		/* LOCAL_STA_SET_BGSCAN_DWELL_TIME_PASSIVE */
	};

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode( skfd, ifname, &current_wifi_mode );
	if (retval < 0) {
		goto ready_to_return;
	}

	if (dwell_time_active_chan < MIN_BGSCAN_DWELL_TIME ||
	    dwell_time_passive_chan < MIN_BGSCAN_DWELL_TIME ||
	    dwell_time_active_chan > MAX_BGSCAN_DWELL_TIME ||
	    dwell_time_passive_chan > MAX_BGSCAN_DWELL_TIME) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	iwpriv_op_table[LOCAL_STA_SET_DWELL_TIME_ACTIVE].param_value = dwell_time_active_chan;
	iwpriv_op_table[LOCAL_STA_SET_DWELL_TIME_PASSIVE].param_value = dwell_time_passive_chan;

	for (iter = 0;
	     iter < ARRAY_SIZE(iwpriv_op_table);
	     iter++) {
		retval = local_wifi_set_private_int_param_by_name(skfd, ifname,
					iwpriv_op_table[iter].param_name,
					iwpriv_op_table[iter].param_value);
		if (retval < 0) {
			goto ready_to_return;
		}
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_bgscan_dwell_times(
	const char *ifname,
	unsigned int *p_dwell_time_active_chan,
	unsigned int *p_dwell_time_passive_chan
)
{
	int			skfd = -1;
	int			retval = 0;
	int			iter;
	qcsapi_wifi_mode	current_wifi_mode = qcsapi_nosuch_mode;
	struct {
		const char *param_name;
		int param_value;
	} iwpriv_op_table[] = {
		{ "get_bg_dt_act", 0 },		/* LOCAL_STA_SET_BGSCAN_DWELL_TIME_ACTIVE */
		{ "get_bg_dt_pas", 0 },		/* LOCAL_STA_SET_BGSCAN_DWELL_TIME_PASSIVE */
	};

	enter_qcsapi();

	if (ifname == NULL ||
	    p_dwell_time_active_chan == NULL ||
	    p_dwell_time_passive_chan == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode( skfd, ifname, &current_wifi_mode );
	if (retval < 0) {
		goto ready_to_return;
	}

	for (iter = 0;
	     iter < ARRAY_SIZE(iwpriv_op_table);
	     iter++) {
		retval = local_wifi_get_private_int_param_by_name(skfd, ifname,
					iwpriv_op_table[iter].param_name,
					&(iwpriv_op_table[iter].param_value));
		if (retval < 0) {
			goto ready_to_return;
		}
	}

	*p_dwell_time_active_chan = iwpriv_op_table[LOCAL_STA_SET_DWELL_TIME_ACTIVE].param_value;
	*p_dwell_time_passive_chan = iwpriv_op_table[LOCAL_STA_SET_DWELL_TIME_PASSIVE].param_value;

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

/*
 * Caution: expected to be only called on a STA; if called on an AP,
 * it will always report it is in association.
 */
static int
local_is_sta_associated( int skfd, const char *ifname, qcsapi_unsigned_int *p_in_association )
{
	int		retval;
	qcsapi_mac_addr	current_bssid;

	if (ifname == NULL || p_in_association == NULL) {
		return(-EFAULT);
	}

	retval = local_wifi_get_BSSID(skfd, ifname, current_bssid);

	if (retval >= 0)
		*p_in_association = !IEEE80211_ADDR_NULL(current_bssid);

	return( retval );
}

static int
local_get_assoc_table(int skfd, const char *ifname, struct assoc_info_table *array)
{
	int retval = 0;
	struct iwreq wrq;

	memset(&wrq, 0, sizeof(wrq));
	wrq.u.data.pointer = array;
	wrq.u.data.length = sizeof(struct assoc_info_table);
	array->unit_size = sizeof(struct assoc_info_report);

	retval = local_priv_ioctl(skfd, ifname, IEEE80211_IOCTL_GET_ASSOC_TBL, &wrq);

	return retval;
}

int
local_get_count_associations(int skfd, const char *ifname, qcsapi_unsigned_int *p_association_count)
{
	int retval;
	qcsapi_mac_addr macaddr;
	struct assoc_info_table	*assoc_arr;
	assoc_info_report *assoc_entry;
	qcsapi_unsigned_int count = 0;
	int16_t i;

	if (ifname == NULL || p_association_count == NULL)
		return -EFAULT;

	assoc_arr = calloc(1, sizeof(struct assoc_info_table));
	if (!assoc_arr)
		return -ENOMEM;

	retval = local_interface_get_mac_addr(skfd, ifname, macaddr);
	if (retval >= 0)
		retval = local_get_assoc_table(skfd, ifname, assoc_arr);

	if (retval >= 0) {
		for (i = 0; i < assoc_arr->cnt; i++){
			assoc_entry = assoc_arr->array + i;
			/*
			 * Ignore any entry with association ID == 0
			 * Ignore any entry not authorized (auth == 0)
			 * Ignore any entry that belongs to the local interface.
			 */
			if (assoc_entry->ai_assoc_id != 0 &&
					assoc_entry->ai_auth != 0 &&
					strncmp(assoc_entry->ai_ifname, ifname, sizeof(assoc_entry->ai_ifname)) == 0 &&
					memcmp(assoc_entry->ai_mac_addr, macaddr, sizeof(macaddr)) != 0) {
				count++;
			}
		}
		*p_association_count = count;
	}

	free(assoc_arr);

	return retval;
}

int
qcsapi_wifi_get_count_associations(const char *ifname, qcsapi_unsigned_int *p_association_count)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (p_association_count == NULL) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = (errno > 0) ? -errno : skfd;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
		if (retval >= 0)
			if (local_wifi_mode != qcsapi_access_point &&
					local_wifi_mode != qcsapi_station &&
					local_wifi_mode != qcsapi_wds)
				retval = -EOPNOTSUPP;
	}

	if (retval >= 0) {
		retval = local_get_count_associations(skfd, ifname, p_association_count);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return( retval );
}

int
local_is_mac_associated(int skfd, const char *ifname, qcsapi_mac_addr macaddr, bool* p_associated)
{
	int retval;
	struct assoc_info_table	*assoc_arr;
	assoc_info_report *assoc_entry;

	if (ifname == NULL || p_associated == NULL) {
		return -EFAULT;
	}

	assoc_arr = calloc(1, sizeof(struct assoc_info_table));
	if (!assoc_arr) {
		return -ENOMEM;
	}

	*p_associated = false;

	retval = local_get_assoc_table(skfd, ifname, assoc_arr);
	if (retval >= 0) {
		int i;
		for (i = 0; i < assoc_arr->cnt; i++) {
			assoc_entry = assoc_arr->array + i;
			if (assoc_entry->ai_assoc_id != 0 && assoc_entry->ai_auth != 0 &&
				strncmp(assoc_entry->ai_ifname, ifname, sizeof(assoc_entry->ai_ifname)) == 0 &&
				memcmp(assoc_entry->ai_mac_addr, macaddr, sizeof(qcsapi_mac_addr)) == 0) {
				*p_associated = true;
				break;
			}
		}
	}

	free(assoc_arr);

	return retval;
}

#if 0
/*
 * Keep the min_rssi entries in decending numeric order
 */
static const struct
{
	u_int8_t	min_rssi;
	u_int8_t	mcs_rate;
} rssi_to_rate[] = {
	{ 26,	13 },
	{ 16,	12 },
	{ 12,	11 },
	{ 10,	10 },
	{ 9,	9 },
	{ 8,	8 },
	{ 0,	0 }
};

static unsigned int
rssi_to_mcs_rate( unsigned int current_rssi )
{
	unsigned int	iter;
	int		retval = 0;
	int		found_entry = 0;

	for (iter = 0; rssi_to_rate[ iter ].min_rssi > 0 && found_entry == 0; iter++)
	{
		if (rssi_to_rate[ iter ].min_rssi < current_rssi)
		{
			found_entry = 1;
			retval = (int) (rssi_to_rate[ iter ].mcs_rate);
		}
	}

	return( retval );
}

/*
 * Input is the MCS rate.
 *
 * Output is a number between 0 and 100
 */

static unsigned int
normalize_link_quality( unsigned int value_from_kernel, unsigned int association_bw  )
{
	static const struct
	{
		int		raw_mcs_rate;
		unsigned int	rate_20MHz;
		unsigned int	rate_40MHz;
	} mcs_rate_mbps[] = {
		{ 0,	7,	14 },			/* actual rates are 6.5 and 13.5 Mbps */
		{ 1,	13,	27 },
		{ 2,	20,	41 },			/* actual rates are 19.5 and 40.5 Mbps */
		{ 3,	26,	54 },
		{ 4,	39,	81 },
		{ 5,	52,	108 },
		{ 6,	59,	123 },			/* actual rate is 58.5 and 122.5 Mbps */
		{ 7,	65,	135 },
		{ 8,	13,	27 },
		{ 9,	26,	54 },
		{ 10,	39,	81 },
		{ 11,	52,	108 },
		{ 12,	78,	162 },
		{ 13,	104,	216 },
		{ 14,	117,	243 },
		{ 15,	130,	270 },
		{ -1,	0 }
	};

	unsigned int	iter;
	unsigned int	local_rate = 0;

	for (iter = 0; mcs_rate_mbps[ iter ].raw_mcs_rate >= 0 && local_rate == 0; iter++)
	{
		if (value_from_kernel == mcs_rate_mbps[ iter ].raw_mcs_rate)
		{
			if (association_bw == 20)
			  local_rate = mcs_rate_mbps[ iter ].rate_20MHz;
			else
			  local_rate = mcs_rate_mbps[ iter ].rate_40MHz;
		}
	}

	return( local_rate );
}
#endif

static int
return_per_association_item(
	const per_association_item association_item,
	const assoc_info_report *p_assoc_info,
	void *retaddr )
{
	int	retval = 0;

	if (p_assoc_info == NULL || retaddr == NULL) {
		retval = -EFAULT;
	} else {
		u_int64_t *p_u64 = retaddr;
		qcsapi_unsigned_int *p_uint = retaddr;
		int *p_int = retaddr;

		/*
		 * All per association items listed in per_association_counter_table
		 * must return a uint64_t.
		 */
		switch (association_item) {
		case RX_BYTES_ASSOCIATION:
			*p_u64 = p_assoc_info->ai_rx_bytes;
			break;

		case TX_BYTES_ASSOCIATION:
			*p_u64 = p_assoc_info->ai_tx_bytes;
			break;

		case RX_PACKETS_ASSOCIATION:
			*p_u64 = p_assoc_info->ai_rx_packets;
			break;

		case TX_PACKETS_ASSOCIATION:
			*p_u64 = p_assoc_info->ai_tx_packets;
			break;

		case RX_ERROR_PACKETS_ASSOCIATION:
			*p_u64 = p_assoc_info->ai_rx_errors;
			break;

		case TX_ERROR_PACKETS_ASSOCIATION:
			*p_u64 = p_assoc_info->ai_tx_errors;
			break;

		case RX_DROPPED_PACKETS_ASSOCIATION:
			*p_u64 = p_assoc_info->ai_rx_dropped;
			break;

		case TX_DROPPED_PACKETS_ASSOCIATION:
			*p_u64 = p_assoc_info->ai_tx_dropped;
			break;

		case TX_ERR_PACKETS_ASSOCIATION:
			*p_uint = p_assoc_info->ai_tx_failed;
			break;

		case RSSI_ASSOCIATION:
			*p_int = p_assoc_info->ai_smthd_rssi;
			break;

		case BW_ASSOCIATION:
			*p_uint = p_assoc_info->ai_bw;
			break;

		case LINK_QUALITY_ASSOCIATION:
			*p_uint = p_assoc_info->ai_link_quality;
			break;

		case TIME_IN_ASSOCIATION:
			*p_uint = p_assoc_info->ai_time_associated;
			break;

		case MAC_ADDR_ASSOCIATION:
			memcpy(retaddr, p_assoc_info->ai_mac_addr, sizeof(qcsapi_mac_addr));
			break;

		case IP_ADDR_ASSOCIATION:
			*p_uint = p_assoc_info->ai_ip_addr;
			break;

		case TX_PHY_RATE_ASSOCIATION:
			*p_uint = p_assoc_info->ai_tx_phy_rate;
			break;

		case RX_PHY_RATE_ASSOCIATION:
			*p_uint = p_assoc_info->ai_rx_phy_rate;
			break;

		case SNR_ASSOCIATION:
			*p_int = p_assoc_info->ai_snr;
			break;

		case MAX_QUEUED_ASSOCIATION:
			*p_int = p_assoc_info->ai_max_queued;
			break;

		case TX_ACHIEVABLE_PHY_RATE_ASSOCIATION:
			*p_uint = p_assoc_info->ai_achievable_tx_phy_rate;
			break;

		case RX_ACHIEVABLE_PHY_RATE_ASSOCIATION:
			*p_uint = p_assoc_info->ai_achievable_rx_phy_rate;
			break;

		case HW_NOISE_ASSOCIATION:
			*p_int = p_assoc_info->ai_hw_noise;
			break;

		case IS_QTN_NODE_ASSOCIATION:
			*p_uint = p_assoc_info->ai_is_qtn_node;
			break;

		case RX_FRAGMENTS_FRAMES:
			*p_uint = p_assoc_info->ai_rx_fragment_pkts;
			break;

		case RX_VLAN_FRAMES:
			*p_uint = p_assoc_info->ai_rx_vlan_pkts;
			break;

		case TX_MCS_ASSOCIATION:
			*p_uint = p_assoc_info->ai_tx_mcs;
			break;

		case RX_MCS_ASSOCIATION:
			*p_uint = p_assoc_info->ai_rx_mcs;
			break;

		default:
			retval = -EINVAL;
			break;
		}
	}

	return retval;
}

static int
local_get_association_record(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	struct assoc_info_report *p_assoc_info
)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	local_wifi_mode = qcsapi_nosuch_mode;
	qcsapi_mac_addr		interface_mac_addr;
	struct assoc_info_table	*assoc_arr;
	assoc_info_report	*assoc_entry;
	int16_t			i, j;

	if (ifname == NULL || p_assoc_info == NULL)
		return -EFAULT;

	if ((assoc_arr = calloc(1, sizeof( struct assoc_info_table ) )) == NULL)
		return -ENOMEM;

	retval = local_open_iw_socket_with_error( &skfd );

	if (retval >= 0) {
		/*
		 * As a side effect, this programming eliminates non-WiFi
		 * interfaces (br0, eth1_0, etc.).
		 */
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
		if (retval >= 0) {
			if (local_wifi_mode != qcsapi_station &&
					local_wifi_mode != qcsapi_access_point &&
					local_wifi_mode != qcsapi_wds) {
				retval = -EOPNOTSUPP;
			}
		}
	}

	/* STA: verify it is in association */
	if (retval >= 0 && local_wifi_mode == qcsapi_station) {
		qcsapi_unsigned_int	in_association = 0;

		retval = local_is_sta_associated( skfd, ifname, &in_association );
		if (in_association == 0) {
			retval = -ENETDOWN;
		}
	}

	if (retval >= 0)
	{
		retval = local_interface_get_mac_addr( skfd, ifname, interface_mac_addr );
	}

	if (retval >= 0)
	{
		retval = local_get_assoc_table( skfd, ifname, assoc_arr );
	}

	if (retval >= 0)
	{
		for (i = 0, j = 0; i < assoc_arr->cnt; i++){
			assoc_entry = assoc_arr->array + i;

			if (assoc_entry->ai_assoc_id != 0 &&
			    assoc_entry->ai_auth != 0 &&
			    strncmp( assoc_entry->ai_ifname, ifname, sizeof(assoc_entry->ai_ifname) ) == 0 &&
			    memcmp( assoc_entry->ai_mac_addr, interface_mac_addr, sizeof( interface_mac_addr ) ) != 0) {

					if (j == association_index){
						memcpy(p_assoc_info, assoc_entry, sizeof(*p_assoc_info));
						break;
					}else
						j++;
			}
		}

		if (i == assoc_arr->cnt)
			retval = -ERANGE;
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	free( assoc_arr );

	return( retval );
}

static int
local_association_get_item(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	const per_association_item association_item,
	void *retaddr
)
{
	struct assoc_info_report assoc_report;
	int retval = 0;

	if (retaddr == NULL) {
		return -EFAULT;
	}

#ifdef CONFIG_QTN_80211K_SUPPORT
	/* Implement dotk to get QSTA IP */
	if (association_item == IP_ADDR_ASSOCIATION) {
		int is_qtn_node;
		retval = local_association_get_item(ifname, association_index,
				IS_QTN_NODE_ASSOCIATION, &is_qtn_node);
		if (retval >= 0) {
			if (is_qtn_node) {
				struct ieee80211req_qtn_rmt_sta_stats req_rmt_sta_stats;
				int skfd = -1;
				uint32_t flags = BIT(RM_QTN_BR_IP);

				retval = local_open_iw_socket_with_error(&skfd);

				if (retval >= 0) {
					retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
					/*
					 * If ifname is not a BSS VAP, further check if it's a WDS VAP since
					 * we also support getting IP address of specified WDS peer
					 */
					if (retval == -qcsapi_only_on_AP)
						retval = local_verify_wifi_mode(skfd, ifname, qcsapi_wds, NULL);
				}

				if (retval >= 0) {
					retval = local_get_association_record_rmt(skfd, ifname, association_index,
							flags, &req_rmt_sta_stats);
				}

				if (retval >= 0) {
					retval = local_get_node_param_rmt(QCSAPI_STA_IP, &req_rmt_sta_stats, retaddr);
				}

				if (skfd >= 0) {
					local_close_iw_sockets(skfd);
				}

				return retval;
			}
		} else {
			return retval;
		}
	}
#endif

	retval = local_get_association_record(ifname, association_index, &assoc_report);
	if (retval >= 0) {
		retval = return_per_association_item(association_item, &assoc_report, retaddr);
	}

	return retval;
}

static int
local_fetch_tpc_report_remote(
	int skfd,
	const char *ifname,
	const qcsapi_unsigned_int node_index,
	struct ieee80211rep_node_tpc_result *tpc_result
)
{
	int retval = 0;
	char buffer[128];
	struct ieee80211req_node_info	*request_info;
	union ieee80211rep_node_info	*resp_info;

	/* TBD:do some limitation on request parameters? */
	memset(buffer, 0, sizeof(buffer));
	request_info = (struct ieee80211req_node_info *)buffer;
	resp_info = (union ieee80211rep_node_info *)buffer;
	request_info->req_type = IOCTL_REQ_TPC;

	retval = local_association_get_item(ifname, node_index, MAC_ADDR_ASSOCIATION, request_info->u_req_info.req_node_tpc.mac_addr);
	if (retval >= 0) {
		retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_GET_11H_11K_NODE_INFO, buffer, sizeof(buffer));
		if (retval >= 0) {
			memcpy(tpc_result, &resp_info->tpc_result, sizeof(struct ieee80211rep_node_tpc_result));
		}
	}

	return retval;
}

static int
local_fetch_measurement_report_remote(
	int skfd,
	const char *ifname,
	const qcsapi_unsigned_int node_index,
	uint8_t	meas_type,
	const qcsapi_measure_request_param *param,
	struct ieee80211rep_node_meas_result *meas_result
)
{
	int retval = 0;
	char buffer[64];
	struct ieee80211req_node_info *request_info;
	union ieee80211rep_node_info *resp_info;

	memset(buffer, 0, sizeof(buffer));
	request_info = (struct ieee80211req_node_info *)buffer;
	resp_info = (union ieee80211rep_node_info *)buffer;
	request_info->req_type = IOCTL_REQ_MEASUREMENT;
	request_info->u_req_info.req_node_meas.type = meas_type;
	switch (meas_type) {
	case IOCTL_MEAS_TYPE_BASIC:
		request_info->u_req_info.req_node_meas.ioctl_basic.channel = param->basic.channel;
		request_info->u_req_info.req_node_meas.ioctl_basic.duration_ms = param->basic.duration;
		request_info->u_req_info.req_node_meas.ioctl_basic.start_offset_ms = param->basic.offset;
		break;
	case IOCTL_MEAS_TYPE_CCA:
		request_info->u_req_info.req_node_meas.ioctl_cca.channel = param->cca.channel;
		request_info->u_req_info.req_node_meas.ioctl_cca.duration_ms = param->cca.duration;
		request_info->u_req_info.req_node_meas.ioctl_cca.start_offset_ms = param->cca.offset;
		break;
	case IOCTL_MEAS_TYPE_RPI:
		request_info->u_req_info.req_node_meas.ioctl_rpi.channel = param->rpi.channel;
		request_info->u_req_info.req_node_meas.ioctl_rpi.duration_ms = param->rpi.duration;
		request_info->u_req_info.req_node_meas.ioctl_rpi.start_offset_ms = param->rpi.offset;
		break;
	case IOCTL_MEAS_TYPE_CHAN_LOAD:
		request_info->u_req_info.req_node_meas.ioctl_chan_load.channel = param->chan_load.channel;
		request_info->u_req_info.req_node_meas.ioctl_chan_load.duration_ms = param->chan_load.duration;
		break;
	case IOCTL_MEAS_TYPE_NOISE_HIS:
		request_info->u_req_info.req_node_meas.ioctl_noise_his.channel = param->noise_his.channel;
		request_info->u_req_info.req_node_meas.ioctl_noise_his.duration_ms = param->noise_his.duration;
		break;
	case IOCTL_MEAS_TYPE_BEACON:
		request_info->u_req_info.req_node_meas.ioctl_beacon.channel = param->beacon.channel;
		request_info->u_req_info.req_node_meas.ioctl_beacon.duration_ms = param->beacon.duration;
		request_info->u_req_info.req_node_meas.ioctl_beacon.op_class = param->beacon.op_class;
		request_info->u_req_info.req_node_meas.ioctl_beacon.mode = param->beacon.mode;
		if (IEEE80211_ADDR_NULL(param->beacon.bssid))
			memset(request_info->u_req_info.req_node_meas.ioctl_beacon.bssid, 0xFF, 6);
		else
			memcpy(request_info->u_req_info.req_node_meas.ioctl_beacon.bssid,
				param->beacon.bssid,
				sizeof(request_info->u_req_info.req_node_meas.ioctl_beacon.bssid));
		break;
	case IOCTL_MEAS_TYPE_FRAME:
		request_info->u_req_info.req_node_meas.ioctl_frame.op_class = param->frame.op_class;
		request_info->u_req_info.req_node_meas.ioctl_frame.channel = param->frame.channel;
		request_info->u_req_info.req_node_meas.ioctl_frame.duration_ms = param->frame.duration;
		request_info->u_req_info.req_node_meas.ioctl_frame.type = param->frame.type;
		if (IEEE80211_ADDR_NULL(param->beacon.bssid))
			memset(request_info->u_req_info.req_node_meas.ioctl_frame.mac_address, 0xFF, 6);
		else
			memcpy(request_info->u_req_info.req_node_meas.ioctl_frame.mac_address,
				param->frame.mac_address,
				sizeof(request_info->u_req_info.req_node_meas.ioctl_frame.mac_address));
		break;
	case IOCTL_MEAS_TYPE_CAT:
		request_info->u_req_info.req_node_meas.ioctl_tran_stream_cat.duration_ms = param->tran_stream_cat.duration;
		request_info->u_req_info.req_node_meas.ioctl_tran_stream_cat.tid = param->tran_stream_cat.tid;
		request_info->u_req_info.req_node_meas.ioctl_tran_stream_cat.bin0 = param->tran_stream_cat.bin0;
		memcpy(request_info->u_req_info.req_node_meas.ioctl_tran_stream_cat.peer_sta, param->tran_stream_cat.peer_sta, 6);
		break;
	case IOCTL_MEAS_TYPE_MUL_DIAG:
		request_info->u_req_info.req_node_meas.ioctl_multicast_diag.duration_ms = param->multicast_diag.duration;
		memcpy(request_info->u_req_info.req_node_meas.ioctl_multicast_diag.group_mac, param->multicast_diag.group_mac, 6);
		break;
	case IOCTL_MEAS_TYPE_LINK:
		break;
	case IOCTL_MEAS_TYPE_NEIGHBOR:
		break;
	default:
		return -EFAULT;
	}

	retval = local_association_get_item(ifname, node_index, MAC_ADDR_ASSOCIATION, request_info->u_req_info.req_node_meas.mac_addr);

	if (retval >= 0) {
		retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_GET_11H_11K_NODE_INFO, buffer, sizeof(buffer));
		if (retval >= 0) {
			memcpy(meas_result, &resp_info->meas_result, sizeof(struct ieee80211rep_node_meas_result));
		}
	}

	return retval;
}

#if defined(CONFIG_QTN_80211K_SUPPORT)
static int
local_get_association_record_rmt(
	int skfd,
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	uint32_t flags,
	struct ieee80211req_qtn_rmt_sta_stats *req_rmt_sta_stats
)
{
	int retval = 0;
	struct ieee80211req_qtn_rmt_sta_stats_setpara setpara;
	const int argc = sizeof(struct ieee80211req_qtn_rmt_sta_stats_setpara);
	char setpara_strs[argc][4];
	char *argv[argc];
	int i = 0;

	setpara.flags = flags;
	retval = local_association_get_item(ifname, association_index, MAC_ADDR_ASSOCIATION, setpara.macaddr);

	if (retval >= 0) {
		for (i = 0; i < argc; i++) {
			sprintf(&setpara_strs[i][0], "%d", ((char *)(&setpara))[i]);
			argv[i] = &setpara_strs[i][0];
		}

		retval = call_private_ioctl(skfd, argv, argc, ifname, "getstastatistic",
				req_rmt_sta_stats, sizeof(struct ieee80211req_qtn_rmt_sta_stats));
		if (retval >= 0) {
			if (req_rmt_sta_stats->status != 0) {
				retval = req_rmt_sta_stats->status;
			}
		}
	}

	return retval;
}

static int
local_get_node_counter_rmt(qcsapi_counter_type counter_type,
		struct ieee80211req_qtn_rmt_sta_stats *req_rmt_sta_stats,
		uint64_t *param)
{
	switch (counter_type)
	{
	case qcsapi_total_bytes_sent:
		*param = req_rmt_sta_stats->rmt_sta_stats.tx_stats.tx_bytes;
		break;
	case qcsapi_total_packets_sent:
		*param = req_rmt_sta_stats->rmt_sta_stats.tx_stats.tx_pkts;
		break;
	case qcsapi_discard_packets_sent:
		*param = req_rmt_sta_stats->rmt_sta_stats.tx_stats.tx_discard;
		break;
	case qcsapi_error_packets_sent:
		*param = req_rmt_sta_stats->rmt_sta_stats.tx_stats.tx_err;
		break;
	case qcsapi_total_bytes_received:
		*param = req_rmt_sta_stats->rmt_sta_stats.rx_stats.rx_bytes;
		break;
	case qcsapi_total_packets_received:
		*param = req_rmt_sta_stats->rmt_sta_stats.rx_stats.rx_pkts;
		break;
	case qcsapi_discard_packets_received:
		*param = req_rmt_sta_stats->rmt_sta_stats.rx_stats.rx_discard;
		break;
	case qcsapi_error_packets_received:
		*param = req_rmt_sta_stats->rmt_sta_stats.rx_stats.rx_err;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
local_get_node_param_rmt(qcsapi_per_assoc_param param_type,
		struct ieee80211req_qtn_rmt_sta_stats *req_rmt_sta_stats,
		int *param)
{
	switch (param_type)
	{
		case QCSAPI_LINK_QUALITY:
			*param = req_rmt_sta_stats->rmt_sta_stats.link_quality;
			break;
		case QCSAPI_RSSI_DBM:
			*param = req_rmt_sta_stats->rmt_sta_stats.rssi_dbm;
			break;
		case QCSAPI_BANDWIDTH:
			*param = req_rmt_sta_stats->rmt_sta_stats.bandwidth;
			break;
		case QCSAPI_SNR:
			*param = req_rmt_sta_stats->rmt_sta_stats.snr;
			break;
		case QCSAPI_TX_PHY_RATE:
			*param = req_rmt_sta_stats->rmt_sta_stats.tx_phy_rate;
			break;
		case QCSAPI_RX_PHY_RATE:
			*param = req_rmt_sta_stats->rmt_sta_stats.rx_phy_rate;
			break;
		case QCSAPI_STA_IP:
			*param = req_rmt_sta_stats->rmt_sta_stats.br_ip;
			break;
		case QCSAPI_RSSI:
			*param = req_rmt_sta_stats->rmt_sta_stats.rssi;
			break;
		case QCSAPI_PHY_NOISE:
			*param = req_rmt_sta_stats->rmt_sta_stats.hw_noise;
			break;
		case QCSAPI_SOC_MAC_ADDR:
			if (param) {
				memcpy(param, req_rmt_sta_stats->rmt_sta_stats.soc_macaddr, 6);
			}
			break;
		case QCSAPI_SOC_IP_ADDR:
			if (param) {
				*param = req_rmt_sta_stats->rmt_sta_stats.soc_ipaddr;
			}
			break;
		default:
			return -EOPNOTSUPP;
	}

	return 0;
}

static int
local_node_param2flag_rmt(qcsapi_per_assoc_param param_type,
		uint32_t *flags)
{
	switch (param_type)
	{
		case QCSAPI_LINK_QUALITY:
			*flags = BIT(RM_QTN_LINK_QUALITY);
			break;
		case QCSAPI_RSSI_DBM:
			*flags = BIT(RM_QTN_RSSI_DBM);
			break;
		case QCSAPI_BANDWIDTH:
			*flags = BIT(RM_QTN_BANDWIDTH);
			break;
		case QCSAPI_SNR:
			*flags = BIT(RM_QTN_SNR);
			break;
		case QCSAPI_TX_PHY_RATE:
			*flags = BIT(RM_QTN_TX_PHY_RATE);
			break;
		case QCSAPI_RX_PHY_RATE:
			*flags = BIT(RM_QTN_RX_PHY_RATE);
			break;
		case QCSAPI_STAD_CCA:
			*flags = RM_STANDARD_CCA;
			break;
		case QCSAPI_RSSI:
			*flags = BIT(RM_QTN_RSSI);
			break;
		case QCSAPI_PHY_NOISE:
			*flags = BIT(RM_QTN_HW_NOISE);
			break;
		case QCSAPI_SOC_MAC_ADDR:
			*flags = BIT(RM_QTN_SOC_MACADDR);
			break;
		case QCSAPI_SOC_IP_ADDR:
			*flags = BIT(RM_QTN_SOC_IPADDR);
			break;
		default:
			return -EOPNOTSUPP;
	}

	return 0;
}
#endif

int
qcsapi_wifi_get_link_quality(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_link_quality
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, LINK_QUALITY_ASSOCIATION, p_link_quality );

	leave_qcsapi();

	return( retval );
}

int qcsapi_wifi_get_link_quality_max(
	const char *ifname, qcsapi_unsigned_int *p_max_quality
)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;
	uint32_t max_quality;

	if (ifname == NULL || p_max_quality == NULL) {
		return -EFAULT;
	}

	enter_qcsapi();

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
		if (retval >= 0) {
			if (local_wifi_mode != qcsapi_station &&
					local_wifi_mode != qcsapi_access_point &&
					local_wifi_mode != qcsapi_wds) {
				retval = -EOPNOTSUPP;
			}
		}
	}

	if (retval >= 0 && local_wifi_mode == qcsapi_station) {
		qcsapi_unsigned_int in_association = 0;

		retval = local_is_sta_associated(skfd, ifname, &in_association );
		if (in_association == 0) {
			retval = -ENETDOWN;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_GET_LINK_QUALITY_MAX,
							&max_quality, sizeof(max_quality));
	}

	if (retval >= 0) {
		*p_max_quality = max_quality;
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_rssi_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_rssi
)
{
	int	retval = 0;
	int	local_rssi = -1;

	if (p_rssi == NULL)
		return -EINVAL;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, RSSI_ASSOCIATION, &local_rssi );

	if (local_rssi == QDRV_REPORTS_CONFIG_ERR) {
		retval = -qcsapi_measurement_not_available;
	} else {
		local_rssi += LOCAL_RSSI_OFFSET_FROM_10THS_DBM;

		if (local_rssi < 0) {
			*p_rssi = 0;
		} else {
			*p_rssi = (qcsapi_unsigned_int)(local_rssi + 5) / 10;
		}
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_hw_noise_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	int *p_hw_noise
)
{
	int	retval = 0;
	int	local_hw_noise = -1;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, HW_NOISE_ASSOCIATION, &local_hw_noise );

	if (local_hw_noise == QDRV_REPORTS_CONFIG_ERR) {
		retval = -qcsapi_measurement_not_available;
	} else {
		*p_hw_noise = local_hw_noise;
	}

	leave_qcsapi();

	return( retval );
}


int
qcsapi_wifi_get_rssi_in_dbm_per_association(
			const char *ifname,
			const qcsapi_unsigned_int association_index,
			int *p_rssi
)
{
	int	retval = 0;
	int	local_rssi = -1;

	if (p_rssi == NULL)
		return -EINVAL;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, RSSI_ASSOCIATION, &local_rssi );

	if (local_rssi == QDRV_REPORTS_CONFIG_ERR) {
		retval = -qcsapi_measurement_not_available;
	} else if (local_rssi < 0) {
		*p_rssi = (local_rssi - 5) / 10;
	} else {
		*p_rssi = (local_rssi + 5) / 10;
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_snr_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	int *p_snr
)
{
	int	retval = 0;
	int	local_evm = -1;

	if (p_snr == NULL)
		return -EINVAL;

	enter_qcsapi();

	/* Internal report is EVM ...  */
	retval = local_association_get_item( ifname, association_index, SNR_ASSOCIATION, &local_evm );

	if (local_evm == QDRV_REPORTS_CONFIG_ERR) {
		retval = -qcsapi_measurement_not_available;
	} else if (local_evm < 0) {
		local_evm = (local_evm - 5) / 10;
	} else {
		local_evm = (local_evm + 5) / 10;
	}

	/* The SNR is the negative of the EVM value ... */
	if (retval >= 0) {
		*p_snr = (0 - local_evm);
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_bw_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_bw
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, BW_ASSOCIATION, p_bw );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_tx_phy_rate_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_tx_rate
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, TX_PHY_RATE_ASSOCIATION, p_tx_rate );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_rx_phy_rate_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_rx_rate
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, RX_PHY_RATE_ASSOCIATION, p_rx_rate );

	leave_qcsapi();

	return( retval );
}

int	qcsapi_wifi_get_tx_mcs_per_association(
		const char *ifname,
		const qcsapi_unsigned_int association_index,
		qcsapi_unsigned_int *p_mcs
)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_association_get_item(ifname, association_index,
			TX_MCS_ASSOCIATION, p_mcs);

	leave_qcsapi();

	return retval;
}

int	qcsapi_wifi_get_rx_mcs_per_association(
		const char *ifname,
		const qcsapi_unsigned_int association_index,
		qcsapi_unsigned_int *p_mcs
)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_association_get_item(ifname, association_index,
			RX_MCS_ASSOCIATION, p_mcs);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_achievable_tx_phy_rate_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_achievable_tx_rate
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, TX_ACHIEVABLE_PHY_RATE_ASSOCIATION, p_achievable_tx_rate );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_achievable_rx_phy_rate_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_achievable_rx_rate
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, RX_ACHIEVABLE_PHY_RATE_ASSOCIATION, p_achievable_rx_rate );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_auth_enc_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_auth_enc
)
{
	int	retval = 0;
	struct	ieee80211req_auth_description auth_descr;
	struct	iwreq iwr;
	int	skfd = -1;

	if (ifname == NULL || p_auth_enc == NULL) {
		return -EFAULT;
	}

	memset(&auth_descr, 0x00, sizeof(auth_descr));
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
	iwr.u.data.flags = SIOCDEV_SUBIO_GET_STA_AUTH;
	iwr.u.data.pointer = &auth_descr;
	iwr.u.data.length = sizeof(auth_descr);

	enter_qcsapi();

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	}

	if (retval >= 0) {
		retval = local_association_get_item(ifname, association_index, MAC_ADDR_ASSOCIATION, auth_descr.macaddr);
	}

	if (retval >= 0) {
		retval = ioctl(skfd, IEEE80211_IOCTL_EXT, &iwr);
	}

	*p_auth_enc = auth_descr.description;

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_tput_caps(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	struct ieee8011req_sta_tput_caps *tput_caps
)
{
	int	retval = 0;
	int	skfd = -1;

	if (ifname == NULL || tput_caps == NULL) {
		return -EFAULT;
	}

	enter_qcsapi();

	memset(tput_caps, 0, sizeof(*tput_caps));

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	}

	if (retval >= 0) {
		retval = local_association_get_item(ifname, association_index,
						    MAC_ADDR_ASSOCIATION, tput_caps->macaddr);
	}

	if (retval >= 0) {
		retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_GET_STA_TPUT_CAPS,
						      (void *)tput_caps, sizeof(*tput_caps));
		if (retval == 0 && tput_caps->mode == IEEE80211_WIFI_MODE_NONE) {
			retval = -qcsapi_mac_not_in_assoc_list;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_connection_mode(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *connection_mode
)
{
	int retval = 0;
	int skfd = -1;
	struct ieee8011req_sta_tput_caps tput_caps;

	if (ifname == NULL || connection_mode == NULL) {
		return -EFAULT;
	}

	enter_qcsapi();

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	}

	if (retval >= 0) {
		retval = local_association_get_item(ifname, association_index,
						    MAC_ADDR_ASSOCIATION, tput_caps.macaddr);
	}

	if (retval >= 0) {
		retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_GET_STA_TPUT_CAPS,
						      (void *)&tput_caps, sizeof(tput_caps));
		if (retval == 0 && tput_caps.mode == IEEE80211_WIFI_MODE_NONE) {
			retval = -qcsapi_mac_not_in_assoc_list;
		}
		*connection_mode = tput_caps.mode;
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_rx_bytes_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	u_int64_t *p_rx_bytes
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, RX_BYTES_ASSOCIATION, p_rx_bytes );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_tx_bytes_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	u_int64_t *p_tx_bytes
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, TX_BYTES_ASSOCIATION, p_tx_bytes );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_rx_packets_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_rx_packets
)
{
	int		retval = 0;
	uint64_t	u64_counter = 0;

	if (p_rx_packets == NULL)
		return -EINVAL;

	enter_qcsapi();

	retval = local_association_get_item(ifname, association_index, RX_PACKETS_ASSOCIATION, &u64_counter);
	if (retval >= 0) {
		*p_rx_packets = (qcsapi_unsigned_int) u64_counter;
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_tx_packets_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_tx_packets
)
{
	int		retval = 0;
	uint64_t	u64_counter = 0;

	if (p_tx_packets == NULL)
		return -EINVAL;

	enter_qcsapi();

	retval = local_association_get_item(ifname, association_index, TX_PACKETS_ASSOCIATION, &u64_counter);
	if (retval >= 0) {
		*p_tx_packets = (qcsapi_unsigned_int) u64_counter;
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_tx_err_packets_per_association(
	const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_tx_err_packets
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, TX_ERR_PACKETS_ASSOCIATION, p_tx_err_packets );


	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_time_associated_per_association( const char *ifname, const qcsapi_unsigned_int association_index, qcsapi_unsigned_int *time_associated )
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_association_get_item( ifname, association_index, TIME_IN_ASSOCIATION, time_associated );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_node_counter(
	const char *ifname,
	const uint32_t node_index,
	qcsapi_counter_type counter_type,
	int local_remote_flag,
	u_int64_t *p_value)
{
	int			retval = 0;
	int			iter;
	int			skfd = -1;
	per_association_item	local_association_item = NOSUCH_ASSOCIATION_ITEM;

	enter_qcsapi();

	if (ifname == NULL || p_value == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (local_remote_flag == QCSAPI_LOCAL_NODE) {
		for (iter = 0; iter < ARRAY_SIZE(per_association_counter_table); iter++) {
			if (per_association_counter_table[iter].pact_counter_type == counter_type) {
				local_association_item = per_association_counter_table[iter].pact_item;
				break;
			}
		}

		if (local_association_item != NOSUCH_ASSOCIATION_ITEM) {
			retval = local_association_get_item(ifname, node_index, local_association_item, p_value );
		} else {
			retval = -EOPNOTSUPP;
		}
	} else if (local_remote_flag == QCSAPI_REMOTE_NODE) {
#if defined(CONFIG_QTN_80211K_SUPPORT)
		/* Remote counters collected from station side by AP */
		struct ieee80211req_qtn_rmt_sta_stats req_rmt_sta_stats;
		uint32_t flags = BIT(RM_QTN_TX_STATS) | BIT(RM_QTN_RX_STATS);
		retval = local_get_association_record_rmt(skfd, ifname, node_index, flags, &req_rmt_sta_stats);
		if (retval < 0) {
			goto ready_to_return;
		}

		retval = local_get_node_counter_rmt(counter_type, &req_rmt_sta_stats, p_value);
		if (retval < 0) {
			goto ready_to_return;
		}
#else
		retval = -EFAULT;
#endif
	} else {
		retval = -EINVAL;
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

static int local_measurement_param_to_type(qcsapi_per_assoc_param param_type, uint8_t *meas_type)
{
	int ret = 0;

	switch(param_type) {
		case QCSAPI_NODE_MEAS_BASIC:
			*meas_type = IOCTL_MEAS_TYPE_BASIC;
			ret = 1;
			break;
		case QCSAPI_NODE_MEAS_CCA:
			*meas_type = IOCTL_MEAS_TYPE_CCA;
			ret = 1;
			break;
		case QCSAPI_NODE_MEAS_RPI:
			*meas_type = IOCTL_MEAS_TYPE_RPI;
			ret = 1;
			break;
		case QCSAPI_NODE_MEAS_CHAN_LOAD:
			*meas_type = IOCTL_MEAS_TYPE_CHAN_LOAD;
			ret = 1;
			break;
		case QCSAPI_NODE_MEAS_NOISE_HIS:
			*meas_type = IOCTL_MEAS_TYPE_NOISE_HIS;
			ret = 1;
			break;
		case QCSAPI_NODE_MEAS_BEACON:
			*meas_type = IOCTL_MEAS_TYPE_BEACON;
			ret = 1;
			break;
		case QCSAPI_NODE_MEAS_FRAME:
			*meas_type = IOCTL_MEAS_TYPE_FRAME;
			ret = 1;
			break;
		case QCSAPI_NODE_MEAS_TRAN_STREAM_CAT:
			*meas_type = IOCTL_MEAS_TYPE_CAT;
			ret = 1;
			break;
		case QCSAPI_NODE_MEAS_MULTICAST_DIAG:
			*meas_type = IOCTL_MEAS_TYPE_MUL_DIAG;
			ret = 1;
			break;
		case QCSAPI_NODE_LINK_MEASURE:
			*meas_type = IOCTL_MEAS_TYPE_LINK;
			ret = 1;
			break;
		case QCSAPI_NODE_NEIGHBOR_REP:
			*meas_type = IOCTL_MEAS_TYPE_NEIGHBOR;
			ret = 1;
			break;
		default:
			break;
	}
	return ret;
}

int
qcsapi_wifi_get_node_param(
	const char *ifname,
	const uint32_t node_index,
	qcsapi_per_assoc_param param_type,
	int local_remote_flag,
	string_128 input_param_str,
	qcsapi_measure_report_result *report_result)
{
	int			retval = 0;
	int			iter;
	int			local_value = 0;
	per_association_item	local_association_item = NOSUCH_ASSOCIATION_ITEM;
	uint8_t			meas_type;
	int			*p_value;
	qcsapi_measure_request_param *request_param;

	if (input_param_str == NULL || report_result == NULL)
		return -EINVAL;

	request_param = (qcsapi_measure_request_param *)input_param_str;
	p_value = report_result->common;
	enter_qcsapi();

	if (local_remote_flag == QCSAPI_LOCAL_NODE) {
		for (iter = 0; iter < ARRAY_SIZE(per_association_parameter_table); iter++) {
			if (per_association_parameter_table[iter].papt_parameter == param_type) {
				local_association_item = per_association_parameter_table[iter].papt_item;
				break;
			}
		}

		if (local_association_item != NOSUCH_ASSOCIATION_ITEM) {
			retval = local_association_get_item(ifname, node_index, local_association_item, &local_value);
			if (retval >= 0 &&
			  (local_association_item == RSSI_ASSOCIATION || local_association_item == SNR_ASSOCIATION)) {
				if (local_value == QDRV_REPORTS_CONFIG_ERR ) {
					retval = -qcsapi_measurement_not_available;
				} else if (local_value < 0) {
					local_value = (local_value - 5) / 10;
				} else {
					local_value = (local_value + 5) / 10;
				}
			}
		} else {
			retval = -EOPNOTSUPP;
		}

		if (retval >= 0) {
			if (local_association_item == SNR_ASSOCIATION) {
				/* The SNR is the negative of the EVM value that the Linux kernel reports */
				*p_value = 0 - local_value;
			} else {
				*p_value = local_value;
			}
		}
	} else if (local_remote_flag == QCSAPI_REMOTE_NODE) {
		if (local_measurement_param_to_type(param_type, &meas_type)) {
			struct ieee80211rep_node_meas_result meas_result;
			int skfd = -1;

			if (ifname == NULL) {
				retval = -EFAULT;
			} else {
				retval = local_open_iw_socket_with_error(&skfd);
			}

			if (retval < 0) {
				goto meas_return;
			}

			retval = local_fetch_measurement_report_remote(skfd,
					ifname,
					node_index,
					meas_type,
					request_param,
					&meas_result);

			if (retval < 0) {
				goto meas_return;
			}

			if (meas_result.status != IOCTL_MEAS_STATUS_SUCC) {
				retval = -EPERM;
				switch (meas_result.status) {
				case IOCTL_MEAS_STATUS_TIMEOUT:
					printf("fail: measurement timeout\n");
					retval = -ETIMEDOUT;
					break;
				case IOCTL_MEAS_STATUS_NODELEAVE:
					printf("fail: node(index = %d) leave the BSS\n", node_index);
					retval = -ECONNREFUSED;
					break;
				case IOCTL_MEAS_STATUS_STOP:
					printf("fail: system stopped\n");
					retval = -ECONNREFUSED;
					break;
				default:
					printf("fail: unknown reason(%d)", meas_result.status);
					break;
				}
				goto meas_return;
			}

			if (meas_result.report_mode != 0) {
				if (meas_result.status & 0x01)
					printf("measurement fail: request too late\n");
				if (meas_result.status & 0x02)
					printf("measurement fail: request is incapable for node %d\n", node_index);
				if (meas_result.status & 0x04)
					printf("measurement fail: request refused by node %d\n", node_index);
				retval = -qcsapi_measurement_not_available;
				goto meas_return;
			}

			switch (param_type) {
			case QCSAPI_NODE_MEAS_BASIC:
				report_result->basic = meas_result.u_data.basic;
				break;
			case QCSAPI_NODE_MEAS_CCA:
				report_result->cca = meas_result.u_data.cca;
				break;
			case QCSAPI_NODE_MEAS_RPI:
				memcpy(report_result->rpi, meas_result.u_data.rpi, 8);
				break;
			case QCSAPI_NODE_MEAS_CHAN_LOAD:
				report_result->channel_load = meas_result.u_data.chan_load;
				break;
			case QCSAPI_NODE_MEAS_NOISE_HIS:
				report_result->noise_histogram.antenna_id = meas_result.u_data.noise_his.antenna_id;
				report_result->noise_histogram.anpi = meas_result.u_data.noise_his.anpi;
				memcpy(report_result->noise_histogram.ipi, meas_result.u_data.noise_his.ipi,
						sizeof(meas_result.u_data.noise_his.ipi));
				break;
			case QCSAPI_NODE_MEAS_BEACON:
				report_result->beacon.rep_frame_info = meas_result.u_data.beacon.reported_frame_info;
				report_result->beacon.rcpi = meas_result.u_data.beacon.rcpi;
				report_result->beacon.rsni = meas_result.u_data.beacon.rsni;
				memcpy(report_result->beacon.bssid, meas_result.u_data.beacon.bssid, 6);
				report_result->beacon.antenna_id = meas_result.u_data.beacon.antenna_id;
				report_result->beacon.parent_tsf = meas_result.u_data.beacon.parent_tsf;
				break;
			case QCSAPI_NODE_MEAS_FRAME:
				report_result->frame.sub_ele_report = meas_result.u_data.frame.sub_ele_report;
				memcpy(report_result->frame.ta, meas_result.u_data.frame.ta, 6);
				memcpy(report_result->frame.bssid, meas_result.u_data.frame.bssid, 6);
				report_result->frame.phy_type = meas_result.u_data.frame.phy_type;
				report_result->frame.avg_rcpi = meas_result.u_data.frame.avg_rcpi;
				report_result->frame.last_rsni = meas_result.u_data.frame.last_rsni;
				report_result->frame.last_rcpi = meas_result.u_data.frame.last_rcpi;
				report_result->frame.antenna_id = meas_result.u_data.frame.antenna_id;
				report_result->frame.frame_count = meas_result.u_data.frame.frame_count;
				break;
			case QCSAPI_NODE_MEAS_TRAN_STREAM_CAT:
				memcpy(&report_result->tran_stream_cat,
						&meas_result.u_data.tran_stream_cat,
						sizeof(report_result->tran_stream_cat));
				break;
			case QCSAPI_NODE_MEAS_MULTICAST_DIAG:
				memcpy(&report_result->multicast_diag,
						&meas_result.u_data.multicast_diag,
						sizeof(report_result->multicast_diag));
				break;
			case QCSAPI_NODE_LINK_MEASURE:
				memcpy(&report_result->link_measure,
						&meas_result.u_data.link_measure,
						sizeof(report_result->link_measure));
				break;
			case QCSAPI_NODE_NEIGHBOR_REP:
				memcpy(&report_result->neighbor_report,
						&meas_result.u_data.neighbor_report,
						sizeof(report_result->neighbor_report));
				break;
			default:
				break;
			}
meas_return:
			if (skfd >= 0) {
				local_close_iw_sockets(skfd);
			}
		} else if (param_type == QCSAPI_NODE_TPC_REP) {
			struct ieee80211rep_node_tpc_result tpc_result;
			int skfd = -1;

			if (ifname == NULL) {
				retval = -EFAULT;
			} else {
				retval = local_open_iw_socket_with_error(&skfd);
			}

			if (retval < 0) {
				goto tpc_return;
			}

			retval = local_fetch_tpc_report_remote(skfd, ifname,
					node_index, &tpc_result);

			if (retval >= 0) {
				if (tpc_result.status == 0) {
					report_result->tpc.link_margin = tpc_result.link_margin;
					report_result->tpc.tx_power = tpc_result.tx_power;
				} else {
					printf("tpc fail\n");
					retval = -ETIMEDOUT;
				}
			}
tpc_return:
			if (skfd >= 0) {
				local_close_iw_sockets(skfd);
			}
		}
		else {
#if defined(CONFIG_QTN_80211K_SUPPORT)
			/* Remote counters collected from station side by AP */
			struct ieee80211req_qtn_rmt_sta_stats req_rmt_sta_stats;
			int skfd = -1;
			uint32_t flags;

			if (ifname == NULL || p_value == NULL) {
				retval = -EFAULT;
			} else {
				retval = local_open_iw_socket_with_error(&skfd);
			}

			if (retval < 0) {
				goto ready_to_return;
			}

			retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
			if (retval < 0) {
				goto ready_to_return;
			}

			retval = local_node_param2flag_rmt(param_type, &flags);
			if (retval < 0) {
				goto ready_to_return;
			}

			retval = local_get_association_record_rmt(skfd, ifname, node_index, flags, &req_rmt_sta_stats);
			if (retval < 0) {
				goto ready_to_return;
			}

			if (flags == RM_STANDARD_CCA) {
				*p_value = 0;
				goto ready_to_return;
			}

			retval = local_get_node_param_rmt(param_type, &req_rmt_sta_stats, p_value);
			if (retval < 0) {
				goto ready_to_return;
			}

			/* Adjust parameter value here if needed */
			if (param_type == QCSAPI_RSSI_DBM || param_type == QCSAPI_SNR) {
				if (*p_value < 0) {
					*p_value = (*p_value - 5) / 10;
				} else {
					*p_value = (*p_value + 5) / 10;
				}
			}
			if (param_type == QCSAPI_SNR) {
				/* The SNR is the negative of the EVM value that the Linux kernel reports */
				*p_value = 0 - *p_value;
			}

			if (param_type == QCSAPI_PHY_NOISE && *p_value > 0) {
				*p_value = 0 - *p_value;
			}

			if (param_type == QCSAPI_PHY_NOISE || param_type == QCSAPI_RSSI) {
				*p_value /= 10;
			}

ready_to_return:
			if (skfd >= 0) {
				local_close_iw_sockets(skfd);
			}
#else
			retval = -EFAULT;
#endif
		}
	} else {
		retval = -EINVAL;
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_node_stats(
	const char *ifname,
	const uint32_t node_index,
	int local_remote_flag,
	struct qcsapi_node_stats *stats)
{
	struct assoc_info_report	assoc_report;
	int				retval = 0;
	int				skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || stats == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (local_remote_flag == QCSAPI_LOCAL_NODE) {
		retval = local_get_association_record(ifname, node_index, &assoc_report);
		if (retval < 0) {
			goto ready_to_return;
		}

		stats->tx_bytes = assoc_report.ai_tx_bytes;
		stats->tx_pkts = assoc_report.ai_tx_packets;
		stats->tx_discard = assoc_report.ai_tx_dropped;
		stats->tx_err = assoc_report.ai_tx_errors;
		stats->tx_unicast = assoc_report.ai_tx_ucast;
		stats->tx_multicast = assoc_report.ai_tx_mcast;
		stats->tx_broadcast = assoc_report.ai_tx_bcast;
		stats->tx_phy_rate = assoc_report.ai_tx_phy_rate;

		stats->rx_bytes = assoc_report.ai_rx_bytes;
		stats->rx_pkts = assoc_report.ai_rx_packets;
		stats->rx_discard = assoc_report.ai_rx_dropped;
		stats->rx_err = assoc_report.ai_rx_errors;
		stats->rx_unicast = assoc_report.ai_rx_ucast;
		stats->rx_multicast = assoc_report.ai_rx_mcast;
		stats->rx_broadcast = assoc_report.ai_rx_bcast;
		stats->rx_phy_rate = assoc_report.ai_rx_phy_rate;
		memcpy(&stats->mac_addr[0],&assoc_report.ai_mac_addr[0],sizeof(stats->mac_addr)),
		stats->hw_noise = assoc_report.ai_hw_noise;
		stats->snr = assoc_report.ai_snr;
		stats->rssi = assoc_report.ai_rssi;
		stats->bw = assoc_report.ai_bw;
	} else if (local_remote_flag == QCSAPI_REMOTE_NODE) {
#if defined(CONFIG_QTN_80211K_SUPPORT)
		/* Remote counters collected from station side by AP */
		struct ieee80211req_qtn_rmt_sta_stats req_rmt_sta_stats;
		uint32_t flags = BIT(RM_QTN_TX_STATS) | BIT(RM_QTN_RX_STATS)
				| BIT(RM_QTN_TX_PHY_RATE) | BIT(RM_QTN_RX_PHY_RATE)
				| BIT(RM_QTN_SOC_MACADDR)
				| BIT(RM_QTN_HW_NOISE) | BIT(RM_QTN_SNR) | BIT(RM_QTN_RSSI) | BIT(RM_QTN_BANDWIDTH);

		retval = local_get_association_record_rmt(skfd, ifname, node_index, flags, &req_rmt_sta_stats);
		if (retval < 0) {
			goto ready_to_return;
		}

		stats->tx_bytes = req_rmt_sta_stats.rmt_sta_stats.tx_stats.tx_bytes;
		stats->tx_pkts = req_rmt_sta_stats.rmt_sta_stats.tx_stats.tx_pkts;
		stats->tx_discard = req_rmt_sta_stats.rmt_sta_stats.tx_stats.tx_discard;
		stats->tx_err = req_rmt_sta_stats.rmt_sta_stats.tx_stats.tx_err;
		stats->tx_unicast = req_rmt_sta_stats.rmt_sta_stats.tx_stats.tx_ucast;
		stats->tx_multicast = req_rmt_sta_stats.rmt_sta_stats.tx_stats.tx_mcast;
		stats->tx_broadcast = req_rmt_sta_stats.rmt_sta_stats.tx_stats.tx_bcast;
		stats->tx_phy_rate = req_rmt_sta_stats.rmt_sta_stats.tx_phy_rate;

		stats->rx_bytes = req_rmt_sta_stats.rmt_sta_stats.rx_stats.rx_bytes;
		stats->rx_pkts = req_rmt_sta_stats.rmt_sta_stats.rx_stats.rx_pkts;
		stats->rx_discard = req_rmt_sta_stats.rmt_sta_stats.rx_stats.rx_discard;
		stats->rx_err = req_rmt_sta_stats.rmt_sta_stats.rx_stats.rx_err;
		stats->rx_unicast = req_rmt_sta_stats.rmt_sta_stats.rx_stats.rx_ucast;
		stats->rx_multicast = req_rmt_sta_stats.rmt_sta_stats.rx_stats.rx_mcast;
		stats->rx_broadcast = req_rmt_sta_stats.rmt_sta_stats.rx_stats.rx_bcast;
		stats->rx_phy_rate = req_rmt_sta_stats.rmt_sta_stats.rx_phy_rate;
		memcpy(&stats->mac_addr[0],&req_rmt_sta_stats.rmt_sta_stats.soc_macaddr[0],sizeof(stats->mac_addr));
		stats->hw_noise = req_rmt_sta_stats.rmt_sta_stats.hw_noise;
		stats->snr = req_rmt_sta_stats.rmt_sta_stats.snr;
		stats->rssi = req_rmt_sta_stats.rmt_sta_stats.rssi;
		stats->bw = req_rmt_sta_stats.rmt_sta_stats.bandwidth;
#else
		retval = -EFAULT;
#endif
	} else {
		retval = -EINVAL;
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_max_queued(
	const char *ifname,
	const uint32_t node_index,
	int local_remote_flag,
	int reset_flag,
	uint32_t *p_max_queued)
{
	int	retval = 0;
	int	skfd = -1;
	qcsapi_mac_addr dev_mac;

	enter_qcsapi();

	if (ifname == NULL || p_max_queued == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (local_remote_flag == QCSAPI_LOCAL_NODE) {
		retval = local_association_get_item( ifname, node_index, MAX_QUEUED_ASSOCIATION, p_max_queued );
		if (retval < 0) {
			goto ready_to_return;
		}

		retval = local_association_get_item( ifname, node_index, MAC_ADDR_ASSOCIATION, dev_mac);
		if (retval < 0) {
			goto ready_to_return;
		}

		if (reset_flag == 1)
			retval = local_wifi_sub_ioctl_submit( ifname, SIOCDEV_SUBIO_RST_QUEUE, dev_mac, sizeof( dev_mac ));

	} else if (local_remote_flag == QCSAPI_REMOTE_NODE) {
#if defined(CONFIG_QTN_80211K_SUPPORT)
		/* Remote counters collected from station side by AP */
		struct ieee80211req_qtn_rmt_sta_stats req_rmt_sta_stats;
		uint32_t flags = BIT(RM_QTN_MAX_QUEUED);
		if (reset_flag == 1)
			flags |= BIT(RM_QTN_RESET_QUEUED);

		retval = local_get_association_record_rmt(skfd, ifname, node_index, flags, &req_rmt_sta_stats);
		if (retval < 0) {
			goto ready_to_return;
		}

		*p_max_queued = req_rmt_sta_stats.rmt_sta_stats.max_queued;
#else
		retval = -EFAULT;
#endif
	} else {
		retval = -EINVAL;
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_associated_device_mac_addr(
	const char *ifname,
	const qcsapi_unsigned_int device_index,
	qcsapi_mac_addr device_mac_addr
)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	local_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || device_mac_addr == NULL) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	/* Only allow this API on the AP */
	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &local_wifi_mode );

		if (retval >= 0) {
			if (local_wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	if (retval >= 0) {
		retval = local_association_get_item( ifname, device_index, MAC_ADDR_ASSOCIATION, device_mac_addr );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_associated_device_ip_addr(
	const char *ifname,
	const qcsapi_unsigned_int device_index,
	unsigned int *ip_addr
)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	local_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || ip_addr == NULL) {
		retval = -EFAULT;
		return retval;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0) {
			retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
	}

	if (retval >= 0) {
		if (local_wifi_mode != qcsapi_access_point && local_wifi_mode != qcsapi_wds) {
			retval = -qcsapi_invalid_wifi_mode;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	if (retval >= 0) {
		retval = local_association_get_item(ifname, device_index, IP_ADDR_ASSOCIATION, ip_addr);
	}

	leave_qcsapi();

	return(retval);
}

/* programs to report on the APs found in the last channel scan */
static int
translate_ie_value( const int ie_value, const int *qcsapi_lookup_table, const size_t lookup_table_size )
{
	int	retval = -1;

	if (ie_value >= 0 && ie_value < (int) lookup_table_size)
	  retval = qcsapi_lookup_table[ ie_value ];

	return (retval );
}

/*
 * Currently only WPA and 11i (WPA2) information elements are parsed.
 * And additional tests are required for both WPA and 11i (WPA2).
 */
static int
is_wpa_or_wpa2_ie( unsigned char *buffer, int ielen )
{
	int	retval = 1;
	int	offset = 2;

	switch (buffer[0])
	{
	case IE_IS_VENDOR:	/* WPA1 */
		if ((ielen < 8) ||
				(memcmp( buffer + offset, wpa1_oui, sizeof(wpa1_oui)) != 0))
			retval = 0;
		break;

	case IE_IS_11i:	/* 11i (WPA2) */
		if (ielen < 4)
			retval = 0;
		break;

	default:
		retval = 0;	/* not WPA, not 11i (WPA2)?  Ignore. */
		break;
	}

	return retval;
}

static int
parse_wpa_11i_ie( unsigned char *iebuf, int ielen, qcsapi_ap_properties *p_current_ap_properties )
{
	int			 retval = 0;
	int			 offset = 2;
	int			 complete = 0;
	int			 protocol_mask = 0;
	const unsigned char	*wpa_oui = NULL;

	if (iebuf[ 0 ] == IE_IS_VENDOR)
	{
		wpa_oui = wpa1_oui;
		protocol_mask = qcsapi_protocol_WPA_mask;

	  /* Skip the OUI type - as found in iwlist.c */

		offset += 4;
	}
	else if (iebuf[ 0 ] == IE_IS_11i)
	{
		wpa_oui = wpa2_oui;
		protocol_mask = qcsapi_protocol_11i_mask;
	}
	else
	{
	  /* should not come here - IE should have been verified as either 11i or WPA. */

		return( -1 );
	}

	offset += 2;

	if(ielen < (offset + 4))
	{
	  /*
	   * We have a short IE.  So we should assume TKIP / PSK.
	   */
		p_current_ap_properties->ap_encryption_modes = qcsapi_ap_TKIP_encryption_mask;
		p_current_ap_properties->ap_authentication_mode = qcsapi_ap_PSK_authentication;
		complete = 1;
	}

  /* Next comes the group cypher - skipped for now. */

	if (complete == 0)
	{
		offset += 4;

	  /* Check if we are done */

		if(ielen < (offset + 2))
		{
		  /*
		   * We don't have a pairwise cypher, or auth method. Assume TKIP / PSK.
		   */
			p_current_ap_properties->ap_encryption_modes = qcsapi_ap_TKIP_encryption_mask;
			p_current_ap_properties->ap_authentication_mode = qcsapi_ap_PSK_authentication;
			complete = 1;
		}
	}

  /* we have some number of pairwise cyphers. */

	if (complete == 0)
	{
		int	cnt = iebuf[offset] | (iebuf[offset + 1] << 8);

		offset += 2;

	  /* Verify the IE defines all the pairwise cyphers it promised. */

		if (ielen < (offset + 4*cnt))
		{
			complete = 1;
			retval = -1;
		}
		else
		{
			int	iter;

			for (iter = 0; iter < cnt; iter++)
			{
				if(memcmp(&iebuf[offset], wpa_oui, 3) == 0)
				{
					int	encryption_mask = translate_ie_value(
							iebuf[ offset+3 ],
							encryption_mask_table,
							TABLE_SIZE( encryption_mask_table )
						);

					if (encryption_mask != -1)
					  p_current_ap_properties->ap_encryption_modes |= encryption_mask;
				}

				offset+=4;
			}
		}

		if(ielen < (offset + 2))
		{
			p_current_ap_properties->ap_authentication_mode = qcsapi_ap_PSK_authentication;
			complete = 1;
		}
	}

  /* we have some number of authentication suites. */

	if (complete == 0)
	{
		int	cnt = iebuf[offset] | (iebuf[offset + 1] << 8);

		offset += 2;

	  /* Verify the IE defines all the pairwise cyphers it promised. */

		if (ielen < (offset + 4*cnt))
		{
			complete = 1;
			retval = -1;
		}
		else
		{
			int	iter;

			for (iter = 0; iter < cnt; iter++)
			{
				if(memcmp(&iebuf[offset], wpa_oui, 3) == 0)
				{
					int	authentication_mode = translate_ie_value(
							iebuf[ offset+3 ],
							authentication_table,
							TABLE_SIZE( authentication_table )
						);

					if (authentication_mode != -1)
					  p_current_ap_properties->ap_authentication_mode = authentication_mode;
				}

				offset+=4;
			}
		}

		if(ielen < (offset + 2))
		{
			complete = 1;
		}
	}

	if (retval >= 0)
	{
		p_current_ap_properties->ap_protocol |= protocol_mask;
	}
  /*
   * Preauthentication could be extracted here if required.
   * Corresponding programming in iwlist stops here.
   */
	return( retval );
}


/* the following defines are borrowed from wps_defs.h, part of wpa_supplicant */
#define ATTR_SELECTED_REGISTRAR			0x1041
#define ATTR_SELECTED_REGISTRAR_CONFIG_METHODS	0x1053
#define ATTR_DEV_PASSWORD_ID			0x1012
#define WPS_CONFIG_PUSHBUTTON			0x0080
#define DEV_PW_PUSHBUTTON			0x0004

static int
verify_and_parse_wsc_ie(unsigned char *buffer, int ielen,
		qcsapi_ap_properties *p_current_ap_properties)
{
	if ((buffer[0] == IE_IS_VENDOR) && (ielen > 8) &&
			(memcmp(buffer + WSC_OUI_OFFSET, wsc_oui, sizeof(wsc_oui)) == 0)) {
		unsigned char *ie_ptr = buffer + WSC_OUI_OFFSET + sizeof(wsc_oui);
		unsigned char *ie_end = ie_ptr + buffer[1] - sizeof(wsc_oui);

		/* indicate general WPS support in bit position 0 */
		p_current_ap_properties->ap_wps = 1 << 0;

		/* scan though IE */
		while (ie_ptr < (ie_end - 4)) {
			unsigned int type;
			unsigned int len;

			/* type is 16 bit value */
			type = (ie_ptr[0] << 8) + ie_ptr[1];
			ie_ptr += 2;
			/* len is 16 bit value */
			len = (ie_ptr[0] << 8) + ie_ptr[1];
			ie_ptr += 2;

			if (len > (ie_end - ie_ptr)) {
				/* error in IE */
				break;
			}

			if (type == ATTR_SELECTED_REGISTRAR && len == 1 && ie_ptr[0]) {
				/* indicate WPS registrar in bit position 1 */
				p_current_ap_properties->ap_wps |= (1 << 1);
			} else if (type == ATTR_SELECTED_REGISTRAR_CONFIG_METHODS && len == 2 &&
					(((ie_ptr[0] << 8) + ie_ptr[1]) & WPS_CONFIG_PUSHBUTTON)) {
				/* indicate WPS push button supported in bit position 2 */
				p_current_ap_properties->ap_wps |= (1 << 2);
			} else if (type == ATTR_DEV_PASSWORD_ID && len == 2 &&
					(((ie_ptr[0] << 8) + ie_ptr[1]) == DEV_PW_PUSHBUTTON)) {
				/* indicate WPS push button activate currently in bit position 3 */
				p_current_ap_properties->ap_wps |= (1 << 3);
			}
			ie_ptr += len;
		}
	} else {
		p_current_ap_properties->ap_wps = 0;
	}

	return 0;
}

static int
parse_generic_ie( unsigned char *buffer, int buflen, qcsapi_ap_properties *p_current_ap_properties )
{
	int	offset = 0;
	int	retval = 0;

  /* Loop on each IE, each IE is minimum 2 bytes */

	while(offset <= (buflen - 2))
	{
		int	ielen = buffer[ offset + 1 ] + 2;

	  /* Check IE type */

		if (is_wpa_or_wpa2_ie(buffer, ielen)) {
			if (buffer[offset] == IE_IS_VENDOR || buffer[offset] == IE_IS_11i) {
				parse_wpa_11i_ie(buffer, ielen, p_current_ap_properties);
			}
		} else {
			verify_and_parse_wsc_ie(buffer, ielen, p_current_ap_properties);
		}

      /* Skip over this IE to the next one in the list. */

		offset += ielen;
	}

	return( retval );
}

/* Rate that must be supported when using 802.11b (bps) */
#define RATE_1MBPS	1000000
#define RATE_2MBPS	2000000

/* Rate that must be supported when using 11a or 11g (bps) */
#define RATE_6MBPS	6000000
#define RATE_12MBPS	12000000
#define RATE_24MBPS	24000000

static int
rate_to_ieee80211_proto(int *bitrate, int num_bitrates, qcsapi_unsigned_int channel) {
	int ret = 0;
	int i;
	int flag_5_ghz = 0;
	int flag_b_1mbps = 0;
	int flag_b_2mbps = 0;
	int flag_ag_6mbps = 0;
	int flag_ag_12mbps = 0;
	int flag_ag_24mbps = 0;

	if (is_in_list_5Ghz_channels(channel))
		flag_5_ghz = 1;

	for (i=0; i < num_bitrates; i++) {
		switch (bitrate[i]) {
		case RATE_1MBPS:
			flag_b_1mbps = 1;
			break;
		case RATE_2MBPS:
			flag_b_2mbps = 1;
			break;
		case RATE_6MBPS:
			flag_ag_6mbps = 1;
			break;
		case RATE_12MBPS:
			flag_ag_12mbps = 1;
			break;
		case RATE_24MBPS:
			flag_ag_24mbps = 1;
			break;
		default:
			break;
		}
	}

	if (flag_b_1mbps && flag_b_2mbps)
		ret |= IEEE80211_PROTO_11B;

	if (flag_ag_6mbps && flag_ag_12mbps && flag_ag_24mbps) {
		if (flag_5_ghz) {
			ret |= IEEE80211_PROTO_11A;
		} else {
			ret |= IEEE80211_PROTO_11G;
		}
	}

	return ret;
}

static int
locate_results_ap_scan( const char *ifname, char *filepath, const size_t pathsize )
{
	int	retval = 0;

	if (ifname == NULL || filepath == NULL)
	  retval = -EFAULT;
	else if (pathsize <= strlen( SCRATCHPAD_FOLDER ) + 1 +
		             strlen( AP_SCAN_RESULTS_FILE ) + 1 + strlen( ifname ))
	  retval = -ENOMEM;
	else
	{
		sprintf( filepath, "%s/%s.%s", SCRATCHPAD_FOLDER, AP_SCAN_RESULTS_FILE, ifname );
	}

	return( retval );
}

static int
remove_results_ap_scan( const char *ifname )
{
	char	path_to_ap_scan_results[ strlen( SCRATCHPAD_FOLDER ) + strlen( AP_SCAN_RESULTS_FILE ) + 16 ];
	int	retval = locate_results_ap_scan( ifname, &path_to_ap_scan_results[ 0 ], sizeof( path_to_ap_scan_results ) );

	if (retval >= 0)
	{
		retval = unlink( &path_to_ap_scan_results[ 0 ] );
		if (retval < 0)
		{
			if (errno == ENOENT)
			  retval = 0;
			else if (errno > 0)
			  retval = -errno;
			else
			  retval = -1;
		}
	}

	return( retval );
}

static int
init_results_ap_scan( const char *ifname )
{
	char	path_to_ap_scan_results[ strlen( SCRATCHPAD_FOLDER ) + strlen( AP_SCAN_RESULTS_FILE ) + 16 ];
	int	retval = locate_results_ap_scan( ifname, &path_to_ap_scan_results[ 0 ], sizeof( path_to_ap_scan_results ) );

	if (retval >= 0)
	{
		FILE	*fh = fopen( &path_to_ap_scan_results[ 0 ], "w" );

		if (fh == NULL)
		  retval = -errno;
		else
		  fclose( fh );
	}

	return( retval );
}

static int
record_ap_properties( const char *ifname, const qcsapi_ap_properties *p_ap_properties )
{
	char	 path_to_ap_scan_results[ strlen( SCRATCHPAD_FOLDER ) + strlen( AP_SCAN_RESULTS_FILE ) + 16 ];
	int	 retval = locate_results_ap_scan( ifname, &path_to_ap_scan_results[ 0 ], sizeof( path_to_ap_scan_results ) );
	FILE	*fh = NULL;

	if (retval >= 0)
	{
		fh = fopen( &path_to_ap_scan_results[ 0 ], "a" );

		if (fh == NULL)
		  retval = -errno;
	}

	if (retval >= 0)
	{
		char	 mac_addr_string[ 24 ];

		sprintf( &mac_addr_string[ 0 ], MACFILTERINGMACFMT,
			  p_ap_properties->ap_mac_addr[ 0 ],
			  p_ap_properties->ap_mac_addr[ 1 ],
			  p_ap_properties->ap_mac_addr[ 2 ],
			  p_ap_properties->ap_mac_addr[ 3 ],
			  p_ap_properties->ap_mac_addr[ 4 ],
			  p_ap_properties->ap_mac_addr[ 5 ]
		);

		fprintf( fh,
			"\"%s\" %s %d %d %x %d %d %d %d %d %d %d\n",
			p_ap_properties->ap_name_SSID,
			&mac_addr_string[ 0 ],
			p_ap_properties->ap_channel,
			p_ap_properties->ap_RSSI,
			p_ap_properties->ap_flags,
			p_ap_properties->ap_protocol,
			p_ap_properties->ap_authentication_mode,
			p_ap_properties->ap_encryption_modes,
			p_ap_properties->ap_best_data_rate,
			p_ap_properties->ap_wps,
			p_ap_properties->ap_80211_proto,
			p_ap_properties->ap_qhop_role
		);
	}

	if (fh != NULL)
	  fclose( fh );

	return( retval );
}

#define AP_SCAN_RESULTS_DEF_BUFF_LEN	(8 * 1024)
#define AP_SCAN_RESULTS_MAX_BUFF_LEN	(32 * 1024)
#define QCSAPI_IW_MAX_AP (2 * IW_MAX_AP)
static int
local_wifi_verified_get_results_AP_scan(
	const char *ifname,
	qcsapi_unsigned_int *p_count_APs
)
{
	int		retval = 0;
	unsigned char	*buffer = NULL;
	unsigned char	*nbuffer = NULL;
	unsigned char	*buf_iter = NULL;
	int		buf_len = AP_SCAN_RESULTS_DEF_BUFF_LEN;
	struct ieee80211_general_ap_scan_result *ge_ap_scan_result;
	struct ieee80211_per_ap_scan_result	*pap_scan_result;
	qcsapi_ap_properties			current_ap_properties;
	int		ap_num = 0;
	int		i,j;

	/* try to get results from driver fully */
	while(1) {
		nbuffer = realloc(buffer, buf_len);
		if (nbuffer == NULL) {
			if (buffer != NULL)
				free(buffer);
			return -ENOMEM;
		}
		buffer = nbuffer;
		retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_AP_SCAN_RESULTS, buffer, buf_len);
		if (retval < 0) {
			if (retval == -E2BIG) {
				if (buf_len * 2 <= AP_SCAN_RESULTS_MAX_BUFF_LEN) {
					buf_len *= 2;
					continue;
				} else {
					/* results could not be retrieved completely, still go on */
					break;
				}
			} else if (retval == -ENOMEM) {
				printf("driver memory allocation fails\n");
			} else {
				free(buffer);
				return retval;
			}
		} else {
			break;
		}
	}

	ge_ap_scan_result = (struct ieee80211_general_ap_scan_result *)buffer;
	if (retval == -E2BIG)
		ge_ap_scan_result->num_ap_results--;

	retval = remove_results_ap_scan(ifname);
	if (retval >= 0)
		retval = init_results_ap_scan(ifname);

	if (retval >= 0) {
		ap_num = ge_ap_scan_result->num_ap_results;

		pap_scan_result = (struct ieee80211_per_ap_scan_result *)(buffer + sizeof(struct ieee80211_general_ap_scan_result));
		for (i = 0; i < ap_num; i++) {
			memset(&current_ap_properties, 0, sizeof(current_ap_properties));
			memcpy(current_ap_properties.ap_mac_addr, pap_scan_result->ap_addr_mac,
					sizeof(current_ap_properties.ap_mac_addr));
			memcpy(current_ap_properties.ap_name_SSID, pap_scan_result->ap_name_ssid,
					sizeof(current_ap_properties.ap_name_SSID));
			current_ap_properties.ap_channel  = pap_scan_result->ap_channel_ieee;
			current_ap_properties.ap_RSSI = pap_scan_result->ap_rssi;
			current_ap_properties.ap_flags = pap_scan_result->ap_flags;
			current_ap_properties.ap_best_data_rate = ge_ap_scan_result->bitrates[ge_ap_scan_result->num_bitrates - 1];
			if (pap_scan_result->ap_htcap)
				current_ap_properties.ap_80211_proto |= IEEE80211_PROTO_11N;
			if (pap_scan_result->ap_vhtcap)
				current_ap_properties.ap_80211_proto |= IEEE80211_PROTO_11AC;
			current_ap_properties.ap_80211_proto |= rate_to_ieee80211_proto(ge_ap_scan_result->bitrates,
					ge_ap_scan_result->num_bitrates, current_ap_properties.ap_channel);
			current_ap_properties.ap_qhop_role = pap_scan_result->ap_qhop_role;
			buf_iter = (unsigned char *)((unsigned char*)pap_scan_result + sizeof(struct ieee80211_per_ap_scan_result));
			for (j = 0; j < pap_scan_result->ap_num_genies; j++) {
				parse_generic_ie(buf_iter, buf_iter[1] + 2, &current_ap_properties);
				buf_iter += buf_iter[1] + 2;
			}
			record_ap_properties(ifname, &current_ap_properties);

			/* to keep address aligned */
			buf_iter = (unsigned char*)(((int)buf_iter + 3) & (~3));

			pap_scan_result = (struct ieee80211_per_ap_scan_result *)buf_iter;
		}
	}

	if (p_count_APs != NULL)
		*p_count_APs = ap_num;

	if (buffer != NULL)
		free(buffer);

	return retval;
}

static int
local_wifi_get_scan_buf_max_size(const char *ifname, unsigned int *p_max_size)
{
	char tmpstring[ 8 ] = {0};
	unsigned int local_max_size = 0;
	int retval = 0;

	retval = send_message_security_daemon(ifname, qcsapi_station,
				"GET scan_buf_max_size", &tmpstring[ 0 ], sizeof( tmpstring ));
	if (retval >= 0) {
		int tmpval = 0;

		retval = sscanf( &tmpstring[ 0 ], "%u", &tmpval );
		if (retval == 1)
			local_max_size = tmpval;
	}

	if (retval >= 0)
		*p_max_size = local_max_size;

	return retval;
}

static int
local_wifi_set_scan_buf_max_size(const char *ifname, const unsigned int max_size)
{
	char cmd[32] = {0};
	int retval = 0;

	snprintf(cmd, sizeof(cmd), "SCAN_BUF_MAX_SIZE %u", max_size);
	retval = send_message_security_daemon(ifname, qcsapi_station,
				cmd, NULL, 0);

	return retval;
}

static int
local_wifi_get_scan_table_max_num(const int skfd,
		const char *ifname, unsigned int *p_max_num)
{
	char setparam_index[ 4 ];
	char *argv[] = {&setparam_index[ 0 ]};
	const int argc =  ARRAY_SIZE(argv);
	unsigned int value = 0;
	int retval = 0;

	snprintf( &setparam_index[ 0 ], sizeof(setparam_index),
			"%u", IEEE80211_PARAM_SCAN_TBL_LEN_MAX);

	retval = call_private_ioctl(
				skfd,
				argv, argc,
				ifname,
				"getparam",
				(void *)&value,
				sizeof(int));

	if (retval >= 0)
		*p_max_num = value;

	return retval;
}

static int
local_wifi_set_scan_table_max_num(const int skfd,
		const char *ifname, const unsigned int max_num)
{
	char setparam_index[ 4 ];
	char setparam_value[ 8 ];
	char *argv[] = { &setparam_index[ 0 ], &setparam_value[ 0 ] };
	const int argc = ARRAY_SIZE(argv);
	int retval = 0;

	snprintf(&setparam_index[ 0 ], sizeof(setparam_index),
			"%u", IEEE80211_PARAM_SCAN_TBL_LEN_MAX);
	snprintf(&setparam_value[ 0 ], sizeof(setparam_value),
			"%u", max_num);

	retval = call_private_ioctl(
				skfd,
				argv, argc,
				ifname,
				"setparam",
				NULL,
				0);

	return retval;
}

int
qcsapi_wifi_set_scan_buf_max_size(const char *ifname, const unsigned int max_buf_size)
{
#define	QCSAPI_SCAN_BUF_MAX_SIZE_MAX	(1024 * 1024)
	char primary_ifname[IFNAMSIZ];
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL)
		retval = -EFAULT;
	else if (max_buf_size > QCSAPI_SCAN_BUF_MAX_SIZE_MAX) {
		retval = -EINVAL;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1);
		if (strcmp(ifname, primary_ifname) != 0)
			retval = -qcsapi_only_on_primary_interface;
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, primary_ifname, &wifi_mode);
		if (wifi_mode != qcsapi_station)
			retval = -qcsapi_only_on_STA;
	}

	if (retval >= 0) {
		retval = local_wifi_set_scan_buf_max_size( ifname, max_buf_size);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd);
	}

	leave_qcsapi();

	return (retval);
}

int
qcsapi_wifi_get_scan_buf_max_size(const char *ifname, unsigned int *max_buf_size)
{
	char primary_ifname[IFNAMSIZ];
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL)
		retval = -EFAULT;
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1);
		if (strcmp(ifname, primary_ifname) != 0)
			retval = -qcsapi_only_on_primary_interface;
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, primary_ifname, &wifi_mode);
		if (wifi_mode != qcsapi_station)
			retval = -qcsapi_only_on_STA;
	}

	if (retval >= 0) {
		retval = local_wifi_get_scan_buf_max_size(ifname, max_buf_size);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd);
	}

	leave_qcsapi();

	return (retval);
}

int
qcsapi_wifi_set_scan_table_max_len(const char *ifname, const unsigned int max_table_len)
{
#define	QCSAPI_QDRV_SCAN_TBL_LEN_MAX	5000
	char primary_ifname[IFNAMSIZ];
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	} else if (max_table_len > QCSAPI_QDRV_SCAN_TBL_LEN_MAX) {
		retval = -EINVAL;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1);
		if (strcmp(ifname, primary_ifname) != 0)
			retval = -qcsapi_only_on_primary_interface;
	}

	if (retval >= 0) {
		retval = local_wifi_set_scan_table_max_num( skfd, ifname, max_table_len);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd);
	}

	leave_qcsapi();

	return (retval);
}

int
qcsapi_wifi_get_scan_table_max_len(const char *ifname, unsigned int *max_table_len)
{
	char primary_ifname[IFNAMSIZ];
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL)
		retval = -EFAULT;
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1);
		if (strcmp(ifname, primary_ifname) != 0)
			retval = -qcsapi_only_on_primary_interface;
	}

	if (retval >= 0) {
		retval = local_wifi_get_scan_table_max_num( skfd, ifname, max_table_len);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd);
	}

	leave_qcsapi();

	return (retval);
}

int
qcsapi_wifi_set_enable_mu(const char *ifname, const unsigned int mu_enable)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0)
		goto ready_to_return;

	retval = local_wifi_set_private_int_param_by_name(skfd,
					ifname,
					"mu_enable_set",
					mu_enable);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_enable_mu(const char *ifname, unsigned int * mu_enable)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0)
		goto ready_to_return;

	retval = local_wifi_get_private_int_param_by_name(skfd,
					ifname,
					"mu_enable_get",
					(int*)mu_enable);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_set_mu_use_precode(const char *ifname, const unsigned int grp,
	const unsigned int prec_enable)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (grp < IEEE80211_VHT_GRP_1ST_BIT_OFFSET || grp > IEEE80211_VHT_GRP_MAX_BIT_OFFSET) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0)
		goto ready_to_return;

	if ((retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL)) < 0)
		goto ready_to_return;

	if (prec_enable) {
		retval = local_wifi_set_private_int_param_by_name(skfd,
						ifname,
						"mu_grp_qmt_ena",
						grp);
	} else {
		retval = local_wifi_set_private_int_param_by_name(skfd,
						ifname,
						"mu_grp_qmt_dis",
						grp);
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_mu_use_precode(const char *ifname, const unsigned int grp,
	unsigned int * prec_enable)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (grp < IEEE80211_VHT_GRP_1ST_BIT_OFFSET || grp > IEEE80211_VHT_GRP_MAX_BIT_OFFSET) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0)
		goto ready_to_return;

	if ((retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL)) < 0)
		goto ready_to_return;

	retval = local_wifi_get_mu_use_precode(skfd, ifname, grp, (int*)prec_enable);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_set_mu_use_eq(const char *ifname, const unsigned int eq_enable)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0)
		goto ready_to_return;

	if ((retval = local_verify_wifi_mode(skfd, ifname, qcsapi_station, NULL)) < 0)
		goto ready_to_return;

	if ((retval = local_wifi_set_private_int_param_by_name(skfd,
					ifname,
					"mu_set_use_eq",
					eq_enable)) < 0)
		goto ready_to_return;

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_mu_use_eq(const char *ifname, unsigned int * eq_enable)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0)
		goto ready_to_return;

	if ((retval = local_verify_wifi_mode(skfd, ifname, qcsapi_station, NULL)) < 0)
		goto ready_to_return;

	retval = local_wifi_get_private_int_param_by_name(skfd,
					ifname,
					"mu_get_use_eq",
					(int*)eq_enable);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_mu_groups(const char *ifname, char * buf, const unsigned int size)
{
	static const char mu_groups_proc[] = "/proc/qdrv_mu";

	int retval = 0;
	int skfd = -1;
	FILE *fh = NULL;

	enter_qcsapi();

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0)
		goto ready_to_return;

	if (retval >= 0) {
		fh = fopen(mu_groups_proc, "r");
		if (fh == NULL) {
			retval = -errno;
			goto ready_to_return;
		}
	}

	retval = fread(buf, sizeof(char), size, fh);
	if (ferror(fh)) {
		retval = -EIO;
	}
	else if (!feof(fh)) {
		retval = -ENOMEM;
	}

ready_to_return:
	if (fh != NULL) {
		fclose(fh);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}


int
qcsapi_wifi_start_cca(const char *ifname, int channel, int duration)
{
	int			retval = 0;
	int			skfd = -1;

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		struct iwreq iwr;
		struct qcsapi_cca_info	data_cca;

		memset(&iwr, 0, sizeof(iwr));
		memset(&data_cca, 0, sizeof(data_cca));
		data_cca.cca_channel = channel;
		data_cca.cca_duration = duration;
		strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);

		iwr.u.data.pointer = (caddr_t) &data_cca;
		iwr.u.data.length  = sizeof(data_cca);

		if (ioctl(skfd, IEEE80211_IOCTL_STARTCCA, &iwr) < 0) {
			retval = -errno;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

        return retval;
}

static int
local_wifi_start_scan(const char *ifname, uint16_t *scanflag_p)
{
	int retval;
	int skfd = -1;

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		struct iwreq iwr;

		memset(&iwr, 0, sizeof(iwr));
		strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);
		iwr.u.data.pointer = scanflag_p;
		iwr.u.data.length = scanflag_p ? sizeof(*scanflag_p) : 0;

		if (ioctl(skfd, SIOCSIWSCAN, &iwr) < 0) {
			retval = -errno;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}
	return retval;
}

int
qcsapi_wifi_start_dfs_reentry(const char *ifname)
{
	int retval;
	uint16_t pick_flags = IEEE80211_PICK_REENTRY | IEEE80211_PICK_DFS;

	enter_qcsapi();

	retval = local_wifi_start_scan(ifname,&pick_flags);

	leave_qcsapi();
	return retval;
}

int
qcsapi_wifi_start_scan_ext(const char *ifname, const int scanflag)
{
	int retval;
	uint16_t scan_flag_tmp = (uint16_t)scanflag;
	uint16_t *scanflag_p = NULL;

	enter_qcsapi();

	if ((scan_flag_tmp & IEEE80211_PICK_ALGORITHM_MASK)) {
		scanflag_p = &scan_flag_tmp;
	}

	retval = local_wifi_start_scan(ifname, scanflag_p);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_scan_status(const char *ifname, int *scanstatus)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (scanstatus == NULL) {
		retval = -EFAULT;
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
	}

	if (retval >= 0) {
		retval = local_wifi_get_private_int_param_by_name(skfd, ifname,
				"get_scanstatus", scanstatus);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_cac_status(const char *ifname, int *cacstatus)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (cacstatus == NULL)
		retval = -EFAULT;

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
		else
			retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	}

	if (retval >= 0) {
		retval = local_wifi_get_private_int_param_by_name(skfd, ifname,
				"get_cacstatus", cacstatus);
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_start_scan(const char *ifname)
{
	int retval;

	enter_qcsapi();

	retval = local_wifi_start_scan(ifname, NULL);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_cancel_scan(const char *ifname, int force)
{
	int retval;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_set_private_int_param_by_name(skfd, ifname, "scan_cancel", force);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

static int
local_wifi_get_results_AP_scan( const char *ifname, qcsapi_unsigned_int *p_count_APs )
{
	int		 retval = 0;
  /*
   * Note: it is OK if p_count_APs is NULL ...
   */
	if (ifname == NULL)
		retval = -EFAULT;

	if (retval >= 0) {
		retval = local_wifi_verified_get_results_AP_scan( ifname, p_count_APs );
	}

	return( retval );
}

int
qcsapi_wifi_get_results_AP_scan( const char *ifname, qcsapi_unsigned_int *p_count_APs )
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_wifi_get_results_AP_scan( ifname, p_count_APs );

	leave_qcsapi();

	return( retval );
}

static int
local_wifi_open_results_AP_scan( const char *ifname, FILE **p_fh )
{
	char	 path_to_ap_scan_results[ strlen( SCRATCHPAD_FOLDER ) + strlen( AP_SCAN_RESULTS_FILE ) + 16 ];
	int	 retval = locate_results_ap_scan( ifname, &path_to_ap_scan_results[ 0 ], sizeof( path_to_ap_scan_results ) );
	FILE	*fh = NULL;
  /*
   * The get count APs scanned and get properties AP APIs should both be blocked on an AP.  This
   * requirement is met in this program, local WiFi open results AP scan.  This program does not
   * does not directly check the WiFi mode, but rather, eliminates APs indirectly.
   *
   * If the AP scan results file is present, this API assumes the get results AP scan put it there.
   * And since that program only works on a STA, this API can conclude the WiFi device is a STA.
   *
   * If the AP scan results file is missing, this API calls the local version of get results AP scan.
   * Latter program only works on a STA.  If that program fails, this API returns the error status.
   */
	if (retval >= 0)
	{
		int	ival = access( &path_to_ap_scan_results[ 0 ], F_OK);

		if (ival < 0)
		{
			if (errno == ENOENT)
			  retval = local_wifi_get_results_AP_scan( ifname, NULL );
			else
			{
				retval = -errno;
				if (retval >= 0)
				  retval = -ENOENT;
			}
		}
	}

	if (retval >= 0)
	{
		fh = fopen( &path_to_ap_scan_results[ 0 ], "r" );
		if (fh == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EACCES;
		}
		else
		 *p_fh = fh;
	}

	return( retval );
}

static int
local_wifi_get_count_APs_scanned( const char *ifname, qcsapi_unsigned_int *p_count_APs )
{
	int	 retval = 0;
	FILE	*fh = NULL;

	if (ifname == NULL || p_count_APs == NULL)
	  retval = -EFAULT;
	else
	  retval = local_wifi_open_results_AP_scan( ifname, &fh );

	if (retval >= 0)
	{
		int	count_APs = 0;
		char	tempbuf[ 32 ];

		while (read_to_eol( &tempbuf[ 0 ], sizeof( tempbuf ), fh ) != NULL)
		{
		  /*
		   * Program expects the 1st character of any valid scanned AP entry
		   * to be a double quote.  First field is the SSID, and that has to
		   * be in quotes in case the SSID itself has embedded blank characters.
		   */
			if (tempbuf[ 0 ] == '"')
			  count_APs++;
		}

		if (p_count_APs != NULL)
		  *p_count_APs = count_APs;
	}

	if (fh != NULL)
	  fclose( fh );

	return( retval );
}

int
qcsapi_wifi_get_count_APs_scanned( const char *ifname, qcsapi_unsigned_int *p_count_APs )
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_wifi_get_count_APs_scanned( ifname, p_count_APs );

	leave_qcsapi();

	return( retval );
}

static int
parse_result_AP_scan( const char *ap_scan_result, qcsapi_ap_properties *p_ap_properties )
{
	int		 retval = 0;
	const char	*parseaddr = ap_scan_result;
	const char *ssid_end = NULL;
	const char *ssid_start = NULL;
	memset( p_ap_properties, 0, sizeof( qcsapi_ap_properties ) );

	if (parseaddr[ 0 ] != '"')
	  retval = -qcsapi_programming_error;
	else
	{
		int	xfer_count = 0;

		parseaddr++;
		ssid_start = parseaddr;
		/* find the last double qutotes */
		while (*parseaddr != '\0' && xfer_count <= IW_ESSID_MAX_SIZE)
		{
			if (*parseaddr == '"')
				ssid_end = parseaddr;
			xfer_count++;
			parseaddr++;
		}

		if (ssid_end)
			parseaddr = ssid_end;
		else
			retval = -qcsapi_internal_format_error;
	}

	if (retval >= 0)
	{
		char		mac_addr_string[ 24 ];
		unsigned int	mac_addr_values[ 6 ];
		int		iter;

		memcpy(p_ap_properties->ap_name_SSID, ssid_start, ssid_end - ssid_start);
		parseaddr++;

		sscanf( parseaddr,
			"%s %d %d %x %d %d %d %d %d %d %d",
			&mac_addr_string[ 0 ],
			&(p_ap_properties->ap_channel),
			&(p_ap_properties->ap_RSSI),
			&(p_ap_properties->ap_flags),
			&(p_ap_properties->ap_protocol),
			&(p_ap_properties->ap_authentication_mode),
			&(p_ap_properties->ap_encryption_modes),
			&(p_ap_properties->ap_best_data_rate),
			&(p_ap_properties->ap_wps),
			&(p_ap_properties->ap_80211_proto),
			&(p_ap_properties->ap_qhop_role)
		);

		sscanf( &mac_addr_string[ 0 ], MACFILTERINGMACFMT,
			&mac_addr_values[ 0 ],
			&mac_addr_values[ 1 ],
			&mac_addr_values[ 2 ],
			&mac_addr_values[ 3 ],
			&mac_addr_values[ 4 ],
			&mac_addr_values[ 5 ]
		);

		for (iter = 0; iter < 6; iter++)
		  p_ap_properties->ap_mac_addr[ iter ] = mac_addr_values[ iter ];
	}

	return( retval );
}

static int
local_wifi_get_properties_AP(
	const char *ifname,
	const qcsapi_unsigned_int index_AP,
	qcsapi_ap_properties *p_ap_properties
)
{
	FILE	*fh = NULL;
	int	 retval = 0;

	if (ifname == NULL || p_ap_properties == NULL)
	  retval = -EFAULT;
	else
	  retval = local_wifi_open_results_AP_scan( ifname, &fh );

	if (retval >= 0)
	{
		int	complete = 0;
		int	count_APs = 0;
		char	tempbuf[ IW_ESSID_MAX_SIZE + 3 + 17 + 60 ];
	  /*
	   * length of tempbuf is SSID + 3 (2 double quotes and space) +
	   * 17 (length of MAC address) + 60 (6 additional fields, each an integer).
	   */

		while (complete == 0 && read_to_eol( &tempbuf[ 0 ], sizeof( tempbuf ), fh ) != NULL)
		{
		  /*
		   * Program expects the 1st character of any valid scanned AP entry
		   * to be a double quote.  First field is the SSID, and that has to
		   * be in quotes in case the SSID itself has embedded blank characters.
		   */
			if (tempbuf[ 0 ] == '"')
			{
				if (count_APs == index_AP)
				{
					complete = 1;
					retval = parse_result_AP_scan( &tempbuf[ 0 ], p_ap_properties );
				}
				else
				  count_APs++;
			}
		}

		if (complete == 0)
		  retval = -ERANGE;
	}

	if (fh != NULL)
	  fclose( fh );

	return( retval );
}

int
qcsapi_wifi_get_properties_AP(
	const char *ifname,
	const qcsapi_unsigned_int index_AP,
	qcsapi_ap_properties *p_ap_properties
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_wifi_get_properties_AP( ifname, index_AP, p_ap_properties );

	leave_qcsapi();

	return( retval );
}

int qcsapi_wifi_set_scan_chk_inv(const char *ifname, int scan_chk_inv)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		retval = local_interface_verify_net_device(ifname);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_set_private_int_param_by_name(skfd,
				ifname, "set_scan_inv", scan_chk_inv);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;

}

int qcsapi_wifi_get_scan_chk_inv(const char *ifname, int *p)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (p == NULL) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
	}

	if (retval >= 0) {
		retval = local_interface_verify_net_device(ifname);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_private_int_param_by_name(skfd,
				ifname,"get_scan_inv",p);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_mcs_rate(const char *ifname, qcsapi_mcs_rate current_mcs_rate)
{
	int skfd = -1;
	int retval = 0;

	enter_qcsapi();

	if (current_mcs_rate == NULL) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0) {
		int internal_mcs = 0;
		int mcs_rate;
		int nss;

		retval = local_wifi_get_mcs_rate(skfd, ifname, &internal_mcs);

		if (retval >= 0) {
			if (internal_mcs == -1) {
				retval = -qcsapi_configuration_error;
			} else if ((internal_mcs & IEEE80211_RATE_PREFIX_MASK) ==
					IEEE80211_N_RATE_PREFIX) {
				mcs_rate = (internal_mcs & 0xFF);
			} else if ((internal_mcs & IEEE80211_RATE_PREFIX_MASK) ==
					IEEE80211_AC_RATE_PREFIX) {
				mcs_rate = (internal_mcs & 0x0F);
				nss = (internal_mcs & 0xF0) >> 4;
				mcs_rate += (nss + 1) * 100;
			} else {
				mcs_rate = (internal_mcs & 0xF);
			}
		}

		if (retval >= 0) {
			snprintf(current_mcs_rate, QCSAPI_MCS_RATE_MAXLEN, "MCS%d", mcs_rate);
		}
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_set_mcs_rate(const char *ifname, const qcsapi_mcs_rate new_mcs_rate)
{
	int		retval = 0;
	int		skfd = -1;
	int32_t		internal_mcs = 0;

	enter_qcsapi();

	if (new_mcs_rate == NULL) {
		retval = -EFAULT;
	} else if (strnlen(new_mcs_rate, MAX_MCS_LEN + 1) > MAX_MCS_LEN) {
		retval = -EINVAL;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0) {
		retval = local_external_mcs_rate_to_internal(new_mcs_rate, &internal_mcs);
	}

	if (retval >= 0) {
		retval = local_wifi_set_mcs_rate(skfd, ifname, internal_mcs);
	}

	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	leave_qcsapi();

	return retval;
}

int
local_wifi_wds_modify_peer(
	int skfd,
	const char *wds_ifname,
	const qcsapi_mac_addr peer_address,
	int b_enable
)
{
	int retval = 0;
	char temp_peer_address_str[20];
	char *argv[] = { &temp_peer_address_str[0] };
	const int argc = sizeof(argv) / sizeof(argv[0]);

	sprintf(temp_peer_address_str, "%02x:%02x:%02x:%02x:%02x:%02x", peer_address[0],
		peer_address[1], peer_address[2], peer_address[3], peer_address[4],
		peer_address[5]);

	if (b_enable) {
		/* add WDS peer */
		retval = call_private_ioctl(skfd, argv, argc, wds_ifname, "wds_add",
					NULL, 0);
	} else {
		/* delete WDS peer */
		retval = call_private_ioctl(skfd, argv, argc, wds_ifname, "wds_del",
					NULL, 0);
	}

	return( retval );
}

/*
 * We support 8 WDS links now.
 * WDS interface name is not aware to customers and use the fixed name as follows.
 */
const char *g_wds_ifname[MAX_WDS_LINKS] =
	{"wds0", "wds1", "wds2", "wds3", "wds4", "wds5", "wds6", "wds7"};

/*
 * Return 1 if mac is used as local address
 */
int is_local_mac_address(int skfd, const qcsapi_mac_addr mac)
{
	int retval = -1;
	int p_found = QCSAPI_FALSE;
	char ifname[IFNAMSIZ] = BRIDGE_DEVICE;
	qcsapi_mac_addr	mac_addr;
	retval = local_interface_get_mac_addr(skfd, ifname, mac_addr);
	if (retval >= 0) {
		retval = memcmp(mac, mac_addr, MAC_ADDR_SIZE);
		if (retval == 0)
			return 1;

		local_check_bss_mac_address((const char *)mac, &p_found);
		if (p_found == QCSAPI_TRUE)
			return 1;
	}

	return 0;
}

int
qcsapi_wds_add_peer(
	const char *ifname,
	const qcsapi_mac_addr peer_address
)
{
	return qcsapi_wds_add_peer_encrypt(ifname, peer_address, 0);
}

int
qcsapi_wds_add_peer_encrypt(
	const char *ifname,
	const qcsapi_mac_addr peer_address,
	const qcsapi_unsigned_int encryption
)
{
	int retval = 0;
	int i = 0;
	int skfd = -1;
	const char *wds_ifname = NULL;
	static const char wds_start_cmd[] = "start 0 wds";
	char primary_ifname[IFNAMSIZ];
	char wds_cmd[sizeof(wds_start_cmd) + IFNAMSIZ + 2];
	struct iwreq wrq;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	int ival = 0;
	int found_empty = 0;
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE];
	char subcmd[10];
	char *argv[2] = {subcmd, "1"};
	int argc = 2;
	struct assoc_info_table	*assoc_arr = NULL;
	qcsapi_interface_status_code status_code = qcsapi_interface_status_error;

	enter_qcsapi();

	if (ifname == NULL || peer_address == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	if (!IS_UNICAST_MAC(peer_address)) {
		retval = -qcsapi_only_unicast_mac;
		goto ready_to_return;
	}

	if ((retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1)) < 0)
		goto ready_to_return;

	/* Check primary interface name */
	if (strcmp(ifname, primary_ifname) != 0) {
		retval = -qcsapi_only_on_primary_interface;
		goto ready_to_return;
	}

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0)
		goto ready_to_return;

	retval = local_verify_repeater_mode(skfd, &wifi_mode);
	if (wifi_mode == qcsapi_repeater) {
		retval = -EOPNOTSUPP;
		goto ready_to_return;
	}

	if (is_local_mac_address(skfd, peer_address)) {
		retval = -qcsapi_invalid_wds_peer_addr;
		goto ready_to_return;
	}

	/* Check if it is AP mode */
	if ((retval = local_wifi_get_mode(skfd, primary_ifname, &wifi_mode)) < 0) {
		goto ready_to_return;
	} else {
		if (wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
			goto ready_to_return;
		}
	}

	if (retval >= 0) {
		assoc_arr = calloc(1, sizeof(*assoc_arr));
		if (!assoc_arr) {
			retval = -ENOMEM;
			goto ready_to_return;
		}
		retval = local_get_assoc_table(skfd, ifname, assoc_arr);
		if (retval >= 0) {
			for (i = 0; i < assoc_arr->cnt; i++) {
				if ((assoc_arr->array[i].ai_assoc_id == 0) ||
						(assoc_arr->array[i].ai_auth == 0))
					continue;
				if (!memcmp(assoc_arr->array[i].ai_mac_addr,
						peer_address, MAC_ADDR_SIZE)) {
					retval = -qcsapi_peer_in_assoc_table;
					goto ready_to_return;
				}
			}
		}
	}

	/* Check whether a matched WDS peer already exists */
	for (i = 0; i < MAX_WDS_LINKS && retval >= 0; i++) {
		wds_ifname = g_wds_ifname[i];
		ival = local_interface_verify_net_device(wds_ifname);

		if (ival == -ENODEV)
			continue;
		retval = ival;

		if (retval < 0)
			goto ready_to_return;

		memset(&wrq, 0x00, sizeof(wrq));
		retval = local_priv_ioctl(skfd, wds_ifname, SIOCGIWAP, &wrq);
		if (retval < 0)
			goto ready_to_return;

		if (memcmp(peer_address, wrq.u.ap_addr.sa_data, sizeof(qcsapi_mac_addr)) == 0) {
			retval = local_interface_get_status(skfd, wds_ifname, &status_code);

			if (retval >= 0) {
				if (status_code == qcsapi_interface_status_running) {
					retval = -EEXIST;
				} else if (status_code == qcsapi_interface_status_disabled) {
					retval = local_interface_enable(wds_ifname, 1);
				} else {
					retval = -qcsapi_iface_error;
				}

				goto ready_to_return;
			}

			break;
		}
	}

	/* Find a empty entry to add */
	for (i = 0; i < MAX_WDS_LINKS && retval >= 0; i++) {
		wds_ifname = g_wds_ifname[i];
		ival = local_interface_verify_net_device(wds_ifname);

		if (ival == -ENODEV) { /* Found */
			found_empty = 1;
			break;
		}
		retval = ival;
	}

	if (retval >= 0 && found_empty == 0)
		retval = -qcsapi_too_many_wds_links;

	/* Add the WDS into empty entry	*/
	if (retval >= 0 && found_empty == 1) {
		memset(wds_cmd, 0, sizeof(wds_cmd));
		snprintf(wds_cmd, sizeof(wds_cmd) - 1, "%s %s", wds_start_cmd, wds_ifname);
		retval = local_wifi_write_to_qdrv(wds_cmd);

		if (retval >= 0) {
			retval = local_wifi_wds_modify_peer(skfd, wds_ifname, peer_address, 1);
		}

		if (retval >= 0) {
			snprintf(cmd, sizeof(cmd),
					"echo 1 > /proc/sys/net/ipv6/conf/%s/disable_ipv6", wds_ifname);
			system(cmd);
		}

		if (retval >= 0) {
			retval = local_interface_enable(wds_ifname, 1);
		}

		if (retval >= 0) {
			retval = local_interface_connect_to_bridge(wds_ifname, BRIDGE_DEVICE, 1);
		}

		if ((retval >= 0) && encryption) {
			snprintf(subcmd, sizeof(subcmd) - 1, "%d",
					IEEE80211_PARAM_PRIVACY);

			retval = call_private_ioctl(skfd, argv, argc, wds_ifname,
					"setparam", NULL, 0);
			if (retval >= 0) {
				memset(subcmd, 0, sizeof(subcmd));
				snprintf(subcmd, sizeof(subcmd) - 1, "%d",
						IEEE80211_PARAM_DROPUNENCRYPTED);
				retval = call_private_ioctl(skfd, argv, argc,
						wds_ifname, "setparam", NULL, 0);
			}
		}
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	if (assoc_arr) {
		free(assoc_arr);
		assoc_arr = NULL;
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wds_remove_peer(
	const char *ifname,
	const qcsapi_mac_addr peer_address
)
{
	int retval = 0;
	int i = 0;
	int skfd = -1;
	const char *wds_ifname;
	static const char wds_stop_cmd[] = "stop 0";
	char primary_ifname[IFNAMSIZ];
	char wds_cmd[sizeof(wds_stop_cmd) + IFNAMSIZ];
	qcsapi_mac_addr temp_peer_address;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	int ival = 0;
	qcsapi_interface_status_code status_code = qcsapi_interface_status_error;

	enter_qcsapi();

	if ((ifname == NULL) || (peer_address == NULL)) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1);
	if (retval < 0)
		goto ready_to_return;

	/* Check primary interface name */
	if (strcmp(ifname, primary_ifname) != 0) {
		retval = -qcsapi_only_on_primary_interface;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_verify_repeater_mode(skfd, &wifi_mode);
	if (wifi_mode == qcsapi_repeater) {
		retval = -EOPNOTSUPP;
		goto ready_to_return;
	}

	/* Check if it is AP mode */
	retval = local_wifi_get_mode(skfd, primary_ifname, &wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	} else {
		if (wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
			goto ready_to_return;
		}
	}

	for (i = 0; i < MAX_WDS_LINKS && retval >= 0; i++) {
		wds_ifname = g_wds_ifname[i];
		ival = local_interface_verify_net_device(wds_ifname);

		if (ival == -ENODEV) {
			retval = 0;
			continue;
		} else
			retval = ival;

		/* Interface found */
		if (retval >= 0) {
			retval = local_interface_get_status(skfd, wds_ifname, &status_code);

			/* Skip interface if marked "down" */
			if (retval >= 0 && status_code != qcsapi_interface_status_running) {
				continue;
			}

			if (retval >= 0) {
				retval = local_wifi_get_BSSID(skfd, wds_ifname, temp_peer_address);
				if (retval >= 0) {
					if (local_generic_verify_mac_addr_valid(temp_peer_address) >= 0 &&
							memcmp(temp_peer_address, peer_address, sizeof(qcsapi_mac_addr)) == 0) {
						/* Delete this interface from the bridge */
						retval = local_interface_connect_to_bridge(wds_ifname, BRIDGE_DEVICE, 0);

						/* Make this interface DOWN */
						if (retval >= 0) {
							retval = local_interface_enable(wds_ifname, 0);
						}
						/* If peer address set, remove it through wds_del iwpriv */
						if (retval >= 0) {
							retval = local_wifi_wds_modify_peer(skfd, wds_ifname, peer_address, 0);
						}

						/* Remove interface */
						if (retval >= 0) {
							memset(wds_cmd, 0, sizeof(wds_cmd));
							snprintf(wds_cmd, sizeof(wds_cmd) - 1, "%s %s", wds_stop_cmd, wds_ifname);
							retval = local_wifi_write_to_qdrv(wds_cmd);
						}

						break;
					}
				}
			}
		}
	}

	if (retval >= 0) {
		if (i >= MAX_WDS_LINKS) {
			retval = -ENODEV;
		}
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wds_get_peer_address(
	const char *ifname,
	const int index,
	qcsapi_mac_addr peer_address
)
{
	int retval = 0;
	int i = 0;
	int up_wds_ifs = 0;
	int skfd = -1;
	const char *wds_ifname;
	char primary_ifname[IFNAMSIZ];
	struct iwreq wrq;
	qcsapi_mac_addr temp_peer_address;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	int ival = 0;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	if ((retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1)) < 0)
		goto ready_to_return;

	/* Check primary interface name */
	if (strcmp(ifname, primary_ifname) != 0) {
		retval = -qcsapi_only_on_primary_interface;
		goto ready_to_return;
	}

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0)
		goto ready_to_return;

	/* Check if it is AP mode */
	if ((retval = local_wifi_get_mode(skfd, primary_ifname, &wifi_mode)) < 0) {
		goto ready_to_return;
	} else {
		if (wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
			goto ready_to_return;
		}
	}

	for (i = 0; i < MAX_WDS_LINKS && retval >= 0; i++) {
		wds_ifname = g_wds_ifname[i];
		ival = local_interface_verify_net_device(wds_ifname);

		if (ival == -ENODEV) {
			retval = 0;
			continue;
		} else
			retval = ival;

		/* Interface found */
		if (retval >= 0) {
			memset(&wrq, 0x00, sizeof(struct iwreq));
			retval = local_priv_ioctl(skfd, wds_ifname, SIOCGIWAP, &wrq);

			if (retval >= 0) {
				memcpy(temp_peer_address, wrq.u.ap_addr.sa_data, sizeof(qcsapi_mac_addr));

				if (local_generic_verify_mac_addr_valid(
						temp_peer_address) >= 0 && up_wds_ifs == index) {
					memcpy(peer_address, temp_peer_address, sizeof(qcsapi_mac_addr));
					break;
				}
			}
			up_wds_ifs ++;
		}
	}

	if (retval >= 0) {
		if (i >= MAX_WDS_LINKS) {
			retval = -ENODEV;
		}
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

static int
local_wifi_wds_set_mode(
	int skfd,
	const char *wds_ifname,
	const qcsapi_mac_addr peer_address,
	const int rbs_mode
)
{
	int retval = 0;
	char setparam_code[QCSAPI_IOCTL_BUFSIZE];
	char setparam_value[QCSAPI_IOCTL_BUFSIZE];
	char *argv[] = {&setparam_code[0], &setparam_value[0]};
	const int argc = ARRAY_SIZE(argv);

	snprintf(setparam_code, sizeof(setparam_code), "%u", IEEE80211_PARAM_WDS_MODE);
	snprintf(setparam_value, sizeof(setparam_value), "%u", rbs_mode);

	retval = call_private_ioctl(
			 skfd,
			 argv,
			 argc,
			 wds_ifname,
			 "setparam",
			 NULL,
			 0
	);

	return( retval );
}

int qcsapi_wds_set_mode(
	const char *ifname,
	const qcsapi_mac_addr peer_address,
	const int rbs_mode
)
{
	int retval = 0;
	int i = 0;
	int skfd = -1;
	const char *wds_ifname;
	char primary_ifname[IFNAMSIZ];
	struct iwreq wrq;
	qcsapi_mac_addr temp_peer_address;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	int ival = 0;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1);
	if (retval < 0) {
		goto ready_to_return;
	}

	/* Check primary interface name */
	if (strcmp(ifname, primary_ifname) != 0) {
		retval = -qcsapi_only_on_primary_interface;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		goto ready_to_return;
	}

	/* Check if it is AP mode */
	retval = local_wifi_get_mode(skfd, primary_ifname, &wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	} else {
		if (wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
			goto ready_to_return;
		}
	}

	for (i = 0; i < MAX_WDS_LINKS && retval >= 0; i++) {
		wds_ifname = g_wds_ifname[i];
		ival = local_interface_verify_net_device(wds_ifname);

		/* Interface not found */
		if (ival == -ENODEV) {
			retval = -ENODEV;
		}

		/* Interface found */
		if (ival >= 0) {
			strncpy(wrq.ifr_name, wds_ifname, sizeof(wrq.ifr_name) - 1);
			retval = ioctl(skfd, SIOCGIWAP, &wrq);

			if (retval >= 0) {
				memcpy(temp_peer_address, wrq.u.ap_addr.sa_data, sizeof(qcsapi_mac_addr));

				if (local_generic_verify_mac_addr_valid(temp_peer_address) >= 0 &&
						memcmp(peer_address, temp_peer_address, sizeof(qcsapi_mac_addr)) == 0) {
					retval = local_wifi_wds_set_mode(skfd, wds_ifname, peer_address, rbs_mode);
					break;
				}
			}
		}
	}

	if (i >= MAX_WDS_LINKS) {
		retval = -EINVAL;
	}

  ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	leave_qcsapi();

	return( retval );
}

static int
local_wifi_wds_get_mode( const int skfd, const char *ifname, int *p_value )
{
	int retval = 0;
	char param_id[6];
	char *argv[] = {param_id};
	int argc = ARRAY_SIZE(argv);
	uint32_t value = 0;

	sprintf(param_id, "%d", IEEE80211_PARAM_WDS_MODE);
	retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"getparam",
			(void *) &value,
			sizeof(uint32_t)
	);
	if (retval >= 0) {
		*p_value = value;
	}

	return( retval );
}

int qcsapi_wds_get_mode(
	const char *ifname,
	const int index,
	int *rbs_mode
)
{
	int retval = 0;
	int i = 0;
	int up_wds_ifs = 0;
	int skfd = -1;
	const char *wds_ifname;
	char primary_ifname[IFNAMSIZ];
	struct iwreq wrq;
	qcsapi_mac_addr temp_peer_address;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	int ival = 0;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1);
	if (retval < 0)
		goto ready_to_return;

	/* Check primary interface name */
	if (strcmp(ifname, primary_ifname) != 0) {
		retval = -qcsapi_only_on_primary_interface;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	/* Check if it is AP mode */
	retval = local_wifi_get_mode(skfd, primary_ifname, &wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	} else {
		if (wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
			goto ready_to_return;
		}
	}

	for (i = 0; i < MAX_WDS_LINKS && retval >= 0; i++) {
		wds_ifname = g_wds_ifname[i];
		ival = local_interface_verify_net_device(wds_ifname);

		/* Interface not found */
		if (ival == -ENODEV) {
			retval = -ENODEV;
		}

		/* Interface found */
		if (ival >= 0) {
			memset(&wrq, 0, sizeof(wrq));
			strncpy(wrq.ifr_name, wds_ifname, sizeof(wrq.ifr_name) - 1);
			retval = ioctl(skfd, SIOCGIWAP, &wrq);

			if (retval >= 0) {
				memcpy(temp_peer_address, wrq.u.ap_addr.sa_data, sizeof(qcsapi_mac_addr));

				if (local_generic_verify_mac_addr_valid(
						temp_peer_address) >= 0 && up_wds_ifs == index) {
					local_wifi_wds_get_mode(skfd, wds_ifname, rbs_mode);
					break;
				}
			}
		}
	}

	if (retval >= 0) {
		if (i >= MAX_WDS_LINKS) {
			retval = -ENODEV;
		}
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_scs_enable(const char *ifname, uint16_t enable_val)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint16_t cmd_value = 0;
	uint32_t scs_value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_SCS_SET_ENABLE;
		cmd_value = enable_val;
		scs_value = cmd_type << 16 | cmd_value;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, scs_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_scs_switch_channel(const char *ifname)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint16_t cmd_value = 0;
	uint32_t scs_value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_SCS_SET_SWITCH_CHANNEL_MANUALLY;
		scs_value = cmd_type << 16 | cmd_value;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, scs_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_scs_verbose(const char *ifname, uint16_t enable_val)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint16_t cmd_value = 0;
	uint32_t scs_value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_SCS_SET_DEBUG_ENABLE;
		cmd_value = enable_val;
		scs_value = cmd_type << 16 | cmd_value;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, scs_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_get_scs_status(const char *ifname, qcsapi_unsigned_int *p_scs_status)
{
	int skfd = -1;
	int retval = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_scs_get_iwpriv(skfd, ifname, p_scs_status);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_scs_smpl_enable(const char *ifname, uint16_t enable_val)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint16_t cmd_value = 0;
	uint32_t scs_value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_SCS_SET_SAMPLE_ENABLE;
		cmd_value = enable_val;
		scs_value = cmd_type << 16 | cmd_value;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, scs_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_scs_smpl_dwell_time(const char *ifname, uint16_t scs_sample_time)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint32_t value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0){
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (scs_sample_time < IEEE80211_SCS_SMPL_DWELL_TIME_MIN ||
		scs_sample_time > IEEE80211_SCS_SMPL_DWELL_TIME_MAX) {
		retval = -ERANGE;
		printf("SCS sample dwell time must be between %d and %d msecs\n",
			IEEE80211_SCS_SMPL_DWELL_TIME_MIN, IEEE80211_SCS_SMPL_DWELL_TIME_MAX);
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_SCS_SET_SAMPLE_DWELL_TIME;
		value = cmd_type << 16 | scs_sample_time;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_scs_sample_intv(const char *ifname, uint16_t scs_sample_intv)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint32_t value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0){
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (scs_sample_intv < IEEE80211_SCS_SMPL_INTV_MIN ||
		scs_sample_intv > IEEE80211_SCS_SMPL_INTV_MAX) {
		retval = -ERANGE;
		printf("SCS sample interval must be between %d and %d secs\n",
			IEEE80211_SCS_SMPL_INTV_MIN, IEEE80211_SCS_SMPL_INTV_MAX);
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_SCS_SET_SAMPLE_INTERVAL;
		value = cmd_type << 16 | scs_sample_intv;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_scs_intf_detect_intv(const char *ifname, uint16_t scs_intf_detect_intv)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint32_t value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0){
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (scs_intf_detect_intv < IEEE80211_SCS_CCA_DUR_MIN ||
		scs_intf_detect_intv > IEEE80211_SCS_CCA_DUR_MAX) {
		retval = -ERANGE;
		printf("SCS interference detection interval must be between %u and %u secs\n",
				IEEE80211_SCS_CCA_DUR_MIN, IEEE80211_SCS_CCA_DUR_MAX);
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_SCS_SET_CCA_SMPL_DUR;
		value = cmd_type << 16 | scs_intf_detect_intv;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_scs_thrshld(const char *ifname,
				  const char *scs_param_name,
				  uint16_t scs_threshold)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint32_t value = 0;
	int i = 0;
	const struct {
		char *threshold_name;
		uint16_t threshold_type;
		int32_t  min;
		int32_t  max;
	} cmd_table[] = {
		{"smpl_pktnum",	IEEE80211_SCS_SET_THRSHLD_SMPL_PKTNUM,
				IEEE80211_SCS_THRSHLD_SMPL_PKTNUM_MIN, IEEE80211_SCS_THRSHLD_SMPL_PKTNUM_MAX},
		{"smpl_airtime", IEEE80211_SCS_SET_THRSHLD_SMPL_AIRTIME,
				IEEE80211_SCS_THRSHLD_SMPL_AIRTIME_MIN, IEEE80211_SCS_THRSHLD_SMPL_AIRTIME_MAX},
		{"intf_low",	IEEE80211_SCS_SET_CCA_INTF_LO_THR,
				IEEE80211_SCS_THRSHLD_MIN, IEEE80211_SCS_THRSHLD_MAX},
		{"intf_high",	IEEE80211_SCS_SET_CCA_INTF_HI_THR,
				IEEE80211_SCS_THRSHLD_MIN, IEEE80211_SCS_THRSHLD_MAX},
		{"intf_ratio",	IEEE80211_SCS_SET_CCA_INTF_RATIO,
				IEEE80211_SCS_THRSHLD_MIN, IEEE80211_SCS_THRSHLD_MAX},
		{"dfs_margin",	IEEE80211_SCS_SET_CCA_INTF_DFS_MARGIN,
				IEEE80211_SCS_THRSHLD_MIN, IEEE80211_SCS_THRSHLD_MAX},
		{"cca_idle",	IEEE80211_SCS_SET_CCA_IDLE_THRSHLD,
				IEEE80211_SCS_THRSHLD_MIN, IEEE80211_SCS_THRSHLD_MAX},
		{"pmbl_err",	IEEE80211_SCS_SET_PMBL_ERR_THRSHLD,
				IEEE80211_SCS_THRSHLD_PMBL_ERR_MIN, IEEE80211_SCS_THRSHLD_PMBL_ERR_MAX},
		{"atten_inc",	IEEE80211_SCS_SET_THRSHLD_ATTEN_INC,
				IEEE80211_SCS_THRSHLD_ATTEN_INC_MIN, IEEE80211_SCS_THRSHLD_ATTEN_INC_MAX},
		{"dfs_reentry",	IEEE80211_SCS_SET_THRSHLD_DFS_REENTRY,
				IEEE80211_SCS_THRSHLD_DFS_REENTRY_MIN, IEEE80211_SCS_THRSHLD_DFS_REENTRY_MAX},
		{"dfs_reentry_minrate",	IEEE80211_SCS_SET_THRSHLD_DFS_REENTRY_MINRATE,
				IEEE80211_SCS_THRSHLD_DFS_REENTRY_MINRATE_MIN,
				IEEE80211_SCS_THRSHLD_DFS_REENTRY_MINRATE_MAX},
	};
	const int cmd_table_size = ARRAY_SIZE(cmd_table);

	enter_qcsapi();

	if (ifname == NULL || scs_param_name == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0) {
			retval = skfd;
		}

		goto ready_to_return;
	}

	retval = verify_we_device(skfd, ifname, NULL, 0);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0) {
		goto ready_to_return;
	}

	for (i = 0; i < cmd_table_size && value == 0; i++ ) {
		if (strcasecmp(cmd_table[i].threshold_name, scs_param_name) == 0) {
			if ((scs_threshold < cmd_table[i].min) ||
				(scs_threshold > cmd_table[i].max)) {
				retval = -ERANGE;
				goto ready_to_return;
			}
			value = scs_threshold;
			cmd_type = cmd_table[i].threshold_type;
			value = (cmd_type << IEEE80211_SCS_COMMAND_S) | value;
		}
	}

	if (value > 0) {
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, value);
	} else {
		retval = -EINVAL;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_scs_report_only(const char *ifname, uint16_t scs_report_only)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint32_t value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_SCS_SET_REPORT_ONLY;
		value = cmd_type << 16 | scs_report_only;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

static int
local_scs_ioctl(int skfd, const char *ifname, uint32_t op, void *data, int len)
{
	struct iwreq iwr;
	struct ieee80211req_scs req;
	int ret;
	uint32_t reason;
	int i;

	memset(&req, 0x0, sizeof(req));
	req.is_op = op;
	req.is_status = &reason;
	req.is_data = data;
	req.is_data_len = len;

	memset(&iwr, 0, sizeof(iwr));
	strcpy(iwr.ifr_name, ifname);
	iwr.u.data.flags = SIOCDEV_SUBIO_SCS;
	iwr.u.data.pointer = &req;
	iwr.u.data.length = sizeof(req);

	ret = ioctl(skfd, IEEE80211_IOCTL_EXT, &iwr);

	if (ret < 0) {
		for (i = 0; i < ARRAY_SIZE(scs_err_tbl); i++) {
			if (reason == scs_err_tbl[i].scs_err_code) {
				printf("SCS ioctl failed because %s\n", scs_err_tbl[i].scs_err_str);
				break;
			}
		}
	}

	return ret;
}

int qcsapi_wifi_get_scs_stat_report(const char *ifname, struct qcsapi_scs_ranking_rpt *scs_rpt)
{
	int skfd;
	int retval = 0;
	struct ieee80211req_scs_ranking_rpt rpt;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;

	if (ifname == NULL || scs_rpt == NULL)
		return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
		if ((retval >= 0) && (local_wifi_mode != qcsapi_access_point)) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		struct ieee80211req_scs_ranking_rpt_chan *rpt_chan;
		int i;

		memset(&rpt, 0x0, sizeof(rpt));
		retval = local_scs_ioctl(skfd, ifname, IEEE80211REQ_SCS_GET_RANKING_RPT,
				&rpt, sizeof(rpt));
		if (retval >= 0) {
			scs_rpt->num = rpt.isr_num;
			for (i = 0; i < rpt.isr_num; i++) {
				rpt_chan = &rpt.isr_chans[i];
				scs_rpt->chan[i] = rpt_chan->isrc_chan;
				scs_rpt->dfs[i] = rpt_chan->isrc_dfs;
				scs_rpt->txpwr[i] = rpt_chan->isrc_txpwr;
				scs_rpt->cca_intf[i] = rpt_chan->isrc_cca_intf;
				scs_rpt->metric[i] = rpt_chan->isrc_metric;
				scs_rpt->metric_age[i] = rpt_chan->isrc_metric_age;
				scs_rpt->pmbl_ap[i] = rpt_chan->isrc_pmbl_ap;
				scs_rpt->pmbl_sta[i] = rpt_chan->isrc_pmbl_sta;
				scs_rpt->duration[i] = rpt_chan->isrc_duration;
				scs_rpt->times[i] = rpt_chan->isrc_times;
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_get_scs_score_report(const char *ifname, struct qcsapi_scs_score_rpt *scs_rpt)
{
	int skfd;
	int retval = 0;
	struct ieee80211req_scs_score_rpt rpt;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;

	if (ifname == NULL || scs_rpt == NULL)
		return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
		if ((retval >= 0) && (local_wifi_mode != qcsapi_access_point)) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		struct ieee80211req_scs_score_rpt_chan *rpt_chan;
		int i;

		memset(&rpt, 0x0, sizeof(rpt));
		retval = local_scs_ioctl(skfd, ifname, IEEE80211REQ_SCS_GET_SCORE_RPT,
				&rpt, sizeof(rpt));
		if (retval >= 0) {
			scs_rpt->num = MIN(rpt.isr_num, IEEE80211REQ_SCS_REPORT_CHAN_NUM);
			for (i = 0; i < scs_rpt->num; i++) {
				rpt_chan = &rpt.isr_chans[i];
				scs_rpt->chan[i] = rpt_chan->isrc_chan;
				scs_rpt->score[i] = rpt_chan->isrc_score;
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_get_scs_currchan_report(const char *ifname, struct qcsapi_scs_currchan_rpt *scs_currchan_rpt)
{
	int skfd;
	int retval = 0;
	struct ieee80211req_scs_currchan_rpt rpt;

	if (ifname == NULL || scs_currchan_rpt == NULL)
		return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		memset(&rpt, 0x0, sizeof(rpt));
		retval = local_scs_ioctl(skfd, ifname, IEEE80211REQ_SCS_GET_CURRCHAN_RPT,
				&rpt, sizeof(rpt));
		if (retval >= 0) {
			scs_currchan_rpt->chan = rpt.iscr_curchan;
			scs_currchan_rpt->cca_try = rpt.iscr_cca_try;
			scs_currchan_rpt->cca_busy = rpt.iscr_cca_busy;
			scs_currchan_rpt->cca_idle = rpt.iscr_cca_idle;
			scs_currchan_rpt->cca_intf = rpt.iscr_cca_intf;
			scs_currchan_rpt->cca_tx = rpt.iscr_cca_tx;
			scs_currchan_rpt->pmbl = rpt.iscr_pmbl;
			scs_currchan_rpt->tx_ms = rpt.iscr_tx_ms;
			scs_currchan_rpt->rx_ms = rpt.iscr_rx_ms;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_scs_stats(const char *ifname, uint16_t start)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint16_t cmd_value = 0;
	uint32_t scs_value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_SCS_SET_STATS_START;
		cmd_value = start;
		scs_value = cmd_type << 16 | cmd_value;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, scs_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_get_autochan_report(const char *ifname, struct qcsapi_autochan_rpt *autochan_rpt)
{
	int skfd;
	int retval = 0;
	struct ieee80211req_scs_ranking_rpt rpt;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;

	if (ifname == NULL || autochan_rpt == NULL)
		return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
		if ((retval >= 0) && (local_wifi_mode != qcsapi_access_point)) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		struct ieee80211req_scs_ranking_rpt_chan *rpt_chan;
		int i;

		memset(&rpt, 0x0, sizeof(rpt));
		retval = local_scs_ioctl(skfd, ifname, IEEE80211REQ_SCS_GET_INIT_RANKING_RPT,
				&rpt, sizeof(rpt));
		if (retval >= 0) {
			autochan_rpt->num = rpt.isr_num;
			for (i = 0; i < rpt.isr_num; i++) {
				rpt_chan = &rpt.isr_chans[i];
				autochan_rpt->chan[i] = rpt_chan->isrc_chan;
				autochan_rpt->dfs[i] = rpt_chan->isrc_dfs;
				autochan_rpt->txpwr[i] = rpt_chan->isrc_txpwr;
				autochan_rpt->numbeacons[i] = rpt_chan->isrc_numbeacons;
				autochan_rpt->metric[i] = rpt_chan->isrc_metric;
				autochan_rpt->cci[i] = rpt_chan->isrc_cci;
				autochan_rpt->aci[i] = rpt_chan->isrc_aci;
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_get_scs_param_report(const char *ifname, struct qcsapi_scs_param_rpt *p_scs_param_rpt, uint32_t param_num)
{
	int skfd;
	int retval = 0;
	void *p_rpt = (qcsapi_scs_param_rpt *)p_scs_param_rpt;

	if (ifname == NULL || p_scs_param_rpt == NULL || param_num > SCS_PARAM_MAX)
		return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_scs_ioctl(skfd, ifname, IEEE80211REQ_SCS_GET_PARAM_RPT,
				p_rpt, param_num * sizeof(struct ieee80211req_scs_param_rpt));
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}
static int local_get_cce_channels(const char *ifname,
				  const char *iwpriv_cmd,
				  qcsapi_unsigned_int *p_prev_channel,
				  qcsapi_unsigned_int *p_cur_channel)
{
	int	retval = 0;
	int	skfd = -1;
	int	packed_channels = 0;

	if (ifname == NULL || iwpriv_cmd == NULL ||
	    p_prev_channel == NULL || p_cur_channel == NULL) {
		return -EFAULT;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = verify_we_device( skfd, ifname, NULL, 0 );
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_private_int_param_by_name(skfd,
							  ifname,
							  iwpriv_cmd,
							 &packed_channels);

	if (retval < 0) {
		goto ready_to_return;
	}

	*p_prev_channel = (packed_channels >> IEEE80211_CCE_PREV_CHAN_SHIFT) & 0xff;
	*p_cur_channel = packed_channels & 0xff;

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	return retval;
}

int qcsapi_wifi_get_dfs_cce_channels(const char *ifname,
				     qcsapi_unsigned_int *p_prev_channel,
				     qcsapi_unsigned_int *p_cur_channel)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_get_cce_channels(ifname, "get_dfs_cce", p_prev_channel, p_cur_channel);

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_scs_cce_channels(const char *ifname,
				     qcsapi_unsigned_int *p_prev_channel,
				     qcsapi_unsigned_int *p_cur_channel)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_get_cce_channels(ifname, "get_scs_cce", p_prev_channel, p_cur_channel);

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_set_scs_cca_intf_smth_fctr(const char *ifname,
					uint8_t smth_fctr_noxp,
					uint8_t smth_fctr_xped)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint32_t value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0){
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if ((smth_fctr_noxp > IEEE80211_CCA_INTF_SMTH_FCTR_MAX) ||
		(smth_fctr_xped > IEEE80211_CCA_INTF_SMTH_FCTR_MAX)) {
		retval = -ERANGE;
		printf("SCS cca interference smoothing factor must be between %d and %d\n",
				IEEE80211_CCA_INTF_SMTH_FCTR_MIN, IEEE80211_CCA_INTF_SMTH_FCTR_MAX);
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_SCS_SET_CCA_INTF_SMTH_FCTR;
		value = cmd_type << 16 |
				smth_fctr_noxp << 8 |
				smth_fctr_xped;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

static int
local_wifi_ocac_set_iwpriv( const int skfd, const char *ifname, uint32_t param_value )
{
	int retval = 0;
	char setparam_value[12];
	char param_id[6];
	char *argv[] = {param_id,  &setparam_value[0]};
	const int argc = ARRAY_SIZE(argv);

	sprintf(param_id, "%d", IEEE80211_PARAM_OCAC);
	snprintf(&setparam_value[0], sizeof(setparam_value), "0x%x", param_value);
	retval = call_private_ioctl(
	  skfd,
	  argv, argc,
	  ifname,
	 "setparam",
	  NULL,
	  0
	);

	return( retval );
}

static int
local_wifi_ocac_get_iwpriv( const int skfd, const char *ifname, uint32_t ocac_cmd, uint32_t *p_value )
{
	int retval = 0;
	char param_id[16];
	char *argv[] = {param_id};
	int argc = ARRAY_SIZE(argv);
	uint32_t value = 0;

	sprintf(param_id, "%d", IEEE80211_PARAM_OCAC | (ocac_cmd << 16));
	retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"getparam",
			(void *) &value,
			sizeof(uint32_t)
	);
	if (retval >= 0) {
		*p_value = value;
	}

	return( retval );
}

int qcsapi_wifi_start_ocac(const char *ifname, uint16_t channel)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type;
	uint32_t ocac_value;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_OCAC);

	if (retval >= 0) {
		if ((channel > QCSAPI_MAX_CHANNEL || channel < QCSAPI_MIN_CHANNEL) &&
				(channel != QCSAPI_ANY_CHANNEL)) {
			retval = -EINVAL;
		}
	}

	if (retval >= 0) {
		if (ifname == NULL) {
			retval = -EFAULT;
		} else {
			retval = local_open_iw_socket_with_error(&skfd);
		}
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_OCAC_SET_ENABLE;
		ocac_value = cmd_type << 16 | channel;
		retval = local_wifi_ocac_set_iwpriv(skfd, ifname, ocac_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_stop_ocac(const char *ifname)
{
	int skfd = -1;
	int retval = 0;
	uint32_t ocac_value = (IEEE80211_OCAC_SET_DISABLE << 16);

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_OCAC);

	if (retval >= 0) {
		if (ifname == NULL) {
			retval = -EFAULT;
		} else {
			retval = local_open_iw_socket_with_error(&skfd);
		}
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_ocac_set_iwpriv(skfd, ifname, ocac_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_get_ocac_status(const char *ifname, qcsapi_unsigned_int *status)
{
	int skfd = -1;
	int retval = 0;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_OCAC);

	if (retval >= 0) {
		if (ifname == NULL) {
			retval = -EFAULT;
		} else {
			retval = local_open_iw_socket_with_error(&skfd);
		}
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_ocac_get_iwpriv(skfd,
				ifname, IEEE80211_OCAC_GET_STATUS, status);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_ocac_dwell_time(const char *ifname, uint16_t dwell_time)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type;
	uint32_t ocac_value;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_OCAC);

	if (retval >= 0) {
		if (dwell_time < IEEE80211_OCAC_DWELL_TIME_MIN ||
				dwell_time > IEEE80211_OCAC_DWELL_TIME_MAX) {
			retval = -EINVAL;
		}
	}

	if (retval >= 0) {
		if (ifname == NULL) {
			retval = -EFAULT;
		} else {
			retval = local_open_iw_socket_with_error(&skfd);
		}
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_OCAC_SET_DWELL_TIME;
		ocac_value = cmd_type << 16 | dwell_time;
		retval = local_wifi_ocac_set_iwpriv(skfd, ifname, ocac_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_ocac_duration(const char *ifname, uint16_t duration)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type;
	uint32_t ocac_value;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_OCAC);

	if (retval >= 0) {
		if (duration < IEEE80211_OCAC_DURATION_MIN ||
				duration > IEEE80211_OCAC_DURATION_MAX) {
			retval = -EINVAL;
		}
	}

	if (retval >= 0) {
		if (ifname == NULL) {
			retval = -EFAULT;
		} else {
			retval = local_open_iw_socket_with_error(&skfd);
		}
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_OCAC_SET_DURATION;
		ocac_value = cmd_type << 16 | duration;
		retval = local_wifi_ocac_set_iwpriv(skfd, ifname, ocac_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_ocac_cac_time(const char *ifname, uint16_t cac_time)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type;
	uint32_t ocac_value;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_OCAC);

	if (retval >= 0) {
		if (cac_time < IEEE80211_OCAC_CAC_TIME_MIN ||
				cac_time > IEEE80211_OCAC_CAC_TIME_MAX) {
			retval = -EINVAL;
		}
	}

	if (retval >= 0) {
		if (ifname == NULL) {
			retval = -EFAULT;
		} else {
			retval = local_open_iw_socket_with_error(&skfd);
		}
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_OCAC_SET_CAC_TIME;
		ocac_value = cmd_type << 16 | cac_time;
		retval = local_wifi_ocac_set_iwpriv(skfd, ifname, ocac_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_ocac_report_only(const char *ifname, uint16_t enable)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type;
	uint32_t ocac_value;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_OCAC);

	if (retval >= 0) {
		if (ifname == NULL) {
			retval = -EFAULT;
		} else {
			retval = local_open_iw_socket_with_error(&skfd);
		}
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_OCAC_SET_REPORT_ONLY;
		ocac_value = cmd_type << 16 | enable;
		retval = local_wifi_ocac_set_iwpriv(skfd, ifname, ocac_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_ocac_thrshld(const char *ifname,
				  const char *param_name,
				  uint16_t threshold)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type = 0;
	uint32_t value = 0;
	int i = 0;
	const struct {
		char *threshold_name;
		uint16_t threshold_type;
		int32_t  min;
		int32_t  max;
	} cmd_table[] = {
		{"fat",IEEE80211_OCAC_SET_THRESHOLD_FAT,
				IEEE80211_OCAC_THRESHOLD_FAT_MIN,
				IEEE80211_OCAC_THRESHOLD_FAT_MAX},
		{"traffic",IEEE80211_OCAC_SET_THRESHOLD_TRAFFIC,
				IEEE80211_OCAC_THRESHOLD_TRAFFIC_MIN,
				IEEE80211_OCAC_THRESHOLD_TRAFFIC_MAX},
		{"cca_intf",IEEE80211_OCAC_SET_THRESHOLD_CCA_INTF,
				IEEE80211_OCAC_THRESHOLD_CCA_INTF_MIN,
				IEEE80211_OCAC_THRESHOLD_CCA_INTF_MAX},
	};
	const int cmd_table_size = ARRAY_SIZE(cmd_table);

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_OCAC);

	if (retval >= 0) {
		if (ifname == NULL || param_name == NULL) {
			retval = -EFAULT;
			goto ready_to_return;
		}
	}

	if (retval >= 0)
		retval = local_open_iw_socket_with_error(&skfd);

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = verify_we_device(skfd, ifname, NULL, 0);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0) {
		goto ready_to_return;
	}

	for (i = 0; i < cmd_table_size; i++ ) {
		if (strcasecmp(cmd_table[i].threshold_name, param_name) == 0) {
			if ((threshold < cmd_table[i].min) ||
					(threshold > cmd_table[i].max)) {
				retval = -ERANGE;
				goto ready_to_return;
			}
			cmd_type = cmd_table[i].threshold_type;
			value = (cmd_type << IEEE80211_OCAC_COMMAND_S) | threshold;
			break;
		}
	}

	if (value > 0) {
		retval = local_wifi_ocac_set_iwpriv(skfd, ifname, value);
	} else {
		retval = -EINVAL;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_get_dfs_s_radio_availability(const char *ifname, qcsapi_unsigned_int *status)
{
	int skfd = -1;
	int retval = 0;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_ocac_get_iwpriv(skfd,
				ifname, IEEE80211_OCAC_GET_AVAILABILITY, status);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_dfs_s_radio_wea_duration(const char *ifname, uint32_t duration)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type;
	uint32_t ocac_value;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_OCAC);

	if (retval >= 0) {
		if (duration < IEEE80211_OCAC_WEA_DURATION_MIN ||
				duration > IEEE80211_OCAC_WEA_DURATION_MAX) {
			retval = -EINVAL;
		}
	}

	if (retval >= 0) {
		if (ifname == NULL) {
			retval = -EFAULT;
		} else {
			retval = local_open_iw_socket_with_error(&skfd);
		}
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_OCAC_SET_WEATHER_DURATION;
		if (duration & ~(IEEE80211_OCAC_COMPRESS_VALUE_M)) {
			duration = (duration >> 2) & IEEE80211_OCAC_COMPRESS_VALUE_M;
			duration |= IEEE80211_OCAC_COMPRESS_VALUE_F;
		}
		ocac_value = cmd_type << 16 | (duration & IEEE80211_OCAC_VALUE_M);
		retval = local_wifi_ocac_set_iwpriv(skfd, ifname, ocac_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_set_dfs_s_radio_wea_cac_time(const char *ifname, uint32_t cac_time)
{
	int skfd = -1;
	int retval = 0;
	uint16_t cmd_type;
	uint32_t ocac_value;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_OCAC);

	if (retval >= 0) {
		if (cac_time < IEEE80211_OCAC_WEA_CAC_TIME_MIN ||
				cac_time > IEEE80211_OCAC_WEA_CAC_TIME_MAX) {
			retval = -EINVAL;
		}
	}

	if (retval >= 0) {
		if (ifname == NULL) {
			retval = -EFAULT;
		} else {
			retval = local_open_iw_socket_with_error(&skfd);
		}
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_OCAC_SET_WEATHER_CAC_TIME;
		if (cac_time & ~(IEEE80211_OCAC_COMPRESS_VALUE_M)) {
			cac_time = (cac_time >> 2) & IEEE80211_OCAC_COMPRESS_VALUE_M;
			cac_time |= IEEE80211_OCAC_COMPRESS_VALUE_F;
		}
		ocac_value = cmd_type << 16 | (cac_time & IEEE80211_OCAC_VALUE_M);
		retval = local_wifi_ocac_set_iwpriv(skfd, ifname, ocac_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}


int qcsapi_wifi_start_dfs_s_radio(const char *ifname, uint16_t channel)
{
	return qcsapi_wifi_start_ocac(ifname, channel);
}

int qcsapi_wifi_stop_dfs_s_radio(const char *ifname)
{
	return qcsapi_wifi_stop_ocac(ifname);
}

int qcsapi_wifi_get_dfs_s_radio_status(const char *ifname, qcsapi_unsigned_int *status)
{
	return qcsapi_wifi_get_ocac_status(ifname, status);
}

int qcsapi_wifi_set_dfs_s_radio_dwell_time(const char *ifname, uint16_t dwell_time)
{
	return qcsapi_wifi_set_ocac_dwell_time(ifname, dwell_time);
}

int qcsapi_wifi_set_dfs_s_radio_duration(const char *ifname, uint16_t duration)
{
	return qcsapi_wifi_set_ocac_duration(ifname, duration);
}

int qcsapi_wifi_set_dfs_s_radio_cac_time(const char *ifname, uint16_t cac_time)
{
	return qcsapi_wifi_set_ocac_cac_time(ifname, cac_time);
}

int qcsapi_wifi_set_dfs_s_radio_report_only(const char *ifname, uint16_t enable)
{
	return qcsapi_wifi_set_ocac_report_only(ifname, enable);
}

int qcsapi_wifi_set_dfs_s_radio_thrshld(const char *ifname,
				  const char *param_name,
				  uint16_t threshold)
{
	return qcsapi_wifi_set_ocac_thrshld(ifname, param_name, threshold);
}

static int local_wifi_set_vendor_fix(const int skfd,
				    const char *ifname,
				    int idx,
				    int value)
{
	int		retval = 0;
	char		qdrv_cmd[48];
	unsigned int	fix_bitmap = 0;
	int		found = 0;
	unsigned int	iter;
	char		qdrv_result[20];

	if (idx < 1 || idx > VENDOR_FIX_IDX_MAX) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	if (value < 0 || value > 1) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	if (retval >= 0) {
		retval = local_wifi_write_to_qdrv("get 0 vendor_fix");
	}

	if (retval >= 0) {
		FILE	*qdrv_fh = fopen(QDRV_RESULTS, "r");
		int	vnum;
		if (qdrv_fh == NULL) {
			retval = -EIO;
			goto ready_to_return;
		}

		read_to_eol(&qdrv_result[0], sizeof(qdrv_result), qdrv_fh);
		vnum = sscanf(qdrv_result, "0x%x", &fix_bitmap);
		if (vnum != 1) {
			fclose(qdrv_fh);
			retval = -EIO;
			goto ready_to_return;
		}
		fclose(qdrv_fh);
	}

	if (retval >= 0) {
		for (iter = 0; iter < ARRAY_SIZE(local_vendor_fix_bitmap_table); iter++) {
			if (local_vendor_fix_bitmap_table[iter].fix_idx == idx) {
				if (value) {
					fix_bitmap |= local_vendor_fix_bitmap_table[iter].enable_bits;
				} else {
					fix_bitmap &= ~local_vendor_fix_bitmap_table[iter].disable_bits;
				}
				found = 1;
				break;
			}
		}
		if (!found) {
			retval = -EINVAL;
			goto ready_to_return;
		}
	}

	if (retval >= 0) {
		memset(qdrv_cmd, 0x00, sizeof(qdrv_cmd));
		sprintf(qdrv_cmd, "set vendor_fix 0x%x", fix_bitmap);
		retval = local_wifi_write_to_qdrv(qdrv_cmd);
	}
ready_to_return:
	return retval;
}

int qcsapi_wifi_set_vendor_fix(const char *ifname,
			      int fix_param,
			      int value)
{
	int	skfd = -1;
	int	retval = 0;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0) {
		goto ready_to_return;
	}

	if ((retval = local_verify_interface_is_primary(ifname)) < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_set_vendor_fix(skfd,
					  ifname,
					  fix_param,
					  value);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_set_scs_chan_mtrc_mrgn(const char *ifname, uint8_t chan_mtrc_mrgn)
{
	int skfd = -1;
	int retval = 0;
	uint32_t value = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0){
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (chan_mtrc_mrgn > IEEE80211_SCS_CHAN_MTRC_MRGN_MAX) {
		retval = -ERANGE;
		printf("SCS chan metric margin must be between 0 and %d\n",
				IEEE80211_SCS_CHAN_MTRC_MRGN_MAX);
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		value = IEEE80211_SCS_SET_CHAN_MTRC_MRGN << 16 | chan_mtrc_mrgn;
		retval = local_wifi_scs_set_iwpriv(skfd, ifname, value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_get_scs_dfs_reentry_request(const char *ifname, qcsapi_unsigned_int *p_scs_dfs_reentry)
{
	int skfd = -1;
	int retval = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_scs_get_dfs_reentry_request_iwpriv(skfd, ifname, p_scs_dfs_reentry);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

static int
local_get_scs_cca_intf( int skfd, const char *ifname, const qcsapi_unsigned_int the_channel, int *p_cca_intf)
{
	int		 retval = 0;
	char		 getparam_str[ 12 ];
	char		*argv[] = { &getparam_str[ 0 ] };
	const int	 argc = sizeof( argv ) / sizeof( argv[ 0 ] );
	u_int32_t	 getparam_int = IEEE80211_PARAM_SCS_CCA_INTF + (the_channel << 16);
	__s32		 local_cca_intf;

	snprintf( &getparam_str[ 0 ], sizeof( getparam_str ), "%u", getparam_int );

	retval = call_private_ioctl(skfd,
				 argv, argc,
				 ifname,
				"getparam",
				&local_cca_intf,
				 sizeof( __s32 ));

	if (retval >= 0) {
		*p_cca_intf = (int) local_cca_intf;
	}

	return( retval );
}

int
qcsapi_wifi_get_scs_cca_intf(const char *ifname, const qcsapi_unsigned_int the_channel, int *p_cca_intf)
{
	int		retval = 0;
	int		skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || p_cca_intf == NULL) {
		retval = -EFAULT;
	} else if (the_channel > QCSAPI_MAX_CHANNEL || the_channel < QCSAPI_MIN_CHANNEL) {
		retval = -EINVAL;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_get_scs_cca_intf( skfd, ifname, the_channel, p_cca_intf);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

static int local_reset_all_counters(
		const char *ifname,
		const uint32_t node_index,
		int local_remote_flag)
{
	int skfd = -1;
	int retval = 0;
	struct ifreq	ifr;

	if (ifname == NULL) {
		retval = -EFAULT;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (local_remote_flag == QCSAPI_LOCAL_NODE) {
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		retval = ioctl(skfd, SIOCR80211STATS, &ifr);

		if (retval < 0) {
			retval = -errno;
		}
	} else if (local_remote_flag == QCSAPI_REMOTE_NODE) {
#if defined(CONFIG_QTN_80211K_SUPPORT)
		struct ieee80211req_qtn_rmt_sta_stats req_rmt_sta_stats;
		uint32_t flags = BIT(RM_QTN_RESET_CNTS);

		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
		if (retval < 0) {
			goto ready_to_return;
		}

		retval = local_get_association_record_rmt(skfd, ifname, node_index, flags, &req_rmt_sta_stats);
		if (retval < 0) {
			goto ready_to_return;
		}
#else
		retval = -EFAULT;
#endif
	} else {
		retval = -EINVAL;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	return retval;
}

int qcsapi_reset_all_counters(const char *ifname, const uint32_t node_index, int local_remote_flag)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_reset_all_counters(ifname, node_index, local_remote_flag);

	leave_qcsapi();

	return retval;
}

int
local_verify_interface_is_ap_mode(const char *ifname)
{
	int retval = 0;
	int skfd = -1;

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0)
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}
	return retval;
}

int
local_security_get_ap_isolate(
	const char *ifname,
	int *p_ap_isolate
)
{
	int retval = 0;
	int current_ap_isolate = (int)qcsapi_ap_isolate_disabled;
	char param_buffer[ 80 ];

	retval = local_verify_interface_is_ap_mode(ifname);

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		int ival_ap_isolate = lookup_ap_security_parameter(
				 ifname,
				 qcsapi_access_point,
				"ap_isolate",
				&param_buffer[ 0 ],
				 sizeof(param_buffer)
			);

		if (ival_ap_isolate >= 0) {
			sscanf(&param_buffer[ 0 ], "%d", &current_ap_isolate);
		}

		if (p_ap_isolate) {
			*p_ap_isolate = !!current_ap_isolate;
		}
	}

	return( retval );
}

int
qcsapi_wifi_get_ap_isolate(
	const char *ifname,
	int *p_ap_isolate
)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_security_get_ap_isolate(ifname, p_ap_isolate);

	leave_qcsapi();

	return( retval );
}

int
local_security_set_ap_isolate(
	const char *ifname,
	const int new_ap_isolate
)
{
	int retval = 0;
	int current_ap_isolate = (int)qcsapi_ap_isolate_disabled;
	char param_buffer[ 80 ];
	char ap_isolate_string[2];
	char primary_ifname[IFNAMSIZ] = {0};

	if ((new_ap_isolate != (int)qcsapi_ap_isolate_disabled) &&
		(new_ap_isolate != (int)qcsapi_ap_isolate_enabled) ) {
		retval = -EINVAL;
	} else {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
	}

	if (retval >= 0) {
		int ival_ap_isolate = lookup_ap_security_parameter(
				 ifname,
				 qcsapi_access_point,
				"ap_isolate",
				&param_buffer[ 0 ],
				 sizeof(param_buffer)
			);

		if (ival_ap_isolate >= 0) {
			sscanf(&param_buffer[ 0 ], "%d", &current_ap_isolate);
		}

		if ( current_ap_isolate != new_ap_isolate ) {
			snprintf(ap_isolate_string,
					sizeof(ap_isolate_string),
					"%d",
					new_ap_isolate);

			update_security_parameter(
					ifname,
					NULL,
					"ap_isolate",
					ap_isolate_string,
					qcsapi_access_point,
					QCSAPI_TRUE,
					qcsapi_bare_string,
					security_update_complete
					);
		}
	}

	return( retval );
}

int
qcsapi_wifi_set_ap_isolate(
	const char *ifname,
	const int new_ap_isolate
)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_security_set_ap_isolate(ifname, new_ap_isolate);

	leave_qcsapi();

	return( retval );
}

static int
local_security_get_intra_bss_isolate(const char *ifname, qcsapi_unsigned_int *p_value)
{
	int retval = 0;
	qcsapi_unsigned_int curr_intra_bss_isolate = 0;
	char param_buffer[80] = {'\0'};

	retval = lookup_ap_security_parameter(
			ifname,
			qcsapi_access_point,
			"intra_bss_isolate",
			&param_buffer[0],
			sizeof(param_buffer)
			);

	if (retval >= 0)
		sscanf(&param_buffer[0], "%u", &curr_intra_bss_isolate);

	*p_value = !!curr_intra_bss_isolate;

	return 0;
}

int
qcsapi_wifi_get_intra_bss_isolate(const char *ifname, qcsapi_unsigned_int *isol)
{
	int retval = 0;

	enter_qcsapi();

	if ((ifname == NULL) || (isol == NULL))
		retval = -EFAULT;

	if (retval >= 0)
		retval = local_verify_interface_is_ap_mode(ifname);

	if (retval >= 0)
		retval = local_security_get_intra_bss_isolate(ifname, isol);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_set_intra_bss_isolate(const char *ifname, const qcsapi_unsigned_int isol)
{
	int retval = 0;
	qcsapi_unsigned_int curr_isol;
	qcsapi_unsigned_int new_isol;
	char intra_bss_isolate[2] = {'\0'};

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_verify_interface_is_ap_mode(ifname);
	if (retval < 0)
		goto ready_to_return;

	retval = local_security_get_intra_bss_isolate(ifname, &curr_isol);
	if (retval < 0)
		goto ready_to_return;

	new_isol = !!isol;
	if (curr_isol != new_isol) {
		snprintf(intra_bss_isolate,
			sizeof(intra_bss_isolate),
			"%u",
			new_isol);

		retval = update_security_parameter(
			ifname,
			NULL,
			"intra_bss_isolate",
			intra_bss_isolate,
			qcsapi_access_point,
			QCSAPI_TRUE,
			qcsapi_bare_string,
			security_update_complete
			);
	}

ready_to_return:
	leave_qcsapi();

	return retval;
}

static int
local_get_bss_isolate(const char *ifname, qcsapi_unsigned_int *isol)
{
	int retval = 0;
	qcsapi_unsigned_int curr_bss_isolate = 0;
	char param_buffer[80] = {'\0'};

	retval = lookup_ap_security_parameter(
			ifname,
			qcsapi_access_point,
			"bss_isolate",
			&param_buffer[0],
			sizeof(param_buffer)
			);

	if (retval >= 0)
		sscanf(&param_buffer[0], "%u", &curr_bss_isolate);

	*isol = !!curr_bss_isolate;

	return 0;
}

int
qcsapi_wifi_get_bss_isolate(const char *ifname, qcsapi_unsigned_int *bss_isol)
{
	int retval = 0;

	enter_qcsapi();

	if ((ifname == NULL) || (bss_isol == NULL))
		retval = -EFAULT;

	if (retval >= 0)
		retval = local_verify_interface_is_ap_mode(ifname);

	if (retval >= 0)
		retval = local_get_bss_isolate(ifname, bss_isol);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_set_bss_isolate(const char *ifname, const qcsapi_unsigned_int bss_isol)
{
	int retval = 0;
	qcsapi_unsigned_int curr_isol;
	qcsapi_unsigned_int new_isol;
	char bss_isolate[2] = {'\0'};

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_verify_interface_is_ap_mode(ifname);
	if (retval < 0)
		goto ready_to_return;

	retval = local_get_bss_isolate(ifname, &curr_isol);
	if (retval < 0)
		goto ready_to_return;

	new_isol = !!bss_isol;
	if (curr_isol != new_isol) {
		snprintf(bss_isolate,
			sizeof(bss_isolate),
			"%u",
			new_isol);

		retval = update_security_parameter(
			ifname,
			NULL,
			"bss_isolate",
			bss_isolate,
			qcsapi_access_point,
			QCSAPI_TRUE,
			qcsapi_bare_string,
			security_update_complete
			);
	}

ready_to_return:
	leave_qcsapi();

	return retval;
}

int qcsapi_get_max_bitrate(const char *ifname, char *max_bitrate, const int max_str_len)
{
	int retval = 0;

	if (!max_bitrate)
		return -EFAULT;

	if (local_interface_verify_net_device(ifname) < 0) {
		return -ENODEV;
	}

	if (max_str_len < QCSAPI_MAX_BITRATE_STR_MIN_LEN) {
		retval = -qcsapi_buffer_overflow;
	}

	enter_qcsapi();

	if (retval >= 0) {
		strncpy(max_bitrate, "auto", QCSAPI_MAX_BITRATE_STR_MIN_LEN);
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_set_max_bitrate(const char *ifname, const char *max_bitrate)
{
	int retval = 0;

	if (!ifname || !max_bitrate)
		return -EFAULT;

	if (local_interface_verify_net_device(ifname) < 0) {
		return -ENODEV;
	}

	enter_qcsapi();

	if (strncmp(max_bitrate, "auto", QCSAPI_MAX_BITRATE_STR_MIN_LEN)) {
		retval = -EINVAL;
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_get_phy_stats(const char *ifname, qcsapi_phy_stats *stats)
{
	int retval = 0;
	local_qcsapi_phy_stats ls;
	unsigned int channel;
	int skfd;
	int iter;

	if (!ifname || !stats)
		return -EFAULT;

	if (local_interface_verify_net_device(ifname) < 0) {
		return -ENODEV;
	}

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0)
		  retval = retval;
	}

	if (retval >= 0) {
		retval = local_wifi_get_channel( skfd, ifname, &channel );
	}

	if (retval < 0)
		channel = 0;

	retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_GET_PHY_STATS, (void *)&ls, sizeof(local_qcsapi_phy_stats));

	if (retval >= 0) {
		stats->tstamp		= ls.tstamp;
		stats->assoc		= ls.assoc;
		stats->atten		= ls.atten;
		stats->cca_total	= ls.cca_total;
		stats->cca_tx		= ls.cca_tx;
		stats->cca_rx		= ls.cca_rx;
		stats->cca_int		= ls.cca_int;
		stats->cca_idle	= ls.cca_idle;
		stats->channel		= channel;
		stats->rx_pkts		= ls.rx_pkts;
		stats->rx_gain		= ls.rx_gain;
		stats->rx_cnt_crc	= ls.rx_cnt_crc;
		stats->rx_noise	= 0 - (abs(ls.rx_noise) / 10.0);
		stats->tx_pkts		= ls.tx_pkts;
		stats->tx_defers	= ls.tx_defers;
		stats->tx_touts	= ls.tx_touts;
		stats->tx_retries	= ls.tx_retries;
		stats->cnt_sp_fail	= ls.cnt_sp_fail;
		stats->cnt_lp_fail	= ls.cnt_lp_fail;
		stats->last_rx_mcs	= ls.last_rx_mcs;
		stats->last_tx_mcs	= ls.last_tx_mcs;
		stats->last_rssi	= 0 - (abs(ls.last_rssi) / 10.0);
		for (iter = 0; iter < QCSAPI_QDRV_NUM_RF_STREAMS; iter++)
			stats->last_rssi_array[iter] = 0 - (abs(ls.last_rssi_array[iter]) / 10.0);
		stats->last_rcpi	= 0 - (abs(ls.last_rcpi) / 10.0);
		stats->last_evm	= 0 - (abs(ls.last_evm) / 10.0);
		for (iter = 0; iter < QCSAPI_QDRV_NUM_RF_STREAMS; iter++)
			stats->last_evm_array[iter] = 0 - (abs(ls.last_evm_array[iter]) / 10.0);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}


static int
local_wifi_run_script(const char *scriptname, const char *param)
{
	int retval;
	int status;
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE];

	snprintf(cmd, QCSAPI_WIFI_CMD_BUFSIZE - 1, "/scripts/%s %s > %s 2>&1", scriptname, param, QCSAPI_SCRIPT_LOG);
	status = system(cmd);

	if (status == -1 || !WIFEXITED(status)) {
		retval = -qcsapi_script_error;
	} else {
		if (WEXITSTATUS(status) == 0)
			retval = 0;
		else
			retval = -qcsapi_script_error;
	}

	return retval;
}


int
qcsapi_wifi_run_script(const char *scriptname, const char *param)
{
	int retval;

	enter_qcsapi();

	retval = local_wifi_run_script(scriptname, param);

	leave_qcsapi();
	return retval;
}

int qcsapi_wifi_get_disconn_info(const char *ifname, qcsapi_disconn_info *disconn_info)
{
	int	retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || disconn_info == NULL)
	      retval = -EFAULT;

	if (retval >= 0)
		retval = local_interface_verify_net_device(ifname);

	if (retval >= 0) {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_DISCONN_INFO,
					(void *)disconn_info, sizeof(*disconn_info));
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return(retval);
}

int qcsapi_wifi_test_traffic(const char *ifname, uint32_t period)
{
	int skfd = -1;
	int retval = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	}

	if (retval >= 0) {
		retval = local_wifi_set_private_int_param_by_name(skfd, ifname, "test_traffic", period);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_get_temperature_info(int *temp_external, int *temp_internal, int *temp_bb_internal)
{
	int retval = 0;
	char tmp[50];

	if (temp_external == NULL || temp_internal == NULL || temp_bb_internal == NULL) {
		return -EFAULT;
	}

	enter_qcsapi();

	retval = local_wifi_write_to_qdrv("calcmd 3 0 4 0");

	if (retval >= 0) {
		retval = local_read_string_from_file(QDRV_RESULTS, tmp, sizeof(tmp));
	}

	if (retval >= 0) {
		sscanf(tmp, "%d %d", temp_external, temp_internal);
	}
	retval = local_read_string_from_file(PROC_TEMP_SENS, tmp, sizeof(tmp));
	if (retval >= 0) {
		int low;
		int high;

		sscanf(tmp, "Temperature between %d - %d C", &low, &high);
		*temp_bb_internal = high * QDRV_TEMPSENS_COEFF10;
	}

	leave_qcsapi();
	return retval;
}

static int
local_calcmd_set_channel(qcsapi_unsigned_int rftest_chan)
{
	char set_channel[30];
	sprintf(&set_channel[0], "calcmd 1 0 8 0 1 1 2 %u", rftest_chan);
	return (local_wifi_write_to_qdrv(&set_channel[0]));
}

static int
local_calcmd_set_test_mode(int channel, int antenna, int mcs, int bw, int pkt_size, int eleven_n, int bf)
{
	int retval;
	char set_test_mode[70];

	retval = local_calcmd_set_channel(channel);
	sprintf(&set_test_mode[0], "calcmd 12 0 16 0 1 %d 2 %d 3 %d 4 %d 5 %d 6 %d", antenna, mcs, bw, pkt_size, !!eleven_n, bf);
	retval = local_wifi_write_to_qdrv(&set_test_mode[0]);
	return retval;
}

static int
local_calcmd_set_mac_filter(int q_num, int sec_enable, const qcsapi_mac_addr macaddr)
{
	int retval = 0;
	char mac_filter[60];

	if (macaddr == NULL)
	      return -EFAULT;

	memset(mac_filter, 0, 60);
	sprintf(&mac_filter[0], "calcmd 39 0 16 0 1 %d 2 %d %d %d %d 3 %d %d 4 %d", q_num, macaddr[0], macaddr[1],
		macaddr[2], macaddr[3], macaddr[4], macaddr[5], sec_enable);

	retval = local_wifi_write_to_qdrv(&mac_filter[0]);

	return retval;
}

static void
local_rftest_parse_packet_report_line(const char *packet_report_line, uint32_t *packet_report)
{
	const char *packet_report_addr = packet_report_line;
	int complete = 0;

	while (complete == 0) {
		int index_entry = -1;
		int i;

		while (isspace(*packet_report_addr)) {
			packet_report_addr++;
		}

		for (i = 0; rftest_counter_table[i].counter_name != NULL && index_entry < 0; i++) {
			unsigned int length_entry_name = strlen(rftest_counter_table[i].counter_name);
			if (strncasecmp(packet_report_addr, rftest_counter_table[i].counter_name, length_entry_name) == 0) {
				index_entry = i;
				packet_report_addr += length_entry_name;
			}
		}

		if(index_entry < 0) {
			complete = 1;
		} else {
			while (isspace( *packet_report_addr)){
				packet_report_addr++;
			}

			if (*packet_report_addr != '='){
				complete = 1;
			} else {
				packet_report_addr++;
			}
		}

		if (complete == 0) {
			int counter_value = atoi(packet_report_addr);
			switch (rftest_counter_table[index_entry].counter_type)
			{
				case 1:
					packet_report[rftest_counter_table[index_entry].report_index] = counter_value;
				break;

				case 2:
					packet_report[rftest_counter_table[index_entry].report_index] = counter_value;
				break;

				case 0:
				default:
				break;
			}

			while (*packet_report_addr != ',' && *packet_report_addr != '&' && *packet_report_addr != '\0'){
				packet_report_addr++;
			}

			if (*packet_report_addr != ',' && *packet_report_addr != '&') {
				complete = 1;
			} else {
				packet_report_addr++;
			}
		}
	}
}


int
qcsapi_calcmd_set_test_mode(
				qcsapi_unsigned_int channel,
				qcsapi_unsigned_int antenna,
				qcsapi_unsigned_int mcs,
				qcsapi_unsigned_int bw,
				qcsapi_unsigned_int pkt_size,
				qcsapi_unsigned_int eleven_n,
				qcsapi_unsigned_int primary_sel)
{
	int retval = 0;

/* To do

	if BW is 40MHz and the value of primary_sel is either 1 or -1
		if the value of primary_sel == 1,
			then it means lower 20MHz
		else the value of primary_sel == -1,
			then it means upper 20MHz

	else if BW is 20MHz and the value of primary_sel is 0,
		then it means 20MHz BW


	else
		No option like this

	local_calcmd_set_prim_channel(primary_sel);  // calcmd interface for this should be implemented
*/
	local_calcmd_set_test_mode(channel, antenna, mcs, bw, pkt_size, eleven_n, primary_sel);
	return retval;
}

int
qcsapi_calcmd_show_test_packet(qcsapi_unsigned_int *tx_packet_num, qcsapi_unsigned_int *rx_packet_num, qcsapi_unsigned_int *crc_packet_num)
{
	int retval = 0;
	qcsapi_unsigned_int result[4] = {0};
	retval = local_wifi_write_to_qdrv("calcmd 15 0 4 0");
	if (retval >= 0)
	{
		FILE *qdrv_fh = fopen(QDRV_RESULTS, "r");
		char qdrv_output[122];

		if (qdrv_fh == NULL) {
			retval = -errno;
		}

		if (retval >= 0) {
			while(fgets(&qdrv_output[0], sizeof(qdrv_output), qdrv_fh) != NULL)
			{
				local_rftest_parse_packet_report_line(&qdrv_output[0], &result[0]);
			}
		}

		*tx_packet_num = result[0];
		*rx_packet_num = result[1];
		*crc_packet_num = result[3];

		if (qdrv_fh != NULL)
			fclose(qdrv_fh);
	}
	return(retval);
}

int
qcsapi_calcmd_set_mac_filter(int q_num, int sec_enable, const qcsapi_mac_addr mac_addr)
{
	int retval = 0;

	enter_qcsapi();
	retval = local_calcmd_set_mac_filter(q_num, sec_enable, mac_addr);
	leave_qcsapi();

	return retval;
}

int
qcsapi_calcmd_send_test_packet(qcsapi_unsigned_int to_transmit_packet_num)
{
	int retval;
	char send_test_packet[50];

	enter_qcsapi();

	sprintf(&send_test_packet[0], "calcmd 8 0 6 0 1 %d",
			to_transmit_packet_num);

	retval = local_wifi_write_to_qdrv(&send_test_packet[0]);

	leave_qcsapi();

	return(retval);
}

int
qcsapi_calcmd_stop_test_packet(void)
{
	int retval;
	retval = 0;

	enter_qcsapi();

	retval = local_wifi_write_to_qdrv("calcmd 16 0 4 0");

	leave_qcsapi();

	return(retval);
}

int
qcsapi_calcmd_send_dc_cw_signal(qcsapi_unsigned_int channel)
{
	int retval;

	enter_qcsapi();

	retval = local_calcmd_set_channel(channel);
	if (retval >= 0) {
		retval = local_wifi_write_to_qdrv("calcmd 55 0 6 0 1 1");
	}

	if (retval >=0 ) {
		retval = local_wifi_write_to_qdrv("calcmd 11 0 6 0 1 0");
	}

	if (retval >=0 ) {
		retval = local_wifi_write_to_qdrv("calcmd 43 0 12 0 1 23 2 23 3 23 4 23");
	}

	if (retval >=0 ) {
		retval = local_wifi_write_to_qdrv("calcmd 58 0 4 0 ");
	}

	leave_qcsapi();

	return(retval);
}

int
qcsapi_calcmd_stop_dc_cw_signal(void)
{
	int retval;
	retval = 0;

	enter_qcsapi();

	retval = local_wifi_write_to_qdrv("calcmd 55 0 6 0 1 0");

	if (retval >=0 ) {
		retval = local_wifi_write_to_qdrv("calcmd 11 0 6 0 1 2");
	}

	leave_qcsapi();

	return(retval);
}

int
qcsapi_calcmd_get_test_mode_antenna_sel(qcsapi_unsigned_int *antenna_bit_mask)
{
	int retval;
	char tmp[50];

	enter_qcsapi();

	retval = local_wifi_write_to_qdrv("calcmd 56 0 4 0");

	if (retval >= 0) {
		retval = local_read_string_from_file(QDRV_RESULTS, tmp, sizeof(tmp));
	}

	if (retval >= 0) {
		sscanf(tmp, "%d", antenna_bit_mask);
	}


	leave_qcsapi();
	return(retval);
}

int
qcsapi_calcmd_get_test_mode_mcs(qcsapi_unsigned_int *test_mode_mcs)
{
	int retval;
	char tmp[50];
	qcsapi_unsigned_int antenna;

	enter_qcsapi();

	retval = local_wifi_write_to_qdrv("calcmd 56 0 4 0");

	if (retval >= 0) {
		retval = local_read_string_from_file(QDRV_RESULTS, tmp, sizeof(tmp));
	}

	if (retval >= 0) {
		sscanf(tmp, "%d %d", &antenna, test_mode_mcs);
	}

	leave_qcsapi();
	return(retval);
}

int
qcsapi_calcmd_get_test_mode_bw(qcsapi_unsigned_int *test_mode_bw)
{
	int retval;
	char tmp[50];
	qcsapi_unsigned_int antenna, mcs;

	enter_qcsapi();

	retval = local_wifi_write_to_qdrv("calcmd 56 0 4 0");

	if (retval >= 0) {
		retval = local_read_string_from_file(QDRV_RESULTS, tmp, sizeof(tmp));
	}

	if (retval >= 0) {
		sscanf(tmp, "%d %d %d", &antenna, &mcs, test_mode_bw);
	}

	leave_qcsapi();
	return(retval);
}

int
qcsapi_calcmd_get_tx_power(qcsapi_calcmd_tx_power_rsp *tx_power)
{
	int retval = 0;
	char tmp[50];

	enter_qcsapi();

	if (tx_power == NULL)
	      retval = -EFAULT;

	if (retval >= 0)
		retval = local_wifi_write_to_qdrv("calcmd 51 0 4 0");

	if (retval >= 0)
		retval = local_read_string_from_file(QDRV_RESULTS, tmp, sizeof(tmp));

	if (retval >= 0) {
		sscanf(tmp, "%d %d %d %d", &tx_power->value[0],
					&tx_power->value[1],
					&tx_power->value[2],
					&tx_power->value[3]);
	}

	leave_qcsapi();
	return(retval);
}

int
qcsapi_calcmd_set_tx_power(qcsapi_unsigned_int tx_power)
{
	int retval;
	char set_tx_power[30];

	enter_qcsapi();

	sprintf(&set_tx_power[0], "calcmd 19 0 6 0 1 %d", tx_power*4);
	retval = local_wifi_write_to_qdrv(set_tx_power);

	leave_qcsapi();
	return(retval);
}

int
qcsapi_calcmd_get_test_mode_rssi(qcsapi_calcmd_rssi_rsp *test_mode_rssi)
{
	int retval = 0;
	char tmp[50];

	enter_qcsapi();

	if (test_mode_rssi == NULL)
	      retval = -EFAULT;

	if (retval >= 0)
		retval = local_wifi_write_to_qdrv("calcmd 15 0 6 0 1 1");

	if (retval >= 0) {
		retval = local_wifi_write_to_qdrv("calcmd 54 0 4 0");
	}

	if (retval >= 0) {
		retval = local_read_string_from_file(QDRV_RESULTS, tmp, sizeof(tmp));
	}

	if (retval >= 0) {
		sscanf(tmp, "%d %d %d %d", &test_mode_rssi->value[0],
				&test_mode_rssi->value[1],
				&test_mode_rssi->value[2],
				&test_mode_rssi->value[3]);
	}

	leave_qcsapi();
	return(retval);
}

int
qcsapi_calcmd_get_antenna_count(qcsapi_unsigned_int *antenna_count)
{
	int retval;

	enter_qcsapi();

	retval = 0;

	*antenna_count = QCSAPI_QDRV_NUM_RF_STREAMS;

	leave_qcsapi();
	return(retval);
}

int
qcsapi_calcmd_clear_counter(void)
{
	int retval;
	char calcmd_clear_counter[30];

	enter_qcsapi();

	sprintf(&calcmd_clear_counter[0], "calcmd 59 0 4 0");
	retval = local_wifi_write_to_qdrv(calcmd_clear_counter);

	leave_qcsapi();
	return(retval);
}

int
qcsapi_calcmd_get_info(string_1024 output_info)
{
	int retval;

	enter_qcsapi();

	retval = local_wifi_write_to_qdrv("get 0 info");

	if (retval >= 0) {
		FILE *qdrv_fh = fopen(QDRV_RESULTS, "r");
		string_128 qdrv_output;
		if (qdrv_fh == NULL) {
			retval = -errno;
		}
		if (retval >= 0) {
			while(fgets(&qdrv_output[0], sizeof(qdrv_output), qdrv_fh) != NULL)
			{
				strncat(output_info, qdrv_output, sizeof(qdrv_output));
			}
		}
		if (qdrv_fh != NULL)
			fclose(qdrv_fh);
	}

	leave_qcsapi();
	return(retval);
}

int
qcsapi_wifi_wait_scan_completes( const char *ifname, time_t timeout )
{
	int	sub_ioctl_ret;
	int	ret = 0;

	enter_qcsapi();

	sub_ioctl_ret = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_WAIT_SCAN_TIMEOUT, &timeout, sizeof(timeout));
	if (sub_ioctl_ret > 0) {
		ret = 1;		/* normal exit */
	} else if (sub_ioctl_ret == 0) {
		ret = -ETIME;		/* timeout */
	} else if (sub_ioctl_ret == -1) {
		ret = 0;		/* no scan in progress */
	} else {
		ret = -EIO;		/* IO error */
	}

	leave_qcsapi();
	return ret;
}

int qcsapi_wifi_disable_dfs_channels( const char *ifname, const int scheme, const int inp_chan )
{
	int			retval = 0,
				skfd = -1;
	qcsapi_bw		band_width = qcsapi_nosuch_bw;
	channel_entry		*p_regulatory_channel = NULL;
	qcsapi_regulatory_entry	*p_regulatory_entry = NULL;
	int			is_channel_DFS = 0;
	char			local_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION];
	qcsapi_regulatory_region the_region = QCSAPI_NOSUCH_REGION;

	enter_qcsapi();

	if (local_use_new_tx_power() == 1) {
		retval = local_qcsapi_regulatory_disable_dfs_channels(ifname, scheme, inp_chan);
		leave_qcsapi();
		return retval;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = skfd;
	}

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0) {
		retval = local_get_internal_regulatory_region(skfd,
					ifname, &local_region[0]);
	        if (retval >= 0 && (strcmp(&local_region[0], "none") == 0))
		      retval = -EOPNOTSUPP;
	}

	if (retval >= 0) {
		if (scheme > 0 && inp_chan > 0) {
			retval = local_wifi_is_channel_DFS(local_region,
						inp_chan, &is_channel_DFS);
			if (retval >= 0 && is_channel_DFS > 0)
				retval = -EINVAL;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_bandwidth(skfd, ifname, &band_width);
	}

	if (retval >= 0)
		the_region = local_wifi_get_region_by_name(local_region);

	if (retval >= 0) {
		p_regulatory_entry = locate_regulatory_entry( the_region );
		if (p_regulatory_entry == NULL)
			retval = -EOPNOTSUPP;
		else
			p_regulatory_channel = p_regulatory_entry->p_channel_table;
	}

	if (retval >= 0) {
		retval = local_wifi_pre_deactive_DFS_channels(skfd, ifname, scheme);
	}
	/* Choose the appropiate scheme defined above and call directly ioctl */
	if (retval >= 0) {
		retval = local_wifi_set_chanlist(skfd, ifname, band_width, p_regulatory_channel );
	}

	/* Forces a channel switch to avoid keep in a DFS channel */
	/* if non DFS option has been selected */
	if (retval >= 0 && skfd >= 0 && inp_chan > 0) {
		retval = local_wifi_set_channel(skfd, ifname, inp_chan);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	if(retval >= 0)
		retval = 0;

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_vht( const char *ifname, const qcsapi_unsigned_int the_vht )
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_VHT);

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = verify_we_device( skfd, ifname, NULL, 0 );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		int	ival;

		ival = local_wifi_option_set_vht( skfd, ifname, the_vht );

		if (ival < 0)
		  retval = ival;
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return (retval);
}

int
qcsapi_wifi_get_vht( const char *ifname, qcsapi_unsigned_int *the_vht)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || the_vht == NULL) {
		retval = -EFAULT;
	} else {
		*the_vht = 0;

	retval = local_swfeat_check_supported(SWFEAT_ID_VHT);

		if (retval >= 0) {
			skfd = local_open_iw_sockets();
			if (skfd < 0) {
				retval = -errno;
				if (retval >= 0)
					retval = skfd;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wifi_option_get_vht( skfd, ifname, the_vht);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd);
	}

	leave_qcsapi();

	return (retval);

}

static int
local_wifi_vlan_cmd_sanity_check(const char *ifname, qcsapi_vlan_cmd cmd)
{
	int retval = 0;
	uint16_t vmode;
	struct qtn_vlan_config *vcfg;

	COMPILE_TIME_ASSERT(sizeof(string_1024) > sizeof(struct qtn_vlan_config));
	if (cmd == e_qcsapi_vlan_enable)
		return retval;

	vcfg = (struct qtn_vlan_config *)malloc(sizeof(struct qtn_vlan_config));
	if (!vcfg) {
		printf("Not enough memory to execute the API\n");
		return -qcsapi_programming_error;
	}
	memset(vcfg, 0, sizeof(*vcfg));

	retval = qcsapi_wifi_show_vlan_config(ifname, (char *)vcfg);
	if (retval >= 0) {
		vmode = qtn_vlancfg_reform(vcfg);
		if (vmode > QVLAN_MODE_MAX)
			retval = -qcsapi_param_value_invalid;
	}
	free(vcfg);

	return retval;
}

int
qcsapi_wifi_vlan_config(const char *ifname, qcsapi_vlan_cmd cmd, uint32_t vlanid, uint32_t flags)
{
	char cmd_params[QCSAPI_WIFI_CMD_BUFSIZE] = {0};
	int retval = 0;
	int skfd = -1;
	int script = 1;

	retval = local_wifi_vlan_cmd_sanity_check(ifname, cmd);
	if (retval < 0)
		return retval;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0)
		retval = -errno;

	if (retval >= 0) {
		if (local_verify_wifi_mode(skfd, ifname, qcsapi_wds, NULL) >= 0)
			retval = -qcsapi_iface_invalid;
	}

	if (retval >= 0) {
		switch (cmd) {
			case e_qcsapi_vlan_bind:
				snprintf(cmd_params, sizeof(cmd_params), "bind %s %d %d", ifname, vlanid, flags);
				break;
			case e_qcsapi_vlan_unbind:
				snprintf(cmd_params, sizeof(cmd_params), "unbind %s %d", ifname, vlanid);
				break;
#ifdef TOPAZ_PLATFORM
			case e_qcsapi_vlan_passthru:
				snprintf(cmd_params, sizeof(cmd_params), "passthru %s %d", ifname, vlanid);
				break;
			case e_qcsapi_vlan_unpassthru:
				snprintf(cmd_params, sizeof(cmd_params), "unpassthru %s %d", ifname, vlanid);
				break;
			case e_qcsapi_vlan_dynamic:
				update_security_parameter(
					ifname,
					NULL,
					"dynamic_vlan",
					"1",
					qcsapi_access_point,
					QCSAPI_TRUE,
					qcsapi_bare_string,
					security_update_complete
					);
				script = 0;
				break;
			case e_qcsapi_vlan_undynamic:
				update_security_parameter(
					ifname,
					NULL,
					"dynamic_vlan",
					"0",
					qcsapi_access_point,
					QCSAPI_TRUE,
					qcsapi_bare_string,
					security_update_complete
					);
				script = 0;
				break;
			case e_qcsapi_vlan_enable:
				snprintf(cmd_params, sizeof(cmd_params), "enable");
				break;
			case e_qcsapi_vlan_disable:
				snprintf(cmd_params, sizeof(cmd_params), "disable");
				break;
#endif
			default:
				retval = -EINVAL;
				break;
		}
		if (retval >= 0 && script) {
			retval = local_wifi_run_script("qvlan", cmd_params);
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return (retval);
}

int qcsapi_wifi_show_vlan_config(const char *ifname, string_1024 vcfg)
{
	int retval = 0;
	int skfd;
	char cmd[64];

	if (!ifname)
		return -EINVAL;

	if (local_interface_verify_net_device(ifname) < 0)
		return -EINVAL;

	skfd = local_open_iw_sockets();
	if (skfd < 0)
		retval = -errno;

	if (retval >= 0) {
		if (local_verify_wifi_mode(skfd, ifname, qcsapi_wds, NULL) >= 0)
			retval = -qcsapi_iface_invalid;
	}

	if (retval < 0)
		return retval;

	snprintf(cmd, sizeof(cmd) - 1, "get 0 vlan_config %s", ifname);

	enter_qcsapi();

	retval = local_wifi_write_to_qdrv(cmd);
	if (retval >= 0) {
		retval = local_read_string_from_file(QDRV_RESULTS, vcfg,
                        sizeof(string_1024));
	}

	leave_qcsapi();
	return retval;
}

int qcsapi_set_soc_mac_addr(const char *ifname, const qcsapi_mac_addr soc_mac_addr)
{
	int retval = 0;

	if (!ifname)
		return -EFAULT;

	if (local_interface_verify_net_device(ifname) < 0) {
		return -ENODEV;
	}

	enter_qcsapi();
#if defined(CONFIG_QTN_80211K_SUPPORT)
	retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_SET_SOC_ADDR_IOCTL, (void *)soc_mac_addr, sizeof(qcsapi_mac_addr));
#endif
	leave_qcsapi();

	return retval;

}

int
qcsapi_wifi_set_vlan_promisc(int enable)
{
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE] = {0};
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd >= 0) {
			retval = local_verify_wifi_mode(skfd, "wifi0", qcsapi_access_point, NULL);
		} else {
			retval = -errno;
		}
	}

	if (retval >= 0) {
		snprintf(cmd, sizeof(cmd), "set vlan_promisc %d", enable);
		retval = local_wifi_write_to_qdrv(cmd);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return (retval);
}

int
qcsapi_enable_vlan_pass_through(const char *ifname, int enabled)
{
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE] = {0};
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0)
		retval = -errno;

	if (retval >= 0) {
		if (local_verify_wifi_mode(skfd, ifname, qcsapi_wds, NULL) >= 0)
			retval = -qcsapi_iface_invalid;
	}

	if (retval >= 0) {
		snprintf(cmd, sizeof(cmd), "set br_vlan_forward %d", enabled);
		retval = local_wifi_write_to_qdrv(cmd);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return (retval);
}

static int
qcsapi_wifi_set_ipff(int add, uint32_t ipaddr)
{
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE] = {0};
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		snprintf(cmd, sizeof(cmd), "%s " NIPQUAD_FMT " port wmac node 0",
			add ? "add" : "del", NIPQUAD(ipaddr));
		retval = local_wifi_write_to_fwt(cmd);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return (retval);
}

int qcsapi_wifi_add_ipff(qcsapi_unsigned_int ipaddr)
{
	return qcsapi_wifi_set_ipff(1, htonl(ipaddr));
}

int qcsapi_wifi_del_ipff(qcsapi_unsigned_int ipaddr)
{
	return qcsapi_wifi_set_ipff(0, htonl(ipaddr));
}

int qcsapi_wifi_get_ipff(char *buf, int buflen)
{
	char *bufp = buf;
	FILE *fd;
	size_t got;
	const char *truncated_str = "\n[list truncated]\n";
	int retval = 0;

	enter_qcsapi();

	fd = fopen(FWT_CONTROL_IPFF, "r");
	if (!fd) {
		retval = -qcsapi_programming_error;
	} else {
		while (fgets(bufp, buflen, fd) != NULL) {
			got = strlen(bufp);
			bufp += got;
			buflen -= got;
		}
		if (buflen < sizeof(truncated_str)) {
			strncpy(bufp - strlen(truncated_str) - 1, truncated_str,
				strlen(truncated_str) + 1);
		}

		fclose(fd);
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_rts_threshold(const char *ifname, qcsapi_unsigned_int *rts_threshold)
{
	int skfd = -1;
	int retval = 0;
	struct iwreq wrq;

	retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0) {
		retval = local_priv_ioctl(skfd, ifname, SIOCGIWRTS, &wrq);
	}

	if ((retval < 0) && (errno > 0)) {
		retval = -errno;
	}

	if (retval >= 0) {
		*rts_threshold = wrq.u.rts.value;
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	return retval;
}

int qcsapi_wifi_set_rts_threshold(const char *ifname, qcsapi_unsigned_int rts_threshold)
{
	int skfd = -1;
	int retval = 0;
	struct iwreq wrq;

	retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0) {
		memset(&wrq, 0, sizeof(wrq));
		wrq.u.rts.value = rts_threshold;
		wrq.u.rts.fixed = 1;
		wrq.u.rts.disabled = (rts_threshold >= IEEE80211_RTS_THRESH_OFF);
	}

	if (retval >= 0) {
		retval = local_priv_ioctl(skfd, ifname, SIOCSIWRTS, &wrq);
	}

	if ((retval < 0) && (errno > 0)) {
		retval = -errno;
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	return retval;
}

static unsigned int atoh(char a)
{
	if ((a>=0x30) && (a<=0x39)){
		return (unsigned int)(a-0x30);
	} else if ((a>=0x61) && (a<=0x66)) {
		return (unsigned int)(a-0x57);
	} else {
		return 0;
	}
}

static unsigned int natoh(char * buf, int len)
{
        unsigned int x = 0;
        while(len-->0){
                x<<=4;
                x|=atoh(*buf);
                buf++;
        }
        return x;
}

int qcsapi_wifi_get_spinor_jedecid(const char * ifname, unsigned int * p_jedecid)
{
#define SWAP32(x)        ((((x) & 0x000000ff) << 24) | (((x) & 0x0000ff00) << 8)|\
                (((x) & 0x00ff0000) >>  8) | (((x) & 0xff000000) >> 24) )
        int retval = -EFAULT;
        FILE * p=popen("/scripts/readmem 0xe2009f00", "r");
        if (p){
                char buffer[100];
                char *b = fgets(buffer, sizeof(buffer), p);
                while(*b!=':' && *b!='\n'){
                        b++;
                };
                if (*b!='\n') {
                        *p_jedecid = natoh(b+2, 8);
                        *p_jedecid = SWAP32(*p_jedecid);
                        retval = 0;
                }
                pclose(p);
        }
        return retval;
}

int qcsapi_get_custom_value(const char *custom_key, string_128 custom_value)
{
	int retval = 0;
	char filename[QCSAPI_CMD_BUFSIZE] = {'\0'};
	FILE *fd = NULL;

	enter_qcsapi();

	if (!custom_key || !custom_value)
		retval = -qcsapi_programming_error;

	if (retval >= 0) {
		if (strstr(custom_key, QCSAPI_FILESYSTEM_SP) != NULL)
			retval = -qcsapi_configuration_error;
	}

	if (retval >= 0) {
		snprintf(filename, sizeof(filename) - 1, "%s%s", QCSAPI_CUSTOM_DIR, custom_key);
		fd = fopen(filename, "r");
		if (fd) {
			if (read_to_eol(custom_value, sizeof(string_128) - 1, fd) == NULL)
				retval = -qcsapi_configuration_error;

			fclose(fd);
		} else {
			retval = -qcsapi_configuration_error;
		}
	}

	leave_qcsapi();

	return retval;
}

static int local_wifi_get_tdls_status(const int skfd, const char *ifname, uint32_t *p_tdls_status)
{
	int retval = 0;
	char setparam_code[QCSAPI_IOCTL_BUFSIZE];
	char *argv[] = {&setparam_code[0]};
	int  argc = sizeof(argv) / sizeof(argv[0]);
	__s32 tdls_status;
	uint32_t ioctl_cmd_value = 0;

	ioctl_cmd_value = IEEE80211_PARAM_TDLS_STATUS;
	snprintf(setparam_code, sizeof(setparam_code), "%u", ioctl_cmd_value);

	retval = call_private_ioctl(
		skfd,
		argv,
		argc,
		ifname,
		"getparam",
		(void *) &tdls_status,
		sizeof(__s32)
	);

	if (retval >= 0)
		*p_tdls_status = (uint32_t)tdls_status;

	return (retval);
}

int qcsapi_wifi_get_tdls_status(const char *ifname, uint32_t *p_tdls_status)
{
	int skfd = -1;
	int retval = 0;

	enter_qcsapi();

	if (p_tdls_status == NULL)
		retval = -EFAULT;

	if (retval >= 0) {
		retval = local_swfeat_check_supported(SWFEAT_ID_TDLS);
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
	}

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_station, NULL);

	if (retval >= 0)
		retval = local_wifi_get_tdls_status(skfd, ifname, p_tdls_status);

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return (retval);
}

static int tdls_type_search(qcsapi_tdls_type type, uint32_t *ioctl_cmd, int32_t *min, int32_t *max)
{
	int retval = 0;
	int found_entry = 0;
	unsigned int iter;

	for(iter = 0; iter < TABLE_SIZE(qcsapi_tdls_type_map_tbl); iter++) {
		if (qcsapi_tdls_type_map_tbl[iter].param_type == type) {
			*ioctl_cmd = qcsapi_tdls_type_map_tbl[iter].ioctl_cmd;
			*min = qcsapi_tdls_type_map_tbl[iter].min_value;
			*max = qcsapi_tdls_type_map_tbl[iter].max_value;
			found_entry = 1;
			break;
		}
	}

	if (found_entry)
		retval = 1;

	return retval;
}

static int tdls_param_value_check(qcsapi_tdls_type type, int param_value, int32_t min, int32_t max)
{
	if (type != qcsapi_tdls_discovery_interval) {
		if (param_value < min || param_value > max)
			return 0;
	} else {
		if ((param_value != 0) && (param_value < min || param_value > max))
			return 0;
	}

	return 1;
}

static int local_wifi_set_tdls_params(const int skfd, const char *ifname, uint32_t ioctl_cmd, int value)
{
	int retval = 0;
	char setparam_code[QCSAPI_IOCTL_BUFSIZE];
	char setparam_value[QCSAPI_IOCTL_BUFSIZE];
	char *argv[] = {&setparam_code[0], &setparam_value[0]};
	const int argc = sizeof(argv) / sizeof(argv[0]);

	snprintf(setparam_code, sizeof(setparam_code), "%u", ioctl_cmd);
	snprintf(setparam_value, sizeof(setparam_value), "%d", value);

	retval = call_private_ioctl(
			 skfd,
			 argv,
			 argc,
			 ifname,
			 "setparam",
			 NULL,
			 0
	);

	return (retval);
}

int qcsapi_wifi_set_tdls_params(const char *ifname, qcsapi_tdls_type type, int param_value)
{
	int skfd = -1;
	int retval;
	int32_t min_value = 0;
	int32_t max_value = 0;
	uint32_t ioctl_cmd = 0;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_TDLS);

	if (retval >= 0)
		retval = tdls_type_search(type, &ioctl_cmd, &min_value, &max_value);

	if(!retval)
		retval = -qcsapi_parameter_not_found;

	if(retval >= 0) {
		retval = tdls_param_value_check(type, param_value, min_value, max_value);
		if (!retval)
			retval = -qcsapi_param_value_invalid;
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
	}

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0)
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_station, NULL);

	if (retval >= 0)
		retval = local_wifi_set_tdls_params(skfd, ifname, ioctl_cmd, param_value);

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return (retval);
}

static int local_wifi_get_tdls_params(const int skfd, const char *ifname, uint32_t ioctl_cmd, int *p_value)
{
	int retval = 0;
	char setparam_code[QCSAPI_IOCTL_BUFSIZE];
	char *argv[] = {&setparam_code[0]};
	int  argc = sizeof(argv) / sizeof(argv[0]);
	int value;

	snprintf(setparam_code, sizeof(setparam_code), "%u", ioctl_cmd);

	retval = call_private_ioctl(
		skfd,
		argv,
		argc,
		ifname,
		"getparam",
		(void *) &value,
		sizeof(int)
	);

	if (retval >= 0)
		*p_value = value;

	return (retval);
}

int qcsapi_wifi_get_tdls_params(const char *ifname, qcsapi_tdls_type type, int *p_value)
{
	int skfd = -1;
	int retval = 0;
	int32_t min_value = 0;
	int32_t max_value = 0;
	uint32_t ioctl_cmd = 0;

	enter_qcsapi();

	if (p_value == NULL)
		retval = -EFAULT;

	if (retval >= 0) {
		retval = local_swfeat_check_supported(SWFEAT_ID_TDLS);
	}

	if (retval >= 0)
		retval = tdls_type_search(type, &ioctl_cmd, &min_value, &max_value);

	if(!retval)
		retval = -qcsapi_parameter_not_found;

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
	}

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_station, NULL);

	if (retval >= 0)
		retval = local_wifi_get_tdls_params(skfd, ifname, ioctl_cmd, p_value);

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_enable_tdls(const char *ifname, uint32_t enable_tdls)
{
	int skfd = -1;
	int retval = 0;
	char message[QCSAPI_WIFI_CMD_BUFSIZE] = {0};
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0)
		retval = -errno;

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
		if (retval >= 0) {
			if (wifi_mode != qcsapi_station)
				retval = -qcsapi_only_on_STA;
		}
	}

	if (retval >= 0) {
		if (!!enable_tdls)
			snprintf(message, sizeof(message), "SET tdls_disabled %u", 0);
		else
			snprintf(message, sizeof(message), "SET tdls_disabled %u", 1);

		retval = send_message_security_daemon(ifname,
				qcsapi_station,
				message,
				NULL,
				0);
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_enable_tdls_over_qhop(const char *ifname, uint32_t tdls_over_qhop_en)
{
	int skfd = -1;
	int retval = 0;
	char message[QCSAPI_WIFI_CMD_BUFSIZE] = {0};
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0)
		retval = -errno;

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
		if (retval >= 0) {
			if (wifi_mode != qcsapi_station)
				retval = -qcsapi_only_on_STA;
		}
	}

	if (retval >= 0) {
		snprintf(message, sizeof(message),
			"SET tdls_over_qhop_enabled %u", !!tdls_over_qhop_en);
		retval = send_message_security_daemon(ifname,
					qcsapi_station,
					message,
					NULL,
					0);

		if (retval >= 0)
			local_wifi_set_tdls_params(skfd, ifname, IEEE80211_PARAM_TDLS_OVER_QHOP_ENABLE,
					!!tdls_over_qhop_en);
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}


static int check_mac_addr_string(const char *mac_addr_str)
{
	unsigned int tmparray[MAC_ADDR_SIZE];
	int ival = 0;
	int iter;

	if ((mac_addr_str == NULL) || (strlen(mac_addr_str) != (MAC_ADDR_STRING_LENGTH - 1)))
		return -qcsapi_invalid_mac_addr;

	for (iter = 0; iter < strlen(mac_addr_str); iter++) {
		if ((mac_addr_str[iter] != ':') && (isxdigit(mac_addr_str[iter]) == 0)) {
			return -qcsapi_invalid_mac_addr;
		}
	}

	ival = sscanf(
		   mac_addr_str,
		   "%2x:%2x:%2x:%2x:%2x:%2x",
		   &tmparray[0],
		   &tmparray[1],
		   &tmparray[2],
		   &tmparray[3],
		   &tmparray[4],
		   &tmparray[5]
	);

	if (ival != MAC_ADDR_SIZE)
		return -qcsapi_invalid_mac_addr;

	return 0;
}

static const char* tdls_oper_search(qcsapi_tdls_oper operate)
{
	unsigned int iter;
	const char *oper_descrpt = NULL;

	for(iter = 0; iter < TABLE_SIZE(qcsapi_tdls_oper_map_tbl); iter++) {
		if (qcsapi_tdls_oper_map_tbl[iter].oper == operate) {
			oper_descrpt = qcsapi_tdls_oper_map_tbl[iter].oper_descrpt;
			break;
		}
	}

	return oper_descrpt;
}

int qcsapi_wifi_tdls_operate(const char *ifname, qcsapi_tdls_oper operate,
		const char *mac_addr_str, int cs_interval)
{
	int skfd = -1;
	int retval = 0;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	const char *oper_descrpt = NULL;
	char cmd_str[QCSAPI_CMD_BUFSIZE] = {0};

	enter_qcsapi();

	retval = check_mac_addr_string(mac_addr_str);

	if (retval < 0)
		retval = -qcsapi_param_value_invalid;

	if (retval >= 0) {
		if ((operate == qcsapi_tdls_oper_switch_chan) &&
				(cs_interval < IEEE80211_TDLS_CHAN_SWITCH_INTV_MIN) &&
					(cs_interval != 0))
			retval = -qcsapi_param_value_invalid;
	}

	if (retval >= 0) {
		oper_descrpt = tdls_oper_search(operate);

		if (oper_descrpt == NULL)
			retval = -qcsapi_parameter_not_found;
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
			retval = -errno;
	}

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
		if (retval >= 0) {
			if (wifi_mode != qcsapi_station)
				retval = -qcsapi_only_on_STA;
		}
	}

	if (operate == qcsapi_tdls_oper_switch_chan)
		snprintf(cmd_str, sizeof(cmd_str) - 1, "%s%s %d", oper_descrpt, mac_addr_str, cs_interval);
	else
		snprintf(cmd_str, sizeof(cmd_str) - 1, "%s%s", oper_descrpt, mac_addr_str);
	cmd_str[sizeof(cmd_str) - 1] = '\0';

	if (retval >= 0) {
		retval = send_message_security_daemon(
				 ifname,
				 qcsapi_station,
				 cmd_str,
				 NULL,
				 0);
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

static int qcsapi_wifi_set_mac_address_reserve_(const char *ifname, const char *addr,
						const char *mask)
{
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE] = {0};
	int retval = 0;
	int skfd = -1;
	string_16 buf = "";
	qcsapi_mac_addr mac_addr;

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0)
		return retval;

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		return retval;

	retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	local_close_iw_sockets(skfd);
	if (retval < 0)
		return retval;

	retval = parse_mac_addr(addr, mac_addr);
	if (retval < 0)
		return retval;

	if (IEEE80211_ADDR_NULL(mac_addr) || IEEE80211_IS_MULTICAST(mac_addr))
		return -qcsapi_invalid_mac_addr;

	if (mask[0] != '\0') {
		retval = parse_mac_addr(mask, mac_addr);
		if (retval < 0)
			return retval;
		if (IEEE80211_ADDR_NULL(mac_addr))
			return -qcsapi_invalid_mac_addr;
	}

	snprintf(cmd, sizeof(cmd) - 1, "get 0 mac_reserve full");
	retval = local_wifi_write_to_qdrv(cmd);
	if (retval < 0)
		return retval;

	retval = local_read_string_from_file(QDRV_RESULTS, buf, sizeof(buf));
	if (retval < 0)
		return retval;
	if (atoi(buf) == 1)
		return -qcsapi_param_count_exceeded;

	snprintf(cmd, sizeof(cmd), "set mac_reserve %s %s", addr, mask);
	return local_wifi_write_to_qdrv(cmd);
}

int qcsapi_wifi_set_mac_address_reserve(const char *ifname, const char *addr, const char *mask)
{
	int retval = 0;

	enter_qcsapi();

	retval = qcsapi_wifi_set_mac_address_reserve_(ifname, addr, mask);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_mac_address_reserve(const char *ifname, string_256 buf)
{
	char *bufp = buf;
	size_t got;
	int retval;
	int skfd;
	FILE *fd;
	int buflen = sizeof(string_256) - 1;

	enter_qcsapi();

	retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0)
		retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
		local_close_iw_sockets(skfd);
	}

	if (retval >= 0)
		retval = local_wifi_write_to_qdrv("get 0 mac_reserve list");

	if (retval >= 0) {
		fd = fopen(QDRV_RESULTS, "r");
		if (!fd) {
			retval = -errno;
		} else {
			while (fgets(bufp, buflen, fd) != NULL) {
				got = strlen(bufp);
				bufp += got;
				buflen -= got;
			}
			fclose(fd);
		}
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_clear_mac_address_reserve(const char *ifname)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0)
		retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
		local_close_iw_sockets(skfd);
	}

	if (retval >= 0)
		retval = local_wifi_write_to_qdrv("set mac_reserve");

	leave_qcsapi();

	return retval;
}

static int local_qcsapi_wifi_get_mlme_stats_per_mac(struct mlme_stats_record *stats_record)
{
	int retval = 0;
	int wstats_fd = -1;

	if ((wstats_fd = open(MLME_STATS_DEVICE, O_RDONLY)) < 0) {
		retval = -qcsapi_mlme_stats_not_supported;
	}

	if (retval >= 0) {
		retval = ioctl(wstats_fd, MLME_STATS_IOC_GET_CLIENT_STATS, stats_record);
		close(wstats_fd);
	}

	return retval;
}
int qcsapi_wifi_get_mlme_stats_per_mac(const qcsapi_mac_addr client_mac_addr, qcsapi_mlme_stats *stats)
{
	int retval = 0;
	struct mlme_stats_record stats_record;

	enter_qcsapi();

	memcpy(stats_record.mac_addr, client_mac_addr, IEEE80211_ADDR_LEN);
	retval = local_qcsapi_wifi_get_mlme_stats_per_mac(&stats_record);
	if (retval >= 0) {
		memcpy(stats, &stats_record.auth, MLME_STAT_MAX * sizeof(unsigned int));
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_mlme_stats_per_association(const char *ifname, const qcsapi_unsigned_int association_index, qcsapi_mlme_stats *stats)
{
	int retval = 0;
	struct mlme_stats_record stats_record;
	qcsapi_mac_addr the_mac_addr;
	int skfd = -1;

	if (ifname == NULL) {
		return -EFAULT;
	}

	enter_qcsapi();

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	}
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	if (retval >= 0) {
		retval = local_association_get_item(ifname, association_index, MAC_ADDR_ASSOCIATION, the_mac_addr);
	}

	if (retval >= 0) {
		memcpy(stats_record.mac_addr, the_mac_addr, IEEE80211_ADDR_LEN);
		retval = local_qcsapi_wifi_get_mlme_stats_per_mac(&stats_record);
	}
	if (retval >= 0) {
		memcpy(stats, &stats_record.auth, MLME_STAT_MAX * sizeof(unsigned int));
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_mlme_stats_macs_list(qcsapi_mlme_stats_macs *macs_list)
{
	int retval = 0;
	int wstats_fd = -1;
	unsigned int max_clients;

	enter_qcsapi();

	if ((wstats_fd = open(MLME_STATS_DEVICE, O_RDONLY)) < 0) {
		retval = -qcsapi_mlme_stats_not_supported;
	}

	if (retval >= 0) {
		retval = ioctl(wstats_fd, MLME_STATS_IOC_GET_MAX_CLIENTS, &max_clients);
	}

	if (retval >= 0 && max_clients != QCSAPI_MLME_STATS_MAX_MACS) {
		retval = -ENOMEM;
	}

	if(retval >= 0) {
		retval = ioctl(wstats_fd, MLME_STATS_IOC_GET_ALL_MACS, &macs_list->addr);
	}

	if(wstats_fd >= 0) {
		close(wstats_fd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_set_nss_cap(const char *ifname, const qcsapi_mimo_type modulation,
			const qcsapi_unsigned_int nss)
{
	int retval;
	int skfd;
	const char *param_name = (modulation == qcsapi_mimo_ht) ? "set_ht_nss_cap" :
									"set_vht_nss_cap";

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	retval = skfd;

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_wifi_set_private_int_param_by_name(skfd, ifname, param_name, nss);

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_nss_cap(const char *ifname, const qcsapi_mimo_type modulation,
			qcsapi_unsigned_int *nss)
{
	int retval;
	int skfd;
	const char *param_name = (modulation == qcsapi_mimo_ht) ? "get_ht_nss_cap" :
									"get_vht_nss_cap";
	int ret_nss;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	retval = skfd;

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0) {
		retval = local_wifi_get_private_int_param_by_name(skfd, ifname, param_name,
									&ret_nss);
		*nss = (qcsapi_unsigned_int)ret_nss;
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;

}

int
qcsapi_wifi_set_security_defer_mode(const char *ifname, int defer)
{
	int retval = 0;
	enter_qcsapi();

	retval = local_verify_interface_is_primary(ifname);
	if (retval >= 0)
		retval = local_wifi_set_security_defer_mode(defer);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_security_defer_mode(const char *ifname, int *defer)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_verify_interface_is_primary(ifname);
	if (retval >= 0)
		*defer = local_wifi_get_security_defer_mode();

	leave_qcsapi();

	return retval;
}

static int
local_wifi_wowlan_set_iwpriv( const int skfd, const char *ifname, uint32_t param_value )
{
	int retval = 0;
	char setparam_value[12];
	char param_id[6];
	char *argv[] = {param_id,  &setparam_value[0]};
	const int argc = ARRAY_SIZE(argv);

	sprintf(param_id, "%d", IEEE80211_PARAM_WOWLAN);
	snprintf(&setparam_value[0], sizeof(setparam_value), "0x%x", param_value);
	retval = call_private_ioctl(
	  skfd,
	  argv, argc,
	  ifname,
	 "setparam",
	  NULL,
	  0
	);

	return( retval );
}

static int
local_wowlan_ioctl(int skfd, const char *ifname, uint32_t op, void *data, uint32_t *len)
{
	struct iwreq iwr;
	struct ieee80211req_wowlan req;
	int ret;

	memset(&req, 0x0, sizeof(req));
	req.is_op = op;
	req.is_data = data;
	req.is_data_len = *len;

	memset(&iwr, 0, sizeof(iwr));
	strcpy(iwr.ifr_name, ifname);
	iwr.u.data.flags = SIOCDEV_SUBIO_WOWLAN;
	iwr.u.data.pointer = &req;
	iwr.u.data.length = sizeof(req);

	ret = ioctl(skfd, IEEE80211_IOCTL_EXT, &iwr);
	if (ret >= 0 && op != IEEE80211_WOWLAN_MAGIC_PATTERN) {
		*len = req.is_data_len;
	}

	return ret;
}
int qcsapi_set_host_state( const char *ifname, const uint32_t host_state)
{
	int retval = 0;
	int skfd = -1;
	uint16_t cmd_type;
	uint16_t cmd_value;
	uint32_t wowlan_value;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device( skfd, ifname, NULL, 0 );
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_WOWLAN_HOST_POWER_SAVE;
		cmd_value = (uint16_t)host_state;
		wowlan_value = cmd_type << 16 | cmd_value;
		retval = local_wifi_wowlan_set_iwpriv(skfd, ifname, wowlan_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wowlan_set_match_type( const char *ifname, const uint32_t wowlan_match)
{
	int retval = 0;
	int skfd = -1;
	uint16_t cmd_type;
	uint16_t cmd_value;
	uint32_t wowlan_value;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device( skfd, ifname, NULL, 0 );
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_WOWLAN_MATCH_TYPE;
		cmd_value = (uint16_t)wowlan_match;
		wowlan_value = cmd_type << 16 | cmd_value;
		retval = local_wifi_wowlan_set_iwpriv(skfd, ifname, wowlan_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return (retval);
}
int qcsapi_wowlan_set_L2_type( const char *ifname, const uint32_t ether_type)
{
	int retval = 0;
	int skfd = -1;
	uint16_t cmd_type;
	uint16_t cmd_value;
	uint32_t wowlan_value;

	if (ether_type >= (2 << 16))
		return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device( skfd, ifname, NULL, 0 );
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_WOWLAN_L2_ETHER_TYPE;
		cmd_value = (uint16_t)ether_type;
		wowlan_value = cmd_type << 16 | cmd_value;
		retval = local_wifi_wowlan_set_iwpriv(skfd, ifname, wowlan_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wowlan_set_udp_port(const char *ifname, const uint32_t udp_port)
{
	int retval = 0;
	int skfd = -1;
	uint16_t cmd_type;
	uint16_t cmd_value;
	uint32_t wowlan_value;

	if (udp_port >= (2 << 16))
		return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device( skfd, ifname, NULL, 0 );
	}

	if (retval >= 0) {
		cmd_type = IEEE80211_WOWLAN_L3_UDP_PORT;
		cmd_value = (uint16_t)udp_port;
		wowlan_value = cmd_type << 16 | cmd_value;
		retval = local_wifi_wowlan_set_iwpriv(skfd, ifname, wowlan_value);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wowlan_set_magic_pattern(const char *ifname,
			struct qcsapi_data_256bytes *pattern,
			uint32_t len)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || pattern  == NULL)
	      retval = -EINVAL;

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = verify_we_device( skfd, ifname, NULL, 0 );
	}

	if (retval >= 0) {
		local_wowlan_ioctl(skfd, ifname, IEEE80211_WOWLAN_MAGIC_PATTERN, pattern->data, &len);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_wowlan_param_get(const char *ifname, uint32_t cmd, void *p_value, uint32_t *len)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (!ifname || !p_value || !len)
	      retval = -EINVAL;

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
	}

	if (retval >= 0) {
		retval = local_wowlan_ioctl(skfd, ifname, cmd, p_value, len);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wifi_wowlan_get_host_state(const char *ifname, uint16_t *p_value, uint32_t *len)
{
	return qcsapi_wifi_wowlan_param_get(ifname, IEEE80211_WOWLAN_HOST_POWER_SAVE, p_value, len);
}

int qcsapi_wifi_wowlan_get_match_type(const char *ifname, uint16_t *p_value, uint32_t *len)
{
	return qcsapi_wifi_wowlan_param_get(ifname, IEEE80211_WOWLAN_MATCH_TYPE, p_value, len);
}

int qcsapi_wifi_wowlan_get_l2_type(const char *ifname, uint16_t *p_value, uint32_t *len)
{
	return qcsapi_wifi_wowlan_param_get(ifname, IEEE80211_WOWLAN_L2_ETHER_TYPE, p_value, len);
}

int qcsapi_wifi_wowlan_get_udp_port(const char *ifname, uint16_t *p_value, uint32_t *len)
{
	return qcsapi_wifi_wowlan_param_get(ifname, IEEE80211_WOWLAN_L3_UDP_PORT, p_value, len);
}

int qcsapi_wifi_wowlan_get_magic_pattern(const char *ifname, struct qcsapi_data_256bytes *p_value, uint32_t *len)
{
	return qcsapi_wifi_wowlan_param_get(ifname, IEEE80211_WOWLAN_MAGIC_PATTERN_GET, p_value, len);
}

static int extender_type_search(qcsapi_extender_type type, uint32_t *ioctl_cmd, int32_t *min, int32_t *max)
{
	int retval = 0;
	int found_entry = 0;
	unsigned int iter;

	for (iter = 0; iter < ARRAY_SIZE(qcsapi_extender_type_map_tbl); iter++) {
		if (qcsapi_extender_type_map_tbl[iter].param_type == type) {
			*ioctl_cmd = qcsapi_extender_type_map_tbl[iter].ioctl_cmd;
			*min = qcsapi_extender_type_map_tbl[iter].min_value;
			*max = qcsapi_extender_type_map_tbl[iter].max_value;
			found_entry = 1;
			break;
		}
	}

	if (found_entry)
		retval = 1;

	return retval;
}

static inline int extender_param_value_check(int param_value, int32_t min,
	int32_t max)
{
	return ((param_value >= min) && (param_value <= max));
}

static int extender_verify_wifi_mode(
	int skfd,
	const char *ifname,
	qcsapi_extender_type type,
	int param_value
)
{
	int retval = 0;

	if ((type == qcsapi_extender_role) && (param_value == IEEE80211_EXTENDER_ROLE_MBS))
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	return retval;
}

static int local_wifi_set_extender_params(const int skfd, const char *ifname,
	uint32_t ioctl_cmd, int value)
{
	int retval = 0;
	char setparam_code[QCSAPI_IOCTL_BUFSIZE];
	char setparam_value[QCSAPI_IOCTL_BUFSIZE];
	char *argv[] = {setparam_code, setparam_value};
	const int argc = ARRAY_SIZE(argv);

	snprintf(setparam_code, sizeof(setparam_code), "%u", ioctl_cmd);
	snprintf(setparam_value, sizeof(setparam_value), "%d", value);

	retval = call_private_ioctl(
			 skfd,
			 argv,
			 argc,
			 ifname,
			 "setparam",
			 NULL,
			 0
	);

	return (retval);
}

int qcsapi_wifi_set_extender_params(const char *ifname, const qcsapi_extender_type type,
	const int param_value)
{
	int skfd = -1;
	int retval = 0;
	int32_t min_value = 0;
	int32_t max_value = 0;
	uint32_t ioctl_cmd = 0;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_QHOP);

	if (retval < 0)
		goto ready_to_return;

	retval = extender_type_search(type, &ioctl_cmd, &min_value, &max_value);

	if (!retval) {
		retval = -qcsapi_parameter_not_found;
		goto ready_to_return;
	}

	if (retval >= 0) {
		retval = extender_param_value_check(param_value, min_value,
			max_value);
		if (!retval) {
			retval = -qcsapi_param_value_invalid;
			goto ready_to_return;
		}
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			goto ready_to_return;
		}
	}

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0)
		retval = extender_verify_wifi_mode(skfd, ifname, type, param_value);

	if (retval >= 0)
		retval = local_wifi_set_extender_params(skfd, ifname, ioctl_cmd,
			param_value);

ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return (retval);
}

static int local_wifi_get_extender_params(const int skfd, const char *ifname,
	uint32_t ioctl_cmd, int *p_value)
{
	int retval = 0;
	char setparam_code[QCSAPI_IOCTL_BUFSIZE];
	char *argv[] = {setparam_code};
	int  argc = sizeof(argv) / sizeof(argv[0]);
	int value;

	snprintf(setparam_code, sizeof(setparam_code), "%u", ioctl_cmd);

	retval = call_private_ioctl(
		skfd,
		argv,
		argc,
		ifname,
		"getparam",
		(void *) &value,
		sizeof(int)
	);

	if (retval >= 0)
		*p_value = value;

	return (retval);
}

int qcsapi_wifi_get_extender_params(const char *ifname, const qcsapi_extender_type type,
	int *p_value)
{
	int skfd = -1;
	int retval = 0;
	int32_t min_value = 0;
	int32_t max_value = 0;
	uint32_t ioctl_cmd = 0;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_QHOP);

	if (retval < 0)
		goto ready_to_return;

	if (p_value == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = extender_type_search(type, &ioctl_cmd, &min_value, &max_value);

	if (!retval) {
		retval = -qcsapi_parameter_not_found;
		goto ready_to_return;
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			goto ready_to_return;
		}
	}

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);

	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0)
		retval = local_wifi_get_extender_params(skfd, ifname, ioctl_cmd,
			p_value);

ready_to_return:

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return (retval);
}

int
qcsapi_wifi_enable_bgscan(const char *ifname, const int enable)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = verify_we_device( skfd, ifname, NULL, 0 );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		int	ival;

		ival = local_wifi_set_private_int_param_by_name( skfd, ifname, "bgscan", enable );
		if (ival < 0)
			retval = ival;
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return (retval);
}

int
qcsapi_wifi_get_bgscan_status(const char *ifname, int *enable)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || enable == NULL)
		retval = -EFAULT;
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_private_int_param_by_name( skfd, ifname, "get_bgscan", enable);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd);
	}

	leave_qcsapi();

	return (retval);
}

int
qcsapi_wifi_get_disassoc_reason( const char *ifname, qcsapi_unsigned_int *reason)
{
        int retval = 0;
        int skfd = -1;

        enter_qcsapi();

        if (ifname == NULL || reason == NULL) {
          retval = -EFAULT;
	}
        else {
                *reason = 0;
                 skfd = local_open_iw_sockets();
                 if (skfd < 0) {
                 	retval = -errno;
                        if (retval >= 0){
                        retval = skfd;
			}
                }
        }

        if (retval >= 0) {
                retval = local_wifi_option_get_disassoc_reason( skfd, ifname, reason);
        }

        if (skfd >= 0) {
                local_close_iw_sockets( skfd);
        }

        leave_qcsapi();

        return (retval);

}

int
qcsapi_wifi_get_tx_amsdu(const char *ifname, int *enable)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if ((ifname == NULL) || (enable == NULL)) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0)
		retval = local_wifi_get_private_int_param_by_name(skfd, ifname,
				"get_vap_txamsdu", enable);

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_set_tx_amsdu(const char *ifname, int enable)
{
	int retval = 0;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0)
		retval = verify_we_device(skfd, ifname, NULL, 0);
	if (retval >= 0)
		retval = local_verify_interface_is_primary(ifname);

	if (retval >= 0)
		retval = local_wifi_set_private_int_param_by_name(skfd, ifname,
				"vap_txamsdu", (enable == 0 ? 0 : 1));

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_vendor_per_association(const char *ifname,
	const qcsapi_unsigned_int association_index,
	qcsapi_unsigned_int *p_vendor)
{
	int		retval = 0;
	qcsapi_mac_addr	macaddr;
	struct		iwreq iwr;
	int		skfd = -1;

	if (ifname == NULL || p_vendor == NULL) {
		return -EFAULT;
	}

	enter_qcsapi();

	memset(macaddr, 0x00, sizeof(macaddr));
	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name) - 1);
	iwr.u.data.flags = SIOCDEV_SUBIO_GET_STA_VENDOR;
	iwr.u.data.pointer = macaddr;
	iwr.u.data.length = sizeof(macaddr);

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	}

	if (retval >= 0) {
		retval = local_association_get_item(ifname, association_index, MAC_ADDR_ASSOCIATION, macaddr);
	}

	if (retval >= 0) {
		retval = ioctl(skfd, IEEE80211_IOCTL_EXT, &iwr);
	}

	*p_vendor = macaddr[0];

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_max_mimo(const char *ifname,
	const qcsapi_unsigned_int association_index,
	string_16 p_max_mimo)
{
	int retval = 0;
	int skfd = -1;
	struct ieee8011req_sta_tput_caps tput_caps;
	struct ieee80211_ie_htcap *htcap = (struct ieee80211_ie_htcap *)tput_caps.htcap_ie;
	struct ieee80211_ie_vhtcap *vhtcap = (struct ieee80211_ie_vhtcap *)tput_caps.vhtcap_ie;
	uint16_t vht_mcsmap;
	uint8_t rx_max = 1;
	uint8_t tx_max = 1;

	if (ifname == NULL || p_max_mimo == NULL) {
		return -EFAULT;
	}

	enter_qcsapi();

	memset(&tput_caps, 0, sizeof(tput_caps));

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval >= 0) {
		retval = local_verify_wifi_mode(skfd, ifname, qcsapi_access_point, NULL);
	}

	if (retval >= 0) {
		retval = local_association_get_item(ifname, association_index,
				MAC_ADDR_ASSOCIATION, tput_caps.macaddr);
	}

	if (retval >= 0) {
		retval = local_wifi_sub_ioctl_submit(ifname, SIOCDEV_SUBIO_GET_STA_TPUT_CAPS,
				(void *)&tput_caps, sizeof(tput_caps));
	}

	if (retval >= 0) {
		switch (tput_caps.mode) {
		case IEEE80211_WIFI_MODE_AC:
			vht_mcsmap = IEEE80211_VHTCAP_GET_RX_MCS_NSS(vhtcap);
			for (rx_max = 0; rx_max < IEEE80211_VHTCAP_MCS_MAX; ++rx_max) {
				if (IEEE80211_VHTCAP_GET_MCS_MAP_ENTRY(vht_mcsmap,
						rx_max) == IEEE80211_VHTCAP_MCS_DISABLED)
					break;
			}
			vht_mcsmap = IEEE80211_VHTCAP_GET_TX_MCS_NSS(vhtcap);
			for (tx_max = 0; tx_max < IEEE80211_VHTCAP_MCS_MAX; ++tx_max) {
				if (IEEE80211_VHTCAP_GET_MCS_MAP_ENTRY(vht_mcsmap,
						tx_max) == IEEE80211_VHTCAP_MCS_DISABLED)
					break;
			}
			break;
		case IEEE80211_WIFI_MODE_NA:
		case IEEE80211_WIFI_MODE_NG:
			if (IEEE80211_HT_IS_4SS_NODE(htcap->hc_mcsset)) {
				rx_max = 4;
			} else if (IEEE80211_HT_IS_3SS_NODE(htcap->hc_mcsset)) {
				rx_max = 3;
			} else if (IEEE80211_HT_IS_2SS_NODE(htcap->hc_mcsset)) {
				rx_max = 2;
			}
			if ((IEEE80211_HTCAP_MCS_PARAMS(htcap) &
					IEEE80211_HTCAP_MCS_TX_SET_DEFINED) &&
					(IEEE80211_HTCAP_MCS_PARAMS(htcap) &
					IEEE80211_HTCAP_MCS_TX_RX_SET_NEQ)) {
				tx_max = IEEE80211_HTCAP_MCS_STREAMS(htcap) + 1;
			} else if (IEEE80211_HTCAP_MCS_PARAMS(htcap) &
					IEEE80211_HTCAP_MCS_TX_RX_SET_NEQ) {
				tx_max = 0;
			} else {
				tx_max = rx_max;
			}
			break;
		default:
			break;
		}
		if (rx_max == 0 || tx_max == 0) {
			strcpy(p_max_mimo, "unknown");
		} else {
			snprintf(p_max_mimo, sizeof(string_16) - 1, "Rx:%u Tx:%u",
				 rx_max, tx_max);
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

static int
local_wifi_get_bb_param ( const int skfd, const char *ifname, qcsapi_unsigned_int *bb_param)
{
        int     retval = 0;
        char     getparam_index[ 4 ];
        char    *argv[] = { &getparam_index[0] };
        int      argc = sizeof( argv ) / sizeof( argv[ 0 ] );
        __s32   param;

        snprintf(&getparam_index[0], sizeof(getparam_index), "%d", IEEE80211_PARAM_BB_PARAM);
        retval = call_private_ioctl(
          skfd,
          argv, argc,
          ifname,
          "getparam",
          (void *) &param,
          sizeof( __s32 )
        );

        if (retval >= 0) {
                *bb_param = param;
        }

        return( retval );
}


static int
local_wifi_set_bb_param ( const int skfd, const char *ifname, const qcsapi_unsigned_int bb_param)
{
        int              retval = 0;
        char             setparam_index[ 4 ], setparam_value[ 4 ];
        char            *argv[] = { &setparam_index[ 0 ],  &setparam_value[ 0 ] };
        const int        argc = sizeof( argv ) / sizeof( argv[ 0 ] );

        snprintf(&setparam_index[0], sizeof(setparam_index), "%d", IEEE80211_PARAM_BB_PARAM);
        snprintf(&setparam_value[0], sizeof(setparam_value), "%d", bb_param);

        retval = call_private_ioctl(
          skfd,
          argv, argc,
          ifname,
         "setparam",
          NULL,
          0
        );

        return retval;
}

int
qcsapi_wifi_get_bb_param(const char *ifname, qcsapi_unsigned_int *bb_param)
{
        int skfd = -1;
        int retval = 0;

        enter_qcsapi();

        skfd = local_open_iw_sockets();
        if (skfd < 0)
        {
                retval = -errno;
                if (retval >= 0)
                        retval = skfd;
        }

        if (retval >= 0)
                retval = verify_we_device(skfd, ifname, NULL, 0);

        if (retval >= 0)
                retval = local_verify_interface_is_primary(ifname);

        if (retval >= 0) {
                retval = local_wifi_get_bb_param(skfd, ifname, bb_param);
        }

        if (skfd >= 0)
                local_close_iw_sockets(skfd);

        leave_qcsapi();

        return retval;
}

int
qcsapi_wifi_set_bb_param(const char *ifname, const qcsapi_unsigned_int bb_param)
{
        int             retval = 0;
        int             skfd = -1;

        enter_qcsapi();
        skfd = local_open_iw_sockets();
        if (skfd < 0) {
                retval = -errno;
                if (retval >= 0)
                        retval = skfd;
        }

        if (retval >= 0) {
                retval = verify_we_device(skfd, ifname, NULL, 0);
        }
        if (retval >= 0) {
                retval = local_verify_interface_is_primary(ifname);
        }

        if (retval >= 0) {
                retval = local_wifi_set_bb_param(skfd, ifname, bb_param);
        }

        if (skfd >= 0)
                local_close_iw_sockets( skfd );

        leave_qcsapi();
        return retval;
}

static int
local_wifi_set_optim_stats ( const int skfd, const char *ifname, const qcsapi_unsigned_int rx_optim_stats)
{
        int              retval = 0;
        char             setparam_index[ 4 ], setparam_value[ 4 ];
        char            *argv[] = { &setparam_index[ 0 ],  &setparam_value[ 0 ] };
        const int        argc = sizeof( argv ) / sizeof( argv[ 0 ] );

        snprintf(&setparam_index[0], sizeof(setparam_index), "%d", IEEE80211_PARAM_ENABLE_RX_OPTIM_STATS);
        snprintf(&setparam_value[0], sizeof(setparam_value), "%d", rx_optim_stats);

        retval = call_private_ioctl(
          skfd,
          argv, argc,
          ifname,
         "setparam",
          NULL,
          0
        );

        return retval;
}

int
qcsapi_wifi_set_optim_stats(const char *ifname, const qcsapi_unsigned_int rx_optim_stats)
{
        int             retval = 0;
        int             skfd = -1;

        enter_qcsapi();
        skfd = local_open_iw_sockets();
        if (skfd < 0) {
                retval = -errno;
                if (retval >= 0)
                        retval = skfd;
        }

        if (retval >= 0) {
                retval = verify_we_device(skfd, ifname, NULL, 0);
        }
        if (retval >= 0) {
                retval = local_verify_interface_is_primary(ifname);
        }

        if (retval >= 0) {
                retval = local_wifi_set_optim_stats(skfd, ifname, rx_optim_stats);
        }

        if (skfd >= 0)
                local_close_iw_sockets( skfd );

        leave_qcsapi();
        return retval;
}

int
qcsapi_wifi_set_sys_time(const uint32_t timestamp)
{
	struct timeval systime;
	int ret;

	if (timestamp == 0 || timestamp == UINT32_MAX)
		return -EINVAL;

	enter_qcsapi();

	systime.tv_sec = timestamp;
	systime.tv_usec = 0;

	ret = settimeofday(&systime, NULL);
	if (ret != 0)
		ret = -errno;

	leave_qcsapi();

	return ret;
}

int
qcsapi_wifi_get_sys_time(uint32_t *timestamp)
{
	struct timeval systime;
	int ret;

	enter_qcsapi();

	ret = gettimeofday(&systime, NULL);
	if (ret == 0) {
		*timestamp = systime.tv_sec;
	} else {
		ret = -errno;
	}

	leave_qcsapi();

	return ret;
}

static int parse_ecmd(const qcsapi_eth_info_type eth_info_type, struct ethtool_cmd *ep)
{
	int retval = qcsapi_eth_info_unknown;

	switch (eth_info_type) {
	case qcsapi_eth_info_speed:
		if (ethtool_cmd_speed(ep) == 10000)
			retval |= qcsapi_eth_info_speed_10000M;
		else if (ethtool_cmd_speed(ep) == 1000)
			retval |= qcsapi_eth_info_speed_1000M;
		else if (ethtool_cmd_speed(ep) == 100)
			retval |= qcsapi_eth_info_speed_100M;
		else if (ethtool_cmd_speed(ep) == 10)
			retval |= qcsapi_eth_info_speed_10M;
		else
			retval |= qcsapi_eth_info_speed_unknown;
		break;
	case qcsapi_eth_info_duplex:
		if (ep->duplex == DUPLEX_FULL)
			retval |= qcsapi_eth_info_duplex_full;
		break;
	case qcsapi_eth_info_autoneg:
		if (ep->autoneg == AUTONEG_ENABLE)
			retval |= qcsapi_eth_info_autoneg_on;
		break;
	default:
		break;
	}

	return retval;
}

static inline struct mii_ioctl_data *if_mii(struct ifreq *rq)
{
	return (struct mii_ioctl_data *) &rq->ifr_ifru;
}

int local_eth_phy_read(int sock, const char *ifname, int regnum, int *val_out)
{
	int			retval = 0;
	struct ifreq		ifr;
	struct mii_ioctl_data	*mii = if_mii(&ifr);

	memset(&ifr, 0, sizeof(ifr));
	mii->reg_num = regnum;
	retval = local_priv_netdev_ioctl(sock, ifname, SIOCGMIIREG, &ifr);
	if (retval >= 0)
		*val_out = mii->val_out;

	return retval;
}

static int local_eth_get_autoneg_status(int skfd, const char *ifname)
{
	int			retval = 0;
	int			val_out = 0;
	struct ifreq		ifr;
	struct ethtool_cmd	ecmd = {0};

	ecmd.cmd = ETHTOOL_GSET;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_data = (void*)&ecmd;
	retval = local_priv_netdev_ioctl(skfd, ifname, SIOCETHTOOL, &ifr);
	if (retval >= 0)
		retval = parse_ecmd(qcsapi_eth_info_autoneg, &ecmd);
	if (retval & qcsapi_eth_info_autoneg_on) {
		retval = local_eth_phy_read(skfd, ifname, MII_BMSR, &val_out);
		if (val_out < 0) {
			retval = val_out;
		} else {
			retval = qcsapi_eth_info_autoneg_on;
			if (val_out & BMSR_ANEGCOMPLETE)
				retval |= qcsapi_eth_info_autoneg_success;
		}
	}

	return retval;
}

int
qcsapi_get_eth_info(const char *ifname, const qcsapi_eth_info_type eth_info_type)
{
	int retval = 0;
	int skfd = -1;
	struct ifreq ifr;
	struct ethtool_value edata = {0};
	struct ethtool_cmd ecmd = {0};
	qcsapi_interface_status_code status_code = qcsapi_interface_status_error;

	enter_qcsapi();
	retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0) {
		retval = local_interface_get_status(skfd, ifname, &status_code);
		if (retval >= 0) {
			if (status_code == qcsapi_interface_status_error)
				retval = -qcsapi_iface_error;
			else if (status_code == qcsapi_interface_status_disabled)
				retval = -qcsapi_bringup_mode_only;
		}
	}

	if (retval >= 0) {
		retval = local_check_ether_name(ifname);
		if (retval == -qcsapi_invalid_ifname)
			retval = -qcsapi_iface_invalid;
	}

	if (retval >= 0) {
		retval = verify_we_device(skfd, ifname, NULL, 0);
		if (retval >= 0)
			retval = -qcsapi_iface_invalid;
		else
			retval = 0;
	}

	if (retval >= 0) {
		switch (eth_info_type) {
		case qcsapi_eth_info_link:
			edata.cmd = ETHTOOL_GLINK;
			memset(&ifr, 0, sizeof(ifr));
			ifr.ifr_data = (void*)&edata;
			retval = local_priv_netdev_ioctl(skfd, ifname, SIOCETHTOOL, &ifr);
			if (retval >= 0 && edata.data)
				retval = qcsapi_eth_info_connected;
			break;
		case qcsapi_eth_info_speed:
		case qcsapi_eth_info_duplex:
			ecmd.cmd = ETHTOOL_GSET;
			memset(&ifr, 0, sizeof(ifr));
			ifr.ifr_data = (void*)&ecmd;
			retval = local_priv_netdev_ioctl(skfd, ifname, SIOCETHTOOL, &ifr);
			if (retval >= 0)
				retval = parse_ecmd(eth_info_type, &ecmd);
			break;
		case qcsapi_eth_info_autoneg:
			retval = local_eth_get_autoneg_status(skfd, ifname);
			break;
		default:
			retval = -EINVAL;
		}
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();
	return retval;
}
static int
local_wifi_block_bss( const int skfd, const char *ifname, const qcsapi_unsigned_int flag)
{
        int              retval = 0;
        char             setparam_index[ 4 ], setparam_value[ 4 ];
        char            *argv[] = { &setparam_index[ 0 ],  &setparam_value[ 0 ] };
        const int        argc = sizeof( argv ) / sizeof( argv[ 0 ] );

        snprintf(&setparam_index[0], sizeof(setparam_index), "%d", IEEE80211_PARAM_QTN_BLOCK_BSS);
        snprintf(&setparam_value[0], sizeof(setparam_value), "%d", flag);

        retval = call_private_ioctl(
          skfd,
          argv, argc,
          ifname,
         "setparam",
          NULL,
          0
        );

        return retval;
}

int
qcsapi_wifi_block_bss(const char *ifname, const qcsapi_unsigned_int flag)
{
        int             retval = 0;
        int             skfd = -1;

        enter_qcsapi();
        skfd = local_open_iw_sockets();
        if (skfd < 0) {
                retval = -errno;
                if (retval >= 0)
                        retval = skfd;
        }

        if (retval >= 0) {
                retval = verify_we_device(skfd, ifname, NULL, 0);
        }

        if (retval >= 0) {
                retval = local_wifi_block_bss(skfd, ifname, flag);
        }

        if (skfd >= 0)
                local_close_iw_sockets( skfd );

        leave_qcsapi();
        return retval;
}

int qcsapi_wifi_chan_control(const char *ifname, const struct qcsapi_data_256bytes *chans, const uint32_t cnt, const uint8_t flag)
{
	int	retval = 0;
	int	i, curr_chan;
	int	valid_chan_number = 0;
	int	skfd = -1;
	char	current_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION];
	qcsapi_chan_disabled_data chan_disable_data;

	if (!ifname || !chans || (cnt > QCSAPI_MAX_CHANNEL) || (local_interface_verify_net_device(ifname) < 0)) {
		return -EFAULT;
	}

	enter_qcsapi();

	for (i = 0; i < cnt; i++) {
		curr_chan = chans->data[i];
		if (is_in_list_5Ghz_channels(curr_chan))
			valid_chan_number++;
		else if (is_in_list_2_4Ghz_channels(curr_chan))
			valid_chan_number++;
	}

	if (valid_chan_number < cnt) {
		leave_qcsapi();
		return -EINVAL;
	}

	chan_disable_data.dir = SET_CHAN_DISABLED;
	chan_disable_data.flag = flag;
	chan_disable_data.list_len = cnt;
	memcpy(chan_disable_data.chan, chans->data, cnt);

	retval = local_wifi_sub_ioctl_submit(ifname,
				SIOCDEV_SUBIO_SETGET_CHAN_DISABLED,
				(void *)&chan_disable_data, sizeof(chan_disable_data));
	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_get_internal_regulatory_region(skfd, ifname, &current_region[0]);
	}

	if (retval >= 0 && strcmp(&current_region[0], "none")) {
		retval = local_regulatory_set_regulatory_region(ifname, current_region);

		if (retval == -qcsapi_region_database_not_found) {
			retval = local_wifi_set_regulatory_region(ifname, current_region);
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_get_chan_disabled(const char *ifname, struct qcsapi_data_256bytes *p_chans, uint8_t *p_cnt)
{
	int		retval = 0;
	qcsapi_chan_disabled_data chan_disable_data;

	enter_qcsapi();

	if (!ifname || !p_chans || !p_cnt) {
		retval = -EFAULT;
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		chan_disable_data.dir = GET_CHAN_DISABLED;
		chan_disable_data.flag = 0;
		chan_disable_data.list_len = 0;
		memset(chan_disable_data.chan, 0, sizeof(chan_disable_data.chan));
		retval = local_wifi_sub_ioctl_submit(ifname,
					SIOCDEV_SUBIO_SETGET_CHAN_DISABLED,
					(void *)&chan_disable_data, sizeof(chan_disable_data));
		if (retval >= 0) {
			*p_cnt = chan_disable_data.list_len;
			memcpy(p_chans->data, chan_disable_data.chan, chan_disable_data.list_len);
		}
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_verify_repeater_mode()
{
        int retval;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

        retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_verify_repeater_mode(skfd, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if (wifi_mode == qcsapi_repeater)
		retval = 1;

ready_to_return:
        if (skfd >= 0)
                local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_set_ap_interface_name(const char *ifname)
{
        int retval;

	enter_qcsapi();

	retval = local_check_bss_name(ifname);
	if (retval < 0)
		goto ready_to_return;

	retval = update_security_parameter(
				"",
				NULL,
				"interface",
				ifname,
				qcsapi_access_point,
				QCSAPI_TRUE,
				qcsapi_bare_string,
				security_update_pending
				);

ready_to_return:
	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_ap_interface_name(char *ifname)
{
        int retval;

	enter_qcsapi();

	retval = lookup_ap_security_parameter("",
				qcsapi_access_point,
				"interface",
				ifname,
				IFNAMSIZ);

	leave_qcsapi();

	return retval;
}

