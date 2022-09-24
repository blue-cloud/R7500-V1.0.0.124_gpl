/*SH1
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2011 Quantenna Communications Inc            **
**                                                                           **
**  File        : qcsapi_private.h                                           **
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
EH1*/

#ifndef _QCSAPI_PRIVATE_H
#define _QCSAPI_PRIVATE_H

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211.h>

#include "wireless.h"
#include "qcsapi_sem.h"

#define SCRATCHPAD_FOLDER	"/tmp"
#define QDRV_RESULTS		"/proc/qdrvdata"
#define QDRV_SYSFS_BASE		"/sys/devices/qdrv/"
#define QDRV_CONTROL		QDRV_SYSFS_BASE "control"
#define FWT_CONTROL		"/proc/topaz_fwt_if"
#define FWT_CONTROL_IPFF	"/proc/topaz_fwt_ipff"
#define QDRV_RSSI_PHY_STATS	QDRV_SYSFS_BASE "rssi_phy_stats"
#define PROC_NET_WIRELESS	"/proc/net/wireless"
#define MLME_STATS_DEVICE	"/dev/mlmestats"
#define PROC_TEMP_SENS		"/proc/temp_sens"

#define LOCAL_NULL_DEVICE		"/dev/null"
#define LOCAL_UPDATE_CONFIG_SCRIPT	"/scripts/update_wifi_config"
#define LOCAL_DEFER_CONFIG		"/tmp/defer"

#define QDRV_SCH_SYSFS_FILE		"/sys/devices/virtual/net/%s/qdrv_sch"

#define QTN_WE_VERSION			22

#define TMP_FILE_IS_STARTPROD_DONE	"/tmp/is_startprod_done"

/*
 * For selected get operations, the Q driver returns -1 as the reported value
 * if the system is not configured correctly.  Example is attempting to get
 * RSSIs when phy stats has been configured to report only errored sums.
 */
#define QDRV_REPORTS_CONFIG_ERR		-1
#define QDRV_AAGC_GAIN_DB_S		0
#define QDRV_AAGC_GAIN_DB_M		0xFF
#define QDRV_DACG_GAIN_S		8
#define QDRV_DACG_GAIN_M		0xFF00
#define QDRV_DACG_SHIFT_S		16
#define QDRV_DACG_SHIFT_M		0xFF0000

#define DEFAULT_DEFAULT_TX_POWER	19
#define DEFAULT_MIN_TX_POWER		9

#define COUNT_802_11_CHANNELS		256

#define NUM_RF_CHAINS			4

#define MAX_WDS_LINKS 8
#define MAX_BSSID 8

#define QCSAPI_WIFI_IWPRIV_SYSLOG_FACILITY	"WiFi Private IOCTL"


#define IS_UNICAST_MAC(a)       ( !((a)[0] & 0x1) )
#define MAX_MCS_LEN	6
#define QCSAPI_WIFI_CMD_BUFSIZE 128
#define QCSAPI_IOCTL_BUFSIZE    8

#ifndef IFNAMSIZ
#define IFNAMSIZ	16
#endif /* IFNAMSIZ */

/*
 * Calculate the percentage level for current transimit power of maximum transmit power
 * The input values must be dbm based.
 */
#define POWER_PERCENTAGE(cur, max)       round(pow(10, ((cur) - (max)) / 10.0) * 100)

/*
 * Value for SCAN_RESULT_SIZE_PER_AP was established empirically
 * based on work with iwlist wifi0 scan.
 */
#define  SCAN_RESULT_SIZE_PER_AP    600

#define IE_IS_VENDOR	0xdd
#define IE_IS_11i	0x30

/* Cypher values in GENIE (pairwise and group) */
#define IW_IE_CIPHER_NONE	0
#define IW_IE_CIPHER_WEP40	1
#define IW_IE_CIPHER_TKIP	2
#define IW_IE_CIPHER_WRAP	3
#define IW_IE_CIPHER_CCMP	4
#define IW_IE_CIPHER_WEP104	5
/* Key management in GENIE */
#define IW_IE_KEY_MGMT_NONE	0
#define IW_IE_KEY_MGMT_802_1X	1
#define IW_IE_KEY_MGMT_PSK	2

#define AP_SCAN_RESULTS_FILE	"ap_scan_results"

#define EXPECTED_QDRV_RESULT	"ok"

#define QCSAPI_MAX_PWM_COUNT		(256)
#define QCSAPI_MIN_PWM_COUNT		(1)

#define QCSAPI_MAX_BRIGHT_LEVEL		(10)
#define QCSAPI_MIN_BRIGHT_LEVEL		(1)

/* GPIO pins */
#define QCSAPI_GPIO_PIN0		(0)
#define QCSAPI_GPIO_PIN1		(1)
#define QCSAPI_GPIO_PIN2		(2)
#define QCSAPI_GPIO_PIN3		(3)
#define QCSAPI_GPIO_PIN4		(4)
#define QCSAPI_GPIO_PIN5		(5)
#define QCSAPI_GPIO_PIN6		(6)
#define QCSAPI_GPIO_PIN7		(7)
#define QCSAPI_GPIO_PIN8		(8)
#define QCSAPI_GPIO_PIN9		(9)
#define QCSAPI_GPIO_PIN10		(10)
#define QCSAPI_GPIO_PIN11		(11)
#define QCSAPI_GPIO_PIN12		(12)
#define QCSAPI_GPIO_PIN13		(13)
#define QCSAPI_GPIO_PIN14		(14)
#define QCSAPI_GPIO_PIN15		(15)
#define QCSAPI_GPIO_PIN16		(16)

/*
 * adopted from Linux kernel include file compat.h
 * See drivers/wlan/compat.h
 */
#ifndef NBBY
#define	NBBY	8			/* number of bits/byte */
#endif
#define	setbit(a,i)	((a)[(i)/NBBY] |= 1<<((i)%NBBY))

#ifndef BIT
#define BIT(x) (1L << (x))
#endif

#ifndef MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif

/*
 * Wireless Extension (WE) refers to the programming found in wireless_tools, e.g iwconfig.
 * Keep WE definitions separate from QCSAPI definitions.
 * WE definitions probably belong in iwlib.h or some place else in wireless_tools.
 * But since that programming comes from the Linux community,
 * we have to leave those source files alone.
 */

/* Based on strings in iw_operation_mode, iwlib.c */

#define WE_MODE_AUTO		0
#define WE_MODE_ADHOC		1
#define WE_MODE_MANAGED		2
#define WE_MODE_MASTER		3
#define WE_MODE_REPEATER	4
#define WE_MODE_SECONDARY	5
#define WE_MODE_MONITOR		5
#define WE_MODE_UNKNOWN		6

#define QCSAPI_TX_POWER_NOT_CONFIGURED	-128


typedef enum {
	qcsapi_2_4_GHz = 1,
	qcsapi_5_GHz,
	qcsapi_dual,
	qcsapi_nosuch_frequency = 0
} qcsapi_base_frequency;

typedef enum {
	qcsapi_status_up = 1,
	qcsapi_status_down,
	qcsapi_status_error,
	qcsapi_nosuch_status = 0
} qcsapi_status;

typedef enum {
	qcsapi_security_not_defined = 1,
	qcsapi_security_off,
	qcsapi_security_on,
	qcsapi_nosuch_security = 0
} qcsapi_security_setting;

/*
 * Defined in connection with update_security_parameter, qcsapi_security.c
 * Argument selects between quotes around the string, or the bare string.
 * Enum's make the programs more readable.
 *
 * This is NOT a instantiable type ...
 */
enum {
	qcsapi_bare_string = 0,
	qcsapi_in_quotes = 1
};

/*
 * Also defined in connection with update_security_parameter, qcsapi_security.c
 * Argument selects between update is complete and thus the security daemon should
 * be notified to reload its parameters, or further updates are coming, and that
 * notification should be delayed.  Enum's make the programs more readable.
 *
 * This is NOT a instantiable type ...
 */
enum {
	security_update_pending = 0,
	security_update_complete = 1
};

typedef enum {
	QCSAPI_NOSUCH_REGION = 0,
	QCSAPI_REGION_JAPAN = 1,
	QCSAPI_REGION_EUROPE,
	QCSAPI_REGION_USA,
	QCSAPI_REGION_RUSSIA,
	QCSAPI_REGION_AUSTRALIA,
} qcsapi_regulatory_region;

struct supported_parameters {
	char *name;
	int (*verify_value)(const char *parameter_value);
};

#define QCSAPI_CHANNELS_2_4GHZ_LIST { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 }
#define QCSAPI_CHANNELS_5GHZ_LIST { 36, 40, 44, 48, 52, 56, 60, 64, 100, \
			104, 108, 112, 116, 120, 124, 128, 132,		\
			136, 140, 144, 149, 153, 157, 161, 165, 169 }

#define QCSAPI_DSCP_MIN_VALUE 0
#define QCSAPI_DSCP_MAX_VALUE 15
#define QCSAPI_DSCP_MIN_LEVEL 0
#define QCSAPI_DSCP_MAX_LEVEL 63


#ifdef __cplusplus
extern "C" {
#endif

extern int local_open_iw_socket_with_error( int *p_skfd );
extern int local_open_iw_sockets(void);
extern int local_close_iw_sockets(int sock_fd);
extern int local_get_priv_ioctls(int sock_fd, const char *p_ifname, int *p_num_priv_ioctls, struct iw_priv_args **pp_priv_ioctls);
extern char *local_interface_get_name(char *name, char *p);
extern int local_interface_verify_net_device(const char *ifname);
extern int local_interface_get_mac_addr(const int skfd, const char *ifname, qcsapi_mac_addr interface_mac_addr);
extern int local_interface_get_status(const int skfd, const char *ifname, qcsapi_interface_status_code *status_code);
extern int local_generic_verify_mac_addr_valid(const qcsapi_mac_addr proposed_mac_addr);
extern int verify_we_device(int skfd, const char *ifname, char *wename, const unsigned int wesize);
extern int local_interface_get_status_string(const int skfd, const char *ifname, char *if_status, size_t status_size);
extern int local_interface_enable(const char *ifname, const int enable_flag);
extern int local_interface_connect_to_bridge(const char *ifname, const char *bridge_dev, const int enable_flag);
extern int local_get_primary_ap_interface(char *ifname, size_t maxlen);
extern int local_get_primary_interface(char *ifname, size_t maxlen);
extern int local_verify_interface_is_primary(const char *ifname);
extern int local_get_we_device_by_index( unsigned int we_index, char *ifname, size_t maxlen);
extern int local_get_if_mac_address(int sock, const char *ifname, char *addr);
extern int local_eth_phy_read(int sock, const char *ifname, int regnum, int *val_out);
extern void local_check_bss_mac_address(const char *mac_addr, int *p_found);
extern int local_wifi_get_mode(const int skfd, const char *ifname, qcsapi_wifi_mode *p_wifi_mode);
extern int local_verify_wifi_mode(const int skfd, const char *ifname,
		qcsapi_wifi_mode required_wifi_mode,
		qcsapi_wifi_mode *p_wifi_mode);
extern int local_verify_repeater_mode(const int skfd, qcsapi_wifi_mode *wifi_mode);
extern int local_check_bss_name(const char *ifname);
extern int local_security_get_security_setting(const int skfd, const char *ifname, qcsapi_security_setting *p_security_setting);
extern int local_security_get_broadcast_SSID(const char *ifname, int *p_broadcast_SSID);
extern int local_security_set_broadcast_SSID(const char *ifname, const int broadcast_SSID);
extern int local_wifi_set_chan_pri_inactive(int skfd, const char *ifname, unsigned int channel, unsigned int inactive, unsigned int flags);
extern int local_wifi_option_get_specific_scan(const char *ifname, int *p_specific_scan);
extern int local_wifi_option_set_specific_scan(const int skfd, const char *ifname, const int specific_scan);
extern int local_wifi_get_BSSID(const int skfd, const char *ifname, qcsapi_mac_addr BSSID_str);
extern int local_wifi_get_SSID(const int skfd, const char *ifname, qcsapi_SSID SSID_str);
extern int local_wifi_set_SSID(const int skfd, const char *ifname, const qcsapi_SSID SSID_str);
extern int local_wifi_write_to_qdrv(const char *command);
extern int local_lookup_file_path_config(const qcsapi_file_path_config e_file_path, char *file_path, qcsapi_unsigned_int path_size);
extern int local_update_file_path_config(const qcsapi_file_path_config e_file_path, const char *new_path);
extern int local_write_string_to_file(const char *file_path, const char *file_contents);
extern int local_read_string_from_file(const char *file_path, char *file_contents, const unsigned int sizeof_contents);
extern int local_generic_locate_process(const char *process_name);
extern int local_bootcfg_get_parameter(const char *parameter_name, char *parameter_value, const size_t value_length);
extern int local_bootcfg_set_parameter(const char *parameter_name, const char *parameter_value,
		const int write_flash);
extern int local_boardparam_get_parameter(const char *parameter_name, char *parameter_value, const size_t value_length);
extern int local_generic_syslog(const char *ident, int priority, const char *format, ...);
extern int local_generic_run_a_command(const char *command,
		const int argc,
		const char *argv[],
		const int subprocess_flags,
		int *p_exit_status,
		int *p_signal_number);
extern int local_get_count_associations(int skfd, const char *ifname, qcsapi_unsigned_int *p_association_count);
extern int local_is_mac_associated(int skfd, const char *ifname, qcsapi_mac_addr macaddr, bool* p_associated);

extern int local_set_internal_regulatory_region(
		int skfd,
		const char *ifname,
		const char *default_regulatory_region,
		int board_provision_enabled);
extern int local_get_internal_regulatory_region(int skfd, const char *ifname, char *region_by_name);
extern int local_bootcfg_get_min_tx_power(void);
extern int local_bootcfg_get_max_sta_dfs_tx_power(int *p_max_sta_dfs_tx_power);
extern int local_bootcfg_get_default_tx_power(void);
extern int local_swfeat_check_supported(const uint16_t feat);
extern int
local_wifi_configure_band_tx_power(
	int skfd,
	const char *ifname,
	const int start_channel,
	const int stop_channel,
	const int max_tx_power,
	const int min_tx_power
);
extern int
local_wifi_configure_bw_tx_power(
	int skfd,
	const char *ifname,
	const int channel,
	const int bf_on,
	const int number_ss,
	const int bandwidth,
	const int power
);

extern int local_wifi_enable_country_ie( const int skfd, const char *ifname, const int32_t enable );
extern int local_wifi_set_country_code( const int skfd, const char *ifname, const char *country_name );

extern const char *get_default_region_name( qcsapi_regulatory_region the_region );

extern int
local_wifi_configure_regulatory_tx_power(
	int skfd,
	const char *ifname,
	const int start_channel,
	const int stop_channel,
	const int regulatory_tx_power
);
extern int local_wifi_set_tx_power(int skfd, const char *ifname, const int start_channel, int tx_power);
extern int local_wifi_set_channel(int skfd, const char *ifname, unsigned int new_channel);
extern int local_wifi_get_channel(int skfd, const char *ifname, unsigned int *p_new_channel);
extern int local_wifi_get_bandwidth(const int skfd, const char *ifname, qcsapi_bw *p_bw);
extern int local_get_tx_power(int skfd, const char *ifname, const qcsapi_unsigned_int the_channel, int *p_tx_power);

extern char *read_to_eol(char *address, int size, FILE *fh);

extern int qcsapi_security_init(void);

extern unsigned int get_count_calls_qcsapi_init(void);
extern int local_lookup_gpio_config(const uint8_t gpio_pin, qcsapi_gpio_config *p_gpio_config);
extern int local_led_get(const uint8_t led_ident, uint8_t *p_led_setting);

extern int call_private_ioctl(int skfd, char *args[], int count, const char *ifname, const char *cmdname, void *result_addr, unsigned int result_size);

extern int lookup_ap_security_parameter(
	const char *ifname,
	const qcsapi_wifi_mode wifi_mode,
	const char *parameter,
	char *value_str,
	const unsigned int value_size);

extern int lookup_SSID_parameter(
	const char *network_SSID,
	const qcsapi_wifi_mode wifi_mode,
	const char *parameter,
	char *value_str,
	const unsigned int value_size);

extern int update_security_parameter(
	const char *ifname,
	const char *station_SSID,
	const char *parameter,
	const char *value_str,
	const qcsapi_wifi_mode wifi_mode,
	const int update_flag,
	const int quote_flag,
	const int complete_update);

extern int remove_security_parameter(
	const char *ifname,
	const char *station_SSID,
	const char *parameter,
	const qcsapi_wifi_mode wifi_mode,
	const int complete_update);

extern int update_security_bss_configuration( const char *ifname );

extern int send_message_security_daemon(
	const char *ifname,
	const qcsapi_wifi_mode wifi_mode,
	const char *message,
	char *reply,
	const size_t reply_len);

extern int reload_security_configuration(
	const char *ifname,
	const qcsapi_wifi_mode wifi_mode);

extern qcsapi_regulatory_region local_wifi_get_region_by_name(const char *region_by_name);

extern int verify_band_value(const char *parameter_value);
extern int verify_mode_value(const char *parameter_value);
extern int verify_bw_value(const char *parameter_value);
extern int verify_channel_value(const char *parameter_value);
extern int verify_mcs_value(const char *parameter_value);
extern int verify_region_value(const char *parameter_value);
extern int verify_pwr_value(const char *parameter_value);
extern int verify_ssid_priority_value(const char *parameter_value);
extern int verify_ssid_vlan_value(const char *parameter_value);
extern int verify_ssid_uapsd_value(const char *parameter_value);
extern int verify_value_one_or_zero(const char *parameter_value);
extern int verify_value_pmf(const char *parameter_value);
extern int verify_value_region_db(const char *parameter_value);
extern int verify_value_ipaddr(const char *ipaddr);
extern int verify_ethtype_value(const char *parameter_value);

extern int local_get_we_range_data(int sock_fd, const char *p_ifname, struct iw_range *p_range);
extern int local_wifi_get_hw_options(int *hw_options);
extern int local_wifi_get_power_table_checksum(char *fname, char *checksum_buf, int bufsize);
extern int local_wifi_get_power_recheck(qcsapi_unsigned_int *p_power_recheck);
extern int local_wifi_get_power_selection(qcsapi_unsigned_int *p_power_selection);
extern int local_get_supported_spatial_streams(int *num_tx_ss, int *num_rx_ss);
extern int local_wifi_check_radar_mode(const char *ifname, const char *region_by_name, int skfd);
extern int local_use_new_tx_power(void);
extern int local_regulatory_set_tx_power(const char *ifname,
		const qcsapi_unsigned_int the_channel,
		const int tx_power);
extern int local_regulatory_set_bw_power(const char *ifname,
		const qcsapi_unsigned_int the_channel,
		const qcsapi_unsigned_int bf_on,
		const qcsapi_unsigned_int number_ss,
		const int power_20M,
		const int power_40M,
		const int power_80M);
extern int local_regulatory_set_chan_power_table(const char *ifname,
		qcsapi_channel_power_table *chan_power_table);
extern int local_regulatory_get_supported_tx_power_levels(const char *ifname,
		string_128 available_percentages);
extern int local_regulatory_get_current_tx_power_level(const char *ifname,
		uint32_t *p_current_percentage);
extern int local_qcsapi_regulatory_disable_dfs_channels(const char *ifname,
		const int scheme, const int inp_chan);
extern int local_regulatory_get_list_regulatory_regions(string_128 list_regulatory_regions);
extern int local_regulatory_set_regulatory_region( const char *ifname, const char *region_by_name);
extern int local_verify_regulatory_regions(
		string_128 list_regulatory_regions, const char *region_in);
extern int local_wifi_set_security_defer_mode(int defer);
extern int local_wifi_get_security_defer_mode(void);
extern int local_wifi_security_update_mode(void);
extern int locate_configuration_file(const qcsapi_wifi_mode wifi_mode, char *config_file_path, const unsigned int size_file_path);
extern int local_wifi_set_regulatory_region(const char *ifname, const char *region_by_name);
extern int local_wifi_option_getparam( const int skfd, const char *ifname, const int param, int *p_value);
extern int local_led_pwm_enable(const uint8_t led_ident, const uint8_t onoff, const qcsapi_unsigned_int high_count, const qcsapi_unsigned_int low_count);
extern int local_parse_mac_addr(const char *mac_addr_as_str, qcsapi_mac_addr mac_addr);
extern int local_wifi_set_chan_power_table(const char *ifname, struct ieee80211_chan_power_table *p_table);
extern int local_wifi_get_chan_power_table(const char *ifname, struct ieee80211_chan_power_table *p_table);
extern int verify_numeric_range(const char *str, uint32_t min, uint32_t max);
extern int local_wifi_pre_deactive_DFS_channels(const int skfd, const char *ifname,
		const int scheme);
extern int local_wifi_sub_ioctl_submit(const char *ifname, int16_t sub_cmd, void *param, uint16_t len);
extern int verify_hexstring(const char *p_value, unsigned int byte_count);
#ifdef __cplusplus
}
#endif

#endif /* _QCSAPI_PRIVATE_H */
