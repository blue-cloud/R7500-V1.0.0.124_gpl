/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2011 Quantenna Communications Inc            **
**                                                                           **
**  File        : qcsapi_generic.c                                           **
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

/*
 * Generic QCSAPI programming
 * (i.e. applies to ethenet as well as wifi)
 * Thus most comes from ifconfig.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>	/* for Get Time Since Start */

#include <linux/sockios.h>
#include <net/if_arp.h>

#include <arpa/inet.h>

#include <linux/random.h>

#include <qtn/qtn_vlan.h>

#include "qcsapi.h"
#include "qcsapi_private.h"
#include "qcsapi_util.h"

#ifndef LOCAL_SYSLOG_MESSAGE_SIZE
#define LOCAL_SYSLOG_MESSAGE_SIZE	100
#endif

#ifndef API_LOG_FILE
#define API_LOG_FILE	"/tmp/api.log"
#endif

#ifndef API_LOG_FILE_LIMIT_SIZE
#define API_LOG_FILE_LIMIT_SIZE 204800
#endif

#define PROC_PM_INTERVAL_PREFIX		"/proc/pm_interval/start_"
#define MAX_PM_INTERVAL_NAME_LEN	8

typedef struct error_message_entry
{
	int	error_value;
	char	*error_message;
} error_message_entry;

/*
 * A lot of this file comes from busybox/busybox-1.10.3/networking/interface.c
 * (part of the source code for ifconfig), but enough differences exist to
 * justify a new and separate source code file.
 */

#define _PATH_PROCNET_DEV		"/proc/net/dev"
#define _PATH_PROCNET_PACKETS		"/proc/net/packets"
#define _PATH_PROCNET_DEV64		"/proc/net/dev64"
#define _PATH_PROCNET_PACKETS64		"/proc/net/packets64"

typedef struct user_net_device_stats {
	unsigned long long rx_packets;	/* total packets received       */
	unsigned long long tx_packets;	/* total packets transmitted    */
	unsigned long long rx_bytes;	/* total bytes received         */
	unsigned long long tx_bytes;	/* total bytes transmitted      */
	unsigned long rx_errors;	/* bad packets received         */
	unsigned long tx_errors;	/* packet transmit problems     */
	unsigned long rx_dropped;	/* no space in linux buffers    */
	unsigned long tx_dropped;	/* no space available in linux  */
	unsigned long rx_multicast;	/* multicast packets received   */
	unsigned long rx_compressed;
	unsigned long tx_compressed;
	unsigned long collisions;

	/* detailed rx_errors: */
	unsigned long rx_length_errors;
	unsigned long rx_over_errors;	/* receiver ring buff overflow  */
	unsigned long rx_crc_errors;	/* recved pkt with crc error    */
	unsigned long rx_frame_errors;	/* recv'd frame alignment error */
	unsigned long rx_fifo_errors;	/* recv'r fifo overrun          */
	unsigned long rx_missed_errors;	/* receiver missed packet     */
	/* detailed tx_errors */
	unsigned long tx_aborted_errors;
	unsigned long tx_carrier_errors;
	unsigned long tx_fifo_errors;
	unsigned long tx_heartbeat_errors;
	unsigned long tx_window_errors;

	/* packets statistics */
	unsigned long long tx_ucast_pkts;
	unsigned long long rx_ucast_pkts;
	unsigned long tx_mcast_pkts;
	unsigned long rx_mcast_pkts;
	unsigned long tx_bcast_pkts;
	unsigned long rx_bcast_pkts;
	unsigned long rx_unknown_pkts;
} user_net_device_stats;

	/* Lie about the size of the int pointed to for %n. */
#if INT_MAX == LONG_MAX
static const char *const ss_fmt[] = {
	"%n%llu%u%u%u%u%n%n%n%llu%u%u%u%u%u",
	"%llu%llu%u%u%u%u%n%n%llu%llu%u%u%u%u%u",
	"%llu%llu%u%u%u%u%u%u%llu%llu%u%u%u%u%u%u"
};
#else
static const char *const ss_fmt[] = {
	"%n%llu%lu%lu%lu%lu%n%n%n%llu%lu%lu%lu%lu%lu",
	"%llu%llu%lu%lu%lu%lu%n%n%llu%llu%lu%lu%lu%lu%lu",
	"%llu%llu%lu%lu%lu%lu%lu%lu%llu%llu%lu%lu%lu%lu%lu%lu"
};
#endif

/* This table lists supported parameter name in wireless_conf.txt */
const struct supported_parameters supported_parameters_tbl[] =
{
	{"bf", verify_value_one_or_zero},
	{"bw", verify_bw_value},
	{"channel", verify_channel_value},
	{"dhcpv6", verify_value_one_or_zero},
	{"f40", verify_value_one_or_zero},
	{"leds", verify_value_one_or_zero},
	{"mode", verify_mode_value},
	{"monitorreset", verify_value_one_or_zero},
	{"monitorrfenable", verify_value_one_or_zero},
	{"mcs", verify_mcs_value},
	{"pwr", verify_pwr_value},
	{"region", verify_region_value},
	{"ssdp_flood", verify_value_one_or_zero},
	{"staticip", verify_value_one_or_zero},
	{"scs", verify_value_one_or_zero},
	{"qtm", NULL},
	{"tx_restrict", verify_value_one_or_zero},
	{"use3way", verify_value_one_or_zero},
	{"vht", verify_value_one_or_zero},
	{"pmf", verify_value_pmf},
	{"region_db", verify_value_region_db},
	{"qevt", verify_value_one_or_zero},
	{"maui", verify_value_one_or_zero},
	{"dfs_s_radio", verify_value_one_or_zero},
	{"non_dfs_channel", verify_channel_value},
	{"band", verify_band_value},
	{"monitor_temperature", verify_value_one_or_zero},
	{"start_down", verify_value_one_or_zero},
	{NULL, NULL}
};

/* This table lists supported parameter name in per_ssid_config.txt */
const struct supported_parameters perssid_supported_parameters_tbl[] =
{
	{"priority", verify_ssid_priority_value},
	{"vlan", verify_ssid_vlan_value},
	{"uapsd", verify_ssid_uapsd_value},
	{NULL, NULL}
};

static int
local_telnet_conf_update(const char *ifname, const char *param_name, const char *param_value)
{
	int retval = 0;
	pid_t status;

	if (strcmp(param_value, "1") == 0)
		status = system("rm -f /mnt/jffs2/telnet-disabled");
	else
		status = system("touch /mnt/jffs2/telnet-disabled");

	if (!WEXITSTATUS(status)) {
		retval = 0;
	} else {
		retval = -EFAULT;
	}

	return retval;
}

static int
local_dhclient_conf_update(const char *ifname, const char *param_name, const char *param_value)
{
	int ret = 0;

	if (strcmp(param_value, "1") == 0)
		ret = qcsapi_config_update_parameter(ifname, "staticip", "0");
	else
		ret = qcsapi_config_update_parameter(ifname, "staticip", "1");

	return ret;
}

static int
local_httpd_conf_update(const char *ifname, const char *param_name, const char *param_value)
{
	int retval = 0;
	pid_t status;

	if (strcmp(param_value, "1") == 0)
		status = system("rm -f /mnt/jffs2/httpd-disabled");
	else
		status = system("touch /mnt/jffs2/httpd-disabled");

	if (!WEXITSTATUS(status)) {
		retval = 0;
	} else {
		retval = -EFAULT;
	}

	return retval;
}

static int
local_wireless_conf_update(const char *ifname, const char *param_name, const char *param_value)
{
	int ret = 0;

	if (strcmp(param_value, "1") == 0) {
		ret = qcsapi_config_update_parameter(ifname, param_name, "1");
	} else {
		ret = qcsapi_config_update_parameter(ifname, param_name, "0");
	}

	return ret;
}

static const struct {
	qcsapi_service_name    serv_idx;
	const char              *serv_name;
	qcsapi_service_start_index start_idx;
	int (*update_service_config)(const char *ifname, const char *service, const char *value);
} service_name_tbl[] =
{
	{QCSAPI_SERVICE_MAUI, "maui",
				qcsapi_service_maui_start_index, qcsapi_config_update_parameter},
	{QCSAPI_SERVICE_TELNET, "inetd",
				qcsapi_service_inetd_start_index, local_telnet_conf_update},
	{QCSAPI_SERVICE_DHCP_CLIENT, "dhclient",
				qcsapi_service_dhclient_start_index, local_dhclient_conf_update},
	{QCSAPI_SERVICE_HTTPD, "httpd", qcsapi_service_httpd_start_index, local_httpd_conf_update},
	{QCSAPI_SERVICE_MONITOR_TEMPERATURE, "monitor_temperature",
				qcsapi_service_monitor_temp_start_index, local_wireless_conf_update}
};

static const struct {
	qcsapi_service_action   action_idx;
	const char              *serv_action;
} service_action_tbl[] =
{
	{QCSAPI_SERVICE_START, "start"},
	{QCSAPI_SERVICE_STOP, "stop"},
	{QCSAPI_SERVICE_ENABLE, "enable"},
	{QCSAPI_SERVICE_DISABLE, "disable"}
};

static int
local_service_name_to_enum(const char * lookup_service,
		qcsapi_service_name *serv_name)
{
	unsigned int    iter;

	for (iter = 0; iter < ARRAY_SIZE(service_name_tbl); iter++)
	{
		if (strcasecmp(service_name_tbl[ iter ].serv_name,
					lookup_service ) == 0) {
			*serv_name = service_name_tbl[ iter ].serv_idx;
			return 0;
		}
	}

	return -EINVAL;
}

static int
local_service_action_to_enum(const char * lookup_action,
		qcsapi_service_action *serv_action)
{
	unsigned int    iter;

	for (iter = 0; iter < ARRAY_SIZE(service_action_tbl); iter++)
	{
		if (strcasecmp( service_action_tbl[ iter ].serv_action,
					lookup_action ) == 0) {
			*serv_action = service_action_tbl[ iter ].action_idx;
			return 0;
		}
	}

	return -EINVAL;
}

int
qcsapi_get_service_name_enum(const char * lookup_service, qcsapi_service_name *serv_name)
{
	int retval = 0;

	if (lookup_service == NULL || serv_name == NULL) {
		retval = -EFAULT;
	}

	if (retval >= 0) {
		retval = local_service_name_to_enum(lookup_service, serv_name);
	}

	return( retval );
}

int
qcsapi_get_service_action_enum(const char * lookup_action, qcsapi_service_action *serv_action)
{
	int retval = 0;

	if (lookup_action == NULL || serv_action == NULL) {
		retval = -EFAULT;
	}

	if (retval >= 0) {
		retval = local_service_action_to_enum(lookup_action, serv_action);
	}

	return( retval );
}

static void
local_interface_get_dev_fields(char *bp, user_net_device_stats *p_stats, int procnetdev_vsn)
{
	memset(p_stats, 0, sizeof(user_net_device_stats));

	sscanf(bp, ss_fmt[procnetdev_vsn],
		   &p_stats->rx_bytes, /* missing for 0 */
		   &p_stats->rx_packets,
		   &p_stats->rx_errors,
		   &p_stats->rx_dropped,
		   &p_stats->rx_fifo_errors,
		   &p_stats->rx_frame_errors,
		   &p_stats->rx_compressed, /* missing for <= 1 */
		   &p_stats->rx_multicast, /* missing for <= 1 */
		   &p_stats->tx_bytes, /* missing for 0 */
		   &p_stats->tx_packets,
		   &p_stats->tx_errors,
		   &p_stats->tx_dropped,
		   &p_stats->tx_fifo_errors,
		   &p_stats->collisions,
		   &p_stats->tx_carrier_errors,
		   &p_stats->tx_compressed /* missing for <= 1 */
	);

	if (procnetdev_vsn <= 1) {
		if (procnetdev_vsn == 0) {
			p_stats->rx_bytes = 0;
			p_stats->tx_bytes = 0;
		}
		p_stats->rx_multicast = 0;
		p_stats->rx_compressed = 0;
		p_stats->tx_compressed = 0;
	}
}

char *
local_interface_get_name(char *name, char *p)
{
	/* Extract <name> from nul-terminated p where p matches
	   <name>: after leading whitespace.
	   If match is not made, set name empty and return unchanged p */

	int namestart = 0, nameend = 0;

	while (isspace(p[namestart]))
		namestart++;
	nameend = namestart;
	while (p[nameend] && p[nameend] != ':' && !isspace(p[nameend]))
		nameend++;
	if (p[nameend] == ':') {
		if ((nameend - namestart) < IFNAMSIZ) {
			memcpy(name, &p[namestart], nameend - namestart);
			name[nameend - namestart] = '\0';
			p = &p[nameend];
		} else {
			/* Interface name too large */
			name[0] = '\0';
		}
	} else {
		/* trailing ':' not found - return empty */
		name[0] = '\0';
	}
	return p + 1;
}

static inline int
procnetdev_version(char *buf)
{
	if (strstr(buf, "compressed"))
		return 2;
	if (strstr(buf, "bytes"))
		return 1;
	return 0;
}

static int
get_net_counter(
	user_net_device_stats *p_current_device_stats,
	qcsapi_counter_type counter_type,
	qcsapi_unsigned_int64 *p_counter_value
)
{
	int	retval = 0;

	switch (counter_type)
	{
	  case qcsapi_total_bytes_sent:
		*p_counter_value = p_current_device_stats->tx_bytes;
		break;

	  case qcsapi_total_bytes_received:
		*p_counter_value = p_current_device_stats->rx_bytes;
		break;

	  case qcsapi_total_packets_sent:
		*p_counter_value = p_current_device_stats->tx_packets;
		break;

	  case qcsapi_total_packets_received:
		*p_counter_value = p_current_device_stats->rx_packets;
		break;

	  case qcsapi_discard_packets_sent:
		*p_counter_value = (qcsapi_unsigned_int64) (p_current_device_stats->tx_dropped);
		break;

	  case qcsapi_discard_packets_received:
		*p_counter_value = (qcsapi_unsigned_int64) (p_current_device_stats->rx_dropped);
		break;

	  case qcsapi_error_packets_sent:
		*p_counter_value = (qcsapi_unsigned_int64) (p_current_device_stats->tx_errors);
		break;

	  case qcsapi_error_packets_received:
		*p_counter_value = (qcsapi_unsigned_int64) (p_current_device_stats->rx_errors);
		break;

	  default:
		retval = -EINVAL;
		break;
	}

	return( retval );
}

static int local_get_network_counter(FILE *fh,
				     const char *ifname,
				     qcsapi_counter_type counter_type,
				     qcsapi_unsigned_int64 *p_counter_value)
{
	char	buf[512];
	int	found_iface = 0;
	int	procnetdev_vsn;
	int	retval = 0;

	if (p_counter_value == NULL || fh == NULL) {
		return -EFAULT;
	}

	read_to_eol(&buf[0], sizeof buf, fh);	/* Discard header */
	read_to_eol(&buf[0], sizeof buf, fh);

	procnetdev_vsn = procnetdev_version(&buf[0]);

	while (found_iface == 0 && read_to_eol(&buf[0], sizeof(buf), fh) != NULL) {
		char	*s, name[IFNAMSIZ];

		s = local_interface_get_name(name, &buf[0]);
		if (strncmp(&name[ 0 ], ifname, IFNAMSIZ) == 0) {
			user_net_device_stats	 current_device_stats;

			local_interface_get_dev_fields(s, &current_device_stats, procnetdev_vsn);
			retval = get_net_counter(&current_device_stats, counter_type, p_counter_value);
			found_iface = 1;
		}
	}

	if (found_iface == 0) {
		return -ENODEV;
	}

	return retval;
}

static int local_interface_get_cumulative_counter(const char *ifname,
						  qcsapi_counter_type counter_type,
						  qcsapi_unsigned_int *p_counter_value)
{
	int	retval;
	FILE *proc_net_dev_fh = NULL;
	qcsapi_unsigned_int64 counter64_value;

	if (p_counter_value == NULL) {
		return -EFAULT;
	}

	proc_net_dev_fh = fopen(_PATH_PROCNET_DEV, "r");
	if (proc_net_dev_fh == NULL) {
		return -qcsapi_no_network_counters;
	}

	retval = local_get_network_counter(proc_net_dev_fh, ifname, counter_type, &counter64_value);
	*p_counter_value = (qcsapi_unsigned_int)counter64_value;

	fclose(proc_net_dev_fh);

	return retval;
}

static int local_interface_get_cumulative_counter64(const char *ifname,
						  qcsapi_counter_type counter_type,
						  uint64_t *p_counter_value)
{
	int	retval;
	FILE *proc_net_dev_fh = NULL;

	if (p_counter_value == NULL || ifname == NULL)
		return -EFAULT;

	proc_net_dev_fh = fopen(_PATH_PROCNET_DEV64, "r");
	if (proc_net_dev_fh == NULL)
		return -qcsapi_no_network_counters;

	retval = local_get_network_counter(proc_net_dev_fh, ifname, counter_type, p_counter_value);

	fclose(proc_net_dev_fh);

	return retval;
}


static void
local_interface_get_packets_fields(char *bp, user_net_device_stats *p_stats)
{
	sscanf(bp, "%llu%lu%lu%lu%llu%lu%lu",
		&p_stats->rx_ucast_pkts,
		&p_stats->rx_mcast_pkts,
		&p_stats->rx_bcast_pkts,
		&p_stats->rx_unknown_pkts,
		&p_stats->tx_ucast_pkts,
		&p_stats->tx_mcast_pkts,
		&p_stats->tx_bcast_pkts
	);
}

int
qcsapi_interface_get_counter(const char *ifname,
			     qcsapi_counter_type counter_type,
			     qcsapi_unsigned_int *p_counter_value)
{
	int	 retval = 0;

	enter_qcsapi();

	retval = local_interface_get_cumulative_counter(ifname, counter_type, p_counter_value);

	leave_qcsapi();

	return( retval );
}

int
qcsapi_interface_get_counter64(const char *ifname,
			     qcsapi_counter_type counter_type,
			     uint64_t *p_counter_value)
{
	int	 retval = 0;

	enter_qcsapi();

	retval = local_interface_get_cumulative_counter64(ifname, counter_type, p_counter_value);

	leave_qcsapi();

	return retval;
}

static int
get_interface_stats(
	user_net_device_stats *p_current_device_stats,
	qcsapi_interface_stats *stats)
{
	if (p_current_device_stats == NULL || stats == NULL)
		return -1;

	stats->tx_bytes		= (uint64_t) p_current_device_stats->tx_bytes;
	stats->tx_pkts		= (uint32_t) p_current_device_stats->tx_packets;
	stats->tx_discard	= (uint32_t) p_current_device_stats->tx_dropped;
	stats->tx_err		= (uint32_t) p_current_device_stats->tx_errors;
	stats->tx_unicast	= (uint32_t) p_current_device_stats->tx_ucast_pkts;
	stats->tx_multicast	= (uint32_t) p_current_device_stats->tx_mcast_pkts;
	stats->tx_broadcast	= (uint32_t) p_current_device_stats->tx_bcast_pkts;

	stats->rx_bytes		= (uint64_t) p_current_device_stats->rx_bytes;
	stats->rx_pkts		= (uint32_t) p_current_device_stats->rx_packets;
	stats->rx_discard	= (uint32_t) p_current_device_stats->rx_dropped;
	stats->rx_err		= (uint32_t) p_current_device_stats->rx_errors;
	stats->rx_unicast	= (uint32_t) p_current_device_stats->rx_ucast_pkts;
	stats->rx_multicast	= (uint32_t) p_current_device_stats->rx_mcast_pkts;
	stats->rx_broadcast	= (uint32_t) p_current_device_stats->rx_bcast_pkts;
	stats->rx_unknown	= (uint32_t) p_current_device_stats->rx_unknown_pkts;

	return 0;

}

static int local_get_network_stats(FILE *fh,
				     const char *ifname,
				     user_net_device_stats *current_device_stats)
{
	char	buf[512];
	int	found_iface = 0;
	int	procnetdev_vsn;
	int	retval = 0;

	if (fh == NULL || current_device_stats == NULL) {
		return -EFAULT;
	}

	read_to_eol(&buf[0], sizeof buf, fh);	/* Discard header */
	read_to_eol(&buf[0], sizeof buf, fh);

	procnetdev_vsn = procnetdev_version(&buf[0]);

	while (found_iface == 0 && read_to_eol(&buf[0], sizeof(buf), fh) != NULL) {
		char	*s, name[IFNAMSIZ];

		s = local_interface_get_name(name, &buf[0]);
		if (strncmp(&name[ 0 ], ifname, IFNAMSIZ) == 0) {
			local_interface_get_dev_fields(s, current_device_stats, procnetdev_vsn);
			found_iface = 1;
		}
	}

	if (found_iface == 0) {
		return -ENODEV;
	}

	return retval;
}

static int local_get_packets_stats(FILE *fh,
				     const char *ifname,
				     user_net_device_stats *current_device_stats)
{
	char	buf[512];
	int	found_iface = 0;
	int	retval = 0;

	if (fh == NULL || current_device_stats == NULL) {
		return -EFAULT;
	}

	read_to_eol(&buf[0], sizeof buf, fh);	/* Discard header */
	read_to_eol(&buf[0], sizeof buf, fh);

	while (found_iface == 0 && read_to_eol(&buf[0], sizeof(buf), fh) != NULL) {
		char	*s, name[IFNAMSIZ];

		s = local_interface_get_name(name, &buf[0]);
		if (strncmp(&name[ 0 ], ifname, IFNAMSIZ) == 0) {
			local_interface_get_packets_fields(s, current_device_stats);
			found_iface = 1;
		}
	}

	if (found_iface == 0) {
		return -ENODEV;
	}

	return retval;
}

static int
local_get_interface_stats(const char *ifname, qcsapi_interface_stats *stats)
{
	int	retval;
	FILE	*proc_net_dev_fh = NULL;
	FILE	*proc_net_packets_fh = NULL;
	user_net_device_stats device_stats;

	if (ifname == NULL || stats == NULL) {
		return -EFAULT;
	}

	proc_net_dev_fh = fopen(_PATH_PROCNET_DEV64, "r");
	if (proc_net_dev_fh == NULL) {
		return -qcsapi_no_network_counters;
	}

	retval = local_get_network_stats(proc_net_dev_fh, ifname, &device_stats);

	fclose(proc_net_dev_fh);

	if (retval)
		return retval;

	proc_net_packets_fh = fopen(_PATH_PROCNET_PACKETS64, "r");
	if (proc_net_packets_fh == NULL) {
		return -qcsapi_no_network_counters;
	}

	retval = local_get_packets_stats(proc_net_packets_fh, ifname, &device_stats);

	fclose(proc_net_packets_fh);

	get_interface_stats(&device_stats, stats);

	return retval;
}

int qcsapi_get_interface_stats(const char *ifname,
				qcsapi_interface_stats *stats)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_get_interface_stats(ifname, stats);

	leave_qcsapi();

	return retval;
}

static int local_pm_get_counter_start_interval(const char *ifname,
						      qcsapi_counter_type counter_type,
						      const char *pm_interval,
						      qcsapi_unsigned_int *p_counter_value)
{
	int	retval;
	FILE	*proc_pmi_fh = NULL;
	char	proc_entry_path[strlen(PROC_PM_INTERVAL_PREFIX) + MAX_PM_INTERVAL_NAME_LEN];
	qcsapi_unsigned_int64 counter64_value = 0;

	if (p_counter_value == NULL || pm_interval == NULL) {
		return -EFAULT;
	}

	snprintf(&proc_entry_path[0], sizeof(proc_entry_path),
		  PROC_PM_INTERVAL_PREFIX "%s", pm_interval);

	proc_pmi_fh = fopen(&proc_entry_path[0], "r");
	if (proc_pmi_fh == NULL) {
		return -qcsapi_invalid_pm_interval;
	}

	retval = local_get_network_counter(proc_pmi_fh, ifname, counter_type, &counter64_value);
	*p_counter_value = (qcsapi_unsigned_int)counter64_value;

	/*
	 * If the interface can't be found in the counters-at-start-of-interval file,
	 * it could be the interface was created since the last time the update routine
	 * in the Performance Monitoring kernel module ran.
	 *
	 * So if the interface can't be found, set the return code to 0 and the counter value to 0.
	 */
	if (retval == -ENODEV) {
		retval = 0;
		*p_counter_value = 0;
	}

	fclose(proc_pmi_fh);

	return retval;
}

int qcsapi_pm_get_counter(const char *ifname,
			  qcsapi_counter_type counter_type,
			  const char *pm_interval,
			  qcsapi_unsigned_int *p_counter_value)
{
	int			retval = 0;
	qcsapi_unsigned_int	cumulative_value = 0;
	qcsapi_unsigned_int	value_at_start = 0;

	enter_qcsapi();

	if (pm_interval == NULL || p_counter_value == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	/*
	 * Call Local Interface Get Cumulative Counter first.
	 * If it can't find an entry for parameter ifname, the interface either does not
	 * exist or is not a network interface.  So the API aborts with an error.
	 *
	 * Above logic does not apply to Local Interface Get Counter at Start of the Interval.
	 */
	if ((retval = local_interface_get_cumulative_counter(ifname, counter_type, &cumulative_value)) < 0) {
		goto ready_to_return;
	}

	if ((retval = local_pm_get_counter_start_interval(ifname,
							  counter_type,
							  pm_interval,
							 &value_at_start)) < 0) {
		goto ready_to_return;
	}

	if (cumulative_value < value_at_start) {
		*p_counter_value = ((qcsapi_unsigned_int) -1) - (value_at_start - cumulative_value) + 1;
	} else {
		*p_counter_value = cumulative_value - value_at_start;
	}

ready_to_return:
	leave_qcsapi();

	return( retval );
}

static int local_pm_get_elapsed_time(const char *pm_interval,
				     qcsapi_unsigned_int *p_elapsed_time)
{
	FILE	*proc_pmi_fh = NULL;
	char	proc_entry_path[strlen(PROC_PM_INTERVAL_PREFIX) + MAX_PM_INTERVAL_NAME_LEN];
	char	proc_entry_line[32];
	int	found_blank_line = 0;
	int	complete = 0;

	if (pm_interval == NULL || p_elapsed_time == NULL) {
		return -EFAULT;
	}

	snprintf(&proc_entry_path[0], sizeof(proc_entry_path),
		  PROC_PM_INTERVAL_PREFIX "%s", pm_interval);

	proc_pmi_fh = fopen(&proc_entry_path[0], "r");
	if (proc_pmi_fh == NULL) {
		return -qcsapi_invalid_pm_interval;
	}

	while (complete == 0 && read_to_eol(&proc_entry_line[0],
					      sizeof(proc_entry_line),
					      proc_pmi_fh) != NULL) {
		if (proc_entry_line[0] == '\n') {
			found_blank_line = 1;
		} else if (found_blank_line) {
			complete = 1;
			*p_elapsed_time = (qcsapi_unsigned_int) atoi(&proc_entry_line[0]);
		}
	}

	fclose(proc_pmi_fh);

	return (complete == 0) ? qcsapi_internal_format_error : 0;
}

int qcsapi_pm_get_elapsed_time(const char *pm_interval,
			       qcsapi_unsigned_int *p_elapsed_time)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_pm_get_elapsed_time(pm_interval, p_elapsed_time);
	leave_qcsapi();

	return( retval );
}

int
local_generic_verify_mac_addr_valid( const qcsapi_mac_addr proposed_mac_addr )
{
	int	retval = 0;

	if ((proposed_mac_addr[ 0 ] & 0x01) != 0)
	  retval = -EINVAL;
	else
	{
		const static qcsapi_mac_addr	all_zeros = { 0, 0, 0, 0, 0, 0 };

		if (memcmp( proposed_mac_addr, all_zeros, sizeof( all_zeros ) ) == 0)
		  retval = -EINVAL;
	}

	return( retval );
}

static const error_message_entry	error_message_table[] =
{
	{ qcsapi_system_not_started,	"System not started" },
	{ qcsapi_parameter_not_found,	"Parameter not found" },
	{ qcsapi_SSID_not_found,	"SSID not found" },
	{ qcsapi_only_on_AP,		"Operation only available on an AP" },
	{ qcsapi_only_on_STA,		"Operation only available on a STA" },
	{ qcsapi_configuration_error,	"Configuration error" },
	{ qcsapi_buffer_overflow,	"Insufficient space in the string to receive results" },
	{ qcsapi_internal_format_error,	"Internal formatting error" },
	{ qcsapi_programming_error,	"Internal API programming error" },
	{ qcsapi_bringup_mode_only,	"Operation only available in bringup mode" },
	{ qcsapi_daemon_socket_error,	"Cannot contact security manager" },
	{ qcsapi_conflicting_options,	"Conflicting settings for API options" },
	{ qcsapi_SSID_parameter_not_found, "Required parameter not found in the SSID configuration block" },
	{ qcsapi_not_initialized,	"Initialization API qcsapi_init has not been called" },
	{ qcsapi_invalid_type_image_file, "Invalid file type for a flash image update file" },
	{ qcsapi_image_file_failed_chkimage, "chkimage utility failed for the flash image update file" },
	{ qcsapi_flash_partition_not_found, "flash partition not found" },
	{ qcsapi_erase_flash_failed,	 "failed to erase the flash memory partition" },
	{ qcsapi_copy_image_flash_failed, "failed to copy the new image to the flash memory partition" },
	{ qcsapi_invalid_wifi_mode,	 "invalid WiFi mode" },
	{ qcsapi_process_table_full,	 "Process table is full" },
	{ qcsapi_measurement_not_available, "measurement not available" },
	{ qcsapi_too_many_bssids,	 "Maximum number of BSSIDs / VAPs exceeded" },
	{ qcsapi_only_on_primary_interface, "Operation only available on the primary WiFi interface" },
	{ qcsapi_too_many_wds_links,	 "Maximum number of WDS links exceeded" },
	{ qcsapi_config_update_failed,	 "Failed to update persistent configuration" },
	{ qcsapi_no_network_counters,	 "Cannot access network counters" },
	{ qcsapi_invalid_pm_interval,	 "Invalid performance monitoring interval" },
	{ qcsapi_only_on_wds,		 "Operation only available on a WDS device" },
	{ qcsapi_only_unicast_mac,		 "Only unicast MAC address is allowed" },
	{ qcsapi_primary_iface_forbidden,	 "Operation is not available on the primary interface" },
	{ qcsapi_invalid_ifname,		 "Invalid BSS name" },
	{ qcsapi_iface_invalid,		"Operation is not supported on this interface" },
	{ qcsapi_iface_error,		"An error happened on interface" },
	{ qcsapi_sem_error,		"Semaphore initialization failed" },
	{ qcsapi_not_supported,		"Feature is not supported" },
	{ qcsapi_invalid_dfs_channel,	"API requires a dfs channel" },
	{ qcsapi_script_error,	"Script failed"},
	{ qcsapi_invalid_wds_peer_addr,	"Local Mac address can't be used as wds peer address"},
	{ qcsapi_band_not_supported,	"Band is not supported"},
	{ qcsapi_region_not_supported,	"Region is not supported"},
	{ qcsapi_region_database_not_found,	"Region database is not found"},
	{ qcsapi_param_name_not_supported,	"Parameter name is not supported"},
	{ qcsapi_param_value_invalid,	"Parameter value is invalid"},
	{ qcsapi_invalid_mac_addr,	"Invalid MAC address"},
	{ qcsapi_option_not_supported,	"Option is not supported"},
	{ qcsapi_wps_overlap_detected,  "WPS Overlap detected"},
	{ qcsapi_mlme_stats_not_supported, "MLME statistics is not supported"},
	{ qcsapi_board_parameter_not_supported,	"Board parameter is not supported"},
	{ qcsapi_peer_in_assoc_table,	"WDS peer is associated"},
	{ qcsapi_mac_not_in_assoc_list,  "MAC address is not in association list"},
	{ qcsapi_param_count_exceeded ,	 "parameter count exceeded"},
	{ qcsapi_duplicate_param,	 "parameter already exists"},
	{ -1,				 NULL }
};

static const error_message_entry	posix_error_messages[] =
{
	{ ERANGE,	"Parameter value out of range" },
	{ -1,		 NULL }
};

static int
locate_error_message(
	int qcsapi_errno,
	const error_message_entry *message_table,
	char *error_msg,
	unsigned int msglen
)
{
	int	retval = 0;
	int	iter, found_entry = 0;

	for (iter = 0; message_table[ iter ].error_message != NULL && found_entry == 0; iter++)
	  if (message_table[ iter ].error_value == qcsapi_errno)
	  {
		unsigned int	ret_msglen = strlen( message_table[ iter ].error_message );

		if (ret_msglen >= msglen)
		  retval = -qcsapi_buffer_overflow;
		else
		  strcpy( error_msg, message_table[ iter ].error_message );

		found_entry = 1;
	  }

	if (found_entry == 0)
	  retval = -EINVAL;

	return( retval );
}

static int
local_errno_get_message( const int qcsapi_retval, char *error_msg, unsigned int msglen )
{
	int	retval = 0;

	if (qcsapi_retval >= 0)
	  retval = -EINVAL;
	else if (error_msg == NULL)
	  retval = -EFAULT;
	else if (msglen < 1)
	  retval = -qcsapi_buffer_overflow;
	else
	{
		int	local_qcsapi_errno = 0 - qcsapi_retval;

		if (local_qcsapi_errno >= qcsapi_errno_base)
		{
			retval = locate_error_message(
					local_qcsapi_errno,
					error_message_table,
					error_msg,
					msglen
			);
		}
		else
		{
		  /* Some POSIX errno's have QCSAPI error messages ... */

			int	ival = locate_error_message(
					local_qcsapi_errno,
					posix_error_messages,
					error_msg,
					msglen
				);

			if (ival < 0)
			  strerror_r( local_qcsapi_errno, error_msg, msglen );
		}
	}

	return( retval );
}

int
qcsapi_errno_get_message( const int qcsapi_retval, char *error_msg, unsigned int msglen )
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_errno_get_message( qcsapi_retval, error_msg, msglen );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_interface_get_BSSID( const char *ifname, qcsapi_mac_addr BSSID_str )
{
	int				retval = 0;
	int				skfd = -1;
	qcsapi_interface_status_code	status_code = qcsapi_interface_status_error;

	enter_qcsapi();

	if (BSSID_str == NULL)
		retval = -EFAULT;
	else
		retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0) {
		retval = local_interface_get_status(skfd, ifname, &status_code);
		if (status_code <= qcsapi_interface_status_disabled) {
			retval = -EFAULT;
		}
	}

	if (retval >= 0)
	{
		retval = local_wifi_get_BSSID(skfd, ifname, BSSID_str);
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int
local_interface_get_mac_addr( const int skfd, const char *ifname, qcsapi_mac_addr interface_mac_addr )
{
	int		retval = 0;

	if (ifname == NULL || interface_mac_addr == NULL)
	  retval = -EFAULT;
	else
	{
		struct ifreq	ifr;

		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		retval = ioctl(skfd, SIOCGIFHWADDR, &ifr);
		if (retval >= 0)
		{
			memcpy( interface_mac_addr, ifr.ifr_hwaddr.sa_data, sizeof( qcsapi_mac_addr ) );
		}
		else
		  retval = -errno;
	}

	return( retval );
}

int
qcsapi_interface_get_mac_addr( const char *ifname, qcsapi_mac_addr interface_mac_addr )
{
	int		retval = 0;
	int		skfd = -1;

	enter_qcsapi();

	if (ifname == NULL || interface_mac_addr == NULL)
	  retval = -EFAULT;
	else
	{
		skfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	if (retval >= 0)
	{
		retval = local_interface_get_mac_addr( skfd, ifname, interface_mac_addr );
	}

	if (skfd >= 0)
	  close( skfd );

	leave_qcsapi();

	return( retval );
}

int
local_interface_set_ipaddr( const int skfd, const char *ifname, const char *if_ipaddr )
{
	int	retval = 0;

	if (ifname == NULL || if_ipaddr == NULL)
		retval = -EFAULT;
	else
	{
		struct ifreq	ifr;

		memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
		ifr.ifr_addr.sa_family = AF_INET;
		struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
		inet_pton(AF_INET, if_ipaddr, &addr->sin_addr);
		if (ioctl(skfd, SIOCSIFADDR, &ifr) < 0)
			retval = -errno;
	}

	return( retval );
}

int
local_interface_set_netmask( const int skfd, const char *ifname, const char *if_netmask )
{
	int	retval = 0;

	if (ifname == NULL || if_netmask == NULL)
		retval = -EFAULT;
	else
	{
		struct ifreq	ifr;

		memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
		ifr.ifr_addr.sa_family = AF_INET;
		struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
		inet_pton(AF_INET, if_netmask, &addr->sin_addr);
		if (ioctl(skfd, SIOCSIFNETMASK, &ifr) < 0)
			retval = -errno;
	}

	return( retval );
}

#define IP_ADDR_STR_LENGTH		16
int
qcsapi_interface_set_ip4( const char *ifname, const char *if_param, uint32_t if_param_val_ne)
{
	int             retval = 0;
	int             skfd = -1;
	uint32_t	if_param_val;
	char            addr_buf[IP_ADDR_STR_LENGTH];

	if (ifname == NULL || if_param == NULL)
		return -EFAULT;

	if_param_val = ntohl(if_param_val_ne);

	if (inet_ntop(AF_INET, &if_param_val, addr_buf, IP_ADDR_STR_LENGTH) == NULL) {
		retval = -errno;
		goto exit;
	}

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
	{
		retval = -errno;
		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0)
	{
		if (strcmp(if_param, "ipaddr") == 0)
			retval = local_interface_set_ipaddr(skfd, ifname, addr_buf);
		else if (strcmp(if_param, "netmask") == 0)
			retval = local_interface_set_netmask(skfd, ifname, addr_buf);
		else
			retval = -EINVAL;
	}

	if (skfd >= 0)
		close( skfd );
exit:
	return( retval );
}

int
local_interface_get_netmask( const int skfd, const char *ifname, string_64 if_netmask )
{
	int     retval = 0;
	struct ifreq    ifr;

	if (ifname == NULL || if_netmask == NULL)
		retval = -EFAULT;
	else
	{
		memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
		retval = ioctl(skfd, SIOCGIFNETMASK, &ifr);
		if (retval >= 0)
		{
			memcpy(if_netmask, inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_netmask )->sin_addr), sizeof(string_64));
		}
		else
			retval = -errno;
	}

	return( retval );
}

int
local_interface_get_ipaddr( const int skfd, const char *ifname, string_64 if_ipaddr)
{
	int     retval = 0;
	struct ifreq    ifr;

	if (ifname == NULL || if_ipaddr == NULL)
		retval = -EFAULT;
	else
	{
		memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
		retval = ioctl(skfd, SIOCGIFADDR, &ifr);
		if (retval >= 0)
		{
			memcpy(if_ipaddr, inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr), sizeof(string_64));
		}
		else
			retval = -errno;
	}

	return( retval );
}

int
local_interface_get_info( const int skfd, const char *ifname, string_64 if_param_val)
{
	int     retval = 0;
	string_64 buf;

	retval = local_interface_get_ipaddr(skfd, ifname, buf);
	sprintf(if_param_val, "IP Address: %s\t", buf);
	if (retval >= 0) {
		memset (buf, 0, sizeof(buf));
		retval = local_interface_get_netmask(skfd, ifname, buf);
		sprintf(if_param_val, "%sNetmask: %s", if_param_val, buf);
	}

	return( retval );
}

int
qcsapi_interface_get_ip4( const char *ifname, const char *if_param, string_64 if_param_val)
{
	int             retval = 0;
	int             skfd = -1;

	if (ifname == NULL || if_param_val == NULL)
		return -EFAULT;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
	{
		retval = -errno;
		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0)
	{
		if (if_param == NULL)
			retval = local_interface_get_info(skfd, ifname, if_param_val);
		else if (strcmp(if_param, "ipaddr") == 0)
			retval = local_interface_get_ipaddr(skfd, ifname, if_param_val);
		else if (strcmp(if_param, "netmask") == 0)
			retval = local_interface_get_netmask(skfd, ifname, if_param_val);
		else
			retval = -EINVAL;
	}

	if (skfd >= 0)
		close( skfd );

	return( retval );
}

int
qcsapi_interface_set_mac_addr( const char *ifname, const qcsapi_mac_addr interface_mac_addr)
{
	int		retval = 0;

	enter_qcsapi();

	if (ifname == NULL || interface_mac_addr == NULL)
		retval = -EFAULT;
	else
		retval = local_generic_verify_mac_addr_valid(interface_mac_addr);

	if (retval == 0)
	{
		int rc;
		FILE *file = NULL;
		int maclen;
		char maccmd[32];

		if (!strcmp(ifname, "wifi0")) {
			file = fopen( "/mnt/jffs2/wifi_mac_addrs","w" );
		} else if (!strcmp( ifname, "eth1_0" )) {
			file = fopen( "/mnt/jffs2/eth_macaddr","w" );
		}

		if (file != NULL) {
			sprintf(maccmd, "%02x:%02x:%02x:%02x:%02x:%02x\n",
				interface_mac_addr[0], interface_mac_addr[1], interface_mac_addr[2],
				interface_mac_addr[3], interface_mac_addr[4], interface_mac_addr[5]);
			maclen = strnlen(maccmd, sizeof(maccmd));
			rc = fwrite(maccmd, maclen, 1, file);
			if (rc == 1)
				retval = 0;
			else
				retval = -1;
			fclose(file);
		}
	}

	leave_qcsapi();

	return( retval );
}

#define IP_ADDR_STR_LEN		16
#define IPADDR_FILE		"/mnt/jffs2/ipaddr"
#define NETMASK_FILE		"/mnt/jffs2/netmask"
#define IPADDR_CHANGED_FILE	"/mnt/jffs2/ipaddr_changed"

int
qcsapi_store_ipaddr(qcsapi_unsigned_int ipaddr, qcsapi_unsigned_int netmask)
{
	int		retval = 0;
	char		addr_buf[IP_ADDR_STR_LEN];

	enter_qcsapi();

	if (inet_ntop(AF_INET, &ipaddr, addr_buf, IP_ADDR_STR_LEN) == NULL) {
		retval = -errno;
		goto exit;
	}

	retval = local_write_string_to_file(IPADDR_FILE, addr_buf);
	if (retval < 0)
		goto exit;

	if (inet_ntop(AF_INET, &netmask, addr_buf, IP_ADDR_STR_LEN) == NULL) {
		retval = -errno;
		goto exit;
	}

	retval = local_write_string_to_file(NETMASK_FILE, addr_buf);
	if (retval < 0)
		goto exit;

	// creating a file to indicate that ip address was changed
	retval = local_write_string_to_file(IPADDR_CHANGED_FILE, "1");
	if (retval < 0)
		goto exit;

exit:
	leave_qcsapi();

	return( retval );
}

int
local_interface_enable(const char *ifname, const int enable_flag)
{
	int		retval = 0;
	int		skfd = -1;
	struct ifreq	ifr;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0) {
	  retval = skfd;
	} else {
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		retval = ioctl(skfd, SIOCGIFFLAGS, &ifr);
		if (retval >= 0) {
			if (enable_flag) {
				ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
			} else {
				ifr.ifr_flags &= ~(IFF_UP);
			}

			retval = ioctl(skfd, SIOCSIFFLAGS, &ifr);
		}

		close( skfd );
	}

	if (retval < 0)
	  retval = -errno;

	return( retval );
}

int
qcsapi_interface_enable( const char *ifname, const int enable_flag )
{
	int		retval = 0;

	enter_qcsapi();

	retval = local_interface_enable(ifname, enable_flag);

	leave_qcsapi();

	return( retval );
}

int
local_interface_get_status(const int skfd, const char *ifname, qcsapi_interface_status_code *status_code)
{
	int		retval = 0;
	struct ifreq	ifr;
	int		interface_up_flags = IFF_UP | IFF_RUNNING;
	int		result_flags;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
	retval = ioctl(skfd, SIOCGIFFLAGS, &ifr);
	if (retval < 0) {
		*status_code = qcsapi_interface_status_error;
		return -errno;
	}

	result_flags = ifr.ifr_flags & interface_up_flags;
	if (result_flags == interface_up_flags)
		*status_code = qcsapi_interface_status_running;
	else if (result_flags == IFF_UP)
		*status_code = qcsapi_interface_status_up;
	else if (result_flags == 0)
		*status_code = qcsapi_interface_status_disabled;
	else
		*status_code = qcsapi_interface_status_error;

	return 0;
}

int
local_interface_get_status_string(const int skfd, const char *ifname, char *if_status, size_t status_size)
{
	int				retval = 0;
	qcsapi_interface_status_code	status_code = qcsapi_interface_status_error;

	if (status_size < QCSAPI_STATUS_MAXLEN)
		return -qcsapi_buffer_overflow;

	retval = local_interface_get_status(skfd, ifname, &status_code);
	if (retval < 0)
		return retval;

	if (status_code == qcsapi_interface_status_running)
		strcpy(if_status, "Running");
	else if (status_code == qcsapi_interface_status_up)
		strcpy(if_status, "Up");
	else if (status_code == qcsapi_interface_status_disabled)
		strcpy(if_status, "Disabled");
	else
		strcpy(if_status, "Error");

	return 0;
}

int
qcsapi_interface_get_status( const char *ifname, char *interface_status )
{
	int				retval = 0;
	int				skfd = -1;
	qcsapi_interface_status_code	status_code = qcsapi_interface_status_error;

	enter_qcsapi();

	if (ifname == NULL || interface_status == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_interface_get_status(skfd, ifname, &status_code);
	if (retval < 0)
		goto ready_to_return;

	/*
	 * qcsapi_interface_status_running is reported as "Up" and
	 * qcsapi_interface_status_up is treated as an error for backward compatibility.
	 */
	if (status_code == qcsapi_interface_status_running)
		strcpy(interface_status, "Up");
	else if (status_code == qcsapi_interface_status_disabled)
		strcpy(interface_status, "Disabled");
	else
		strcpy(interface_status, "Error");

ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int
qcsapi_eth_phy_power_control(int on_off, const char *interface)
{
	int		retval = 0;
	FILE		*phy_fd;
	char		cmd[2] = {0};

	if (on_off) {
		strcpy(cmd, "1");
	} else {
		strcpy(cmd, "0");
	}

	enter_qcsapi();

	retval =  local_interface_verify_net_device(interface);
	if (retval < 0)
		goto end;

	/*
	 * In the S40network script, the ethernet interface name is changed.
	 * If there are two interfaces, eth1_emac0 will be changed to eth1_1 and
         * eth1_emac1 will be changed to eth1_0.
	 * If there is only one interface,the interface name will be eth1_0
	 * no matter the interface is eth1_emac0 or eth1_emac1.
	 * But the file phy_pw0 is mapped to eth1_emac0 and phy_pw1 is mapped to
	 * eth1_emac1.
	 */
	if (strcmp(interface, "eth1_1") == 0) {

		/* There must be 2 emac ports using. eth1_1 --> phy_pw0 and eth1_0 --> phy_pw1*/
		phy_fd = fopen("/proc/phy_pw0", "w");
	} else if (strcmp(interface, "eth1_0") == 0) {
		phy_fd = fopen("/proc/phy_pw1", "w");
		/* This case is that only eth1_emac0 is used.*/
		if (!phy_fd) {
			phy_fd = fopen("/proc/phy_pw0", "w");
		}
	} else {
		retval = -errno;
		goto end;
	}

	if (phy_fd == NULL) {
		retval = -errno;
	} else {
		retval = fwrite(cmd, (strlen(cmd) + 1), 1, phy_fd);
		if (retval ==  1) {
			retval = 0;
		} else {
			retval = -1;
		}

		fclose(phy_fd);
	}
end:
	leave_qcsapi();

	return retval;
}

#define VMAC_SYS_FILE "/sys/class/net/pcie0/dbg"

int qcsapi_set_aspm_l1(int enable, int latency)
{
#define VMAC_ASPM_ENABLE_CMD		(69)
#define VMAC_ASPM_DISABLE_CMD		(70)
	char buffer[8] = {0};
	int vmac_fd = -1;
	int retval;

	vmac_fd = open(VMAC_SYS_FILE, O_WRONLY);
	if (vmac_fd < 0)
		retval = -ENXIO;

	if (enable) {
		if (latency < 7 && latency >= 0) {
			sprintf(buffer, "%d %d", VMAC_ASPM_ENABLE_CMD, latency);
			retval = 0;
		} else {
			retval = -EINVAL;
		}
	} else {
		sprintf(buffer, "%d", VMAC_ASPM_DISABLE_CMD);
		retval = 0;
	}

	if (vmac_fd && !retval) {
		retval = write(vmac_fd, buffer, sizeof(buffer));
	}

	if (vmac_fd)
		close(vmac_fd);

	return retval;

#undef VMAC_ASPM_DISABLE_CMD
#undef VMAC_ASPM_ENABLE_CMD
}

int qcsapi_set_l1(int enter)
{
	char buffer[3] = {0};
	int vmac_fd = -1;
	int cmd = 0;
	int retval;

	vmac_fd = open(VMAC_SYS_FILE, O_WRONLY);
	if (vmac_fd < 0) {
		return -ENXIO;
	}

	if (enter) {
		cmd = 71;
	} else {
		cmd = 72;
	}

	sprintf(buffer, "%d", cmd);
	retval = write(vmac_fd, buffer, sizeof(buffer));

	if (vmac_fd)
		close(vmac_fd);

	return retval;
}

#define  BOOT_CONFIG_FILE		"/proc/bootcfg/env"
#define  BOARDPARAM_CONFIG_FILE		"/proc/bootcfg/boardparam"
#define  BOOTCFG_COMMIT_FILE		"/proc/bootcfg/pending"
#define  GPIO_CONFIG_FILE		"/proc/bootcfg/gpio.bin"
#define  GPIO_CONFIG_SIZE		 0x200				/* 256 x 2 bytes */
#define  CREATE_GPIO_CONFIG		"create gpio.bin 0x200"
#define  GPIO_CONFIG_MAGIC		 0x1234
#define  GPIO_CONFIG_MAGIC_OFFSET	 sizeof( uint16_t )

/*
 * Program equivalent of command:
 *     echo “create gpio.bin 0x200” >/proc/syscfg/env
 */

static int
create_gpio_config( void )
{
	int	retval = 0;
	int	bootenv_fd = open( BOOT_CONFIG_FILE, O_WRONLY );
	int	gpio_fd = -1;

	if (bootenv_fd < 0)
	  retval = -ENXIO;
	else
	{
		int	ival = write( bootenv_fd, CREATE_GPIO_CONFIG, strlen( CREATE_GPIO_CONFIG ) + 1 );

	    //printf( "create_gpio_config, write to env returned %d\n", ival );
		if (ival < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EIO;
		}

		close( bootenv_fd );
	}

	if (retval >= 0)
	{
		gpio_fd = open( GPIO_CONFIG_FILE, O_WRONLY );

		if (gpio_fd < 0)
		  retval = -ENOENT;
	}

	if (retval >= 0)
	{
		char			base_gpio_config[ GPIO_CONFIG_SIZE ];
		int			ival = -1;
		union {
			char		as_bytes[ sizeof( uint16_t ) ];
			uint16_t	as_uint16;
		}			gpio_config_magic;

		memset( &base_gpio_config[ 0 ], 0, sizeof( base_gpio_config ) );

		gpio_config_magic.as_uint16 = GPIO_CONFIG_MAGIC;
		base_gpio_config[ 0 ] = gpio_config_magic.as_bytes[ 0 ];
		base_gpio_config[ 1 ] = gpio_config_magic.as_bytes[ 1 ];

		ival = write( gpio_fd, &base_gpio_config[ 0 ], GPIO_CONFIG_SIZE );
	    //printf( "create_gpio_config, write to gpio returned %d\n", ival );
		if (ival < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EIO;
		}

		close( gpio_fd );
	}

	return( retval );
}

/*
 * Do what it takes to access the GPIO config data.
 *
 * base_gpio_config is expected to address at least GPIO_CONFIG_SIZE bytes.
 */

static int
access_gpio_config( char *base_gpio_config, int access_flags )
{
	int	retval = 0;
	int	gpio_fd = -1;

	if (base_gpio_config == NULL)
	  retval = -EFAULT;
	else
	{
		gpio_fd = open( GPIO_CONFIG_FILE, O_RDONLY );
		if (gpio_fd < 0)
		{
			if (access_flags != O_RDONLY)
			{
				retval = create_gpio_config();
				if (retval >= 0)
				{
					gpio_fd = open( GPIO_CONFIG_FILE, O_RDONLY );
					if (gpio_fd < 0)
					  retval = -ENOENT;
				}
			}
			else
			  retval = -ENOENT;
		}
	}

	if (retval >= 0)
	{
		int	ival = read( gpio_fd, base_gpio_config, GPIO_CONFIG_SIZE );

	    //printf( "access_gpio_config, read returned %d\n", ival );
		if (ival < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EIO;
		}

		close( gpio_fd );
	}

	return( retval );
}

int
local_lookup_gpio_config( const uint8_t gpio_pin, qcsapi_gpio_config *p_gpio_config )
{
	int	retval = 0;
	char	base_gpio_config[ GPIO_CONFIG_SIZE ];

	if (gpio_pin > QCSAPI_MAX_LED)
	  retval = -EINVAL;
	else if (p_gpio_config == NULL)
	  retval = -EFAULT;
	else
	  retval = access_gpio_config( &base_gpio_config[ 0 ], O_RDONLY );

	if (retval >= 0)
	{
		*p_gpio_config = base_gpio_config[ gpio_pin + GPIO_CONFIG_MAGIC_OFFSET ];
	    //printf( "local_lookup_gpio_config config for pin %d is %d\n", gpio_pin, *p_gpio_config );
	}

	return( retval );
}

int
qcsapi_gpio_get_config( const uint8_t gpio_pin, qcsapi_gpio_config *p_gpio_config )
{
	int		retval = 0;

	enter_qcsapi();
/*
 * All functionality is in local_lookup_gpio_config, including check for p_gpio_config == NULL
 */
	retval = local_lookup_gpio_config( gpio_pin, p_gpio_config );

	leave_qcsapi();

	return( retval );
}

static int
local_update_gpio_config( const uint8_t gpio_pin, const qcsapi_gpio_config new_gpio_config )
{
	int	retval = 0;
	int	gpio_fd = -1;
	char	base_gpio_config[ GPIO_CONFIG_SIZE ];

	if (new_gpio_config != qcsapi_gpio_input_only &&
	    new_gpio_config != qcsapi_gpio_output &&
	    new_gpio_config != qcsapi_gpio_not_available)
	  retval = -EINVAL;
	else if (gpio_pin > QCSAPI_MAX_LED)
	  retval = -EINVAL;
	else
	{
		char	calstate_value[ 4 ] = { '\0' };
		int	ival = local_bootcfg_get_parameter( "calstate", &calstate_value[ 0 ], sizeof( calstate_value ) );

		if (ival < 0 || strcmp( &calstate_value[ 0 ], "1" ) != 0)
		  retval = -qcsapi_bringup_mode_only;
	}

	if (retval >= 0)
	{
		retval = access_gpio_config( &base_gpio_config[ 0 ], O_RDWR );
	}

	if (retval >= 0)
	{
	  /*
	   * File is supposed to exist now ...
	   */
		gpio_fd = open( GPIO_CONFIG_FILE, O_WRONLY );
		if (gpio_fd < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -ENOENT;
		}
	}

	if (retval >= 0)
	{
		int	ival;

		base_gpio_config[ gpio_pin + GPIO_CONFIG_MAGIC_OFFSET ] = (char) new_gpio_config;
		ival = write( gpio_fd, &base_gpio_config[ 0 ], GPIO_CONFIG_SIZE );

	    //printf( "local_update_gpio_config, write returned %d\n", ival );
		if (ival < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EIO;
		}

		close( gpio_fd );
		gpio_fd = -1;
	}

	return( retval );
}

int
qcsapi_gpio_set_config( const uint8_t gpio_pin, const qcsapi_gpio_config new_gpio_config )
{
	int		retval = 0;

	enter_qcsapi();
/*
 * All functionality is in local_update_gpio_config, including verifying the value of new_gpio_config
 */
	retval = local_update_gpio_config( gpio_pin, new_gpio_config );

	leave_qcsapi();

	return( retval );
}

/*
 *  Currently all LEDs are access thru the corresponding GPIO pins.
 */

static int
verify_led_ident( const uint8_t led_ident, const int input_flag )
{
	qcsapi_gpio_config	gpio_config;
	int			retval = local_lookup_gpio_config( led_ident, &gpio_config );

	if (retval >= 0)
	{
	  /*
	   * Use inverted logic (normally we start with retval = 0 and test for errors)
	   * as it is easier to follow here.
	   */
		retval = -EINVAL;

		if (gpio_config == qcsapi_gpio_output ||
		    (input_flag != 0 && gpio_config == qcsapi_gpio_input_only))
		  retval = 0;
	}

	return( retval );
}

#define ARC_GPIO_DIR		"/sys/class/gpio"
#define ARC_GPIO_PATH_MAXLEN	(40)

static int
open_gpio_file( const char *filename, const uint8_t led_ident, int mode )
{
	char	gpio_file_name[ARC_GPIO_PATH_MAXLEN];
	int	gpio_file_fd = -1;

	/*
	 * maybe
	 * /sys/class/gpio/gpioN/value
	 * or
	 * /sys/class/gpio/gpioN/direction
	 */
	if (snprintf(&gpio_file_name[0], sizeof(gpio_file_name),
			"%s/gpio%d/%s", ARC_GPIO_DIR,
			led_ident, filename) >= sizeof(gpio_file_name))
		goto ready_to_return;


	if ((gpio_file_fd = open(&gpio_file_name[0], mode)) < 0) {
		int	gpio_export_fd = -1;
		char	gpio_export_cmd[8];
		char	gpio_export_name[ARC_GPIO_PATH_MAXLEN];
		int	clen;
		int	ret;

		/*
		 * /sys/class/gpio/export
		 */
		if (snprintf(&gpio_export_name[0], sizeof(gpio_export_name),
				"%s/export", ARC_GPIO_DIR) >= sizeof(gpio_export_name))
			goto ready_to_return;


		if ((gpio_export_fd = open(&gpio_export_name[0], O_WRONLY)) >= 0) {

			clen = sprintf(&gpio_export_cmd[0], "%d", led_ident);

			ret = write(gpio_export_fd, gpio_export_cmd, clen + 1);

			close(gpio_export_fd);

			if (ret > 0)
				gpio_file_fd = open(&gpio_file_name[0], mode);
		}
	}
ready_to_return:
	return gpio_file_fd;
}

static int unexport_gpio(int gpio)
{
	char		path[ARC_GPIO_PATH_MAXLEN];
	char		cmd_data[8];
	int		cmd_data_len;
	int		gpio_unexport_fd = -1;
	int		ret = -1;
	struct stat	gpio_stat;

	if (snprintf(&path[0], sizeof(path), "%s/gpio%d", ARC_GPIO_DIR, gpio)
			>= sizeof(path)) {
		return -1;
	}

	if (stat(&path[0], &gpio_stat) < 0) {
		return -1;
	}

	snprintf(&path[0], sizeof(path), "%s/unexport", ARC_GPIO_DIR);
	if ((gpio_unexport_fd = open(&path[0], O_WRONLY)) >= 0) {
		cmd_data_len = snprintf(&cmd_data[0], sizeof(cmd_data), "%d", gpio);
		if (write(gpio_unexport_fd, cmd_data, cmd_data_len + 1) > 0)
			ret = 0;
		close(gpio_unexport_fd);
	}

	return ret;
}

int
local_led_get( const uint8_t led_ident, uint8_t *p_led_setting )
{
	int	retval = 0;
	int	gpio_fd = -1;

	if (p_led_setting == NULL)
	  retval = -EFAULT;
	else
	  retval = verify_led_ident(led_ident, 1);

	if (retval < 0)
		goto ready_to_return;

	retval = -EIO;
	if ((gpio_fd = open_gpio_file("value", led_ident, O_RDONLY)) >= 0)
	{

		char	tmpbuf[20];
		int	clen;
		int	value;

		clen = read(gpio_fd, tmpbuf, sizeof(tmpbuf) - 1);

		close(gpio_fd);

		if (clen > 0) {
			tmpbuf[clen] = 0;
			if(1 == sscanf(&tmpbuf[0], "%d", &value) &&
					(value == 0 || value == 1)) {
				*p_led_setting = (uint8_t)value;
				retval = 0;
			}
		}
	}

ready_to_return:
	return(retval);
}

int
qcsapi_led_get( const uint8_t led_ident, uint8_t *p_led_setting )
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_led_get(led_ident, p_led_setting);

	leave_qcsapi();

	return(retval);
}

int
qcsapi_led_set( const uint8_t led_ident, const uint8_t new_led_setting )
{
	int	retval = 0;
	int	gpio_fd = -1;

	enter_qcsapi();

	retval = verify_led_ident(led_ident, 0);

	if (retval < 0)
		goto ready_to_return;

	retval = -EIO;
	if ((gpio_fd = open_gpio_file("direction", led_ident, O_WRONLY)) >= 0)
	{
		char	*bufcmd;

		bufcmd = new_led_setting ? "high" : "low";

		if (write(gpio_fd, bufcmd, strlen(bufcmd) + 1) > 0)
			retval = 0;

		close(gpio_fd);
	}

ready_to_return:
	leave_qcsapi();
	return(retval);
}

int
local_led_pwm_enable(const uint8_t led_ident, const uint8_t onoff, const qcsapi_unsigned_int high_count, const qcsapi_unsigned_int low_count)
{
	char qdrv_command[64];

	switch (led_ident) {
		case QCSAPI_GPIO_PIN1:
		case QCSAPI_GPIO_PIN3:
		case QCSAPI_GPIO_PIN9:
		case QCSAPI_GPIO_PIN12:
		case QCSAPI_GPIO_PIN13:
		case QCSAPI_GPIO_PIN15:
		case QCSAPI_GPIO_PIN16:
			break;
		default:
			return -EINVAL;
	}

	if (onoff == 0) {
		snprintf(qdrv_command, sizeof(qdrv_command), "pwm disable %d", led_ident);
	} else {
		if (high_count > QCSAPI_MAX_PWM_COUNT || low_count > QCSAPI_MAX_PWM_COUNT ||
			high_count < QCSAPI_MIN_PWM_COUNT || low_count < QCSAPI_MIN_PWM_COUNT) {
			return -EINVAL;
		}
		snprintf(qdrv_command, sizeof(qdrv_command), "pwm enable %d %d %d", led_ident, high_count, low_count);
	}

	return local_wifi_write_to_qdrv(qdrv_command);
}

int
qcsapi_led_pwm_enable( const uint8_t led_ident, const uint8_t onoff, const qcsapi_unsigned_int high_count, const qcsapi_unsigned_int low_count )
{
	int retval = 0;

	enter_qcsapi();

	retval = local_led_pwm_enable(led_ident, onoff, high_count, low_count);

	leave_qcsapi();

	return (retval);
}

int
qcsapi_led_brightness(const uint8_t led_ident, const qcsapi_unsigned_int level)
{
	int retval = 0;
	uint8_t onoff = 1;
	uint32_t level_count[QCSAPI_MAX_BRIGHT_LEVEL] = {30, 20, 12, 8, 5, 4, 3, 2, 1, 0};

	enter_qcsapi();

	if (level < QCSAPI_MIN_BRIGHT_LEVEL || level > QCSAPI_MAX_BRIGHT_LEVEL) {
		retval = -EINVAL;
	} else {
		if (level == QCSAPI_MAX_BRIGHT_LEVEL)
			onoff = 0;

		retval = local_led_pwm_enable(led_ident, onoff, 1, level_count[level - 1] );
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_gpio_monitor_reset_device(
	const uint8_t reset_device_pin,
	const uint8_t active_logic,
	const int blocking_flag,
	reset_device_callback respond_reset_device
)
{
	int	retval = 0;
	uint8_t	led_setting;

	enter_qcsapi();

	if (getuid() != 0)
	  retval = -EPERM;
	else if (blocking_flag == 0)
	  retval = -EOPNOTSUPP;
	else if (active_logic != 1 && active_logic != 0)
	  retval = -EINVAL;
	else
	  retval = local_led_get( reset_device_pin, &led_setting );

	if (retval >= 0 && led_setting == active_logic)
	{
		retval = -EINVAL;
	}

	if (retval >= 0)
	{
		if (access( RESTORE_DEFAULT_CONFIG, X_OK ) != 0)
		{
			openlog("monitor reset device", LOG_CONS | LOG_NDELAY, LOG_DAEMON);
			syslog(LOG_WARNING, "No script to restore the default configuration\n" );
			closelog();
		}
	}

	leave_qcsapi();
  /*
   * Necessary to leave the QSCAPI at thsi point, since the
   * programming below will block the calling process until
   * the Reset Device button is pressed.
   */
	if (retval >= 0 && blocking_flag) {
		int	complete = 0;

		while (complete == 0) {
			sleep( 1 );

			retval = local_led_get( reset_device_pin, &led_setting );

			if (retval < 0) {
				continue;
			} else if (led_setting == active_logic) {
				complete = 1;
				if (respond_reset_device) {
					(*respond_reset_device)(reset_device_pin, led_setting);
				}
			}
		}
	}

	return( retval );
}

int
qcsapi_gpio_enable_wps_push_button(
	const uint8_t wps_push_button,
	const uint8_t active_logic,
	const uint8_t use_interrupt_flag
)
{
	int	retval = 0;
	uint8_t	led_setting;

	enter_qcsapi();

	if (getuid() != 0)
	  retval = -EPERM;
	else if (active_logic != 1 && active_logic != 0)
	  retval = -EINVAL;
	else
	  retval = local_led_get( wps_push_button, &led_setting );

	/* wps push button gpio would be used by qdrv exclusively,
	 * unexport it from user space */
	if (retval >= 0)
		unexport_gpio(wps_push_button);

	if (retval >= 0 && led_setting == active_logic && use_interrupt_flag)
	{
		retval = -EINVAL;
	}

	if (retval >= 0)
	{
		char	qdrv_command[ 32 ];

		if (use_interrupt_flag)
		  sprintf( &qdrv_command[ 0 ], "gpio set wps %u intr", wps_push_button );
		else
		  sprintf( &qdrv_command[ 0 ], "gpio set wps %u %u", wps_push_button, active_logic );

		retval = local_wifi_write_to_qdrv( &qdrv_command[ 0 ] );
	}

	leave_qcsapi();

	return( retval );
}

#define  FILE_PATH_CONFIG_FILE		"/proc/bootcfg/filepath.txt"
#define  FILE_PATH_CONFIG_SIZE		 0x400				/* 1024 bytes */
#define  CREATE_FILE_PATH_CONFIG	"create filepath.txt 0x400"
#define  FILE_PATH_CONFIG_MAGIC		 0x1234
#define  FILE_PATH_CONFIG_MAGIC_OFFSET	 sizeof( uint16_t )
#define  SECURITY_FILE_PATH_TOKEN	"security"
#define  SECURITY_FILE_PATH_DEFAULT	"/mnt/jffs2/"
#define  MAX_LENGTH_FILE_PATH		 80

/*
 * Program equivalent of command:
 *     echo “create filepath.txt 0x200” >/proc/syscfg/env
 */

static int
create_file_path_config( void )
{
	int	retval = 0;
	int	bootenv_fd = open( BOOT_CONFIG_FILE, O_WRONLY );
	int	file_path_fd = -1;

	if (bootenv_fd < 0)
	  retval = -ENXIO;
	else
	{
		int	ival = write( bootenv_fd, CREATE_FILE_PATH_CONFIG, strlen( CREATE_FILE_PATH_CONFIG ) + 1 );

	    //printf( "create_file_path_config, write to env returned %d\n", ival );
		if (ival < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EIO;
		}

		close( bootenv_fd );
	}

	if (retval >= 0)
	{
		file_path_fd = open( FILE_PATH_CONFIG_FILE, O_WRONLY );

		if (file_path_fd < 0)
		  retval = -ENOENT;
	}

	if (retval >= 0)
	{
		char			base_file_path_config[ FILE_PATH_CONFIG_SIZE ];
		int			ival = -1;
		union {
			char		as_bytes[ sizeof( uint16_t ) ];
			uint16_t	as_uint16;
		}			file_path_config_magic;

		memset( &base_file_path_config[ 0 ], 0, sizeof( base_file_path_config ) );

		file_path_config_magic.as_uint16 = FILE_PATH_CONFIG_MAGIC;
		base_file_path_config[ 0 ] = file_path_config_magic.as_bytes[ 0 ];
		base_file_path_config[ 1 ] = file_path_config_magic.as_bytes[ 1 ];

		ival = write( file_path_fd, &base_file_path_config[ 0 ], FILE_PATH_CONFIG_SIZE );
	    //printf( "create_file_path_config, write to file path returned %d\n", ival );
		if (ival < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EIO;
		}

		close( file_path_fd );
	}

	return( retval );
}

/*
 * Do what it takes to access the GPIO config data.
 *
 * base_file_path_config is expected to address at least GPIO_CONFIG_SIZE bytes.
 */

static int
access_file_path_config( char *base_file_path_config, int access_flags )
{
	int	retval = 0;
	int	file_path_fd = -1;

	if (base_file_path_config == NULL)
	  retval = -EFAULT;
	else
	{
		file_path_fd = open( FILE_PATH_CONFIG_FILE, O_RDONLY );
		if (file_path_fd < 0)
		{
			if (access_flags != O_RDONLY)
			{
				retval = create_file_path_config();
				if (retval >= 0)
				{
					file_path_fd = open( FILE_PATH_CONFIG_FILE, O_RDONLY );
					if (file_path_fd < 0)
					  retval = -ENOENT;
				}
			}
			else
			  retval = -ENOENT;
		}
	}

	if (retval >= 0)
	{
		int	ival = read( file_path_fd, base_file_path_config, FILE_PATH_CONFIG_SIZE );

	    //printf( "access_file_path_config, read returned %d\n", ival );
		if (ival < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EIO;
		}

		close( file_path_fd );
	}

	return( retval );
}

/*
 * Preliminary version.  Ony accepts qcsapi_security_configuration_path as a file path configuration.
 * Imposing this limitation makes the underlying programming a LOT simpler.
 * No need to shuffle strings around in the file, or look for the "\0\0" to end the file.
 */

int
local_lookup_file_path_config( const qcsapi_file_path_config e_file_path, char *file_path, qcsapi_unsigned_int path_size )
{
	int		 retval = 0;
	char		 base_file_path_config[ FILE_PATH_CONFIG_SIZE ];
	const char	*tmpaddr = &base_file_path_config[ FILE_PATH_CONFIG_MAGIC_OFFSET ];
	size_t		 length_file_path;

	if (e_file_path != qcsapi_security_configuration_path || path_size < 1)
	  return -EINVAL;
	else if (file_path == NULL)
	  return -EFAULT;

	retval = access_file_path_config( &base_file_path_config[ 0 ], O_RDONLY );

	/* If file does not exist return default path */
	if (retval < 0)
	{
		length_file_path = strlen( SECURITY_FILE_PATH_DEFAULT );
		if (length_file_path + 1 > path_size)
		  retval = -ENOMEM;
		else
		{
			strncpy(file_path, SECURITY_FILE_PATH_DEFAULT, length_file_path + 1);
			retval = 0;
		}
	}
	else
	{
		if (strncmp( SECURITY_FILE_PATH_TOKEN, tmpaddr, strlen( SECURITY_FILE_PATH_TOKEN )) != 0)
		{
			file_path[ 0 ] = '\0';
		}
		else
		{
			tmpaddr += strlen( SECURITY_FILE_PATH_TOKEN );

			while (isspace( *tmpaddr ) != 0)
			  tmpaddr++;

			length_file_path = strlen( tmpaddr );
			if (length_file_path + 1 > path_size)
			  retval = -ENOMEM;
			else
			{
				strcpy( file_path, tmpaddr );
			}
		}
	}

	return( retval );
}

int
qcsapi_file_path_get_config( const qcsapi_file_path_config e_file_path, char *file_path, qcsapi_unsigned_int path_size )
{
	int	retval = 0;

	enter_qcsapi();
/*
 * All functionality is in local_lookup_file_path_config.
 */
	retval = local_lookup_file_path_config( e_file_path, file_path, path_size );

	leave_qcsapi();

	return( retval );
}

/*
 * Preliminary version.  Ony accepts qcsapi_security_configuration_path as a file path configuration.
 * Imposing this limitation makes the underlying programming a LOT simpler.
 * No need to shuffle strings around in the file, or look for the "\0\0" to end the file.
 */

int
local_update_file_path_config( const qcsapi_file_path_config e_file_path, const char *new_path )
{
	int	 retval = 0;
	int	 file_path_fd = -1;
	char	 base_file_path_config[ FILE_PATH_CONFIG_SIZE ];
	char	*tmpaddr = &base_file_path_config[ FILE_PATH_CONFIG_MAGIC_OFFSET ];

	if (e_file_path != qcsapi_security_configuration_path)
	  retval = -EINVAL;
	else if (new_path == NULL)
	  retval = -EFAULT;
	else
	{
		char	calstate_value[ 4 ] = { '\0' };
		int	ival = local_bootcfg_get_parameter( "calstate", &calstate_value[ 0 ], sizeof( calstate_value ) );

		if (ival < 0 || strcmp( &calstate_value[ 0 ], "1" ) != 0)
		  retval = -qcsapi_bringup_mode_only;
	}

	if (retval >= 0)
	{
		size_t	path_size = strnlen( new_path, MAX_LENGTH_FILE_PATH + 1 );

		if (path_size > MAX_LENGTH_FILE_PATH)
		  retval = -EINVAL;
	}

	if (retval >= 0)
	  retval = access_file_path_config( &base_file_path_config[ 0 ], O_RDWR );

	if (retval >= 0)
	{
	  /*
	   * File is supposed to exist now ...
	   */
		file_path_fd = open( FILE_PATH_CONFIG_FILE, O_WRONLY );
		if (file_path_fd < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -ENOENT;
		}
	}

	if (retval >= 0)
	{
		int	ival;

		sprintf( tmpaddr, "%s %s", SECURITY_FILE_PATH_TOKEN, new_path );

		ival = write( file_path_fd, &base_file_path_config[ 0 ], FILE_PATH_CONFIG_SIZE );

	    //printf( "local_update_file_path_config, write returned %d\n", ival );
		if (ival < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EIO;
		}

		close( file_path_fd );
	}

	return( retval );
}

int
qcsapi_file_path_set_config( const qcsapi_file_path_config e_file_path, const char *new_path )
{
	int	retval = 0;

	enter_qcsapi();
/*
 * All functionality is in local_update_file_path_config.
 */
	retval = local_update_file_path_config( e_file_path, new_path );

	leave_qcsapi();

	return( retval );
}

#define MTD_DEV_ENTRY_MAX_SIZE	 12
#define MTD_PROC_ENTRY		"/proc/mtd"
#define CHKIMAGE_PROG		"chkimage"
#define CHKIMAGE_ARGC		 8
#define ERASE_FLASH_PROG	"flash_eraseall"
#define ERASE_FLASH_ARGC	 1
#define COPY_IMAGE_FLASH_PROG	"cp"
#define COPY_IMAGE_FLASH_ARGV	 2

/*
 * Returns 1 if target device / partition was found, 0 if not found.
 * mtd_device is updated if the partition has "linux" in its name.
 * mtd_device is expected to address a buffer with at least 12 chars ...
 * (MTD_DEV_ENTRY_MAX_SIZE)
 */

static int
local_process_mtd_proc_line(const char *mtd_proc_line,
			    const qcsapi_flash_partiton_type partition_to_update,
			    char *mtd_device,
			    size_t *p_partition_size)
{
	int		 retval = 0;
	const char	*tmpaddr = NULL;

	while (isspace( *mtd_proc_line )) {
		mtd_proc_line++;
	}

	if (strncmp( "mtd", mtd_proc_line, 3 ) != 0) {
		return( 0 );
	}

	if ((tmpaddr = strstr( mtd_proc_line, ":" )) == NULL) {
		local_generic_syslog("Flash Image Update",
				      LOG_ERR,
				     "Cannot parse line \"%s\" from %s",
				      mtd_proc_line,
				      MTD_PROC_ENTRY);

		return( 0 );
	}

	if (strcasestr( mtd_proc_line, "linux" ) != NULL) {
		int		mtd_unit = atoi( mtd_proc_line + 3 );
		unsigned int	local_partition_size = 0;
	  /*
	   * Sanity check - restrict range of the MTD unit to [0 - 9]
	   */
		if (mtd_unit > 9 || mtd_unit < 0) {
			local_generic_syslog("Flash Image Update",
					      LOG_ERR,
					     "Unexpected MTD unit %d in %s",
					      mtd_unit,
					      MTD_PROC_ENTRY);

			return( 0 );
		}
	  /*
	   * tmpaddr points to the size in hexadecimal
	   */
		tmpaddr++;

		while (isspace( *tmpaddr ))
		  tmpaddr++;

		sscanf( tmpaddr, "%x", &local_partition_size );
		if (p_partition_size != NULL) {
			*p_partition_size = (size_t) local_partition_size;
		}

		sprintf( mtd_device, "/dev/mtd%d", mtd_unit );
		if (partition_to_update == qcsapi_safety_image) {
			if (strcasestr( mtd_proc_line, "safety" ) != NULL) {
				retval = 1;
			}
		} else {
			if (strcasestr( mtd_proc_line, "live" ) != NULL) {
				retval = 1;
			}
		}
	}

	return( retval );
}

/*
 * Special note:  char *mtd_device is expected to address a buffer with at least 10 chars ...
 */

static int
local_verify_flash_update_image( const char *flash_image_file, size_t max_size )
{
	struct stat	image_file_stat;
	int		retval = stat(flash_image_file, &image_file_stat);

	if (retval >= 0) {
		if (S_ISREG( image_file_stat.st_mode ) == 0) {
			retval = -qcsapi_invalid_type_image_file;
		} else if (image_file_stat.st_size > max_size ) {
			retval = -EFBIG;
		}
	}

  /*
   * Command: "chkimage -A arc -O linux -T kernel -v <flash image file>"
   */
	if (retval >= 0) {
		const char	*chkimage_argv[ CHKIMAGE_ARGC ];
		int		 signal_number = 0;
		int		 exit_status = -1;

		chkimage_argv[ 0 ] = "-A";
		chkimage_argv[ 1 ] = "arc";		// BBIC3 ONLY !!!
		chkimage_argv[ 2 ] = "-O";
		chkimage_argv[ 3 ] = "linux";
		chkimage_argv[ 4 ] = "-T";
		chkimage_argv[ 5 ] = "kernel";
		chkimage_argv[ 6 ] = "-v";
		chkimage_argv[ 7 ] = flash_image_file;

		retval = local_generic_run_a_command(CHKIMAGE_PROG,
						     CHKIMAGE_ARGC,
						     chkimage_argv,
						     0,
						    &exit_status,
						    &signal_number);

		if (retval >= 0) {
			if (signal_number != 0 || exit_status != 0) {
				retval = -qcsapi_image_file_failed_chkimage;
			}
		}
	}

	return( retval );
}

static int
local_flash_locate_partition(const qcsapi_flash_partiton_type partition_to_update,
			     char *mtd_device,
			     size_t *p_partition_size)
{
	int		 retval = 0;

	if (partition_to_update != qcsapi_live_image && partition_to_update != qcsapi_safety_image) {
		local_generic_syslog("Flash Image Update",
				      LOG_ERR,
				     "Invalid flash memory partition %d",
				      partition_to_update);
		retval = -EINVAL;
	} else {
		int	 complete = 0;
		char	 mtd_proc_line[ 40 ];
		FILE	*mtd_proc_fh = fopen( MTD_PROC_ENTRY, "r" );

		if (mtd_proc_fh == NULL) {
			retval = -errno;
			if (retval >= 0) {
				retval = -ENOENT;
			}
		} else {
			while (complete == 0 &&
			       read_to_eol( &mtd_proc_line[ 0 ], sizeof( mtd_proc_line ), mtd_proc_fh ) != NULL) {
				complete = local_process_mtd_proc_line(&mtd_proc_line[ 0 ],
									partition_to_update,
									mtd_device,
									p_partition_size);
			}

			fclose( mtd_proc_fh );

			if (complete == 0) {
				retval = -qcsapi_flash_partition_not_found;
			}
		}
	}

	return( retval );
}

static int
local_erase_flash_partition( const char *mtd_device )
{
	int		 retval = 0;
	const char	*erase_flash_partition_argv[ ERASE_FLASH_ARGC ];
	int		 signal_number = 0;
	int		 exit_status = -1;

	erase_flash_partition_argv[ 0 ] = mtd_device;

	retval = local_generic_run_a_command(ERASE_FLASH_PROG,
					     ERASE_FLASH_ARGC,
					     erase_flash_partition_argv,
					     0,
					    &exit_status,
					    &signal_number);

	if (retval >= 0) {
		if (signal_number != 0 || exit_status != 0) {
			retval = -qcsapi_erase_flash_failed;
		}
	}

	return( retval );
}

static int
local_copy_image_to_flash( const char *image_file, const char * mtd_device )
{
	int		 retval = 0;
	const char	*copy_image_to_flash_argv[ COPY_IMAGE_FLASH_ARGV ];
	int		 signal_number = 0;
	int		 exit_status = -1;

	copy_image_to_flash_argv[ 0 ] = image_file;
	copy_image_to_flash_argv[ 1 ] = mtd_device;

	retval = local_generic_run_a_command(COPY_IMAGE_FLASH_PROG,
					     COPY_IMAGE_FLASH_ARGV,
					     copy_image_to_flash_argv,
					     0,
					    &exit_status,
					    &signal_number);

	if (retval >= 0) {
		if (signal_number != 0 || exit_status != 0) {
			retval = -qcsapi_copy_image_flash_failed;
		}
	}

	return( retval );
}

int
qcsapi_flash_image_update( const char *image_file, qcsapi_flash_partiton_type partition_to_update )
{
	int		retval = 0;
	char		mtd_device[ MTD_DEV_ENTRY_MAX_SIZE ] = { '\0' };
	size_t		partition_size = 0;

	enter_qcsapi();

	if (image_file == NULL) {
		retval = -EFAULT;
	}
	else {
		retval = local_flash_locate_partition( partition_to_update, &mtd_device[ 0 ], &partition_size );
	}

	if (retval >= 0) {
		retval = local_verify_flash_update_image( image_file, partition_size );
	}

	if (retval >= 0) {
		local_generic_syslog("Flash Image Update",
				      LOG_NOTICE,
				     "Preparing to upgrade %s with %s",
				      &mtd_device[ 0 ], image_file);
		retval = local_erase_flash_partition( &mtd_device[ 0 ] );
	}

	if (retval >= 0) {
		retval = local_copy_image_to_flash( image_file, &mtd_device[ 0 ] );
	}

	leave_qcsapi();

	return( retval );
}

/*
 * Note: image_file_path and image_flags parameters are not used in the function at the moment,
 * they are passed through QFTC CONNECT command to the server
 */
int qcsapi_send_file(const char *image_file_path, const int image_flags)
{
	int retval = 0;
	const char *sh_argv[] = {
		"-c",
		"/sbin/qfts &"
	};
	int signal_number = 0;
	int exit_status = -1;

	enter_qcsapi();

	retval = local_generic_run_a_command("sh", 2, sh_argv, 0, &exit_status, &signal_number);

	if ((retval >= 0) && (signal_number != 0 || exit_status != 0))
		retval = -EFAULT;

	leave_qcsapi();

	return retval;
}

#define FIRMWARE_GET_VERSION_MIN_LEN	3

int
qcsapi_firmware_get_version( char *firmware_version, const qcsapi_unsigned_int version_size )
{
	int	retval = 0;

	enter_qcsapi();

	if (firmware_version == NULL) {
		retval = -EFAULT;
	}
	else if (version_size < FIRMWARE_GET_VERSION_MIN_LEN) {
		retval = -qcsapi_buffer_overflow;
	} else {
		retval = local_wifi_write_to_qdrv( "get 0 fwver" );
	}

	if (retval >= 0) {
		retval = local_read_string_from_file( QDRV_RESULTS, firmware_version, version_size );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_system_get_time_since_start(qcsapi_unsigned_int *p_elapsed_time)
{
	int		retval = 0;
	struct sysinfo	info;

	enter_qcsapi();

	if (p_elapsed_time == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = sysinfo(&info);

	if (retval >= 0) {
		*p_elapsed_time = (qcsapi_unsigned_int) info.uptime;
	}

  ready_to_return:
	leave_qcsapi();

	return( retval );
}

int
qcsapi_get_system_status(qcsapi_unsigned_int *p_status)
{
	int retval = 0;
	FILE *status_fd = NULL;
	char line[1024] = {0};
	enter_qcsapi();

	if (p_status == NULL) {
		retval = -EFAULT;
	}

	if (retval >=0 ) {
		*p_status = 0;
		status_fd = fopen(QCSAPI_SYSTEM_STATUS_FILE, "r");
		if (status_fd) {
			if (fgets(line, sizeof(line), status_fd) != NULL) {
				sscanf(line, "%u", p_status);
			}
			fclose(status_fd);
		} else {
			retval = -ENOENT;
		}
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_get_random_seed(struct qcsapi_data_512bytes *random_buf)
{
	int retval = 0;
	FILE *urandom_file = NULL;
	size_t items_read = 0;

	if (!random_buf) {
		retval = -EFAULT;
	}

	enter_qcsapi();

	urandom_file = fopen("/dev/urandom", "r");
	if (urandom_file == NULL) {
		retval = -errno;
	}

	if (retval >= 0) {
		items_read = fread(&random_buf->data[0],
				sizeof(random_buf->data[0]),
				ARRAY_SIZE(random_buf->data),
				urandom_file);
		if (items_read != ARRAY_SIZE(random_buf->data)) {
			if (ferror(urandom_file)) {
				retval = -EIO;
			} else {
				retval = -ENODATA;
			}
		}
	}

	if (urandom_file) {
		if (fclose(urandom_file) != 0) {
			retval = -errno;
		}
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_set_random_seed(const struct qcsapi_data_512bytes *random_buf,
		const qcsapi_unsigned_int entropy)
{
	int retval = 0;
	int urandom_fd = -1;
	struct rand_pool_info *rand_pool_info = NULL;

	if (!random_buf) {
		retval = -EFAULT;
	}

	enter_qcsapi();

	urandom_fd = open("/dev/urandom", O_RDWR);
	if (urandom_fd < 0) {
		retval = -errno;
	}

	if (retval >= 0) {
		rand_pool_info = malloc(sizeof(*rand_pool_info) + sizeof(random_buf->data));
		if (!rand_pool_info) {
			retval = -ENOMEM;
		} else {
			rand_pool_info->entropy_count = entropy;
			rand_pool_info->buf_size = sizeof(random_buf->data) /
					sizeof(rand_pool_info->buf[0]);
			memcpy((void *)rand_pool_info->buf, (void *)random_buf->data,
					sizeof(random_buf->data));

			retval = ioctl(urandom_fd, RNDADDENTROPY, rand_pool_info);
			if (retval < 0) {
				retval = -errno;
			}
		}
	}

	free(rand_pool_info);
	if (urandom_fd >= 0) {
		if (close(urandom_fd) == -1) {
			retval = -errno;
		}
	}

	leave_qcsapi();

	return retval;
}

/*
 * Disconnect from the controlling terminal.
 * Required for a process to run in background.
 *
 * Do not call enter_qcsapi / leave_qcsapi as this API creates a child process.
 * If the child process is successfully created, the parent exits.  Facility
 * enter_qcsapi / leave_qcsapi is in place in case we ever need to work with
 * a synchronization construct (semaphore) in connection with these APIs.
 */

int
qcsapi_console_disconnect( void )
{
        /* Our process ID and Session ID */
	pid_t pid, sid;

	pid = fork();
	if (pid < 0) {
		return( -qcsapi_process_table_full );
	}
        /*
	 * If we got a good PID, then parent process exits.
	 */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	umask(0);

        /* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		return( -qcsapi_programming_error );
	}

	if ((chdir("/")) < 0) {
		return( -qcsapi_programming_error );
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	return( 0 );
}

/*
 * Special demonstration API to set the WiFi MAC address.
 * To be called between starting the Q driver (and thus setting the MAC address thru set_macaddr)
 * and selecting the WiFi mode for the VAP (e.g. wifi0), STA or AP.
 *
 * No error checking currently.
 *
 * Although formally a WiFi API, the source is present here as it really is / should be a generic API.
 */
int
qcsapi_wifi_set_wifi_macaddr( const qcsapi_mac_addr new_mac_addr )
{
	int		retval = 0;

	enter_qcsapi();

	if (new_mac_addr == NULL)
	  retval = -EFAULT;
	else
	  retval = local_generic_verify_mac_addr_valid( new_mac_addr );

	if (retval == 0)
	{
		char	qdrv_command[ 48 ];

		sprintf( &qdrv_command[ 0 ], "set wifimacaddr %02x:%02x:%02x:%02x:%02x:%02x",
			  new_mac_addr[ 0 ],
			  new_mac_addr[ 1 ],
			  new_mac_addr[ 2 ],
			  new_mac_addr[ 3 ],
			  new_mac_addr[ 4 ],
			  new_mac_addr[ 5 ]
		);
		retval = local_wifi_write_to_qdrv( &qdrv_command[ 0 ] );
	}

	leave_qcsapi();

	return( retval );
}

static void
local_rotate_file(const char *file_path)
{
	struct stat st;
	char new_file_path[sizeof(API_LOG_FILE) + 5] = { 0 };

	if (stat(file_path, &st) != 0)
		return ;

	if (st.st_size < API_LOG_FILE_LIMIT_SIZE)
		return ;

	strncpy(new_file_path, file_path, sizeof(API_LOG_FILE));
	strcat(new_file_path, ".0");

	rename(file_path, new_file_path);

	return ;
}

int
local_append_string_to_file( const char *file_path, const char *file_contents )
{
	int	 retval = 0;
	FILE	*update_fh;

	local_rotate_file(file_path);

	update_fh = fopen(file_path, "a");

	if (update_fh == NULL)
	{
		retval = -errno;
		if (retval >= 0)
		  retval = -1;
	}

	if (retval >= 0)
	{
		retval = fputs( file_contents, update_fh );
	}

	if (update_fh != NULL)
	{
		fclose( update_fh );
	}

	return( retval );
}

int
local_generic_syslog( const char *ident, int priority, const char *format, ... )
{
	va_list	ap;
	char	syslog_message[ LOCAL_SYSLOG_MESSAGE_SIZE ];
	size_t	syslog_msglen;
	size_t	index_last_char = 0;
	int	append_newline = 1;

	va_start( ap, format );
	vsnprintf( &syslog_message[ 0 ], sizeof( syslog_message ), format, ap );

	syslog_msglen = strnlen( &syslog_message[ 0 ], sizeof( syslog_message ) - 1 );
	if (syslog_msglen < 1) {
		return( -1 );
	}

	openlog( ident, LOG_CONS | LOG_PID, priority );
	syslog( priority, "%s", &syslog_message[ 0 ] );
	closelog();

	if (syslog_msglen > sizeof( syslog_message ) - 1) {
		index_last_char = sizeof( syslog_message ) - 2;
	} else {
		index_last_char = syslog_msglen - 1;
	}

	if (syslog_message[ index_last_char ] == '\n') {
		append_newline = 0;
	}

	local_append_string_to_file( API_LOG_FILE, &syslog_message[ 0 ] );
	if (append_newline) {
		local_append_string_to_file( API_LOG_FILE, "\n" );
	}

	return( 0 );
}

static int
local_cfg_get_parameter(const char *filename,
	const char *parameter_name,
	char *parameter_value,
	const size_t value_length,
	char sep)
{
	int retval = 0;
	char line_from_file[QCSAPI_MAX_PARAMETER_NAME_LEN + QCSAPI_MAX_PARAMETER_VALUE_LEN + 3];
	FILE *fh = fopen(filename, "r");
	int complete = 0;

	if (fh == NULL) {
		return -errno;
	}

	if (parameter_name == NULL || parameter_value == NULL) {
		fclose(fh);
		return -EFAULT;
	}

	while (fgets(&line_from_file[0], sizeof(line_from_file), fh) != NULL && complete == 0) {
		char *addr_param_value = strchr(&line_from_file[0], sep);

		if (addr_param_value != NULL) {
			*addr_param_value = '\0';
			addr_param_value++;

			if (strcmp(&line_from_file[ 0 ], parameter_name) == 0) {
				char *tmpaddr = strchr(addr_param_value, '\n');

				if (tmpaddr != NULL) {
					*tmpaddr = '\0';
				}

				if (strlen(addr_param_value) < value_length) {
					strcpy(parameter_value, addr_param_value);
				} else {
					retval = -ENOBUFS;
				}

				complete = 1;
			}
		}
	}

	if (complete == 0) {
		retval = -ENODATA;
	}

	fclose(fh);

	return retval;
}

int
local_bootcfg_get_parameter(const char *parameter_name, char *parameter_value,
	const size_t value_length)
{
	return local_cfg_get_parameter(BOOT_CONFIG_FILE,
		parameter_name, parameter_value, value_length, '=');
}

int
local_boardparam_get_parameter(const char *parameter_name, char *parameter_value,
	const size_t value_length)
{
	return local_cfg_get_parameter(BOARDPARAM_CONFIG_FILE,
		parameter_name, parameter_value, value_length, '\t');
}

static int
local_bootcfg_commit(void)
{
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE] = {0};

	sprintf(cmd, "cat %s > /dev/null", BOOTCFG_COMMIT_FILE);
	if (system(cmd) == -1) {
		return -1;
	} else {
		return 0;
	}
}

int
qcsapi_bootcfg_commit(void)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_bootcfg_commit();

	leave_qcsapi();

	return retval;
}

int
local_bootcfg_set_parameter( const char *parameter_name, const char *parameter_value,
				const int write_flash)
{
	int	 retval = 0;
	FILE	*env_fh = fopen(BOOT_CONFIG_FILE, "w");

	if (env_fh == NULL) {
		retval = -errno;

		if (retval >= 0) {
			retval = -ENOENT;
		}

		return(retval);
	} else {
		if (parameter_name == NULL || parameter_value == NULL) {
			fclose(env_fh);
			return(-EFAULT);
		}
	}

	if ((strnlen(parameter_name, QCSAPI_MAX_PARAMETER_NAME_LEN + 1) >
				QCSAPI_MAX_PARAMETER_NAME_LEN) ||
			(strnlen(parameter_value, QCSAPI_MAX_PARAMETER_VALUE_LEN + 1) >
				QCSAPI_MAX_PARAMETER_VALUE_LEN)) {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		fprintf(env_fh, "%s %s", parameter_name, parameter_value );
		if (write_flash)
			retval = local_bootcfg_commit();
	}

	fclose(env_fh);

	return(retval);
}

int
local_interface_connect_to_bridge( const char *ifname, const char *bridge_dev, const int enable_flag )
{
	int		retval = 0;
	int		skfd = -1;
	struct ifreq	ifr;

	memset( (char *) &ifr, 0, sizeof( ifr ) );

	if (ifname == NULL || bridge_dev == NULL)
	  retval = -EFAULT;
	else
	{
	  /*
	   * Character string in struct ifreq is IFNAMSIZ.
	   * Leave space for terminating NUL character.
	   */
		if ((strnlen( ifname, IFNAMSIZ + 1 ) >= IFNAMSIZ) ||
		    (strnlen( bridge_dev, IFNAMSIZ + 1 ) >= IFNAMSIZ))
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		skfd = socket( AF_INET, SOCK_DGRAM, 0 );
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	if (retval >= 0)
	{
		if ( (ifr.ifr_ifindex = if_nametoindex( ifname )) == 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -ENODEV;
		}
	}

	if (retval >= 0)
	{
	  /*
 	   * We know bridge_dev is short enough to fit ...
 	   */
		strcpy(ifr.ifr_name, bridge_dev );

		retval = ioctl( skfd, (enable_flag == 0) ? SIOCBRDELIF : SIOCBRADDIF, &ifr );
		if (retval < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EIO;
		}
	}

	if (skfd >= 0)
	  close( skfd );

	return( retval );
}

int
local_write_string_to_file( const char *file_path, const char *file_contents )
{
	int	 retval = 0;
	FILE	*update_fh = fopen( file_path, "w" );

	if (update_fh == NULL)
	{
		retval = -errno;
		if (retval >= 0)
		  retval = -1;
	}

	if (retval >= 0)
	{
		retval = fputs( file_contents, update_fh );
	}

	if (update_fh != NULL)
	{
		fclose( update_fh );
	}

	return( retval );
}

int
local_read_string_from_file( const char *file_path, char *file_contents, const unsigned int sizeof_contents )
{
	int	 retval = 0;
	FILE	*status_fh = fopen( file_path, "r" );

	if (status_fh == NULL)
	{
		retval = -errno;
		if (retval >= 0)
		  retval = -ENOENT;
	}

	if (retval >= 0)
	{
		char	*tmpaddr = NULL;
	  /*
	   * fgets() reads in at most one less than sizeof_contents characters from status_fh
	   */
		if (fgets( file_contents, (int) sizeof_contents, status_fh ) == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EIO;
		}
	  /*
 	   * Remove the new-line char if found in the file contents,
 	   * so the application can call strcmp without worrying about '\n'.
 	   */
		tmpaddr = strchr( file_contents, '\n' );
		if (tmpaddr != NULL)
		  *tmpaddr = '\0';
	}

	if (status_fh != NULL)
	{
		fclose( status_fh );
	}

	return( retval );
}

int
local_wifi_get_security_defer_mode(void)
{
	int defer = 0;
	FILE	*status_fh = fopen( LOCAL_DEFER_CONFIG, "r" );

	if (status_fh) {
		defer = 1;
		fclose(status_fh);
	}

	return defer;
}

int local_wifi_security_update_mode(void)
{
	int defer = local_wifi_get_security_defer_mode();

	if (1 == defer)
		return security_update_pending;
	else
		return security_update_complete;
}

int
local_wifi_set_security_defer_mode(int defer)
{
	int retval = 0;
	FILE	*status_fh = NULL;

	if (1 == defer) {
		status_fh = fopen(LOCAL_DEFER_CONFIG, "wb");
		if (!status_fh)
			retval = -ENOENT;
		else
			fclose(status_fh);
	} else {
		status_fh = fopen(LOCAL_DEFER_CONFIG, "r");
		if (status_fh) {
			fclose(status_fh);
			unlink(LOCAL_DEFER_CONFIG);
		}
	}

	return retval;
}

char *
read_to_eol( char *address, int size, FILE *fh )
{
	int	 current_char = 0;
	int	 read_complete = 0;
	char	*xfer_addr = address;
	char	*retaddr = address;
	int	 xfer_count = 0;

	if (address != NULL && size >= 2)
	{
		while (xfer_count < size - 1 && read_complete == 0)
		{
			current_char = fgetc( fh );
			if (current_char == EOF || current_char == '\n')
			  read_complete = 1;

			if (current_char != EOF)
			{
				*xfer_addr = current_char;
				xfer_addr++;
				xfer_count++;
			}
		}
	}

	if (xfer_addr != NULL)
	  *xfer_addr = '\0';

	while (read_complete == 0)
	{
		current_char = fgetc( fh );
		if (current_char != EOF)
		  xfer_count++;

		if (current_char == EOF || current_char == '\n')
		  read_complete = 1;
	}

	if (xfer_count == 0)
	  retaddr = NULL;

	return( retaddr );
}

int
local_interface_verify_net_device( const char *ifname )
{
	int	 retval = 0;
	FILE	*proc_net_dev_fh = NULL;

	if (ifname == NULL)
	  retval = -EFAULT;
	else
	{
		proc_net_dev_fh = fopen( _PATH_PROCNET_DEV, "r" );

		if (proc_net_dev_fh == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -ENOENT;
		}
	}

	if (retval >= 0)
	{
		char	tmpbuf[ IFNAMSIZ + 4 ];
		int	complete = 0;

		while (complete == 0 && read_to_eol( &tmpbuf[ 0 ], sizeof( tmpbuf ), proc_net_dev_fh ) != NULL)
		{
			char	namebuf[ IFNAMSIZ + 4 ];
		  /*
		   * Note: get_name will look at no more than IFNAMSIZ chars.  See implementation, above.
		   * Leave room for colon and space char following the interface name.
		   */
			local_interface_get_name( &namebuf[ 0 ], &tmpbuf[ 0 ] );
			if (strcmp( &namebuf[ 0 ], ifname ) == 0)
			  complete = 1;
		}

		if (complete == 0)
		  retval = -ENODEV;
	}

	if (proc_net_dev_fh != NULL)
	  fclose( proc_net_dev_fh );

	return( retval );
}

/*
 * Program accepts the argument count and argument vector,
 * creates a separate copy of the argument vector.  Reason
 * is the argv passed to execvp is required to be terminated
 * with a NULL address, and this requirement should not be
 * pushed back onto the calling program.
 *
 * XXX: consider requiring the calling program to put the
 *      name of the program in argv[0], rather than effectively
 *      inserting "command" as argv[0].
 */

int
local_generic_run_a_command(const char *command,
			    const int argc,
			    const char *argv[],
			    const int subprocess_flags,
			    int *p_exit_status,
			    int *p_signal_number)
{
	int		  retval = 0;
	int		  iter;
	pid_t	  	  child_pid;
	const char	**local_argv;

	if (argc < 0) {
		return( -EINVAL );
	}

	local_argv = (const char **) malloc( (argc + 2) * sizeof( char * ) );
	if (local_argv == NULL) {
		return( -ENOMEM );
	}

	local_argv[ 0 ] = command;
	for (iter = 0; iter < argc; iter++) {
		local_argv[ iter + 1 ] = argv[ iter ];
	}

  /* Terminating NULL entry required for execvp ... */

	local_argv[ argc + 1 ] = NULL;

	child_pid = fork();
	if (child_pid < 0) {
		retval = -errno;
	} else if (child_pid > 0) {
		int	complete = 0;
	  /*
	   * By default the process did NOT exit as a result of receiving a signal.
	   */
		if (p_signal_number != NULL)
		  *p_signal_number = 0;
	  /*
	   * The child process SHOULD have completed after the 1st call to waitpid returns.
	   * Use while loop to confirm that process really has exited and avoid zombie processes just in case ...
	   */
		while (complete == 0) {
			int	child_status = 0, ival;

			ival = waitpid( child_pid, &child_status, 0 );

			if (WIFEXITED( child_status )) {
				if (p_exit_status != NULL)
				  *p_exit_status = WEXITSTATUS( child_status );
				complete = 1;
			} else if (WIFSIGNALED( child_status )) {
				if (p_signal_number != NULL)
				  *p_signal_number = WTERMSIG( child_status );
				complete = 1;
			} else if (ival < 0) {
				complete = 1;
				retval = -errno;
			}
		}
	}
	else {
	  /*
 	   * Child process ...
 	   *
 	   * No input to the sub process.
 	   * Suppress all output, both standard and error.
 	   */
		freopen( "/dev/null", "r", stdin );
		freopen( "/dev/null", "w", stdout );
		freopen( "/dev/null", "w", stderr );
	  /*
	   * Cast of local_argv appears unavoidable.  If local_argv is declared initially
	   * as (char * const *), compiler balks as assigned values to it ...
	   *
	   * Use execvp to enable searching the PATH for the executable.
	   */
		execvp( command, (char * const *) local_argv );
	  /*
	   * execvp should not return; if it does, call exit with status of 1.
	   */
		exit( 1 );
	}

	free( (void *) local_argv );

	return( retval );
}

int local_get_parameter(const char *ifname,
				const char *param_name,
				char *param_value,
				const size_t max_param_len,
				const char *script_path)
{
	int		retval = 0;
	const size_t	config_command_len = strlen(script_path) + 1 + IFNAMSIZ + 1 +
						QCSAPI_MAX_PARAMETER_NAME_LEN + 1;
	char		get_config_command[config_command_len];
	FILE		*popen_output = NULL;
	char		from_popen[8];
	char		*addr_eol_char = NULL;

	if (ifname == NULL || param_name == NULL || param_value == NULL) {
		retval = -EFAULT;
	} else if (strnlen(param_name, QCSAPI_MAX_PARAMETER_NAME_LEN + 1) >
				QCSAPI_MAX_PARAMETER_NAME_LEN) {
		retval = -EINVAL;
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	snprintf(&get_config_command[0], config_command_len, "%s %s %s",
			script_path, ifname, param_name);
	popen_output = popen(&get_config_command[0], "r");
	if (popen_output == NULL) {
		retval = -errno;
		if (retval >= 0) {
			retval = -ENOMEM;
		}
		goto ready_to_return;
	}

	if (read_to_eol(param_value, max_param_len, popen_output) == NULL) {
		retval = -qcsapi_programming_error;
		goto ready_to_return;
	}

	addr_eol_char = strchr(param_value, '\n');
	if (addr_eol_char != NULL) {
		*addr_eol_char = '\0';
	}

	while (read_to_eol(&from_popen[0], sizeof(from_popen), popen_output) != NULL) {
	}

ready_to_return:
	if (popen_output != NULL) {
		int	ival = pclose(popen_output);

		if (retval == 0 && ival != 0) {
			retval = -qcsapi_parameter_not_found;
		}
	}

	return retval;
}

int qcsapi_config_get_parameter(const char *ifname,
				const char *param_name,
				char *param_value,
				const size_t max_param_len)
{
	int retval;

	enter_qcsapi();

	retval = local_get_parameter(ifname,
				param_name,
				param_value,
				max_param_len,
				LOCAL_GET_CONFIG_SCRIPT);

	leave_qcsapi();

	return retval;
}

int qcsapi_config_get_ssid_parameter(const char *ifname,
				const char *param_name,
				char *param_value,
				const size_t max_param_len)
{
	int retval;

	enter_qcsapi();

	retval = local_get_parameter(ifname,
				param_name,
				param_value,
				max_param_len,
				LOCAL_GET_PER_SSID_CONFIG_SCRIPT);

	leave_qcsapi();

	return retval;
}

int verify_numeric_range(const char *str, uint32_t min, uint32_t max)
{
	uint32_t v;

	if (qcsapi_verify_numeric(str) < 0) {
		printf("Invalid parameter %s - must be an unsigned integer\n", str);
		return 0;
	}

	v = atoi(str);

	if (v < min || v > max) {
		printf("Invalid parameter %s - value must be between %u and %u\n", str, min, max);
		return 0;
	}

	return 1;
}

int verify_hexstring(const char *p_value, unsigned int byte_count)
{
	int len = 0;

	while(*p_value != '\0') {
		if (!isxdigit(*p_value))
			return -1;
		p_value++;
		len++;
	}

	if ((len & 1) || ((len / 2) != byte_count))
		return -1;

	return 0;
}

int verify_value_one_or_zero(const char *parameter_value) {
	if (strcmp(parameter_value, "1") == 0 ||
			strcmp(parameter_value, "0") == 0)
		return 0;

	return -1;
}

int verify_value_region_db(const char *parameter_value) {
	if (strcmp(parameter_value, "2") == 0 ||
			strcmp(parameter_value, "1") == 0 ||
			strcmp(parameter_value, "0") == 0)
		return 0;

	return -1;
}

int verify_band_value(const char *parameter_value) {
	if (strcmp(parameter_value, "11ac") == 0 ||
			strcmp(parameter_value, "11na") == 0 ||
			strcmp(parameter_value, "11a") ==0)
		return 0;

	return -1;
}

int verify_mode_value(const char *parameter_value) {
	if (strcmp(parameter_value, "ap") == 0 ||
			strcmp(parameter_value, "sta") ==0)
		return 0;

	return -1;
}

int verify_bw_value(const char *parameter_value) {
	qcsapi_unsigned_int	current_bw;

	if (qcsapi_verify_numeric(parameter_value) < 0)
			return -1;

	current_bw = (qcsapi_unsigned_int)atoi(parameter_value);
	if (current_bw == 20 || current_bw == 40 || current_bw == 80)
		return 0;

	return -1;
}

int verify_channel_value(const char *parameter_value) {
	int id;
	qcsapi_unsigned_int channel_value;
	qcsapi_unsigned_int qcsapi_channels_5ghz[] = QCSAPI_CHANNELS_5GHZ_LIST;
	if (qcsapi_verify_numeric(parameter_value) < 0)
		return -1;

	channel_value = atoi(parameter_value);
	if (channel_value == 0)
		return 0;
	for (id = 0; id < TABLE_SIZE(qcsapi_channels_5ghz); id++) {
		if (channel_value == qcsapi_channels_5ghz[id])
			return 0;
	}
	return -1;
}

int verify_mcs_value(const char *parameter_value) {
	int	mcs_rate;

	if (qcsapi_verify_numeric(parameter_value) < 0)
		return -1;

	mcs_rate = atoi(parameter_value);
	if (mcs_rate < 0 || mcs_rate > 76 || mcs_rate == 32)
		return -1;

	return 0;
}

int verify_region_value(const char *parameter_value) {
	qcsapi_regulatory_region the_region;
	string_256	supported_regions;
	int	qcsapi_retval;

	if (strcasecmp(parameter_value, "none") == 0)
		return 0;

	qcsapi_retval = local_use_new_tx_power();
	if (qcsapi_retval > 0) {
		qcsapi_retval = local_regulatory_get_list_regulatory_regions(supported_regions);
		if (!qcsapi_retval) {
			qcsapi_retval = local_verify_regulatory_regions(supported_regions, parameter_value);
			if (qcsapi_retval < 0)
				return -1;
			return 0;
		} else
			return -1;
	} else {
		the_region = local_wifi_get_region_by_name(parameter_value);
		if (the_region == QCSAPI_NOSUCH_REGION)
			return -1;
	}
	return 0;
}

int verify_pwr_value(const char *parameter_value) {
	int	min_tx_power, max_tx_power, pwr;

	if (qcsapi_verify_numeric(parameter_value) < 0)
		return -1;

	pwr = atoi(parameter_value);
	min_tx_power = local_bootcfg_get_min_tx_power();
	max_tx_power = local_bootcfg_get_default_tx_power();
	if (pwr > max_tx_power || pwr < min_tx_power)
		return -1;

	return 0;
}

int verify_ssid_priority_value(const char *parameter_value) {
	int	ssid_priority;

	if (qcsapi_verify_numeric(parameter_value) < 0)
		return -1;

	ssid_priority = atoi(parameter_value);
	if (ssid_priority < 0 || ssid_priority > 3)
		return -1;

	return 0;
}

int verify_ssid_vlan_value(const char *parameter_value) {
	int	vlan;

	if (qcsapi_verify_numeric(parameter_value) < 0)
		return -1;

	vlan = atoi(parameter_value);
	if (vlan < 0 || vlan >= QVLAN_VID_MAX)
		return -1;

	return 0;
}

int verify_ssid_uapsd_value(const char *parameter_value) {
	int	uapsd;

	if (qcsapi_verify_numeric(parameter_value) < 0)
		return -1;

	uapsd = atoi(parameter_value);
	if (uapsd > 1)
		return -1;

	return 0;
}

static int verify_parameter_name_and_value(const struct supported_parameters *table,
		const char *param_name, const char *param_value)
{
	int retval = 0;
	int index = 0;

	if (param_name == NULL || param_value == NULL) {
		return -qcsapi_programming_error;
	}

	for (index = 0; table[index].name != NULL; index++) {
		if (strcmp(param_name, table[index].name) == 0)
			break;
	}
	if (table[index].name == NULL) {
		return -qcsapi_param_name_not_supported;
	}

	if (table[index].verify_value != NULL) {
		retval = table[index].verify_value(param_value);
		if (retval < 0)
			return -qcsapi_param_value_invalid;
	}

	return 0;
}


int verify_value_pmf(const char *parameter_value) {
	if (strcmp(parameter_value, "2") == 0 ||
		strcmp(parameter_value, "1") == 0 ||
		strcmp(parameter_value, "0") == 0)
		return 0;

	return -1;
}

int verify_value_ipaddr(const char *ip)
{
	unsigned char tmpbuf[sizeof(struct in_addr)];

	if (!inet_pton(AF_INET, ip, tmpbuf))
		return 0;

	return 1;
}

int verify_ethtype_value(const char *parameter_value) {
	if (strcmp(parameter_value, "emac0") == 0 ||
			strcmp(parameter_value, "emac1") ==0)
		return 0;

	return -1;
}

int local_update_parameter(const char *ifname,
				   const char *param_name,
				   const char *param_value,
				   const char *script_path)
{
	int	retval = 0;
	int	status_system_call;
	char	*update_config_command = NULL;
	size_t	config_command_len = strlen(script_path) + IFNAMSIZ +
			QCSAPI_MAX_PARAMETER_NAME_LEN + QCSAPI_MAX_PARAMETER_VALUE_LEN +
			strlen(LOCAL_NULL_DEVICE) + 8;

	enter_qcsapi();

	if (ifname == NULL || param_name == NULL || param_value == NULL) {
		retval = -EFAULT;
	} else if ((strnlen(param_name, QCSAPI_MAX_PARAMETER_NAME_LEN + 1) >
				QCSAPI_MAX_PARAMETER_NAME_LEN) ||
		   (strnlen(param_value, QCSAPI_MAX_PARAMETER_VALUE_LEN + 1) >
				QCSAPI_MAX_PARAMETER_VALUE_LEN)) {
		retval = -EINVAL;
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	if ((update_config_command = malloc(config_command_len)) == NULL) {
		retval = -ENOMEM;
		goto ready_to_return;
	}

	snprintf(update_config_command, config_command_len, "%s %s %s %s >%s",
			script_path, ifname, param_name, param_value, LOCAL_NULL_DEVICE);
	status_system_call = system(update_config_command);
	if (status_system_call != 0) {
		retval = -qcsapi_config_update_failed;
	}

ready_to_return:
	if (update_config_command != NULL) {
		free(update_config_command);
	}

	leave_qcsapi();

	return( retval );
}

int qcsapi_config_update_parameter(const char *ifname,
				   const char *param_name,
				   const char *param_value)
{
	int	retval = 0;

	retval = verify_parameter_name_and_value(supported_parameters_tbl, param_name, param_value);

	if (retval >= 0)
		retval = local_update_parameter(ifname, param_name, param_value, LOCAL_UPDATE_CONFIG_SCRIPT);

	return retval;
}

int qcsapi_config_update_ssid_parameter(const char *ifname,
				   const char *param_name,
				   const char *param_value)
{
	int	retval = 0;

	retval = verify_parameter_name_and_value(perssid_supported_parameters_tbl, param_name, param_value);

	if (retval >= 0)
		retval = local_update_parameter(ifname, param_name, param_value, LOCAL_UPDATE_PER_SSID_CONFIG_SCRIPT);

	return retval;
}

int qcsapi_bootcfg_get_parameter(const char *param_name,
				 char *param_value,
				 const size_t max_param_len)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_bootcfg_get_parameter(param_name, param_value, max_param_len);

	leave_qcsapi();

	return( retval );
}

int qcsapi_bootcfg_update_parameter(const char *param_name,
				    const char *param_value)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_bootcfg_set_parameter(param_name, param_value, 0);

	leave_qcsapi();

	return( retval );
}

#define SERVICE_PATH       "/etc/init.d/"

int
qcsapi_service_control(qcsapi_service_name index, qcsapi_service_action action)
{
	int retval = 0;
	pid_t status;
	char ifname[IFNAMSIZ];
	string_64  serv_cmd;
	string_64  shell_command;
	int service_start_index;

	retval = qcsapi_get_primary_interface(ifname, IFNAMSIZ - 1);
	if (retval < 0) {
		/* Initialize ifname with the default iface "wifi0" on failure.
		 *                         Need this inteface name to update the config file */
		strcpy(ifname, "wifi0");
	}

	service_start_index = service_name_tbl[index].start_idx;
	snprintf(serv_cmd, sizeof(serv_cmd) - 1, "%sS%d%s",
			SERVICE_PATH, service_start_index, service_name_tbl[index].serv_name);

	switch (action) {
		case QCSAPI_SERVICE_ENABLE:
			retval =  service_name_tbl[index].update_service_config
				(ifname, service_name_tbl[index].serv_name, "1");
			snprintf(shell_command, sizeof(shell_command), "%s %s", serv_cmd, "start");
			break;
		case QCSAPI_SERVICE_START:
			snprintf(shell_command, sizeof(shell_command), "%s %s", serv_cmd, "start");
			break;
		case QCSAPI_SERVICE_DISABLE:
			retval = service_name_tbl[index].update_service_config
				(ifname, service_name_tbl[index].serv_name, "0");
			snprintf(shell_command, sizeof(shell_command), "%s %s", serv_cmd, "stop");
			break;
		case QCSAPI_SERVICE_STOP:
			snprintf(shell_command, sizeof(shell_command), "%s %s", serv_cmd, "stop");
			break;
		default:
			retval = -EINVAL;
			goto out;
	}

	status = system(shell_command);

	if (!WEXITSTATUS(status)) {
		retval = 0;
	} else {
		retval = -EFAULT;
	}
out:
	return retval;
}

int qcsapi_telnet_enable(const qcsapi_unsigned_int onoff)
{
	int ret = 0;
	pid_t status;
	char shell_command[64];

	enter_qcsapi();

	snprintf(shell_command, sizeof(shell_command), "/scripts/enable_telnet %d", !!onoff);
	status = system(shell_command);

	if(status == -1){
		ret = -EFAULT;
	}else if(WIFEXITED(status)){
		if(!WEXITSTATUS(status)){
		   ret = 0;
		}else{
		   ret = -EFAULT;
		}
	}else{
		ret = -EFAULT;
	}

	leave_qcsapi();
	return ret;
}

int qcsapi_wfa_cert_mode_enable(uint16_t enable)
{
	int ret = 0;
	pid_t status;
	char shell_command[64];

	enter_qcsapi();

	snprintf(shell_command, sizeof(shell_command),
			"/scripts/enable_wfa_cert_mode %d", enable);
	status = system(shell_command);

	if(status == -1){
		ret = -EFAULT;
	}else if(WIFEXITED(status)){
		if(!WEXITSTATUS(status)){
		   ret = 0;
		}else{
		   ret = -EFAULT;
		}
	}else{
		ret = -EFAULT;
	}

	leave_qcsapi();
	return ret;
}

int
qcsapi_restore_default_config(int flag)
{
	char cmd[QCSAPI_CMD_BUFSIZE];
	int ret = 0;
	int status;

	enter_qcsapi();

	if ((flag & QCSAPI_RESTORE_FG_AP) && (flag & QCSAPI_RESTORE_FG_STA)) {
		ret = -EINVAL;
		goto out;
	}

	memset(cmd, 0, sizeof(cmd));
	strncpy(cmd, RESTORE_DEFAULT_CONFIG, sizeof(cmd));

	if (flag & QCSAPI_RESTORE_FG_IP)
		strcat(cmd, " -ip");
	if (flag & QCSAPI_RESTORE_FG_NOREBOOT)
		strcat(cmd, " -nr");

	if (flag & QCSAPI_RESTORE_FG_AP) {
		strcat(cmd, " -m ap");
	} else if (flag & QCSAPI_RESTORE_FG_STA) {
		strcat(cmd, " -m sta");
	}

	status = system(cmd);
	if (status == -1) {
		ret = -EFAULT;
	} else if (WIFEXITED(status)) {
		if (!WEXITSTATUS(status))
			ret = 0;
		else
			ret = -EFAULT;
	}

out:
	leave_qcsapi();

	return ret;
}

int
qcsapi_pm_set_mode(int set_power_save)
{
	int rc;
	FILE *soc_pm;
	char cmd[32];
	int cmdlen;

	const char *governor = BOARD_PM_GOVERNOR_QCSAPI;

	snprintf(cmd, sizeof(cmd), "update %s %d", governor, set_power_save);
	cmdlen = strnlen(cmd, sizeof(cmd));

	enter_qcsapi();

	soc_pm = fopen("/proc/soc_pm", "w");
	if (soc_pm == NULL) {
		rc = -errno;
	} else {
		rc = fwrite(cmd, cmdlen, 1, soc_pm);
		if (rc == cmdlen) {
			rc = 0;
		} else {
			rc = -1;
		}

		fclose(soc_pm);
	}

	leave_qcsapi();

	return 0;
}

int
qcsapi_pm_get_mode(int *mode)
{
	int rc = 0;
	FILE *soc_pm;

	enter_qcsapi();

	soc_pm = fopen("/proc/soc_pm", "r");
	if (soc_pm == NULL) {
		rc = -errno;
	} else {
		if (fscanf(soc_pm, "%d", mode) != 1) {
			rc = -errno;
		}
		fclose(soc_pm);
	}

	leave_qcsapi();

	return rc;
}

static int
local_wifi_get_qpm_level(const int skfd, const char *ifname, int *p_value)
{
	int  retval = 0;
	char *argv[] = { NULL };
	int  argc = 0;
	int  value[QTN_PM_IOCTL_MAX];

	retval = call_private_ioctl( skfd,
					argv, argc,
					ifname,
					"get_pm",
					(void *)&value,
					sizeof(value));

	if (retval >= 0) {
		memcpy(p_value, value, sizeof(value));
	}

	return( retval );
}

int
qcsapi_get_qpm_level(int *qpm_level)
{
	int  rc = 0;
	const char *ifname = "wifi0";
	int  ic_pm_state[QTN_PM_IOCTL_MAX];
	int  skfd = -1;
	int  retval = 0;

	enter_qcsapi();

	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0) {
			retval = skfd;
		}
	}

	if (retval >= 0) {
		memset(ic_pm_state, 0, sizeof(ic_pm_state));
		retval = local_wifi_get_qpm_level(skfd, ifname, ic_pm_state);
	}

	if (retval < 0)
		rc = -errno;
	else
		*qpm_level = ic_pm_state[QTN_PM_CURRENT_LEVEL];

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return rc;
}

static unsigned int	count_qcsapi_init_called = 0;

unsigned int
get_count_calls_qcsapi_init( void )
{
	return( count_qcsapi_init_called );
}

int
qcsapi_init( void )
{
	int	retval =  qcsapi_security_init();

	count_qcsapi_init_called++;

	if (retval >= 0)
		retval = qcsapi_sem_init();

	return( retval );
}

static int
local_get_carrier_id( const int skfd, const char *ifname, uint32_t *p_value )
{
	int retval = 0;
	char	param_id[6];
	char	*argv[] = {param_id};
	int	argc = ARRAY_SIZE(argv);
	uint32_t	value = 0;
	sprintf(param_id, "%d", IEEE80211_PARAM_CARRIER_ID);
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

int qcsapi_get_carrier_id(qcsapi_unsigned_int *p_carrier_id)
{
	int	retval = 0;
	int	skfd = -1;

	if (p_carrier_id == NULL) {
		return -EFAULT;
	}

	enter_qcsapi();
	skfd = local_open_iw_sockets();

	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}
	if (retval >= 0) {
		retval = local_get_carrier_id(skfd, "wifi0", p_carrier_id);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}
	leave_qcsapi();

	return (retval);
}

static int
local_set_carrier_id( const int skfd, const char *ifname, uint32_t param_value )
{
	int	retval = 0;
	char	param_id[6];
	char	setparam_value[12];
	char	*argv[] = {param_id, &setparam_value[0]};
	const int	argc = ARRAY_SIZE(argv);

	sprintf(param_id, "%d", IEEE80211_PARAM_CARRIER_ID);
	snprintf(&setparam_value[0], sizeof(setparam_value), "0x%x", param_value);
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

/*******************************************************************************
   Function:    qcsapi_get_uboot_info
   Purpose:     Secondary userspace call_qcsapi handler in libqcsapi.a
   Returns:     0 - Success, otherwise error
*******************************************************************************/
int qcsapi_get_uboot_info(string_32 uboot_version, struct early_flash_config *ef_config)
{
	FILE *f;
	int ret = 0;

	enter_qcsapi();
	f = fopen(MTD_DEV_BLOCK0, "r");
	if (!f) {
		ret = -ENXIO;
		goto out;
	}

	if (fseek(f, MTD_UBOOT_VER_OFFSET, SEEK_SET) < 0) {
		ret = -errno;
		goto out;
	}

	if (!fread(uboot_version, sizeof(string_32) - 1, 1, f) || ferror(f)) {
		ret = -EIO;
		goto out;
	}
	uboot_version[sizeof(string_32) - 1] = '\0';

	if (fseek(f, MTD_UBOOT_OTHER_INFO_OFFSET, SEEK_SET) < 0) {
		ret = -errno;
		goto out;
	}

	if (!fread(ef_config, sizeof(*ef_config), 1, f) || ferror(f)) {
		ret = -EIO;
		goto out;
	}
out:
	if (f)
		fclose(f);
	leave_qcsapi();

	return ret;
}

int qcsapi_set_carrier_id(uint32_t carrier_id, uint32_t update_uboot)
{
	int	skfd = -1;
	int	retval = 0;
	int	status;
	char	carrier_process[48];

	enter_qcsapi();

	/*set carrier ID to qdrv*/
	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;

		if (retval >= 0)
			retval = skfd;
	}
	if (retval >= 0) {
		retval = local_set_carrier_id(skfd, "wifi0", carrier_id);
	}

	if (retval >= 0) {
		memset(carrier_process, 0, sizeof(carrier_process));
		sprintf(carrier_process, "/scripts/carrier_process %d %d", carrier_id, update_uboot);
		status = system(carrier_process);
		if (status == -1 || !WIFEXITED(status)) {
			retval = -qcsapi_script_error;
		} else {
			if (WEXITSTATUS(status) == 0)
				retval = 0;
			else
				retval = -qcsapi_script_error;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}
	leave_qcsapi();

	return (retval);
}

#define EMAC_COMM_PATH "/sys/class/net/eth1_0/device_emacx_xflow_update"
#define EMAC_COMM_PATH_CONFIG_SIZE 1
int qcsapi_get_emac_switch(char *buf)
{
	int retval = 0;
	int file_path_fd = -1;

	enter_qcsapi();

	if (buf == NULL) {
		retval = -EFAULT;
	}

	file_path_fd = open(EMAC_COMM_PATH, O_RDONLY);
	if (file_path_fd < 0) {
		retval = -ENOENT;
	}

	if (retval >= 0) {
		int ival = read(file_path_fd, buf, EMAC_COMM_PATH_CONFIG_SIZE);

		if (ival < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = -EIO;
			}
		}

		close(file_path_fd);
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_set_emac_switch(qcsapi_emac_switch value)
{
	int retval = 0;
	int emac_fd = -1;
	char eth_value[2] = {'e', 'd'};
	char buffer[2] = {0};

	enter_qcsapi();

	if (value < 0 || value > 1) {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		emac_fd = open(EMAC_COMM_PATH, O_WRONLY);
		if (emac_fd < 0) {
			retval = -ENXIO;
		}
	}

	if (retval >= 0) {
		sprintf(buffer, "%c", eth_value[value]);

		retval = write(emac_fd, buffer, EMAC_COMM_PATH_CONFIG_SIZE);

		close(emac_fd);
	}

	leave_qcsapi();

	return retval;
}

static int local_run_script(const char *cmd)
{
	int retval = 0;
	int status;

	status = system(cmd);
	if (status == -1 || !WIFEXITED(status)) {
		retval = -qcsapi_script_error;
	} else {
		if (WEXITSTATUS(status) == 0) {
			retval = 0;
		} else {
			retval = -qcsapi_script_error;
		}
	}

	return retval;
}

static int local_qcsapi_dscp_fill(qcsapi_eth_dscp_oper oper,
				  const char *eth_type,
				  const char *value)
{
	int retval = 0;
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE];

	if (value == NULL) {
		retval = -EFAULT;
	} else if (!verify_numeric_range(value, QCSAPI_DSCP_MIN_VALUE, QCSAPI_DSCP_MAX_VALUE)) {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		snprintf(cmd, QCSAPI_WIFI_CMD_BUFSIZE - 1,
				"/scripts/dscp fill %s %s", eth_type, value);
		retval = local_run_script(cmd);
	}

	return retval;
}

static int local_qcsapi_dscp_poke(qcsapi_eth_dscp_oper oper,
				  const char *eth_type,
				  const char *level,
				  const char *value)
{
	int retval = 0;
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE];

	if (level == NULL || value == NULL) {
		retval = -EFAULT;
	} else if (!verify_numeric_range(level, QCSAPI_DSCP_MIN_LEVEL, QCSAPI_DSCP_MAX_LEVEL) ||
		!verify_numeric_range(value, QCSAPI_DSCP_MIN_VALUE, QCSAPI_DSCP_MAX_VALUE)) {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		snprintf(cmd, QCSAPI_WIFI_CMD_BUFSIZE - 1,
				"/scripts/dscp poke %s %s %s", eth_type, level, value);
		retval = local_run_script(cmd);
	}

	return retval;
}

static int local_qcsapi_dscp_dump(qcsapi_eth_dscp_oper oper,
			const char *eth_type,
			char *buf,
			const unsigned int size)
{
#define QCSAPI_DSCP_LINE_MAX 25
	int retval = 0;
	char cmd[QCSAPI_WIFI_CMD_BUFSIZE];
	FILE *popen_output = NULL;
	int buflen = 0;

	if (buf == NULL) {
		retval = -EFAULT;
	}

	if (retval >= 0) {
		snprintf(cmd, QCSAPI_WIFI_CMD_BUFSIZE - 1, "/scripts/dscp dump %s", eth_type);
		popen_output = popen(&cmd[0], "r");
		if (popen_output == NULL) {
			retval = -errno;
			if (retval >= 0) {
				retval = -ENOMEM;
			}
		} else {
			while ((!retval) &&
				read_to_eol(buf, QCSAPI_DSCP_LINE_MAX, popen_output) != NULL) {
				buflen += strlen(buf);
				buf += strlen(buf);
				if ((buflen + QCSAPI_DSCP_LINE_MAX) > size)
					retval = -ENOMEM;
			}
		}
	}

	return retval;
}

int qcsapi_eth_dscp_map(qcsapi_eth_dscp_oper oper,
			const char *eth_type,
			const char *level,
			const char *value,
			char *buf,
			const unsigned int size)
{
	int retval = 0;

	enter_qcsapi();

	if (eth_type == NULL) {
		retval = -EFAULT;
	} else if (verify_ethtype_value(eth_type)) {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		switch(oper) {
			case qcsapi_eth_dscp_fill:
				local_qcsapi_dscp_fill(oper, eth_type, value);
				break;
			case qcsapi_eth_dscp_poke:
				local_qcsapi_dscp_poke(oper, eth_type, level, value);
				break;
			case qcsapi_eth_dscp_dump:
				local_qcsapi_dscp_dump(oper, eth_type, buf, size);
				break;
		}
	}

	leave_qcsapi();

	return retval;
}

