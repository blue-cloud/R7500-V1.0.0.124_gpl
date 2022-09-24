/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2011 Quantenna Communications Inc            **
**                                                                           **
**  File        : qcsapi_security.c                                          **
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
 * QCSAPI programming relating to security, including the beacon type
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>

#include <arpa/inet.h>
#include <net80211/ieee80211_ioctl.h>

#include "qcsapi.h"
#include "qcsapi_private.h"
#include "qcsapi_util.h"


#define QCSAPI_WPA_PSK_MAX_SIZE	64

#ifndef HOST_APD_PROCESS
#define HOST_APD_PROCESS	"hostapd"
#endif /* HOST_APD_PROCESS */

#ifndef HOST_APD_CONF
#define HOST_APD_CONF	"hostapd.conf"
#endif /* HOST_APD_CONF */

#ifndef WPA_SUPPLICANT_PROCESS
#define WPA_SUPPLICANT_PROCESS	"wpa_supplicant"
#endif /* WPA_SUPPLICANT_PROCESS */

#ifndef WPA_SUPPLICANT_CONF
#define WPA_SUPPLICANT_CONF	"wpa_supplicant.conf"
#endif /* WPA_SUPPLICANT_CONF */

#ifndef HOSTAPD_DENY
#define HOSTAPD_DENY	"hostapd.deny"
#endif /* HOSTAPD_DENY */

#ifndef HOSTAPD_ACCEPT
#define HOSTAPD_ACCEPT	"hostapd.accept"
#endif /* HOSTAPD_ACCEPT */

#ifndef HOSTAPD_ACCEPT_OUI
#define HOSTAPD_ACCEPT_OUI "hostapd.accept.oui"
#endif

#define ADD_INTO_LIST 1
#define REMOVE_FROM_LIST 0
/*
 * Avoid problems with rename Linux system call by putting the QCSAPI temporary configuration file
 * in the same directory as the actual configuration file.
 */

#ifndef QCSAPI_TEMPORARY_CONF
#define QCSAPI_TEMPORARY_CONF	"qcsapi_security.conf"
#endif /* QCSAPI_CONF */

#ifndef QSCAPI_DEFAULT_SECURITY_FOLDER
#define QSCAPI_DEFAULT_SECURITY_FOLDER	"/scripts"
#endif

#ifndef MAX_SECURITY_BASE_FILE_LENGTH
#define MAX_SECURITY_BASE_FILE_LENGTH	(24)
#endif /* MAX_SECURITY_BASE_FILE_LENGTH */

#ifndef MAX_SECURITY_CONFIG_LENGTH
#define MAX_SECURITY_CONFIG_LENGTH	(QCSAPI_MAX_PARAMETER_NAME_LEN + QCSAPI_MAX_PARAMETER_VALUE_LEN + 1)
#endif
/*
 * #defines relating to STA backoff feature
 */

#define MIN_BACKOFF_FAIL_MAX	2
#define MAX_BACKOFF_FAIL_MAX	20
#define MIN_BACKOFF_TIMEOUT	10
#define MAX_BACKOFF_TIMEOUT	300
#define GET_WPA_STATUS_STR_LEN	32

#define WPS_VENDOR_NETGEAR	"Netgear"
#define NAI_REALM_PARAM		"nai_realm"

enum
{
	accept_mac_address = 1,
	deny_mac_address = 2,
	accept_oui = 3
};

typedef enum
{
	e_searching_for_generic_param,
	e_searching_for_network,
	e_found_network_token,
	e_found_current_network
} SSID_parsing_state;

enum conf_parsing_parameter_s
{
	E_PARAMETER_INVALID = 0,
	E_PARAMETER_FOUND = 1,
	E_PARAMETER_NOT_FOUND = 2,
	E_PARAMETER_EXCEED_LIMIT = 3
};

enum
{
	E_NORMAL_BSS = 0,
	E_RESTRICTED_BSS = 1
};

typedef struct parameter_translation_entry
{
	char	*qcsapi_value;
	char	*internal_value;
} parameter_translation_entry;

#define MAXLEN_SECURITY_DAEMON_MESSAGE	100

/*
 * struct socket_ctrl - Internal structure for control interface library
 *
 * Adopted from the hostapd_cli and wpa_cli programming.
 *
 * This structure is used by the wpa_supplicant/hostapd control interface
 * routines to store internal data. Programs calling these routines should
 * not touch this data directly. They can only use the pointer to the data
 * structure as an identifier for the control interface connection and use
 * this as one of the arguments for the control interface routines.
 */
typedef struct socket_ctrl {
	int s;
	struct sockaddr_un local;
	struct sockaddr_un dest;
} socket_ctrl;


typedef enum {
	bss_ifstatus_invalid,	/* The bss net device is unknown */
	bss_ifstatus_up,	/* The bss net device is Up	 */
	bss_ifstatus_down	/* The bss net device is Down	 */
}bss_ifstatus_type;

/*
 * struct bss_status_node - Internal struct.
 *
 * This structure is used to save the BSS name and status( Up / Down / Error ),
 * so we can restore it later.
 */
typedef struct bss_status_node {
	char			ifname[IFNAMSIZ + 1];	/* It is a invalid node if first char is 0  */
	bss_ifstatus_type	ifstatus;
} bss_status_node;


/*
 *  Return values from entry points of this type are:
 *      1:  stop processing, no error.
 *      0:  continue, no error.
 *      < 0:  error, with the actual value corresponding to a QCSAPI error return value.
 */
typedef int	(*mac_addr_file_cb)(qcsapi_mac_addr current_mac_addr, void *arg1, void *arg2);

static const char *wpa_ctrl_iface_dir = "/var/run/wpa_supplicant";
static const char *hostapd_ctrl_iface_dir = "/var/run/hostapd";
static socket_ctrl *ctrl_conn = NULL;

/* index for beacon type is the value of wpa, as located in hostapd.conf */

static const char	*beacon_type[] =
{
	"Basic",			/* wpa = 0 */
	"WPA",				/* wpa = 1 */
	"11i",				/* wpa = 2 */
	"WPAand11i"			/* wpa = 3 */
};

static const parameter_translation_entry	authentication_mode_table[] =
{
	{ "SHA256PSKAuthenticationMixed",	"WPA-PSK WPA-PSK-SHA256" },
	{ "SHA256PSKAuthentication",	"WPA-PSK-SHA256" },
	{ "PSKAuthentication",	"WPA-PSK" },
	{ "EAPAuthentication",	"WPA-EAP" },
	{ "NONE",		"NONE" },
	{  NULL,		 NULL },
};

#define AUTH_MODE_TABLE_NONE_INDEX 4

#define TKIP_AND_AES_ENTRY_INDEX	0
#define TKIP_ENTRY_INDEX		1
#define AES_ENTRY_INDEX			2

/*
 * Encryption mode table is not just a two-way lookup table.
 *
 * It IS a lookup table when SETTING the encryption mode,
 * for the QCSAPI must receive a string that matches the qcsapi_value.
 *
 * But when GETTING the encryption mode, the API is required to scan the value (wpa_pairwise).
 * If it finds just TKIP or just CCMP, then the returned encryption mode is the corresponding
 * qcsapi_value.  But if it finds both, then the API is required to return "TKIPandAESEncryption".
 * The internal value can have the tokens (TKIP and CCMP) in any order, with one or mode tabs
 * or spaces separating the two.
 */

static const parameter_translation_entry	encryption_mode_table[] =
{
	{ "TKIPandAESEncryption",	"CCMP TKIP" },
	{ "TKIPEncryption",		"TKIP" },
	{ "AESEncryption",		"CCMP" },
	{  NULL,			 NULL },
};

/*
 * Same comment about encryption mode table also applies to the SSID proto(col) table.
 * For this table, keep the length of the 1st entry in each pair (qcsapi_entry)
 * to 16 or fewer chars, as the entry point that receives this entry
 * (qcsapi_SSID_get_protocol) declares the receiving string to be of type string_16.
 */

static const parameter_translation_entry	SSID_proto_table[] =
{
	{ "WPA",	"WPA" },
	{ "11i",	"RSN" },
	{ "WPAand11i",	"WPA RSN" }
};

enum
{
	index_beacon_type_basic = 0,
	index_beacon_WPA_only = 1,
	index_beacon_11i_only = 2,
	index_beacon_WPA_11i = 3,

	index_proto_WPA_only = 0,
	index_proto_11i_only = 1,
	index_proto_WPA_11i = 2,
	max_SSID_proto_index = index_proto_WPA_11i
};

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

/**
 * hexstr2bin - Convert ASCII hex string into binary data
 * @hex: ASCII hex string (e.g., "01ab")
 * @buf: Buffer for the binary data
 * @len: Length of the text to convert in bytes (of buf); hex will be double
 * this size
 * Returns: 0 on success, -1 on failure (invalid hex string)
 */
static int hexstr2bin(const char *hex, unsigned char *buf, size_t len)
{
	size_t i;
	int a;
	const char *ipos = hex;
	unsigned char *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0)
			return -1;
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

static int verify_uuid_value(const char *value)
{
	unsigned char binary[16];
	unsigned char *opos;
	const char *pos;

	pos = value;
	opos = binary;

	if (hexstr2bin(pos, opos, 4))
		return -EINVAL;
	pos += 8;
	opos += 4;

	if (*pos++ != '-' || hexstr2bin(pos, opos, 2))
		return -EINVAL;
	pos += 4;
	opos += 2;

	if (*pos++ != '-' || hexstr2bin(pos, opos, 2))
		return -EINVAL;
	pos += 4;
	opos += 2;

	if (*pos++ != '-' || hexstr2bin(pos, opos, 2))
		return -EINVAL;
	pos += 4;
	opos += 2;

	if (*pos++ != '-' || hexstr2bin(pos, opos, 6))
		return -EINVAL;

	return 0;
}

static const char *wps_config_methods[] = {
	"usba",
	"ethernet",
	"label",
	"display",
	"ext_nfc_token",
	"int_nfc_token",
	"nfc_interface",
	"push_button",
	"keypad",
	"virtual_display",
	"virtual_push_button",
	"physical_push_button"
};

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


static int __verify_wps_methods_value(const char *value, int len)
{
	int i;

	for (i = 0; i < TABLE_SIZE(wps_config_methods); i++)
		if (strncmp(value, wps_config_methods[i], len) == 0)
			return 0;

	return -EINVAL;
}

static int verify_wps_methods_value(const char *value)
{
#define MAX_WPS_CONFIG_METHODS_LEN 32
#define WPS_METHOD_CHAR_VALID	0
#define WPS_METHOD_CHAR_INVALID	1
	const char *value_tmp =value;
	char method[MAX_WPS_CONFIG_METHODS_LEN];
	int len = 0;
	int last_byte;

	if (value == NULL)
		return -EINVAL;

	if (isalpha(*value_tmp) || *value_tmp == '_')
		last_byte = WPS_METHOD_CHAR_VALID;
	else
		last_byte = WPS_METHOD_CHAR_INVALID;

	memset(method, 0, sizeof(method));
	len = 0;
	while (*value_tmp != '\0') {
		/* only alpha and _ ara valid input char */
		if (isalpha(*value_tmp) || *value_tmp == '_') {
			if (len >= sizeof(method)) {
				return -EINVAL;
			}
			method[len++] = *value_tmp;
			last_byte = WPS_METHOD_CHAR_VALID;
		} else {
			if (last_byte == WPS_METHOD_CHAR_VALID) {
				if (__verify_wps_methods_value(method, len) != 0)
					return -EINVAL;

				memset(method, 0, sizeof(method));
				len = 0;
			}
			last_byte = WPS_METHOD_CHAR_INVALID;
		}
		value_tmp++;
	}

	if (len && (__verify_wps_methods_value(method, len) != 0))
			return -EINVAL;

	return 0;
#undef WPS_METHOD_CHAR_INVALID
#undef WPS_METHOD_CHAR_VALID
#undef MAX_WPS_CONFIG_METHODS_LEN
}

int
qcsapi_wifi_get_WEP_encryption_level( const char *ifname, string_64 current_encryption_level )
{
	int		skfd = -1;
	int		retval = 0;
	unsigned int	remaining_length = sizeof( string_64 );
	struct iw_range	range;

	enter_qcsapi();

	if (current_encryption_level == NULL)
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
		int	ival = local_get_we_range_data(skfd, ifname, &range);

		if (ival < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = ival;
		}
	}

	if (retval >= 0)
	{
		if (range.num_encoding_sizes >= IW_MAX_ENCODING_SIZES )
		  retval = -EMSGSIZE;
	}

	if (retval >= 0)
	{
		unsigned int	iter, token_size;
		char		encryption_token[ 12 ];
		int		no_more_space = 0;

		strcpy( current_encryption_level, "Disabled" );
		token_size = strlen( current_encryption_level );
		no_more_space = token_size > (int) remaining_length;
		if (no_more_space == 0)
		{
			remaining_length = remaining_length - token_size;
			current_encryption_level += token_size;
		}

		for (iter = 0; iter < range.num_encoding_sizes && no_more_space == 0; iter++)
		{
			sprintf( &encryption_token[ 0 ], "%u-bit", range.encoding_size[ iter ] * 8 );
			token_size = strlen( &encryption_token[ 0 ] );
			no_more_space = (token_size + 1) > remaining_length;
			if (no_more_space == 0)
			{
				*(current_encryption_level++) = ',';
				strcpy( current_encryption_level, &encryption_token[ 0 ] );
				current_encryption_level += token_size;
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
 * Remainder of the WEP APIs are stubs.
 * It should be possible to CONFIGURE following the iwconfig model.
 * But REPORTING does not work at all.
 * Bugzilla ID 438 tracks this limitation.
 */

int
qcsapi_wifi_get_WEP_key_index( const char *ifname, qcsapi_unsigned_int *p_key_index )
{
	enter_qcsapi();

	(void) ifname;
	(void) p_key_index;

	leave_qcsapi();

	return( -EOPNOTSUPP );
}

int
qcsapi_wifi_set_WEP_key_index( const char *ifname, const qcsapi_unsigned_int key_index )
{
	enter_qcsapi();

	(void) ifname;
	(void) key_index;

	leave_qcsapi();

	return( -EOPNOTSUPP );
}

int
qcsapi_wifi_get_WEP_key_passphrase( const char *ifname, string_64 current_passphrase )
{
	enter_qcsapi();

	(void) ifname;
	(void) current_passphrase;

	leave_qcsapi();

	return( -EOPNOTSUPP );
}

int
qcsapi_wifi_set_WEP_key_passphrase( const char *ifname, const string_64 new_passphrase )
{
	enter_qcsapi();

	(void) ifname;
	(void) new_passphrase;

	leave_qcsapi();

	return( -EOPNOTSUPP );
}

int
qcsapi_wifi_get_basic_encryption_modes( const char *ifname, string_32 encryption_modes )
{
	enter_qcsapi();

	(void) ifname;
	(void) encryption_modes;

	leave_qcsapi();

	return( -EOPNOTSUPP );
}

int
qcsapi_wifi_set_basic_encryption_modes( const char *ifname, const string_32 encryption_modes )
{
	enter_qcsapi();

	(void) ifname;
	(void) encryption_modes;

	leave_qcsapi();

	return( -EOPNOTSUPP );
}

int
qcsapi_wifi_get_basic_authentication_mode( const char *ifname, string_32 authentication_mode )
{
	enter_qcsapi();

	(void) ifname;
	(void) authentication_mode;

	leave_qcsapi();

	return( -EOPNOTSUPP );
}

int
qcsapi_wifi_set_basic_authentication_mode( const char *ifname, const string_32 authentication_mode )
{
	enter_qcsapi();

	(void) ifname;
	(void) authentication_mode;

	leave_qcsapi();

	return( -EOPNOTSUPP );
}

int
qcsapi_wifi_get_WEP_key( const char *ifname, qcsapi_unsigned_int key_index, string_64 current_passphrase )
{
	enter_qcsapi();

	(void) ifname;
	(void) key_index;
	(void) current_passphrase;

	leave_qcsapi();

	return( -EOPNOTSUPP );
}

int
qcsapi_wifi_set_WEP_key( const char *ifname, qcsapi_unsigned_int key_index, const string_64 new_passphrase )
{
	enter_qcsapi();

	(void) ifname;
	(void) key_index;
	(void) new_passphrase;

	leave_qcsapi();

	return( -EOPNOTSUPP );
}


/* Programs to locate and send a signal to the security configuration process. */

/*
 * Assume we are processing output from busybox ps
 * and that the process name is present in the line of output from ps.
 */

static int
process_line_ps( const char *ps_output_line, const char *process_name )
{
	const unsigned int	 count_busybox_ps_fields = 5;
	unsigned int		 iter;
	const char		*ps_output_addr = ps_output_line;
	int			 found_problem = 0, retval = -1;
  /*
   *  Output from busybox ps has 5 (count_busybox_ps_fields) fields, with the process name in the 5th field.
   */
	for (iter = 0; iter < count_busybox_ps_fields && found_problem == 0; iter++)
	{
		while(isspace( *ps_output_addr ) == 0 && *ps_output_addr != '\0')
		  ps_output_addr++;

		if (*ps_output_addr == '\0')
		  found_problem = 1;

		if (found_problem == 0)
		{
			while(isspace( *ps_output_addr ))
			  ps_output_addr++;

			if (*ps_output_addr == '\0')
			  found_problem = 1;
		}
	}

	if (found_problem == 0)
	{
		const char	*ps_field = strstr( ps_output_addr, process_name );

		if (ps_field != NULL)
		{
			if (ps_field > ps_output_addr)
			{
				ps_field--;
				if (*ps_field != '/')
				  found_problem = 1;
			}
			else if (ps_field < ps_output_addr)
			  found_problem = 1;
		}
	}

	if (found_problem == 0)
	{
		int	proposed_process_id = -1;
		int	ival = sscanf( ps_output_line, "%d", &proposed_process_id );

		if (ival > 0)
		  retval = proposed_process_id;
	}

	return( retval );
}

int
local_generic_locate_process( const char *process_name )
{
#define SEARCH_COMMAND	"grep"
	int		 retval = -1;
	char		 ps_command[ 32 ];
	FILE		*ps_ph = NULL;
	unsigned int	 length_of_name = strlen( process_name );

	if (length_of_name > 22)
	{
		fprintf( stderr, "locate process: process name of %s is too long\n", process_name );
		return( -1 );
	}

	if (strstr( process_name, SEARCH_COMMAND ) != NULL)
	{
		fprintf( stderr, "locate process: process name cannot contain \"%s\"\n", SEARCH_COMMAND );
		return( -1 );
	}
/*
 * Assume use of busybox ps.
 * This version of ps requires NO parameters; unlike the ps command on other kinds of Linux.
 */
	sprintf( &ps_command[ 0 ], "ps|%s %s", SEARCH_COMMAND, process_name );
	ps_ph = popen( &ps_command[ 0 ], "r" );

	if (ps_ph != NULL)
	{
		char	ps_output_line[ 122 ];
	  /*
	   * Note:  fgets reads in at most one less than sizeof( ps_output_line ) characters from ps_ph.
	   */
		while (retval < 0 && fgets( &ps_output_line[ 0 ], sizeof( ps_output_line ), ps_ph ) != NULL)
		{
			int	proposed_process_id = -1;

			if (strstr( &ps_output_line[ 0 ], SEARCH_COMMAND ) == NULL)
			{
				proposed_process_id = process_line_ps( &ps_output_line[ 0 ], process_name );
			}

			if (proposed_process_id > 0)
			{
				retval = proposed_process_id;
			}
		}

		pclose( ps_ph );
	}

	return( retval );
}

/* End of programs to locate a process. */

static socket_ctrl *
socket_ctrl_open(const char *ctrl_path)
{
	socket_ctrl *ctrl;
	static int counter = 0;
	int ret;
	int tries = 0;
	int bound_the_socket = 0;

	if (strnlen( ctrl_path, sizeof( ctrl->dest.sun_path ) + 1 ) >= sizeof( ctrl->dest.sun_path ))
	  return( NULL );

	ctrl = malloc(sizeof(*ctrl));
	if (ctrl == NULL)
	  return NULL;
	memset(ctrl, 0, sizeof(*ctrl));

	ctrl->s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ctrl->s < 0) {
		free(ctrl);
		return NULL;
	}

	ctrl->local.sun_family = AF_UNIX;
	counter++;

	while (bound_the_socket == 0)
	{
		ret = sprintf(ctrl->local.sun_path, "/tmp/wpa_ctrl_%d-%d", getpid(), counter);
		if (ret < 0 || (size_t) ret >= sizeof(ctrl->local.sun_path)) {
			close(ctrl->s);
			free(ctrl);
			return NULL;
		}
		tries++;
		if (bind(ctrl->s, (struct sockaddr *) &ctrl->local, sizeof(ctrl->local)) < 0) {
			if (errno == EADDRINUSE && tries < 2) {
				/*
				 * getpid() returns unique identifier for this instance
				 * of socket_ctrl, so the existing socket file must have
				 * been left by unclean termination of an earlier run.
				 * Remove the file and try again.
				 */
				unlink(ctrl->local.sun_path);
			}
			else
			{
				close(ctrl->s);
				free(ctrl);
				return NULL;
			}
		}
		else
		  bound_the_socket = 1;
	}

	ctrl->dest.sun_family = AF_UNIX;
	strncpy(ctrl->dest.sun_path, ctrl_path, sizeof(ctrl->dest.sun_path));
	if (connect(ctrl->s, (struct sockaddr *) &ctrl->dest, sizeof(ctrl->dest)) < 0) {
		close(ctrl->s);
		unlink(ctrl->local.sun_path);
		free(ctrl);
		return NULL;
	}

	return ctrl;
}

static socket_ctrl *
socket_open_connection(const char *ifname, const qcsapi_wifi_mode wifi_mode )
{
	char		*cfile;
	const char	*ctrl_iface_dir;
	int		 flen;

	if (ifname == NULL)
	  return NULL;
	else if (wifi_mode == qcsapi_access_point)
	  ctrl_iface_dir = hostapd_ctrl_iface_dir;
	else if (wifi_mode == qcsapi_station)
	  ctrl_iface_dir = wpa_ctrl_iface_dir;
	else
	  return NULL;

	flen = strlen(ctrl_iface_dir) + strlen(ifname) + 2;
	cfile = malloc(flen);
	if (cfile == NULL)
	  return NULL;

	sprintf(cfile, "%s/%s", ctrl_iface_dir, ifname);
  /*
   * Publish the socket control connection so the signal handler can find it.
   */
	ctrl_conn = socket_ctrl_open(cfile);
	free(cfile);

	return ctrl_conn;
}

static int
socket_ctrl_request(socket_ctrl *ctrl, const char *cmd, size_t cmd_len,
		     char *reply, size_t *reply_len,
		     void (*msg_cb)(char *msg, size_t len))
{
	struct timeval tv;
	int res;
	fd_set rfds;
	const char *_cmd;
	size_t _cmd_len;

	_cmd = cmd;
	_cmd_len = cmd_len;

	if (send(ctrl->s, _cmd, _cmd_len, 0) < 0) {
		return -1;
	}

	for (;;) {
		tv.tv_sec = 15;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(ctrl->s, &rfds);
		res = select(ctrl->s + 1, &rfds, NULL, NULL, &tv);
		if (FD_ISSET(ctrl->s, &rfds)) {
			res = recv(ctrl->s, reply, *reply_len, 0);
			if (res < 0)
				return res;
			if (res > 0 && reply[0] == '<') {
				/*
				 * This is an unsolicited message from the
				 * security daemon, not the reply to the
				 * request. Use msg_cb to report this.
				 */
				if (msg_cb) {
					/* Make sure the message is nul
					 * terminated. */
					if ((size_t) res == *reply_len)
						res = (*reply_len) - 1;
					reply[res] = '\0';
					msg_cb(reply, res);
				}
				continue;
			}
			*reply_len = res;
			break;
		} else {
			return -2;
		}
	}
	return 0;
}

static void
cli_msg_cb(char *msg, size_t len)
{
	local_generic_syslog( "Contact Security Daemon", LOG_ERR,
			      "Unexpected message %s", msg );
}

/*
 * Assumes receive_buf addresses at least receive_len chars.
 * receive_buf is ALWAYS NUL-terminated.
 */
static size_t
local_copy_security_daemon_reply(char *receive_buf,
				 const char *source_buf,
				 const size_t receive_len)
{
	int complete = 0;
	int count_remaining = receive_len - 1;
	size_t retval = 0;
	int in_double_quotes = source_buf[0] == '\"';
	/*
	 * Sanity check: verify room for at least 1 non-NUL character.
	 */
	if (receive_len < 2) {
		complete = 1;
	} else if (in_double_quotes) {
		source_buf++;
	}

	while (complete == 0) {
		if (*source_buf == '\n' || *source_buf == '\0' ||
		    (in_double_quotes && *source_buf == '\"')) {
			complete = 1;
			*receive_buf = '\0';
		} else {
			*(receive_buf)++ = *(source_buf)++;

			retval++;
			count_remaining--;

			if (count_remaining <= 0) {
				complete = 1;
				*receive_buf = '\0';
			}
		}
	}

	return( retval );
}

#define  SECURITY_SIZE_DAEMON_CONTACT_BUFFER	4096

/*
 * Return value from this program is suitable as a return value from a QCS API.
 */

static int
socket_ctrl_command(socket_ctrl *ctrl,
		    const char *cmd,
		    char *reply,
		    const size_t reply_len)
{
	int retval = 0;
	char *buf = NULL;
	size_t len = SECURITY_SIZE_DAEMON_CONTACT_BUFFER - 1;
	int ret;

	if (ctrl == NULL) {
		return -EFAULT;
	}

	buf = malloc( SECURITY_SIZE_DAEMON_CONTACT_BUFFER );
	if (buf == NULL) {
		return -ENOMEM;
	}

	ret = socket_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len, cli_msg_cb);
	if (ret == -2) {
		local_generic_syslog( "Contact Security Daemon", LOG_ERR,
				      "%s: timed out", cmd );
		retval = -ETIMEDOUT;
	} else if (ret < 0) {
		local_generic_syslog( "Contact Security Daemon", LOG_ERR,
				      "%s: failed", cmd );
		retval = -EIO;
	} else {
		buf[len] = '\0';
		if (reply != NULL && reply_len > 1) {
			local_copy_security_daemon_reply(reply, buf, reply_len);
		} else {
			local_generic_syslog( "Contact Security Daemon", LOG_ERR,
					      "%s: got reply %s", cmd, buf );
		}
	}

	free( buf );

	return retval;
}

static void
socket_ctrl_close(socket_ctrl *ctrl)
{
	close(ctrl->s);
	unlink(ctrl->local.sun_path);
	free(ctrl);
}

/*
 * Signal handler that reload_security_configuration registers for SIGINT and SIGTERM.
 */

static void
socket_ctrl_terminate( int sig )
{
	if (ctrl_conn != NULL)
	  socket_ctrl_close( ctrl_conn );
  /*
   * Note: exit() is not included in the list of functions that may be called from a signal handler.
   */
	_exit( 0 );
}

/*
 * Use the CLI socket interface to notify the security daemon it should reload its configuration.
 * Interface is helpful now, might be required when multiple VAPs are present.
 * WiFi mode selects the CLI, hostapd_cli or wpa_cli.
 */

int
send_message_security_daemon(const char *ifname,
			     const qcsapi_wifi_mode wifi_mode,
			     const char *message,
			     char *reply,
			     const size_t reply_len)
{
	int			 retval = 0;
	sigset_t		 to_be_blocked, previous_sigset;
	struct sigaction	 socket_ctrl_action, previous_sighup, previous_sigint, previous_sigterm;

	if (strnlen( message, MAXLEN_SECURITY_DAEMON_MESSAGE + 1 ) > MAXLEN_SECURITY_DAEMON_MESSAGE) {
		  return( -EMSGSIZE );
	}

	sigemptyset( &to_be_blocked );
	sigaddset( &to_be_blocked, SIGHUP );
	sigaddset( &to_be_blocked, SIGINT );
	sigaddset( &to_be_blocked, SIGTERM );

	memset( &socket_ctrl_action, 0, sizeof( socket_ctrl_action ) );
	socket_ctrl_action.sa_mask = to_be_blocked;
	socket_ctrl_action.sa_handler = socket_ctrl_terminate;
	socket_ctrl_action.sa_flags = 0;

	if (sigaction( SIGHUP, &socket_ctrl_action, &previous_sighup ) < 0) {
		retval = -errno;
		if (retval >= 0)
		  retval = -qcsapi_programming_error;
	}
	else {
		if (sigaction( SIGINT, &socket_ctrl_action, &previous_sigint ) < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = -qcsapi_programming_error;
			}

			sigaction( SIGHUP, &previous_sighup, NULL );
		}
		else {
			if (sigaction( SIGTERM, &socket_ctrl_action, &previous_sigterm ) < 0) {
				retval = -errno;
				if (retval >= 0) {
					retval = -qcsapi_programming_error;
				}

				sigaction( SIGHUP, &previous_sighup, NULL );
				sigaction( SIGINT, &previous_sigint, NULL );
			}
		}
	}

	if (retval >= 0)
	{
	  /*
	   *  Come here if all the signal handlers were registered.
	   */
		socket_ctrl	*p_ctrl = socket_open_connection( ifname, wifi_mode );

		if (p_ctrl == NULL || ctrl_conn == NULL) {
			retval = -qcsapi_daemon_socket_error;
		}
		else {
		  /*
		   * Use pthread_sigmask instead of sigprocmask, as the action of
		   * the latter is unspecified in a multi-threaded application.
		   */
			int	ival_2 = pthread_sigmask( SIG_BLOCK, &to_be_blocked, &previous_sigset );
			int	ival = socket_ctrl_command( ctrl_conn, message, reply, reply_len );
		  /*
		   * Any pause to test catching signals should be put here.
		   */
			socket_ctrl_close( ctrl_conn );
			ctrl_conn = NULL;

			if (ival_2 >= 0) {
				pthread_sigmask( SIG_SETMASK, &previous_sigset, NULL );
			}

			if (ival < 0) {
				retval = ival;
			}
		}

		sigaction( SIGHUP, &previous_sighup, NULL );
		sigaction( SIGINT, &previous_sigint, NULL );
		sigaction( SIGTERM, &previous_sigterm, NULL );
	}

	return( retval );
}

int
reload_security_configuration( const char *ifname, const qcsapi_wifi_mode wifi_mode )
{
	int retval = 0;
	char primary_ifname[IFNAMSIZ];

	memset(primary_ifname, 0, sizeof(primary_ifname));
	if (wifi_mode == qcsapi_access_point)
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
	else
		strncpy(primary_ifname, ifname, sizeof(primary_ifname) - 1);

	/*
	 * Use the primary interface name as parameter
	 * Keep consistancy with fix of hostapd_cli reconfigure for MBSS support
	 */
	if (retval >= 0)
		retval = send_message_security_daemon(primary_ifname, wifi_mode, "RECONFIGURE", NULL, 0);

	return( retval );
}

int
create_security_bss_configuration( const char *ifname )
{
	int retval = 0;
	char primary_ifname[IFNAMSIZ];
	char cmd[256];

	memset(primary_ifname, 0, sizeof(primary_ifname));
	retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);

	/*
	 * Use the primary interface name as parameter
	 * Keep consistancy with fix of hostapd_cli reconfigure for MBSS support
	 */
	if (retval >= 0) {
		snprintf(cmd, sizeof(cmd), "CREATE_BSSCONFIG %s", ifname);
		retval = send_message_security_daemon(primary_ifname, qcsapi_access_point, cmd, NULL, 0);
	}

	return( retval );
}

int
update_security_bss_configuration( const char *ifname )
{
	int retval = 0;
	char primary_ifname[IFNAMSIZ];
	char cmd[64] = {0};

	memset(primary_ifname, 0, sizeof(primary_ifname));
	retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
	/*
	 * Use the primary interface name as parameter
	 * Keep consistancy with fix of hostapd_cli reconfigure for MBSS support
	 */
	if (retval >= 0) {
		snprintf(cmd, sizeof(cmd), "UPDATE_BSSCONFIG %s", ifname);
		retval = send_message_security_daemon(primary_ifname, qcsapi_access_point, cmd, NULL, 0);
	}

	return( retval );
}

int
remove_security_bss_configuration( const char *ifname )
{
	int retval = 0;
	char primary_ifname[IFNAMSIZ];
	char cmd[256];

	memset(primary_ifname, 0, sizeof(primary_ifname));
	retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);

	/*
	 * Use the primary interface name as parameter
	 * Keep consistancy with fix of hostapd_cli reconfigure for MBSS support
	 */
	if (retval >= 0) {
		snprintf(cmd, sizeof(cmd), "REMOVE_BSSCONFIG %s", ifname);
		retval = send_message_security_daemon(primary_ifname, qcsapi_access_point, cmd, NULL, 0);
	}

	return( retval );
}

int
qcsapi_wifi_backoff_fail_max(  const char *ifname, const int fail_max )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL)
	  retval = -EFAULT;
	else if (fail_max < MIN_BACKOFF_FAIL_MAX || fail_max > MAX_BACKOFF_FAIL_MAX)
	  retval = -EINVAL;
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_station)
			  retval = -qcsapi_only_on_STA;
		}
	}

	if (retval >= 0)
	{
		char	security_daemon_message[ 32 ];

		snprintf( &security_daemon_message[ 0 ], sizeof( security_daemon_message ) - 1,
			   "SET blacklistFailMax %d", fail_max );
		retval = send_message_security_daemon( ifname, wifi_mode, &security_daemon_message[ 0 ], NULL, 0 );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_backoff_timeout(  const char *ifname, const int timeout )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL)
	  retval = -EFAULT;
	else if (timeout < MIN_BACKOFF_TIMEOUT || timeout > MAX_BACKOFF_TIMEOUT)
	  retval = -EINVAL;
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_station)
			  retval = -qcsapi_only_on_STA;
		}
	}

	if (retval >= 0)
	{
		char	security_daemon_message[ 32 ];

		snprintf( &security_daemon_message[ 0 ], sizeof( security_daemon_message ) - 1,
			   "SET blacklistTimeout %d", timeout );
		retval = send_message_security_daemon( ifname, wifi_mode, &security_daemon_message[ 0 ], NULL, 0 );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

/*
 * verify_PSK is a predicate.  Returns TRUE (1) if proposed PSK is indeed a PSK;
 * returns FALSE (0) if it is not a PSK.  Assumes proposed_PSK is not the NULL address.
 */
static int
verify_PSK( const char *proposed_PSK )
{
	int		retval = 1;		/* assume a PSK until shown otherwise */
	unsigned int	iter, psk_len = 0;
  /*
   * A PSK is required to be EXACTLY 64 hex digits (256 bits) long.
   */
	psk_len = strnlen( proposed_PSK, QCSAPI_WPA_PSK_MAX_SIZE + 1 );
	if (psk_len != QCSAPI_WPA_PSK_MAX_SIZE)
	  retval = 0;
	else
	{
		for (iter = 0; iter < psk_len && retval != 0; iter++)
		{
			if (isxdigit( proposed_PSK[ iter ] ) == 0)
			  retval = 0;
		}
	}

	return( retval );
}

/*
 * A return value of -ENOMEM from the next two entry points should be considered a programming error.
 */

static int
locate_security_file( const char *base_file_name, char *config_file_path, const unsigned int size_file_path )
{
	int		retval = 0;
	unsigned int	base_file_length = 0, folder_length = 0;

	if (base_file_name == NULL)
	  retval = -EFAULT;
	else
	  base_file_length = strnlen( base_file_name, MAX_SECURITY_BASE_FILE_LENGTH );

	if (base_file_length >= size_file_path)
	  retval = -ENOMEM;
	else
	  folder_length = size_file_path - base_file_length;

	if (folder_length + 1 < strlen( QSCAPI_DEFAULT_SECURITY_FOLDER ) )
	  retval = -ENOMEM;

	if (retval >= 0)
	{
		config_file_path[ 0 ] = '\0';
		retval = local_lookup_file_path_config( qcsapi_security_configuration_path, config_file_path, folder_length );
	}

	if (retval != -ENOMEM && retval != -EFAULT && config_file_path[ 0 ] == '\0')
	{
		strcpy( config_file_path, QSCAPI_DEFAULT_SECURITY_FOLDER );
		retval = 0;
	}

	if (retval >= 0)
	{
		unsigned int	config_file_path_len = strlen( config_file_path );

		if (config_file_path_len > 0 &&
		    config_file_path[ strlen( config_file_path ) - 1 ] != '/')
		{
			strcat( config_file_path, "/" );
		}

		strcat( config_file_path, base_file_name );
	}

	return( retval );
}

int
locate_configuration_file( const qcsapi_wifi_mode wifi_mode, char *config_file_path, const unsigned int size_file_path )
{
	int		retval = 0;
	unsigned int	base_file_length = 0, folder_length = 0;
  /*
   *  No check on validity of wifi_mode ...
   *
   *  Account for "/", directory separator.
   */
	if (wifi_mode == qcsapi_access_point)
	  base_file_length = strlen( HOST_APD_CONF ) + 1;
	else
	  base_file_length = strlen( WPA_SUPPLICANT_CONF ) + 1;

	if (base_file_length >= size_file_path)
	  retval = -ENOMEM;
	else
	  folder_length = size_file_path - base_file_length;

	if (folder_length + 1 < strlen( QSCAPI_DEFAULT_SECURITY_FOLDER ) )
	  retval = -ENOMEM;

	if (retval >= 0)
	{
		config_file_path[ 0 ] = '\0';
		retval = local_lookup_file_path_config( qcsapi_security_configuration_path, config_file_path, folder_length );
	}

	if (retval != -ENOMEM && config_file_path[ 0 ] == '\0')
	{
		strcpy( config_file_path, QSCAPI_DEFAULT_SECURITY_FOLDER );
		retval = 0;
	}

	if (retval >= 0)
	{
		strcat( config_file_path, "/" );

		if (wifi_mode == qcsapi_access_point)
		  strcat( config_file_path, HOST_APD_CONF );
		else
		  strcat( config_file_path, WPA_SUPPLICANT_CONF );
	}

	return( retval );
}

static int
extract_integer_parameter( const char *config_addr, int *p_return_value )
{
	int	retval = 0;
	char	first_non_wchar;

	while (isspace( *config_addr ))
	  config_addr++;

	first_non_wchar = *config_addr;
	if (first_non_wchar == '-' || isdigit( first_non_wchar ))
	{
		*p_return_value = atoi( config_addr );
		retval = 1;
	}

	return( retval );
}

static int
parse_config_line(const char *config_line,
		  char *param_name,
		  const size_t length_name,
		  char *param_value,
		  const size_t length_value)
{
	const char	*config_addr = config_line;
	char		*tmp_addr;
	char		*local_param_value;
	char		 tmp_char;
	size_t		 local_length;
	size_t		 remaining_length = length_value;

	if (param_name == NULL || param_value == NULL ||
	    length_name <= 1 || length_value <= 1) {
		return( -qcsapi_programming_error );
	}

	while (isspace( *config_addr )) {
		config_addr++;
	}

	tmp_char = *config_addr;
	if (tmp_char == '\0' || tmp_char == '\n' || tmp_char == '#') {
		return( 0 );
	}

	local_param_value = strchr( config_addr, '=' );
	if (local_param_value == NULL || local_param_value == config_addr) {
		return( -qcsapi_internal_format_error );
	} else if ((local_length = local_param_value - config_addr) >= length_name) {
		return( -qcsapi_buffer_overflow );
	}

	strncpy( param_name, config_addr, local_length );
	tmp_addr = param_name + (local_length -1);
	while (isspace( *tmp_addr ) && tmp_addr != param_name) {
		tmp_addr--;
	}

	tmp_addr++;
	*tmp_addr = '\0';

	local_param_value++;

	while (isspace( *local_param_value )) {
		local_param_value++;
	}

	if (*local_param_value == '"') {
		local_param_value++;
	}

	tmp_addr = param_value;
	remaining_length--;

	while (*local_param_value != '"' &&
	       *local_param_value != '\n' &&
	       *local_param_value != '\0' &&
	       remaining_length > 0) {
		*(tmp_addr++) = *(local_param_value++);
		remaining_length--;
	}

	*tmp_addr = '\0';

	return( 1 );
}


static const char *
locate_parameter_line( const char *parameter, const char *config_line )
{
	const char	*config_addr;
	const char	*retaddr = NULL;
	char		 first_non_wchar;
	int		 continue_program = 1;

	config_addr = config_line;

	while (isspace( *config_addr ))
	  config_addr++;

  /* eliminate comment lines */

	first_non_wchar = *config_addr;
	if (first_non_wchar == '\0' || first_non_wchar == '#')
	  continue_program = 0;

  /* does this line define the parameter? */

	if (continue_program)
	{
		unsigned int	length_of_parameter = strlen( parameter );
		int		found_match = (strncmp( parameter, config_addr, length_of_parameter ) == 0);

		if (found_match)
		{
			char	current_char;
		  /*
 		   * Parameter "wpa" matches "wpa_passphrase"
 		   * But that of course is not a match.
 		   * Eliminate situation here.
 		   */
			config_addr += length_of_parameter;
			current_char = *config_addr;
			found_match = (isspace( current_char ) || current_char == '=');

			continue_program = found_match;
		}
		else
		  continue_program = 0;
	}

	if (continue_program)
	  retaddr = config_addr;

	return( retaddr );
}

static int
process_ap_config_line(
	const char *ifname,
	SSID_parsing_state *p_parse_state,
	const char *parameter,
	char *config_line
)
{
	int		 retval = 0;
	const char	*config_addr = config_line;

	switch (*p_parse_state)
	{
	  case e_searching_for_network:
		if ((config_addr = locate_parameter_line( "interface", config_line )) != NULL ||
			(config_addr = locate_parameter_line( "bss", config_line )) != NULL)
		{
			if (*config_addr == '=')
			  config_addr++;

			if (strncmp(parameter, "interface", 9) == 0) {
				/*
				 * This is the case of Looking up the parameter "interface"
				 * without the interface name.
				 */
				retval = 1;
			} else {
				if (strncmp( config_addr, ifname, strlen(ifname) ) == 0)
				{
					char	check_char = *(config_addr + strlen(ifname));

					if (isspace( check_char ) || check_char == '\0')
					{
						*p_parse_state = e_found_current_network;

						if (strcmp(parameter, "bss") == 0) {
							/*
							 * This is the case of Looking up the parameter "bss"
							 * with the given interface name.
							 */
							retval = 1;
						}
					}
				}
			}
		}
		break;

	  case e_found_current_network:
		if (locate_parameter_line( parameter, config_line ) != NULL) {
			retval = 1;
		} else if (locate_parameter_line( "bss", config_line ) != NULL) {
			*p_parse_state = e_searching_for_network;
		}
		break;

	  default:
		break;
	}

	return( retval );

}

static const char *
locate_ap_parameter_file (
	const char *ifname,
	FILE *config_fh,
	const char *parameter,
	char *config_line,
	const unsigned int line_size
)
{
	int		 complete = 0;
	const char	*retaddr = NULL;
	SSID_parsing_state	e_parse_state = e_searching_for_network, e_previous_state = e_searching_for_network;

	if (ifname && (strcmp(parameter, "interface") != 0) &&
			local_verify_interface_is_primary(ifname) == 0) {
		e_parse_state = e_found_current_network;
	}

	while (complete == 0 && read_to_eol( config_line, line_size, config_fh ) != NULL)
	{
		complete = process_ap_config_line( ifname, &e_parse_state, parameter, config_line );
		if (complete == 0) {
			if (e_previous_state == e_found_current_network &&
				e_parse_state == e_searching_for_network)
			{
				complete = 1;
			}
			else
			{
				e_previous_state = e_parse_state;
			}
		} else {
			/* parameter line found */
			char	current_char = *config_line;
			while (current_char != '=' && current_char != '\0')
			{
				config_line++;
				current_char = *config_line;
			}

			if (current_char == '=')
			{
				 retaddr = config_line + 1;
			}
		}
	}

	return( retaddr );
}


/*
 * Program to get the value of an integer parameter, presumably in connection with a GET API.
 *
 * This program takes the path to the configuration file as one of its parameters.
 * Access to the configuration file is isolated to this program.
 * The calling program should have no further interaction with the contents of this file.
 */

static int
lookup_ap_integer_security_parameter( const char *ifname, const char *config_path, const char *parameter, int *p_return_value )
{
	int		 retval = -ENXIO;			// return value if the parameter is never found
	int		 found_entry = 0, local_param_value;
	char		 config_line[ 122 ];
	const char	*config_addr;
	FILE		*config_fh = fopen( config_path, "r" );

	if (config_fh == NULL)
	{
		retval = -errno;
		if (retval >= 0)
		  retval = -ENOENT;
	}
	else
	{
		if ((config_addr = locate_ap_parameter_file( ifname, config_fh, parameter, &config_line[ 0 ], sizeof( config_line ) )) != NULL)
		  found_entry = extract_integer_parameter( config_addr, &local_param_value );
	}

	if (found_entry)
	{
		retval = 0;
		*p_return_value = local_param_value;
	}

	if (config_fh != NULL)
	  fclose( config_fh );

	return( retval );
}

static int
locate_ap_parameter_with_xfer(
	const char *ifname,
	const char *parameter,
	FILE *config_fh,
	FILE *temp_fh,
	char *config_buffer,
	const unsigned int sizeof_buffer,
	int multi_flag,
	char *value_str,
	size_t sizeof_value_str
)
{
	int	retval = E_PARAMETER_INVALID;
	int	complete = 0;
	SSID_parsing_state	e_parse_state = e_searching_for_network, e_previous_state = e_searching_for_network;
	unsigned int value_len = 0;

	if (ifname == NULL) {
		retval = -EFAULT;
	}

	if (multi_flag) {
		if (value_str == NULL || sizeof_value_str <= 0)
			retval = -EFAULT;
	}

	if (retval >= 0) {
		if ((strcmp(parameter, "interface") != 0) &&
				local_verify_interface_is_primary(ifname) == 0) {
			e_parse_state = e_found_current_network;
		}

		while (complete == 0 && read_to_eol ( config_buffer, sizeof_buffer, config_fh ) != NULL)
		{
			complete = process_ap_config_line( ifname, &e_parse_state, parameter, config_buffer );
			if (complete == 0) {
				if (e_previous_state == e_found_current_network &&
				    e_parse_state == e_searching_for_network)
				{
					if (retval != E_PARAMETER_FOUND)
						retval = E_PARAMETER_NOT_FOUND;
					complete = 1;
				}
				else
				{
					e_previous_state = e_parse_state;
					if (!multi_flag) {
						fprintf( temp_fh, "%s", config_buffer );
					}
				}
			} else {
				retval = E_PARAMETER_FOUND;
				if (multi_flag) {
					char	*temp_config_buffer = config_buffer;
					char    current_char;
					complete = 0;
					current_char = *temp_config_buffer;
					while (current_char != '=' && current_char != '\0') {
						temp_config_buffer++;
						current_char = *temp_config_buffer;
					}
					if (current_char == '=') {
						int len;
						temp_config_buffer++;
						len = strlen(temp_config_buffer);
						if ((value_len + len) < sizeof_value_str) {
							sprintf(value_str, "%s", temp_config_buffer);
							value_str = value_str + len;
							value_len = value_len + len;
						} else {
							retval = E_PARAMETER_EXCEED_LIMIT;
							complete = 1;
						}
					}
				}
			}
		}
	}

	/*
	  * A special case, the parameter which we want to be set to the
	  * last network block doesn't exsit( There isn't any network block behind
	  * the last one, so we can't use "bss" to indicate a new one start)
	  */
	if (e_previous_state == e_found_current_network && complete != 1 && retval == 0) {
		retval = E_PARAMETER_NOT_FOUND;
	}

	return( retval );
}

/*
 * Returns 0 if the target (parameter in Service Set with station_SSID) is not found; 1 if target was found
 */

static int
process_SSID_config_line(
	const char *station_SSID,
	SSID_parsing_state *p_parse_state,
	const char *parameter,
	char *config_line
)
{
	int		 retval = 0;
	const char	*config_addr = config_line;

	switch (*p_parse_state)
	{
	  case e_searching_for_generic_param:
		/* For non BSS-specific config options in the WPA supplicant file */
		if (locate_parameter_line( parameter, config_line ) != NULL) {
			retval = 1;
		}
		break;

	  case e_searching_for_network:
		if (locate_parameter_line( "network", config_line ) != NULL)
		{
			*p_parse_state = e_found_network_token;
		}
		break;

	  case e_found_network_token:
		if ((config_addr = locate_parameter_line( "ssid", config_line )) != NULL)
		{
			unsigned int	length_station_SSID = strlen( station_SSID );

			if (*config_addr == '=')
			  config_addr++;
			if (*config_addr == '"')
			  config_addr++;
		  /*
		   * Don't do just a straight strcmp for the station SSID.
		   * Maybe some additional chars on the line.
		   * If the character following the match is a space char, we have located the network entry.
		   */
			if (strncmp( config_addr, station_SSID, length_station_SSID ) == 0)
			{
				char	check_char = *(config_addr + length_station_SSID);

				if (isspace( check_char ) || check_char == '\0' || check_char == '"')
				{
					*p_parse_state = e_found_current_network;
				}
			}
		  /*
		   * Parameter 'ssid' is a special case.
		   * For it serves as the ID for each network configuration.
		   * If the current network SSID (config_addr) matches the network SSID
		   * (station_SSID, the SSID we are looking for), then this program is
		   * complete.
		   */
			if (*p_parse_state == e_found_current_network && strcmp( parameter, "ssid" ) == 0)
			{
				retval = 1;
			}
		}
		else if (*config_line == '}')
		{
			*p_parse_state = e_searching_for_network;
		}

		break;

	  case e_found_current_network:
		if (locate_parameter_line( parameter, config_line ) != NULL)
		{
			retval = 1;
		}
		else if (*config_line == '}')
		{
			*p_parse_state = e_searching_for_network;
		}
		break;

	/* Do not report if the supplicant parse state is invalid */

	  default:
		break;
	}

	return( retval );
}

static int
locate_SSID_parameter_file(
	const char *station_SSID,
	FILE *config_fh,
	const char *parameter,
	char *config_line,
	const unsigned int config_size,
	char *value_str,
	const unsigned int value_size
)
{
	int			retval = -qcsapi_SSID_not_found;
	int			complete = 0;
	SSID_parsing_state	e_parse_state = e_searching_for_network;

	if (station_SSID == NULL) {
		e_parse_state = e_searching_for_generic_param;
		retval = -qcsapi_parameter_not_found;
	}

  /*
   * Note:  fgets reads in at most one less than config_size characters from config_fh.
   */
	while (complete == 0 && fgets( config_line, config_size, config_fh ) != NULL)
	{
		complete = process_SSID_config_line( station_SSID, &e_parse_state, parameter, config_line );

		if (e_parse_state == e_found_current_network)
		  retval = -qcsapi_SSID_parameter_not_found;

		if (complete)
		{
			const char	*config_addr = locate_parameter_line( parameter, config_line );
		  /*
		   * Accomodate an application that is merely interersted whether the SSID / parameter
		   * is present, and thus sets either value_size to 0 or value_str (address) to NULL.
		   */
			if (config_addr != NULL && value_size > 0 && value_str != NULL)
			{
				int remaining_count = (int) (value_size) - 1;

				*value_str = 0;

				if (*config_addr == '=')
				  config_addr++;
				if (*config_addr == '"')
				  config_addr++;
			  /*
 			   * Because config_addr is obtained from a routine that returns a const char *,
 			   * we can't write to an address with config_addr as its base.
 			   * So the copy below is a bit less elegant, since we can't just look for
 			   * the closing quote (strchr) and set the char at that address to '\0'.
 			   */
				while (*config_addr != '"' && *config_addr != '\0' &&
						*config_addr != '\n' && remaining_count > 0)
				{
					*(value_str++) = *(config_addr++);
					remaining_count--;
				}

				*value_str = '\0';

				retval = 0;
			}
			else
			{
				if (config_addr == NULL)
				  retval = -qcsapi_programming_error;
				else
				  retval = 0;
			}
		}
	}

	return( retval );
}

int get_radius_sever_multi_conf(const char *ifname, FILE *config_fh, const char *parameter,
		char *value_str, char *config_buffer)
{
	char config_line[MAX_SECURITY_CONFIG_LENGTH];
	char *config_addr;
	int retval = E_PARAMETER_NOT_FOUND;

	config_addr = (char *)locate_ap_parameter_file(ifname, config_fh, parameter, config_line,
									sizeof(config_line));
	if (config_addr) {
		config_addr[strlen(config_addr) - 1] = '\0';
		int len = sprintf(value_str, "%s", config_addr);
		value_str = value_str + len;
		retval = E_PARAMETER_FOUND;
		while (read_to_eol(config_line, sizeof (config_line), config_fh ) != NULL) {
			config_addr = (char *)locate_parameter_line(parameter, config_line);
			if (config_addr) {
				config_addr[strlen(config_addr) - 1] = '\0';
				len = sprintf(value_str, "\n%s", config_addr + 1);
				value_str = value_str + len;
			} else if ((config_addr = (char *)locate_parameter_line(
						  "auth_server_port", config_line))) {
				config_addr[strlen(config_addr) - 1] = '\0';
				len = sprintf(value_str, " %s", config_addr + 1);
				value_str = value_str + len;
			} else if ((config_addr = (char *)locate_parameter_line(
					"auth_server_shared_secret", config_line))) {
				config_addr[strlen(config_addr) - 1] = '\0';
				len = sprintf(value_str, " %s", config_addr + 1);
				value_str = value_str + len;
			} else
				break;
		}
	}

	return retval;
}

/*
 * To get the value when multiple param of same type are in hostapd.conf
 */
static int
local_security_get_multi_parameter(
	const char *ifname,
	const qcsapi_wifi_mode wifi_mode,
	const char *parameter,
	char *value_str,
	size_t value_size,
	const int multi_set
)
{
	int		retval = E_PARAMETER_INVALID;
	char		config_line_addr[MAX_SECURITY_CONFIG_LENGTH];
	char		config_file_path[MAX_SECURITY_CONFIG_LENGTH];
	unsigned int	sizeof_buffer = sizeof( config_line_addr );
	char		*config_buffer = &config_line_addr[0];
	int		local_error_val;
	FILE		*config_fh = NULL;

	if (ifname == NULL) {
		retval = -EFAULT;
	}
	if (wifi_mode != qcsapi_access_point) {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		local_error_val = locate_configuration_file( wifi_mode,
							&config_file_path[ 0 ],
							sizeof( config_file_path ) );
		if (local_error_val >= 0)
			config_fh = fopen( &config_file_path[ 0 ], "r" );

		if (config_fh == NULL) {
			if (local_error_val < 0)
				retval = local_error_val;
			else {
				retval = -errno;
				if (retval >= 0)
				  retval = -ENOENT;
			}
		} else {
			if (multi_set) {
				local_error_val = get_radius_sever_multi_conf(ifname, config_fh,
								parameter, value_str,
								config_buffer);
			} else {
				local_error_val = locate_ap_parameter_with_xfer(ifname,
										parameter,
										config_fh,
										NULL,
										config_buffer,
										sizeof_buffer,
										1,
										value_str,
										value_size);
			}

			if (local_error_val == E_PARAMETER_EXCEED_LIMIT) {
				retval = -qcsapi_buffer_overflow;
			} else if (local_error_val != E_PARAMETER_FOUND) {
				retval = -qcsapi_parameter_not_found;
			}
		}
	}

	if (config_fh != NULL)
		fclose( config_fh );

	return( retval );
}

int
lookup_ap_security_parameter(
	const char *ifname,
	const qcsapi_wifi_mode wifi_mode,
	const char *parameter,
	char *value_str,
	const unsigned int value_size
)
{
	int		 retval = -qcsapi_parameter_not_found;
	char		 config_line[MAX_SECURITY_CONFIG_LENGTH];
	char		 config_file_path[MAX_SECURITY_CONFIG_LENGTH];
	const char	*config_addr;
	FILE		*config_fh = NULL;
	int		 local_error_val = locate_configuration_file( wifi_mode, &config_file_path[ 0 ], sizeof( config_file_path ) );

	if (local_error_val >= 0)
	  config_fh = fopen( &config_file_path[ 0 ], "r" );

	if (config_fh == NULL)
	{
		if (local_error_val < 0)
		  retval = local_error_val;
		else
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -ENOENT;
		}
	}
	else
	{
		if (wifi_mode == qcsapi_access_point)
		{
			config_addr = locate_ap_parameter_file(ifname, config_fh, parameter,
						   &config_line[0], sizeof (config_line));
			if (config_addr)
			{
				/*
				 * locate_parameter_file calls fgets to read lines from the file.
				 * But fgets includes the newline character.
				 * Keep newline character out of the returned value string
				 */
				unsigned int	iter;

				for (iter = 0; iter < value_size - 1 && *config_addr != '\n' &&
				                                *config_addr != '\0'; iter++) {
					*(value_str++) = *(config_addr++);
				}

				*value_str = '\0';
				retval = 0;
			}
		}
	}

	if (config_fh != NULL)
		fclose( config_fh );

	return( retval );
}

static int
lookup_ap_ifname_by_index(
	const unsigned int if_index,
	char *if_name,
	const unsigned int if_name_size
)
{
	int retval = 0;
	char config_line[ 122 ];
	char config_file_path[ 122 ];
	const char *config_addr = NULL;
	FILE *config_fh = NULL;
	int local_error_val = locate_configuration_file( qcsapi_access_point, &config_file_path[ 0 ], sizeof( config_file_path ) );

	if (local_error_val >= 0)
	  config_fh = fopen( &config_file_path[ 0 ], "r" );

	if (config_fh == NULL)
	{
		if (local_error_val < 0)
		  retval = local_error_val;
		else
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -ENOENT;
		}
	}
	else
	{
		int complete = 0;
		int i = 0;

		while (complete == 0 && fgets( config_line, sizeof( config_line ), config_fh ) != NULL)
		{
			if ((config_addr = locate_parameter_line( "interface", config_line )) != NULL ||
				(config_addr = locate_parameter_line( "bss", config_line )) != NULL) {
				if (i == if_index) {
					complete = 1;
				} else {
					i++;
				}
			}
		}

		if (complete == 0) {
			retval = -EINVAL;
		}

		if (retval >= 0)
		{
			unsigned int iter;

			if (*config_addr == '=') {
				config_addr++;
			}

			for (iter = 0; iter < if_name_size - 1 && *config_addr != '\n' && *config_addr != '\0'; iter++)
			  *(if_name++) = *(config_addr++);
			*if_name = '\0';
		}
	}

	if (config_fh != NULL)
	  fclose( config_fh );

	return( retval );
}

int
lookup_SSID_parameter(
	const char *network_SSID,
	const qcsapi_wifi_mode wifi_mode,
	const char *parameter,
	char *value_str,
	const unsigned int value_size
)
{
	int		 retval = 0;
	char		 config_line[ 122 ];
	FILE		*config_fh = NULL;

	char	config_file_path[ 122 ];

	retval = locate_configuration_file( wifi_mode, &config_file_path[ 0 ], sizeof( config_file_path ) );

	if (retval >= 0)
	{
		config_fh = fopen( &config_file_path[ 0 ], "r" );
	}

	if (config_fh == NULL)
	{
		retval = -errno;
		if (retval >= 0)
			retval = -ENOENT;
	}

	if (retval >= 0)
	{
		retval = locate_SSID_parameter_file(
			 network_SSID,
			 config_fh,
			 parameter,
			&config_line[ 0 ],
			 sizeof( config_line ),
			 value_str,
			 value_size
		);
	}

	if (config_fh != NULL)
	  fclose( config_fh );

	return( retval );
}

static int
locate_SSID_parameter_with_xfer(
	const char *station_SSID,
	const char *parameter,
	FILE *config_fh,
	FILE *temp_fh,
	char *config_buffer,
	const unsigned int sizeof_buffer
)
{
	int			retval = E_PARAMETER_INVALID;
	int			complete = 0;
	SSID_parsing_state	e_parse_state = e_searching_for_network, e_previous_state = e_searching_for_network;

	if (station_SSID == NULL) {
		e_parse_state = e_searching_for_generic_param;
	}
  /*
   * Note:  fgets reads in at most one less than sizeof_buffer characters from config_fh.
   */
	while (complete == 0 && fgets( config_buffer, sizeof_buffer, config_fh ) != NULL)
	{
		complete = process_SSID_config_line( station_SSID, &e_parse_state, parameter, config_buffer );

		if (complete == 0)
		{
			if (e_previous_state == e_found_current_network &&
			    e_parse_state == e_searching_for_network)
			{
				retval = E_PARAMETER_NOT_FOUND;
				complete = 1;
			}
			else
			{
				e_previous_state = e_parse_state;
				fprintf( temp_fh, "%s", config_buffer );
			}
		}
		else
			retval = E_PARAMETER_FOUND;
	}

	if ((complete == 0) && (e_parse_state == e_searching_for_generic_param))
		retval = E_PARAMETER_NOT_FOUND;

	return( retval );
}

static int
find_first_ssid(char *first_SSID, int SSID_len, FILE *config_fh)
{
	int retval = E_PARAMETER_NOT_FOUND;
	char config_buffer[128];
	unsigned int sizeof_buffer = sizeof(config_buffer);
	const char *ssid_addr;
	int ssid_len;

	if ( (first_SSID == NULL) || (config_fh == NULL)) {
		return (E_PARAMETER_INVALID);
	}

	while (fgets(config_buffer, sizeof_buffer, config_fh) != NULL) {
		if ((ssid_addr = locate_parameter_line("ssid", config_buffer)) != NULL) {
			if (ssid_addr[0] == '=' && ssid_addr[1] == '\"') {
				memset(first_SSID, 0, SSID_len);
				strncpy(first_SSID, &ssid_addr[2], SSID_len - 1);
				ssid_len = strlen(first_SSID);
				if (first_SSID[ssid_len - 2] == '\"') {
					first_SSID[ssid_len - 1] = 0;	/* /n */
					first_SSID[ssid_len - 2] = 0;	/* close quote */
				} else {
					printf("Incorrect SSID format\n");
				}
				printf("first ssid: [%s]\n", first_SSID);
				retval = 0;
				break;
			}
		}
	}

	return (retval);
}

static int
count_ssid_networks(
	const char *ssid,
	int *p_counter,
	FILE *config_fh
)
{
	int counter = 0;
	int retval = 0;
	char config_buffer[122];
	unsigned int sizeof_buffer = sizeof(config_buffer);
	SSID_parsing_state e_parse_state = e_searching_for_network;

	if ( (ssid == NULL) || (p_counter == NULL) || (config_fh == NULL)) {
		return (E_PARAMETER_INVALID);
	}
	/*
	* Note:  fgets reads in at most one less than sizeof_buffer characters from config_fh.
	*/
	while (fgets(config_buffer, sizeof_buffer, config_fh) != NULL) {
		process_SSID_config_line(ssid, &e_parse_state, "ssid", config_buffer);

		if (e_parse_state == e_searching_for_network) {
			if (config_buffer[0] == '}')
				counter++;
		} else if (e_parse_state == e_found_current_network) {
			retval = -EEXIST;
			counter = 0;
			break;
		}
	}

	*p_counter = counter;
	return (retval);
}

static int
remove_SSID_network_file_xfer(
	const char *station_SSID,
	const char *parameter,
	FILE *config_fh,
	FILE *temp_fh,
	char *config_buffer,
	const unsigned int sizeof_buffer
)
{
	char temp_network_content[256] = {0};
	int retval = E_PARAMETER_INVALID;
	int pre_complete = 0, complete = 0;
	SSID_parsing_state e_parse_state = e_searching_for_network, e_previous_state = e_searching_for_network;

	if (station_SSID == NULL) {
		return E_PARAMETER_NOT_FOUND;
	}
  /*
   * Note:  fgets reads in at most one less than sizeof_buffer characters from config_fh.
   */
	while (fgets( config_buffer, sizeof_buffer, config_fh ) != NULL) {
		complete = process_SSID_config_line(station_SSID, &e_parse_state, parameter, config_buffer);
		if (complete == 0 && pre_complete == 0) {
			if (e_previous_state == e_found_current_network &&
				e_parse_state == e_searching_for_network) {
				retval = E_PARAMETER_NOT_FOUND;
				complete = 1;
				pre_complete = 1;
			} else {
				if ((e_parse_state == e_searching_for_network) &&
					(e_previous_state == e_found_network_token)) {
					fprintf(temp_fh, "%s", temp_network_content);
					memset(temp_network_content, 0, sizeof(temp_network_content));
				}
				e_previous_state = e_parse_state;
				if (e_previous_state == e_found_network_token) {
					sprintf( temp_network_content
						+ strlen(temp_network_content),
						"%s", config_buffer );
				} else {
					fprintf(temp_fh, "%s", config_buffer);
				}
			}
		} else {
			if (e_previous_state == e_found_current_network &&
					e_parse_state == e_searching_for_network) {
				retval = E_PARAMETER_FOUND;
				break;
			} else {
				e_previous_state = e_parse_state;
			}
			pre_complete = 1;
		}
	}

	return(retval);
}


/*
 * Read through the rest of the security file and output it unmodifed.
 */
static int
complete_security_file_xfer(FILE *config_fh, FILE *temp_fh, char *config_buffer, const unsigned int sizeof_buffer, int remove_null_line)
{
	int	retval = 0;
  /*
   * Note:  fgets reads in at most one less than sizeof_buffer characters from config_fh.
   */
	while (read_to_eol( config_buffer, sizeof_buffer, config_fh) != NULL) {
		if (remove_null_line == 0 || strcmp(config_buffer, "\n"))
			fprintf(temp_fh, "%s", config_buffer);
	}

	return (retval);
}
static int local_security_get_param_len(const char * value, char ch)
{
	int count = 0;
	if (value == NULL)
		return 0;
	while(*value) {
		if (*value == ch)
			return count;
		count++;
		value++;
	}
	return count;
}
static const char * local_security_get_nai_realm_ptr(const char *value)
{
	const char *nai = value;
	if (value == NULL)
		return NULL;
	nai = nai + local_security_get_param_len(nai, ',');
	if (nai == value)
		return NULL;
	return (nai + 1);
}

static int
local_security_traverse_nai(FILE *config_fh, FILE *temp_fh,
	char *config_buffer, const unsigned int sizeof_buffer, const char *value)
{
	int	retval = 0;
	const char *config_addr;
	int	buf_len = 0;
	int value_nai_len;
	int line_count = 1;

#define MAX_NAI_REALM 10

	/* Config_buffer has starting line of nai_realm */
	if (config_buffer == NULL) {
		return retval;
	}
	if (value == NULL){
		return E_PARAMETER_NOT_FOUND;
	}
	value_nai_len = local_security_get_param_len(value, ',');
	do {
		if ((config_addr = locate_parameter_line(NAI_REALM_PARAM, config_buffer))) {
			config_addr = local_security_get_nai_realm_ptr(config_addr);
			if (config_addr == NULL)
				continue;
			buf_len = local_security_get_param_len(config_addr, ',');
		} else {
			/* nai_realm param was not present in current line*/
			return E_PARAMETER_NOT_FOUND;
		}


		if (!((value_nai_len == buf_len) && (strncmp(config_addr, value, buf_len) == 0))) {
			fprintf(temp_fh, "%s", config_buffer);
			if (line_count >= MAX_NAI_REALM)
				return E_PARAMETER_EXCEED_LIMIT;
			line_count++;
		} else
			return E_PARAMETER_FOUND;
	} while ((!retval) && (read_to_eol( config_buffer, sizeof_buffer, config_fh)));

	return (retval);
}

static int
local_security_traverse_param(FILE *config_fh, FILE *temp_fh,
	char *config_buffer, const unsigned int sizeof_buffer,
	const char *param, const char *value)
{
	int	retval = 0;
	const char *config_addr;
	int	buf_len = 0;
	int param_len;

	/* Config_buffer has starting line of Param */
	if (config_buffer == NULL) {
		return retval;
	}
	param_len = strlen(value);
	do {
		if ((config_addr = locate_parameter_line(param, config_buffer))) {
			/* skip '=' character */
			config_addr++;
			buf_len = local_security_get_param_len(config_addr, '\n');
		} else {
			/* Param was not present in current line*/
			return E_PARAMETER_NOT_FOUND;
		}

		/* Checking argument param with hostapd.conf for avoid duplicate*/
		if (!((param_len == buf_len) && (strncmp(config_addr, value, buf_len) == 0)))
			fprintf(temp_fh, "%s", config_buffer);
		else
			return E_PARAMETER_FOUND;
	} while ((!retval) && (read_to_eol( config_buffer, sizeof_buffer, config_fh)));

	return (retval);
}

static void skip_current_config(FILE *config_fh, char *config_buffer, const unsigned int sizeof_buffer)
{
	while (read_to_eol( config_buffer, sizeof_buffer, config_fh)) {
		if ((locate_parameter_line("auth_server_port", config_buffer))) {
			continue;
		} else if ((locate_parameter_line("auth_server_shared_secret",
							config_buffer))) {
			continue;
		} else {
			return;
		}
	}
}

static int
local_security_traverse_multiset(FILE *config_fh, FILE *temp_fh, char *config_buffer,
				const unsigned int sizeof_buffer, const char *ipaddr,
				const char *port)
{
	int	retval = 0;
	const char *config_addr;
	char temp_config_buffer[MAX_SECURITY_CONFIG_LENGTH];

	do {
		config_addr = locate_parameter_line("auth_server_addr", config_buffer);
		if (config_addr) {
			config_addr++;
			if (strncmp(config_addr, ipaddr, strlen(ipaddr)) == 0) {
				strncpy(temp_config_buffer, config_buffer, sizeof(temp_config_buffer) - 1);
				read_to_eol(config_buffer, sizeof_buffer, config_fh);
				config_addr = locate_parameter_line("auth_server_port",
								config_buffer);
				if (config_addr) {
					config_addr++;
					if (strncmp(config_addr, port, strlen(port)) == 0) {
						retval = E_PARAMETER_FOUND;
					} else {
						fprintf(temp_fh, "%s", temp_config_buffer);
						fprintf(temp_fh, "%s", config_buffer);
					}
				}
			} else {
				fprintf(temp_fh, "%s", config_buffer);
			}
		} else if ((locate_parameter_line("auth_server_port", config_buffer))) {
			fprintf(temp_fh, "%s", config_buffer);
		} else if ((locate_parameter_line("auth_server_shared_secret", config_buffer))) {
			fprintf(temp_fh, "%s", config_buffer);
		} else {
			retval = E_PARAMETER_NOT_FOUND;
		}
	} while (!retval && read_to_eol(config_buffer, sizeof_buffer, config_fh));

	return (retval);
}

static int
local_security_traverse_hs20_conn_capab(FILE *config_fh, FILE *temp_fh,
	char *config_buffer, const unsigned int sizeof_buffer, const char *value)
{
	int		retval = 0;
	const char	*config_addr;
	int		buf_len = 0;
	int		value_len;
	char		*pch;

	/* Config_buffer has starting line of hs20_conn_capab */
	if (config_buffer == NULL) {
		return retval;
	}
	if (value == NULL){
		return E_PARAMETER_NOT_FOUND;
	}
	pch = strrchr(value, ':');
	if (!pch)
		return -EINVAL;

	value_len = pch - value;

	do {
		if ((config_addr = locate_parameter_line("hs20_conn_capab", config_buffer))) {
			config_addr++;
			pch = strrchr(config_addr, ':');
			if (pch == NULL)
				continue;
			buf_len = pch - config_addr;
		} else {
			/* hs20_conn_capab param was not present in current line*/
			return E_PARAMETER_NOT_FOUND;
		}


		if (!((value_len == buf_len) && (strncmp(config_addr, value, buf_len) == 0))) {
			fprintf(temp_fh, "%s", config_buffer);
		} else
			return E_PARAMETER_FOUND;
	} while (!retval && read_to_eol( config_buffer, sizeof_buffer, config_fh));

	return (retval);
}

static int locate_radius_config_param(
	const char *parameter,
	const char *value_str,
	const int remove_param,
	FILE *config_fh,
	FILE *temp_fh,
	char *config_buffer,
	const unsigned int sizeof_buffer
)
{
	int val;
	char *ip = NULL;
	char *port = NULL;
	char *sh_secret = NULL;
	string_256 val_buf;

	strncpy(val_buf, value_str, sizeof(val_buf));
	ip = strtok(val_buf, ",");
	port = strtok(NULL, ",");
	sh_secret = strtok(NULL, ",");
	val_buf[sizeof(val_buf) - 1] = '\0';

	val = local_security_traverse_multiset(config_fh, temp_fh,
			&config_buffer[0], sizeof_buffer, ip, port);

	if (remove_param == 0) {
		fprintf(temp_fh, "auth_server_addr=%s\n", ip);
		fprintf(temp_fh, "auth_server_port=%s\n", port);
		fprintf(temp_fh, "auth_server_shared_secret=%s\n", sh_secret);
	}

	if (val == E_PARAMETER_FOUND) {
		skip_current_config(config_fh, &config_buffer[0], sizeof_buffer);
		fprintf(temp_fh, "%s", config_buffer);
	}

	return val;
}

static int
local_security_add_multi_parameter(
	const char *parameter,
	const char *value_str,
	const int remove_param,
	FILE *config_fh,
	FILE *temp_fh,
	char *config_buffer,
	const unsigned int sizeof_buffer
)
{
	int retval = 0;
	int val;
	const char *config_addr;

	if (strcmp(parameter ,"auth_server_addr") == 0) {
		val = locate_radius_config_param(parameter, value_str, remove_param, config_fh,
							temp_fh, config_buffer, sizeof_buffer);
	} else if (strcmp(parameter , NAI_REALM_PARAM) == 0) {
		val = local_security_traverse_nai(config_fh, temp_fh,
			&config_buffer[0], sizeof_buffer,
			remove_param ? value_str : local_security_get_nai_realm_ptr(value_str));
		if (remove_param == 0) {
			if (val == E_PARAMETER_EXCEED_LIMIT)
				retval = -qcsapi_param_count_exceeded;
			fprintf(temp_fh, "%s=%s\n", parameter, value_str);
		}
	} else if (strcmp(parameter , "hs20_conn_capab") == 0) {
		val = local_security_traverse_hs20_conn_capab(config_fh, temp_fh,
			&config_buffer[0], sizeof_buffer, value_str);
		if (remove_param == 0) {
			if (val == E_PARAMETER_FOUND) {
				config_addr = locate_parameter_line("hs20_conn_capab",
								config_buffer);
				config_addr++;
				if (!strncmp(config_addr, value_str, strlen(value_str)))
					retval = -qcsapi_duplicate_param;
			}
			fprintf(temp_fh, "%s=%s\n", parameter, value_str);
		}
	} else {
		val = local_security_traverse_param(config_fh, temp_fh,
			&config_buffer[0], sizeof_buffer, parameter,value_str);
		if (remove_param == 0) {
			if (val == E_PARAMETER_FOUND)
				retval = -qcsapi_duplicate_param;
			fprintf(temp_fh, "%s=%s\n", parameter, value_str);
		}
	}
	if(remove_param == 1) {
		if (val != E_PARAMETER_FOUND)
			retval = -qcsapi_parameter_not_found;
	}
	/* To write next line of nai_realm */
	if (val == E_PARAMETER_NOT_FOUND){
		fprintf(temp_fh, "%s", config_buffer);
	}
	return retval;
}

/*
 * Argument update_flag is present for PSK and pass phrase.
 * Only one of the two should be present in the file.
 * So that both can be configured, if the PSK or the pass phrase are configured with
 * the 0-length string, the corresponding entry in the file is removed.
 *
 * Argument quote_flag is also present for PSK and pass phrase.  On the AP (currently)
 * these values are NOT in double quotes; on the station, they are in double quotes.
 * Other security parameters are NOT in double quotes.
 */

static int
update_security_parameter_i(
	const char *ifname,
	const char *station_SSID,
	const char *parameter,
	const char *value_str,
	const qcsapi_wifi_mode wifi_mode,
	const int update_flag,
	const int quote_flag,
	const int complete_update,
	const int remove_param,
	const int multi_flag
)
{
	int		 retval = 0;
	char		 configuration_file[MAX_SECURITY_CONFIG_LENGTH];
	char		 qcsapi_temporary_conf[MAX_SECURITY_CONFIG_LENGTH];
	const char	*configuration_program = NULL;
	FILE		*config_fh = NULL, *temp_fh = NULL;
	int update_mode = local_wifi_security_update_mode();

	if (update_mode == security_update_complete)
		update_mode = complete_update;

  /*
   * If the real User ID is not root, then abort now.
   */
	if (getuid() != 0)
	{
		retval = -EPERM;
	}
	else
	{
		retval = locate_configuration_file( wifi_mode, &configuration_file[ 0 ], sizeof( configuration_file ) );
		configuration_program = (wifi_mode == qcsapi_access_point) ? HOST_APD_PROCESS : WPA_SUPPLICANT_PROCESS;
	}

	if (retval >= 0)
	{
		config_fh = fopen( configuration_file, "r" );
		if (config_fh == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval =  -ENOENT;
		}
	}

	if (retval >= 0)
	{
		retval = local_lookup_file_path_config(
				 qcsapi_security_configuration_path,
				&qcsapi_temporary_conf[ 0 ],
				 sizeof( qcsapi_temporary_conf ) - (strlen( QCSAPI_TEMPORARY_CONF ) + 1)
		);
	}

	if (retval >= 0)
	{
		strcat( &qcsapi_temporary_conf[ 0 ], "/" );
		strcat( &qcsapi_temporary_conf[ 0 ], QCSAPI_TEMPORARY_CONF );

		temp_fh = fopen( &qcsapi_temporary_conf[ 0 ], "w" );
		if (temp_fh == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval =  -EACCES;

			if (config_fh != NULL)
			  fclose( config_fh );
			config_fh = NULL;
		}
	}

	if (retval >= 0)
	{
		int		ival;
		char		config_buffer[MAX_SECURITY_CONFIG_LENGTH];
		unsigned int	sizeof_buffer = sizeof( config_buffer );

		if (wifi_mode == qcsapi_access_point) {
			ival = locate_ap_parameter_with_xfer(ifname, parameter, config_fh,
					temp_fh, &config_buffer[0], sizeof_buffer, 0, NULL, 0);
			if (ival == E_PARAMETER_FOUND || ival == E_PARAMETER_NOT_FOUND) {
				if (update_flag) {
					if (!multi_flag) {
						if (!remove_param) {
							fprintf(temp_fh, "%s=%s\n",
								parameter, value_str);
						}
					} else {
						retval = local_security_add_multi_parameter(
									parameter,
									value_str,
									remove_param,
									config_fh,
									temp_fh,
									config_buffer,
									sizeof_buffer
									);
					}
				}

				/*
				 * If the param was not found, config_buffer
				 * now points to the next network block or EOF,
				 * If it's another BSS, need to output the line
				 * now so it is not lost by the next read in
				 * complete_security_file_xfer
				 */
				if ((!multi_flag) && (ival == E_PARAMETER_NOT_FOUND) &&
						(strncmp(&config_buffer[0], "bss=", 4) == 0)) {
					fprintf(temp_fh, "%s", &config_buffer[0]);
				}
			} else {
				/* Network block ifname not found */
				retval = -EINVAL;
			}

			if (ival > 0) {
				complete_security_file_xfer(config_fh, temp_fh,
					&config_buffer[0], sizeof_buffer, 0);
			}
		} else {
			ival = locate_SSID_parameter_with_xfer(
				 station_SSID,
				 parameter,
				 config_fh,
				 temp_fh,
				&config_buffer[ 0 ],
				 sizeof_buffer
			);

			if (ival == E_PARAMETER_FOUND)
			{
				if (update_flag)
				{
					if (!remove_param) {
						char *update_start = strstr( &config_buffer[ 0 ], parameter );

						if (update_start != NULL)
						{
							update_start += strlen( parameter );
							strcpy( update_start, "=" );
							if (quote_flag)
							  strcat( update_start, "\"" );
							strcat( update_start, value_str );
							if (quote_flag)
							  strcat( update_start, "\"" );
						}
						/*
						* We should always be able to find the name of the parameter.
						* If not, just write out parameter=value
						*/
						else
						{
							if (quote_flag)
							  sprintf( &config_buffer[ 0 ], "\t%s=\"%s\"\n", parameter, value_str );
							else
							  sprintf( &config_buffer[ 0 ], "\t%s=%s\n", parameter, value_str );
						}
						/*
						* The new-line character has been lost ...
						* Let the C-library figure out the correct representation ...
						*/
						fprintf( temp_fh, "%s\n", &config_buffer[ 0 ] );
					}
				}
			}
			else if (ival == E_PARAMETER_NOT_FOUND)
			{
				/*
				 * station_SSID is NULL, means that the parameter is global,
				 * so avoid to intend.
				 */
				if (!remove_param) {
					if (station_SSID == NULL) {
						if (quote_flag)
							fprintf( temp_fh, "%s=\"%s\"\n", parameter, value_str );
						else
							fprintf( temp_fh, "%s=%s\n", parameter, value_str );
					} else {
						if (quote_flag)
							fprintf( temp_fh, "\t%s=\"%s\"\n", parameter, value_str );
						else
							fprintf( temp_fh, "\t%s=%s\n", parameter, value_str );

						fprintf( temp_fh, "%s\n", &config_buffer[ 0 ] );
					}
				} else if (station_SSID != NULL) {
					fprintf( temp_fh, "%s\n", &config_buffer[ 0 ] );
				}
			}
			else
			{
				retval = -qcsapi_SSID_not_found;
			}

			if (ival > 0)
			{
				complete_security_file_xfer(config_fh, temp_fh, &config_buffer[ 0 ], sizeof_buffer, 0);
			}
		}

		fclose( config_fh );
		config_fh = NULL;
		fclose( temp_fh );

		if (retval >= 0)
		{
			ival = unlink( configuration_file );
			if (ival < 0)
			{
				retval = -errno;
				if (retval >= 0)
				  retval = ival;
			}
		}
	}

	if (retval >= 0)
	{
		int	ival = rename( qcsapi_temporary_conf, configuration_file );

		if (ival < 0)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = ival;
		}
	}

	if (retval >= 0 && update_mode != security_update_pending)
	{
		if (wifi_mode == qcsapi_access_point)
			retval = update_security_bss_configuration( ifname );
		else
			retval = reload_security_configuration( ifname, wifi_mode );
	}

	if (config_fh != NULL)
		fclose( config_fh );

	return( retval );
}

int
qcsapi_wifi_apply_security_config(const char *ifname)
{
	int retval = 0;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	int skfd = -1;

	enter_qcsapi();

	if (ifname == NULL)
		retval = -EFAULT;

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = skfd;
		}
	}

	if (retval >= 0)
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);

	if (retval >= 0) {
		if (wifi_mode == qcsapi_access_point)
			retval = update_security_bss_configuration(ifname);
		else
			retval = reload_security_configuration(ifname, wifi_mode);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int update_security_parameter(
	const char *ifname,
	const char *station_SSID,
	const char *parameter,
	const char *value_str,
	const qcsapi_wifi_mode wifi_mode,
	const int update_flag,
	const int quote_flag,
	const int complete_update
)
{
	return update_security_parameter_i(ifname,
			station_SSID,
			parameter,
			value_str,
			wifi_mode,
			update_flag,
			quote_flag,
			complete_update,
			0,
			0);
}

int remove_security_parameter(
	const char *ifname,
	const char *station_SSID,
	const char *parameter,
	const qcsapi_wifi_mode wifi_mode,
	const int complete_update)
{
	return update_security_parameter_i(ifname,
					   station_SSID,
					   parameter,
					   NULL,
					   wifi_mode,
					   QCSAPI_TRUE,
					   0,
					   complete_update,
					   QCSAPI_TRUE,
					   QCSAPI_FALSE);
}

int
local_security_get_multi_entry_param( const char *ifname, const char *param, char *p_value,
					size_t value_size )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (p_value == NULL || value_size <= 0) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		string_4096	value;
		const char	*actual_param = param;

		retval = local_security_get_multi_parameter( ifname,
							wifi_mode,
							actual_param,
							&value[0],
							value_size,
							0);

		if (retval >= 0)
			strcpy( p_value, value );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
local_security_update_multi_entry_param(
	const char *ifname,
	const char *param,
	const char *p_value,
	int remove_param
)
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (p_value == NULL ) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = update_security_parameter_i(
				 ifname,
				 NULL,
				 param,
				 p_value,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete,
				 remove_param,
				 1
			);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

/*
 * Create a new "network" (configuration) for a station (not an access point).
 * Canned content based on the current contents of wpa_supplicant.conf.
 */

static int
write_new_SSID_instantiation( FILE *temp_fh, const char *new_SSID )
{
	int	retval = 0;

	fprintf( temp_fh, "\n" );
	fprintf( temp_fh, "network={\n" );
	fprintf( temp_fh, "\tssid=\"%s\"\n", new_SSID );
	fprintf( temp_fh, "\tproto=WPA2\n" );
	fprintf( temp_fh, "\tkey_mgmt=WPA-PSK\n" );
	fprintf( temp_fh, "\tpairwise=CCMP\n" );
	fprintf( temp_fh, "\tscan_ssid=1\n" );
	fprintf( temp_fh, "\tpsk=\"0123456789ABCDEF\"\n" );
	fprintf( temp_fh, "\tieee80211w=0\n" );
	fprintf( temp_fh, "}\n" );

	return( retval );
}

static int
check_before_new_ssid_instantiation(const char *new_SSID, const qcsapi_wifi_mode wifi_mode);

static int
instantiate_new_SSID_config( const char *new_SSID, const qcsapi_wifi_mode wifi_mode )
{
	int		 retval = 0;
	int		 continue_update = 0;
	char		 configuration_file[ 122 ];
	char		 qcsapi_temporary_conf[ 122 ];
	FILE		*config_fh = NULL, *temp_fh = NULL;
  /*
   * If the real User ID is not root, then abort now.
   */
	if (getuid() != 0)
	{
		retval = -EPERM;
	}

	if (retval >=0)
	{
		retval = check_before_new_ssid_instantiation(new_SSID, wifi_mode);
	}

	if (retval >= 0)
	{
		retval = locate_configuration_file( wifi_mode, &configuration_file[ 0 ], sizeof( configuration_file ) );
	}

	if (retval >= 0)
	{
		config_fh = fopen( configuration_file, "r" );

		if (config_fh == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval =  -ENOENT;
		}
	}

	if (retval >= 0)
	{
		retval = local_lookup_file_path_config(
				 qcsapi_security_configuration_path,
				&qcsapi_temporary_conf[ 0 ],
				 sizeof( qcsapi_temporary_conf ) - (strlen( QCSAPI_TEMPORARY_CONF ) + 1)
		);
	}

	if (retval >= 0)
	{
		strcat( &qcsapi_temporary_conf[ 0 ], "/" );
		strcat( &qcsapi_temporary_conf[ 0 ], QCSAPI_TEMPORARY_CONF );

		temp_fh = fopen( &qcsapi_temporary_conf[ 0 ], "w" );
		if (temp_fh == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval =  -EACCES;

			if (config_fh != NULL)
			  fclose( config_fh );
			config_fh = NULL;
		}
	}

	if (retval >= 0)
	{
		char		config_buffer[ 122 ];
		unsigned int	sizeof_buffer = sizeof( config_buffer );
		int		ival;

		if (locate_SSID_parameter_with_xfer(
			 new_SSID,
			"ssid",
			 config_fh,
			 temp_fh,
			&config_buffer[ 0 ],
			 sizeof_buffer
		) == 0)
		{
			ival = write_new_SSID_instantiation( temp_fh, new_SSID );
			continue_update = 1;
		}
		else
		{
		  /*
 		   * If this SSID is present in the WPA configuration file, no further action is required.
 		   * QSCAPI temporary file will get overwritten
 		   * the next time an update to the WPA configuration file is required.
 		   */
			continue_update = 0;
			retval = -EEXIST;
		}

		fclose( config_fh );
		config_fh = NULL;
		fclose( temp_fh );

		if (continue_update)
		{
			ival = unlink( configuration_file );
			if (ival < 0)
			{
				retval = -errno;
				if (retval >= 0)
				  retval = ival;
			}

			if (retval >= 0)
			{
				ival = rename( qcsapi_temporary_conf, configuration_file );

				if (ival < 0)
				{
					retval = -errno;
					if (retval >= 0)
					  retval = ival;
				}
			}
		  /*
		   * No reload of security parameters.
		   * No signal to the security daemon (hostapd or wpa_supplicant).
		   */
		}
	}

	if (config_fh != NULL)
		fclose( config_fh );

	return( retval );
}

static int
qcsapi_wifi_remove_SSID(const char *del_SSID, const qcsapi_wifi_mode wifi_mode)
{
	int retval = 0;
	int continue_update = 0;
	char configuration_file[122];
	char qcsapi_temporary_conf[122];
	FILE *config_fh = NULL, *temp_fh = NULL;
	/*
	* If the real User ID is not root, then abort now.
	*/
	if (getuid() != 0) {
		retval = -EPERM;
	}

	if (retval >= 0) {
		retval = locate_configuration_file(wifi_mode,
			&configuration_file[0], sizeof(configuration_file));
	}

	if (retval >= 0) {
		config_fh = fopen(configuration_file, "r");

		if (config_fh == NULL) {
			retval = -errno;
			if (retval >= 0)
			  retval =  -ENOENT;
		}
	}

	if (retval >= 0) {
		retval = local_lookup_file_path_config(
				 qcsapi_security_configuration_path,
				&qcsapi_temporary_conf[0],
				 sizeof(qcsapi_temporary_conf)
				 - (strlen(QCSAPI_TEMPORARY_CONF) + 1));
	}

	if (retval >= 0) {
		strcat(&qcsapi_temporary_conf[0], "/");
		strcat(&qcsapi_temporary_conf[0], QCSAPI_TEMPORARY_CONF);

		temp_fh = fopen(&qcsapi_temporary_conf[0], "w");
		if (temp_fh == NULL) {
			retval = -errno;
			if (retval >= 0)
			  retval =  -EACCES;

			if (config_fh != NULL)
			  fclose(config_fh);
			config_fh = NULL;
		}
	}

	if (retval >= 0) {
		char config_buffer[122];
		unsigned int sizeof_buffer = sizeof(config_buffer);
		int ival;

		if (remove_SSID_network_file_xfer(del_SSID,
				"ssid", config_fh,
				temp_fh, &config_buffer[0],
				 sizeof_buffer) == E_PARAMETER_FOUND) {
			complete_security_file_xfer(config_fh, temp_fh,
				&config_buffer[0], sizeof_buffer, 1);
			continue_update = 1;
		} else {
			continue_update = 0;
			retval = -ENODEV;
		}

		fclose(config_fh);
		config_fh = NULL;
		fclose(temp_fh);

		if (continue_update) {
			ival = unlink(configuration_file);
			if (ival < 0) {
				retval = -errno;
				if (retval >= 0)
				  retval = ival;
			}

			if (retval >= 0) {
				ival = rename(qcsapi_temporary_conf, configuration_file);

				if (ival < 0) {
					retval = -errno;
					if (retval >= 0)
					  retval = ival;
				}
			}
		  /*
		   * No reload of security parameters.
		   * No signal to the security daemon (hostapd or wpa_supplicant).
		   */
		}
	}

	if (config_fh != NULL)
		fclose( config_fh );

	return (retval);
}

static int
check_before_new_ssid_instantiation(const char *new_SSID, const qcsapi_wifi_mode wifi_mode)
{
	int retval = 0;
	int counter = 0;
	char configuration_file[122];
	/* extra space for quotes and /n */
	char first_ssid[QCSAPI_SSID_MAXLEN + 2];
	FILE *config_fh = NULL;

	if (retval >= 0) {
		retval = locate_configuration_file(wifi_mode, &configuration_file[0], sizeof( configuration_file ));
	}

	if (retval >= 0) {
		config_fh = fopen(configuration_file, "r");

		if (config_fh == NULL) {
			retval = -errno;
			if (retval >= 0)
			  retval =  -ENOENT;
		}
	}

	if (retval >= 0) {
		retval = count_ssid_networks(new_SSID, &counter, config_fh);
		rewind(config_fh);
		while (counter >= QCSAPI_SSID_MAX_RECORDS) {
			if (find_first_ssid(first_ssid, sizeof(first_ssid),
							config_fh) == 0) {
				fclose(config_fh);
				config_fh = NULL;
				retval = qcsapi_wifi_remove_SSID(first_ssid, wifi_mode);
				if (retval >= 0) {
					counter--;
					config_fh = fopen(configuration_file, "r");
					if (config_fh == NULL) {
						retval = -errno;
						if (retval >= 0)
						  retval =  -ENOENT;
						break;
					}
				} else {
					break;
				}
			} else {
				break;
			}
		}
		if (config_fh)
			fclose(config_fh);
	}

	return (retval);
}

static int
write_new_restricted_bss_instantiation(FILE *temp_fh, const char *ifname, char *mac_addr)
{
	int retval = 0;

	fprintf(temp_fh, "\n");
	fprintf(temp_fh, "bss=%s\n", ifname);
	if (mac_addr != NULL)
		fprintf(temp_fh, "bssid=%s\n", mac_addr);
	fprintf(temp_fh, "hw_mode=a\n");
	fprintf(temp_fh, "ssid=Quantenna\n");
	fprintf(temp_fh, "wpa=2\n");
	fprintf(temp_fh, "wpa_key_mgmt=WPA-PSK\n");
	fprintf(temp_fh, "wpa_pairwise=CCMP\n");
	fprintf(temp_fh, "wpa_passphrase=qtn01234\n");
	fprintf(temp_fh, "auth_algs=1\n");
	fprintf(temp_fh, "ieee80211w=0\n");
	fprintf(temp_fh, "wpa_group_rekey=300000\n");
	fprintf(temp_fh, "wpa_strict_rekey=0\n");
	fprintf(temp_fh, "wpa_gmk_rekey=300000\n");
	fprintf(temp_fh, "\n");

	return retval;
}

static struct mbss_wps_cfg_item {
	char *name;
	char *def_val;
} mbss_default_wps_items[] = {
	{"manufacturer", "Quantenna"},
	{"device_name", "Reference Design"},
#if defined(TOPAZ_PLATFORM)
	{"model_name", "Topaz"},
	{"model_number", "QHS840.410"},
#else
	{"model_name", "Ruby"},
	{"model_number", "QHS710.10"},
#endif
	{"serial_number", "000000000000"},
	{"friendly_name", "UPnP Access Point"},
	{"device_type", "6-0050F204-1"}
};

static int
write_new_bss_instantiation(FILE *temp_fh, const char *ifname, char *mac_addr)
{
	int i;
	int retval = 0;
	char wps_current_val[64];

	fprintf(temp_fh, "\n");
	fprintf(temp_fh, "bss=%s\n", ifname);
	if (mac_addr != NULL)
		fprintf(temp_fh, "bssid=%s\n", mac_addr);
	fprintf(temp_fh, "bridge=%s\n", BRIDGE_DEVICE);
	fprintf(temp_fh, "hw_mode=a\n");
	fprintf(temp_fh, "ssid=Quantenna\n");
	fprintf(temp_fh, "wpa=2\n");
	fprintf(temp_fh, "wpa_key_mgmt=WPA-PSK\n");
	fprintf(temp_fh, "wpa_pairwise=CCMP\n");
	fprintf(temp_fh, "wpa_passphrase=qtn01234\n");
	fprintf(temp_fh, "auth_algs=1\n");
	fprintf(temp_fh, "ieee80211w=0\n");
	fprintf(temp_fh, "wpa_group_rekey=300000\n");
	fprintf(temp_fh, "wpa_strict_rekey=0\n");
	fprintf(temp_fh, "wpa_gmk_rekey=300000\n");
	fprintf(temp_fh, "eap_server=1\n");
	fprintf(temp_fh, "wps_state=0\n");
	fprintf(temp_fh, "ap_setup_locked=0\n");
	fprintf(temp_fh, "config_methods=virtual_push_button, virtual_display, physical_push_button\n");
	fprintf(temp_fh, "pbc_in_m1=1\n");
	fprintf(temp_fh, "wps_pp_devname=test\n");
	fprintf(temp_fh, "wps_pp_enable=0\n");

	/* copy wps configuration from primary BSS */
	i = 0;
	while (i < ARRAY_SIZE(mbss_default_wps_items)) {
		retval = lookup_ap_security_parameter("wifi0",
				qcsapi_access_point,
				mbss_default_wps_items[i].name,
				wps_current_val,
				sizeof(wps_current_val));
		if (retval < 0)
			fprintf(temp_fh, "%s=%s\n", mbss_default_wps_items[i].name, mbss_default_wps_items[i].def_val);
		else
			fprintf(temp_fh, "%s=%s\n", mbss_default_wps_items[i].name, wps_current_val);
		i++;
	}

	return retval;
}

static int
instantiate_new_bss_config( const char *ifname, const qcsapi_mac_addr mac_addr, int is_restricted )
{
	int retval = 0;
	int continue_update = 0;
	char configuration_file[122];
	char qcsapi_temporary_conf[122];
	FILE *config_fh = NULL, *temp_fh = NULL;
	char mac_addr_str[20] = {0};
	const char zero_mac[ETH_ALEN] = {0};
	char *mac_addr_str_p = NULL;

	/*
	 * If the real User ID is not root, then abort now.
	 */
	if (getuid() != 0)
	{
	  retval = -EPERM;
	}

	if ((E_RESTRICTED_BSS != is_restricted) &&
		(E_NORMAL_BSS != is_restricted)) {
	  retval = -EFAULT;
	}

	if (retval >= 0)
	{
	  retval = locate_configuration_file(qcsapi_access_point,
				&configuration_file[0], sizeof( configuration_file ));
	}

	if (retval >= 0)
	{
		config_fh = fopen(configuration_file, "r");

		if (config_fh == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -ENOENT;
		}
	}

	if (retval >= 0)
	{
		retval = local_lookup_file_path_config(
				 qcsapi_security_configuration_path,
				&qcsapi_temporary_conf[0],
				 sizeof(qcsapi_temporary_conf) - (strlen(QCSAPI_TEMPORARY_CONF) + 1)
		);
	}

	if (retval >= 0)
	{
		strcat(&qcsapi_temporary_conf[0], "/");
		strcat(&qcsapi_temporary_conf[0], QCSAPI_TEMPORARY_CONF);

		temp_fh = fopen(&qcsapi_temporary_conf[0], "w");
		if (temp_fh == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EACCES;

			if (config_fh != NULL)
			  fclose(config_fh);
			config_fh = NULL;
		}
	}

	if (retval >= 0)
	{
		char config_buffer[122];
		unsigned int sizeof_buffer = sizeof(config_buffer);
		int ival;

		if (locate_ap_parameter_with_xfer(
			ifname,
			"bss",
			config_fh,
			temp_fh,
			&config_buffer[0],
			sizeof_buffer,
			0,
			NULL,
			0
		) != E_PARAMETER_FOUND)
		{
			if ((mac_addr != NULL) && (memcmp(zero_mac, mac_addr, ETH_ALEN) != 0)) {
				sprintf(mac_addr_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0],
					mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
				mac_addr_str_p = mac_addr_str;
			}

			/* write new bss network block to the end of configuration file */
			if (E_RESTRICTED_BSS == is_restricted) {
				write_new_restricted_bss_instantiation(temp_fh, ifname, mac_addr_str_p);
			} else if (E_NORMAL_BSS == is_restricted) {
				write_new_bss_instantiation(temp_fh, ifname, mac_addr_str_p);
			}
			continue_update = 1;
		}
		else
		{
			continue_update = 0;
			retval = -EEXIST;
		}

		fclose(config_fh);
		config_fh = NULL;
		fclose(temp_fh);

		if (continue_update)
		{
			ival = unlink(configuration_file);
			if (ival < 0)
			{
				retval = -errno;
				if (retval >= 0)
				  retval = ival;
			}

			if (retval >= 0)
			{
				ival = rename(qcsapi_temporary_conf, configuration_file);

				if (ival < 0)
				{
					retval = -errno;
					if (retval >= 0)
					  retval = ival;
				}
			}
		}

		/* reload security configuration */
		if (continue_update) {
			if (retval >= 0) {
				retval = create_security_bss_configuration(ifname);
			}
		} else {
			/* This case maybe never exists, interface down but network block exists */
			retval = create_security_bss_configuration(ifname);
		}
	}

	if (config_fh != NULL)
		fclose( config_fh );

	return retval;
}

static int
locate_next_bss(
	FILE *config_fh,
	FILE *temp_fh,
	char *config_buffer,
	const unsigned int sizeof_buffer
)
{
	int retval = 0;
	int complete = 0;

	while (complete == 0 && fgets(config_buffer, sizeof_buffer, config_fh) != NULL)
	{
		if (locate_parameter_line("bss", config_buffer) != NULL) {
			fprintf(temp_fh, "%s", config_buffer);
			complete = 1;
		}
	}

	return retval;
}


static int
delete_bss_config( const char *ifname )
{
	int retval = 0;
	int continue_update = 0;
	char configuration_file[122];
	char qcsapi_temporary_conf[122];
	FILE *config_fh = NULL, *temp_fh = NULL;

	/*
	 * If the real User ID is not root, then abort now.
	 */
	if (getuid() != 0)
	{
	  retval = -EPERM;
	}

	if (retval >= 0)
	{
	  retval = locate_configuration_file(qcsapi_access_point, &configuration_file[0],
				sizeof(configuration_file));
	}

	if (retval >= 0)
	{
		config_fh = fopen(configuration_file, "r");

		if (config_fh == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -ENOENT;
		}
	}

	if (retval >= 0)
	{
		retval = local_lookup_file_path_config(
				 qcsapi_security_configuration_path,
				&qcsapi_temporary_conf[0],
				 sizeof(qcsapi_temporary_conf) - (strlen(QCSAPI_TEMPORARY_CONF) + 1)
				);
	}

	if (retval >= 0)
	{
		strcat(&qcsapi_temporary_conf[0], "/");
		strcat(&qcsapi_temporary_conf[0], QCSAPI_TEMPORARY_CONF);

		temp_fh = fopen(&qcsapi_temporary_conf[0], "w");
		if (temp_fh == NULL)
		{
			retval = -errno;
			if (retval >= 0)
			  retval = -EACCES;

			if (config_fh != NULL)
			  fclose(config_fh);
			config_fh = NULL;
		}
	}

	if (retval >= 0)
	{
		char config_buffer[122];
		unsigned int sizeof_buffer = sizeof(config_buffer);
		int ival;

		if (locate_ap_parameter_with_xfer(
			ifname,
			"bss",
			config_fh,
			temp_fh,
			&config_buffer[0],
			sizeof_buffer,
			0,
			NULL,
			0
		) == E_PARAMETER_FOUND)
		{
			locate_next_bss(config_fh, temp_fh, &config_buffer[0], sizeof_buffer);
			complete_security_file_xfer(config_fh, temp_fh, &config_buffer[0], sizeof_buffer, 0);
			continue_update = 1;
		}
		else
		{
			continue_update = 0;
			retval = -ENODEV;
		}

		fclose(config_fh);
		config_fh = NULL;
		fclose(temp_fh);

		if (continue_update)
		{
			ival = unlink(configuration_file);
			if (ival < 0)
			{
				retval = -errno;
				if (retval >= 0)
				  retval = ival;
			}

			if (retval >= 0)
			{
				ival = rename(qcsapi_temporary_conf, configuration_file);

				if (ival < 0)
				{
					retval = -errno;
					if (retval >= 0)
					  retval = ival;
				}
			}
		}

		/* reload security configuration */
		if (continue_update) {
			if (retval >= 0) {
				retval = remove_security_bss_configuration(ifname);
			}
		}
	}

	if (config_fh != NULL)
		fclose( config_fh );

	return retval;
}

static int
check_bss_ifname(const char *ifname, int *p_found)
{
	int retval = 0;
	char config_line[122];
	char config_file_path[122];
	FILE *config_fh = NULL;
	SSID_parsing_state e_parse_state = e_searching_for_network;
	int local_error_val = locate_configuration_file(qcsapi_access_point,
								&config_file_path[0], sizeof(config_file_path));

	if (local_error_val >= 0)
		config_fh = fopen(&config_file_path[0], "r");

	if (config_fh == NULL) {
		if (local_error_val < 0) {
			retval = local_error_val;
		} else {
			retval = -errno;
			if (retval >= 0)
				retval = -ENOENT;
		}
	} else {
		while (fgets(config_line, sizeof(config_line), config_fh) != NULL) {
			process_ap_config_line(ifname, &e_parse_state, "bss", config_line);
			if (e_parse_state == e_found_current_network) {
				*p_found = QCSAPI_TRUE;
				break;
			}
		}

		if (e_parse_state != e_found_current_network) {
			*p_found = QCSAPI_FALSE;
		}
	}

	if (config_fh != NULL)
		fclose(config_fh);

	return retval;
}

int
local_get_if_mac_address(int sock, const char *ifname, char *addr)
{
	int retval = 0;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
		if (errno > 0)
			retval = -errno;
	}

	if (retval >= 0)
		memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return retval;
}

static int
local_validate_mac_address(const char *mac_addr)
{
	int ret = 0;

	if (mac_addr && (mac_addr[0] & 0x01)) {
		ret = -EINVAL;
	}

	return ret;
}

void
local_check_bss_mac_address(const char *mac_addr, int *p_found)
{
	int retval =  0;
	int skfd = -1;
	unsigned int if_index = 0;
	char if_name[IFNAMSIZ] = {0};
	char if_mac[ETH_ALEN] = {0};

	*p_found = QCSAPI_FALSE;

	if (mac_addr == NULL)
		return;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
		return;

	for (if_index = 0; if_index < MAX_BSSID; if_index++) {
		retval = lookup_ap_ifname_by_index(if_index, if_name, IFNAMSIZ);
		if (retval >= 0) {
			retval = local_get_if_mac_address(skfd, if_name, if_mac);

			if (retval >= 0) {
				if (memcmp(if_mac, mac_addr, ETH_ALEN) == 0) {
					*p_found = QCSAPI_TRUE;
					break;
				}
			}
		}
	}

	close(skfd);
}

static int
get_bss_count(int *p_count)
{
	int retval = 0;
	char config_line[122];
	char config_file_path[122];
	FILE *config_fh = NULL;
	int local_error_val = locate_configuration_file(qcsapi_access_point,
						&config_file_path[0], sizeof(config_file_path));
	int count = 0;

	if (local_error_val >= 0)
		config_fh = fopen(&config_file_path[0], "r");

	if (config_fh == NULL) {
		if (local_error_val < 0) {
			retval = local_error_val;
		} else {
			retval = -errno;
			if (retval >= 0)
				retval = -ENOENT;
		}
	} else {
		while (fgets(config_line, sizeof(config_line), config_fh) != NULL) {
			if ((locate_parameter_line( "interface", config_line )) != NULL ||
				(locate_parameter_line( "bss", config_line )) != NULL) {
				count++;
			}
		}
		*p_count= count;
	}

	if (config_fh != NULL)
		fclose(config_fh);

	return retval;
}


static int
get_interface_by_index(unsigned int if_index, char *ifname, size_t maxlen)
{
	int retval = 0;
	char primary_ifname[IFNAMSIZ];

	memset( primary_ifname, 0, IFNAMSIZ );
	retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);

	if (retval >= 0) {
		retval = lookup_ap_ifname_by_index(if_index, ifname, maxlen);
	} else {
		retval = -qcsapi_only_on_AP;
	}

	return retval;
}

/*
 * Backup the All the BSS status.
 * Now only net device status / interface name be saved.
 */
static void
backup_bss_status(struct bss_status_node *node_array, unsigned int node_num)
{
	int				retval		=  0;
	int				skfd		= -1;
	int				if_count	=  0;
	unsigned int			if_index	=  0;
	qcsapi_interface_status_code	status_code	= qcsapi_interface_status_error;

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		return;
	}

	if_count = 0;

	for (if_index = 0; if_index < node_num; if_index++) {
		char *if_curr = &(node_array->ifname[0]);

		retval = get_interface_by_index(if_index, if_curr, IFNAMSIZ);

		if (retval >= 0) {
			retval = local_interface_get_status(skfd, if_curr, &status_code);
		}

		if (retval >= 0) {
			if (status_code >= qcsapi_interface_status_up) {
				node_array->ifstatus = bss_ifstatus_up;
			} else if (status_code == qcsapi_interface_status_disabled) {
				node_array->ifstatus = bss_ifstatus_down;
			} else {
				node_array->ifstatus = bss_ifstatus_invalid;
			}
			if_count++;
		} else {
			*if_curr = 0;
		}

		node_array++;
	}

	local_close_iw_sockets(skfd);
}


/*
 * Remove a bss information from the bss list.
 * Note : just cleanup this node and not change the others position.
 */
static void
remove_if_from_backup_bss_list(struct bss_status_node *node_array, unsigned int node_num, const char *if_name)
{
	unsigned int	 if_index = 0;
	char		*if_curr;

	for (if_index = 0; if_index < node_num; if_index++) {
		if_curr = &(node_array->ifname[0]);

		if (*if_curr && (strcmp(if_curr, if_name) == 0) ) {
			*if_curr		= 0;
			node_array->ifstatus	= bss_ifstatus_invalid;
			break;
		}

		node_array++;
	}
}


/*
 * Now we just disable the interface which status is 'Down' previously.
 */
static void
restore_bss_status(struct bss_status_node *node_array, unsigned int node_num)
{
	unsigned int		if_index;
	bss_ifstatus_type	if_stat;

	for (if_index = 0; if_index < node_num; if_index++) {
		if_stat = node_array->ifstatus;

		if (node_array->ifname[0] && (if_stat == bss_ifstatus_down) ) {
			local_interface_enable(&node_array->ifname[0], 0);
		}

		node_array++;
	}
}

/*
 * The prefix of BSS name MUST be "wifi".
 */
int
local_check_bss_name(const char *ifname) {
	const char *ifname_format_string = "wifi%d";
	int if_index = MAX_BSSID;
	char ifname_valid[ IFNAMSIZ + 1];

	if (sscanf(ifname, ifname_format_string, &if_index) == 1) {

		/*
		 * Especially, "wifi0aaa" is invalid.
		 * So, rebuild a valid one by the index and compare it.
		 */
		if ( (if_index >= 0) && (if_index < MAX_BSSID) ) {

			sprintf(ifname_valid, ifname_format_string, if_index);

			if (strcmp(ifname, ifname_valid) == 0) {
				return 0;
			}
		}
	}

	return -qcsapi_invalid_ifname;
}

/*
 * argument mac_addr indicates the configured mac address by user. If mac_addr is
 * 0, driver will generate one local mac address base on primary interface mac address.
 */
int
qcsapi_wifi_create_restricted_bss(const char *ifname, const qcsapi_mac_addr mac_addr)
{
	int retval = 0;
	int skfd = -1;
	char primary_ifname[IFNAMSIZ] = {0};
	int b_found = QCSAPI_FALSE;
	int bss_count = 0;
	struct bss_status_node bss_status_array[MAX_BSSID];

	enter_qcsapi();

	if (ifname == NULL)
		retval = -EFAULT;
	else
		retval = local_check_bss_name(ifname);

	if (retval >= 0) {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	/* Mask MBSS feature untill it's supported in repeater mode */
	if (retval >= 0) {
		qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
		retval = local_verify_repeater_mode(skfd, &wifi_mode);
		if (wifi_mode == qcsapi_repeater)
			retval = -EOPNOTSUPP;
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
		if (retval < 0)
		      retval = -qcsapi_only_on_AP;
	}

	if (retval >= 0) {
		retval = get_bss_count(&bss_count);
		if (retval >= 0) {
			if (bss_count >= MAX_BSSID) {
				retval = -qcsapi_too_many_bssids;
			} else {
				retval = check_bss_ifname(ifname, &b_found);

				if (retval >= 0) {
					if (b_found) {
						retval = -EEXIST;
					} else {
						retval = local_validate_mac_address((const char*)mac_addr);
						if (retval >= 0) {
							b_found = QCSAPI_FALSE;
							local_check_bss_mac_address((const char*)mac_addr, &b_found);

							if (b_found == QCSAPI_TRUE) {
								retval = -EEXIST;
							} else {
								memset(bss_status_array, 0, sizeof(bss_status_array));
								backup_bss_status(&bss_status_array[0], MAX_BSSID);
								retval = instantiate_new_bss_config(ifname, mac_addr, E_RESTRICTED_BSS);
							}
						}
					}
				}
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	if (retval >= 0) {
		restore_bss_status(&bss_status_array[0], MAX_BSSID);
	}

	leave_qcsapi();

	return retval;
}

static int local_random_array_gen(unsigned char *data, int len)
{
	int index;

	if (data == NULL || len <= 0)
		return -EFAULT;

	srand((unsigned int)time(NULL));
	for (index = 0; index < len; index++) {
		data[index] = (unsigned char)rand();
	}

	return 0;
}

static int local_update_bss_serial_number(const int skfd, const char *ifname)
{
	int retval = 0;
	qcsapi_mac_addr mac_addr;
	char serial_number_array[16];
	int update = 0;

	memset(serial_number_array, 0, sizeof(serial_number_array));
	retval = local_interface_get_mac_addr(skfd, ifname, mac_addr);
	if (retval >= 0) {
		snprintf(serial_number_array, sizeof(serial_number_array),
				"%02X%02X%02X%02X%02X%02X", mac_addr[0],
				mac_addr[1],
				mac_addr[2],
				mac_addr[3],
				mac_addr[4],
				mac_addr[5]);
		update = 1;

	} else {
		retval = local_random_array_gen(mac_addr, sizeof(mac_addr));
		if (retval >= 0) {
			snprintf(serial_number_array, sizeof(serial_number_array),
					"%02X%02X%02X%02X%02X%02X", mac_addr[0],
					mac_addr[1],
					mac_addr[2],
					mac_addr[3],
					mac_addr[4],
					mac_addr[5]);
			update = 1;
		}
	}

	if (update) {
		retval = update_security_parameter(ifname,
				0,
				"serial_number",
				serial_number_array,
				qcsapi_access_point,
				QCSAPI_TRUE,
				qcsapi_bare_string,
				security_update_complete);
	}

	return retval;
}

/*
 * argument mac_addr indicates the configured mac address by user. If mac_addr is
 * 0, driver will generate one local mac address base on primary interface mac address.
 */
int
qcsapi_wifi_create_bss(const char *ifname, const qcsapi_mac_addr mac_addr)
{
	int retval = 0;
	int skfd = -1;
	char primary_ifname[IFNAMSIZ] = {0};
	int b_found = QCSAPI_FALSE;
	int bss_count = 0;
	struct bss_status_node bss_status_array[MAX_BSSID];

	enter_qcsapi();

	if (ifname == NULL)
		retval = -EFAULT;
	else
		retval = local_check_bss_name(ifname);

	if (retval >= 0) {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	/* Mask MBSS feature untill it's supported in repeater mode */
	if (retval >= 0) {
		qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
		retval = local_verify_repeater_mode(skfd, &wifi_mode);
		if (wifi_mode == qcsapi_repeater)
			retval = -EOPNOTSUPP;
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
		if (retval < 0)
		      retval = -qcsapi_only_on_AP;
	}

	if (retval >= 0) {
		retval = get_bss_count(&bss_count);
		if (retval >= 0) {
			if (bss_count >= MAX_BSSID) {
				retval = -qcsapi_too_many_bssids;
			} else {
				retval = check_bss_ifname(ifname, &b_found);

				if (retval >= 0) {
					if (b_found) {
						retval = -EEXIST;
					} else {
						retval = local_validate_mac_address((const char*)mac_addr);
						if (retval >= 0) {
							b_found = QCSAPI_FALSE;
							local_check_bss_mac_address((const char*)mac_addr, &b_found);

							if (b_found == QCSAPI_TRUE) {
								retval = -EEXIST;
							} else {
								memset(bss_status_array, 0, sizeof(bss_status_array));
								backup_bss_status(&bss_status_array[0], MAX_BSSID);
								retval = instantiate_new_bss_config(ifname, mac_addr, E_NORMAL_BSS);
								if (retval >= 0) {
									retval = local_update_bss_serial_number(skfd, ifname);
								}
							}
						}
					}
				}
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	if (retval >= 0) {
		restore_bss_status(&bss_status_array[0], MAX_BSSID);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_remove_bss(const char *ifname)
{
	int retval = 0;
	int skfd = -1;
	char primary_ifname[IFNAMSIZ] = {0};
	int b_found = QCSAPI_FALSE;
	struct bss_status_node bss_status_array[MAX_BSSID];

	enter_qcsapi();

	if (ifname == NULL)
	  retval = -EFAULT;
	else
	  retval = local_open_iw_socket_with_error(&skfd);

	/* Mask MBSS feature untill it's supported in repeater mode */
	if (retval >= 0) {
		qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
		retval = local_verify_repeater_mode(skfd, &wifi_mode);
		if (wifi_mode == qcsapi_repeater)
			retval = -EOPNOTSUPP;
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
		if (retval < 0)
		      retval = -qcsapi_only_on_AP;
	}

	if (retval >= 0) {
		if (strcmp(ifname, primary_ifname) == 0) {
			retval = -qcsapi_primary_iface_forbidden;
		}
	}

	if (retval >= 0) {
		retval = check_bss_ifname(ifname, &b_found);

		if (retval >= 0) {
			if (b_found) {
				memset(bss_status_array, 0, sizeof(bss_status_array));
				backup_bss_status(&bss_status_array[0], MAX_BSSID);

				retval = delete_bss_config(ifname);
			} else {
				retval = -EINVAL;
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	if (retval >= 0) {
		remove_if_from_backup_bss_list(&bss_status_array[0], MAX_BSSID, ifname);

		restore_bss_status(&bss_status_array[0], MAX_BSSID);
	}

	leave_qcsapi();

	return retval;
}

int
local_get_primary_ap_interface(char *ifname, size_t maxlen)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char local_ifname[IFNAMSIZ] = {0};

	if (ifname == NULL) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = lookup_ap_security_parameter("",
				qcsapi_access_point,
				"interface",
				local_ifname,
				IFNAMSIZ);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, &local_ifname[0], &wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (wifi_mode == qcsapi_access_point) {
		strncpy(ifname, &local_ifname[0], maxlen);
	} else {
		retval = -EFAULT;
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	return retval;
}

/*
 * FIXME: may need to be revisited if MESH is ever implemented.
 * (1 physical device has both an AP VAP and a STA VAP).
 */
int
local_get_primary_interface(char *ifname, size_t maxlen)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char local_ifname[IFNAMSIZ];

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_get_we_device_by_index(0, &local_ifname[0], sizeof(local_ifname));
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, &local_ifname[0], &wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (wifi_mode == qcsapi_access_point) {
		retval = lookup_ap_security_parameter(NULL,
						      wifi_mode,
						     "interface",
						      ifname,
						      maxlen);
		if (retval < 0) {
			goto ready_to_return;
		}
	} else {
		strncpy(ifname, &local_ifname[0], maxlen);
	}

  ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	return retval;
}

/*
 * Returns 0 if primary, -qcsapi_only_on_primary_interface otherwise.
 */
int
local_verify_interface_is_primary(const char *ifname)
{
	int	retval = -qcsapi_only_on_primary_interface;
	char	primary_interface[IFNAMSIZ] = {0};
	int	ival = local_get_primary_interface(&primary_interface[0], IFNAMSIZ);

	if (ival >= 0) {
		if (strncmp(ifname, &primary_interface[0], IFNAMSIZ) == 0) {
			retval = 0;
		}
	} else {
		retval = ival;
	}

	return retval;
}

int
qcsapi_get_primary_interface(char *ifname, size_t maxlen)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_get_primary_interface(ifname, maxlen);

	leave_qcsapi();

	return retval;
}

int
qcsapi_get_interface_by_index(unsigned int if_index, char *ifname, size_t maxlen)
{
	int retval = 0;

	enter_qcsapi();

	retval = get_interface_by_index(if_index, ifname, maxlen);

	leave_qcsapi();

	return retval;
}

int
qcsapi_wifi_get_SSID( const char *ifname, qcsapi_SSID SSID_str )
{
	int		retval = 0;
	int		skfd = -1;
	qcsapi_unsigned_int association_count = 0;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	}

	if (SSID_str == NULL) {
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
		retval = local_interface_verify_net_device(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &local_wifi_mode);
	}

	if ((retval >= 0) && (local_wifi_mode == qcsapi_station)) {
		retval = local_get_count_associations(skfd, ifname, &association_count);
	}

	if (retval >= 0) {
		if (((local_wifi_mode == qcsapi_station) && (association_count >= 1)) ||
			(local_wifi_mode == qcsapi_access_point)) {
			retval = local_wifi_get_SSID( skfd, ifname, SSID_str );
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();
	return( retval );
}

int
local_security_get_security_setting( const int skfd, const char *ifname, qcsapi_security_setting *p_security_setting )
{
	int		retval = 0;
	struct iwreq	wrq;
  	unsigned char	key[IW_ENCODING_TOKEN_MAX];

	memset( &wrq, 0, sizeof( wrq ) );
  /*
   *  You have to provide a valid address even though here we are only interested in the flag.
   */
	wrq.u.data.pointer = (caddr_t) key;
	wrq.u.data.length = IW_ENCODING_TOKEN_MAX;
	strncpy(wrq.ifr_name, ifname, sizeof(wrq.ifr_name) - 1);

	if ((retval = ioctl(skfd, SIOCGIWENCODE, &wrq)) >= 0)
	{
		qcsapi_security_setting	local_security_setting = qcsapi_security_on;

		if (wrq.u.data.length < 1)
		  local_security_setting = qcsapi_security_off;

		*p_security_setting = local_security_setting;
	}
	else
	{
		int	ival = errno;

		if (ival > 0)
		  retval = -ival;
	}

	return( retval );
}

int
local_security_get_broadcast_SSID( const char *ifname, int *p_broadcast_SSID )
{
	char	tmpstring[ 8 ];
	int	retval = 0;
	int	ival = lookup_ap_security_parameter( ifname, qcsapi_access_point, "ignore_broadcast_ssid", &tmpstring[ 0 ], sizeof( tmpstring ) );
	int	local_broadcast_SSID = 1;

	if (ival >= 0)
	{
		int	tmpval = 0;

		ival = sscanf( &tmpstring[ 0 ], "%d", &tmpval );
		if (ival == 1)
		{
			local_broadcast_SSID = (tmpval == 0) ? 1 : 0;
		}
	}

	if (retval >= 0)
	  *p_broadcast_SSID = local_broadcast_SSID;

	return( retval );
}

int
local_security_set_broadcast_SSID( const char *ifname, const int broadcast_SSID )
{
	char	tmpstring[ 2 ];
	int	retval = 0;

	if (broadcast_SSID)
	  strcpy( &tmpstring[ 0 ], "0" );
	else
	  strcpy( &tmpstring[ 0 ], "1" );

	retval = update_security_parameter(
			 ifname,
			 NULL,
			"ignore_broadcast_ssid",
			&tmpstring[ 0 ],
			 qcsapi_access_point,
			 QCSAPI_TRUE,
			 qcsapi_bare_string,
			 security_update_complete
	);

	return( retval );
}


int
local_wifi_option_get_specific_scan( const char *ifname, int *p_specific_scan )
{
	char tmpstring[ 8 ] = {0};
	int local_specific_scan = 0;
	int ival = 0;

	ival = send_message_security_daemon(ifname, qcsapi_station,
				"GET specific_scan", &tmpstring[ 0 ], sizeof( tmpstring ));
	if (ival >= 0)
	{
		int tmpval = 0;

		ival = sscanf( &tmpstring[ 0 ], "%d", &tmpval );
		if (ival == 1)
		{
			local_specific_scan = tmpval;
		}
	}

	if (ival >= 0)
	  *p_specific_scan = local_specific_scan;

	return( ival );
}

int
local_wifi_option_set_specific_scan( const int skfd, const char *ifname, const int specific_scan )
{
	char setparam_index[ 4 ];
	char setparam_value[ 4 ];
	char *argv[] = { &setparam_index[ 0 ], &setparam_value[ 0 ] };
	const int argc = sizeof( argv ) / sizeof( argv[ 0 ] );
	char scan_mode[2];
	int retval = 0;

	snprintf( &setparam_index[ 0 ], sizeof(setparam_index), "%d", IEEE80211_PARAM_SPECIFIC_SCAN);
	if (specific_scan)
		strcpy( &setparam_value[ 0 ], "1" );
	else
		strcpy( &setparam_value[ 0 ], "0" );

	retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"setparam",
			NULL,
			0);

	if (retval < 0)
		return( retval );

	snprintf(scan_mode, sizeof(scan_mode), "%d", !!specific_scan);
	retval = update_security_parameter_i(ifname,
				NULL,
				"specific_scan",
				scan_mode,
				qcsapi_station,
				QCSAPI_TRUE,
				qcsapi_bare_string,
				security_update_complete,
				((!!specific_scan) ? 1 : 0),
				0);

	return ( retval );
}


static int
local_security_validate_SSID( const qcsapi_SSID SSID_str )
{
	int	retval = 0;
	size_t	ssid_len = strnlen( SSID_str, IW_ESSID_MAX_SIZE + 1 );

	if (ssid_len > IW_ESSID_MAX_SIZE || ssid_len < 1) {
		retval = -EINVAL;
	} else {
		size_t	iter;

		for (iter = 0; iter < ssid_len && retval >= 0; iter++) {
			unsigned char	ssid_char = SSID_str[ iter ];

			if (ssid_char < ' ' || ssid_char == 127)
				retval = -EINVAL;
		}
	}

	return( retval );
}

int
qcsapi_wifi_set_SSID( const char *ifname, const qcsapi_SSID SSID_str )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (SSID_str == NULL || ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_security_validate_SSID( SSID_str );
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
			  retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
		if (retval >= 0 && wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
			retval = local_wifi_set_SSID(skfd, ifname, SSID_str);
	}

	if (retval >= 0) {
		update_security_parameter(ifname,
					  SSID_str,
					 "ssid",
					  SSID_str,
					  wifi_mode,
					  QCSAPI_TRUE,
					  qcsapi_bare_string,
					  security_update_complete);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

static int
local_security_search_beacon_table( const char *p_new_beacon )
{
	int			retval = -1;
	const unsigned int	beacon_table_size = TABLE_SIZE( beacon_type );
	unsigned int		iter;

	if (p_new_beacon == NULL)
	  return( -EFAULT );

	for (iter = 0; iter < beacon_table_size && retval < 0; iter++)
	{
		if (strcmp( beacon_type[ iter ], p_new_beacon ) == 0)
		{
			retval = (int) iter;
		}
	}

	return( retval );
}

int
qcsapi_wifi_get_beacon_type( const char *ifname, char *p_current_beacon )
{
	int			retval = 0;
	int			skfd = -1;
	char			configuration_file[ 122 ];
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (p_current_beacon == NULL)
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	  retval = locate_configuration_file( qcsapi_access_point, &configuration_file[ 0 ], sizeof( configuration_file ) );

	if (retval >= 0)
	{
		int	wpa_value = 0;

		retval = lookup_ap_integer_security_parameter( ifname, &configuration_file[ 0 ], "wpa", &wpa_value );
		if (retval >= 0)
		{
			wpa_value = wpa_value & 0x03;

		  /* Next test should always fail; an ERANGE error should never occur. */

			if (wpa_value >= TABLE_SIZE( beacon_type ))
			{
				retval = -ERANGE;
			}
			else
			{
				strcpy( p_current_beacon, beacon_type[ wpa_value ] );
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
qcsapi_wifi_set_beacon_type( const char *ifname, const char *p_new_beacon )
{
	int			 retval = 0;
	int			 skfd = -1;
	int			 new_wpa_value = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;
	char			 new_wpa_string[ 4 ];

	enter_qcsapi();

	if (p_new_beacon == NULL)
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
		new_wpa_value = local_security_search_beacon_table( p_new_beacon );

		if (new_wpa_value < 0)
		  retval = -EINVAL;
		else
		  sprintf( &new_wpa_string[ 0 ], "%d", new_wpa_value );
	}

	if (retval >= 0)
	{
		retval = update_security_parameter(
				 ifname,
				 NULL,
				"wpa",
				&new_wpa_string[ 0 ],
				 qcsapi_access_point,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

#define  FOUND_TKIP	0x01
#define  FOUND_CCMP	0x02

static const char *
local_parse_wpa_pairwise( const char *wpa_pairwise )
{
	const char	*retaddr = NULL;
	const char	*current_addr = wpa_pairwise;
	int		 complete = 0, pairwise_modes_found = 0;

	do
	{
		while (isspace( *current_addr ))
		  current_addr++;
		complete = (*current_addr == '\0');

		if (complete == 0)
		{
			unsigned int	iter;
			int		entry_index = -1;

			for (iter = 0; encryption_mode_table[ iter ].internal_value != NULL && entry_index < 0; iter++)
			{
				const parameter_translation_entry	*p_pte = &encryption_mode_table[ iter ];
				const unsigned int			 internal_length = strlen( p_pte->internal_value );

				if (strncmp( p_pte->internal_value, current_addr, internal_length ) == 0)
			  	{
					const char	*current_addr_2 = current_addr + internal_length;

					if (*current_addr_2 == '\0' || isspace( *current_addr_2 ))
					{
						entry_index = iter;
						current_addr = current_addr_2;
			  		}
			  	}
			}
		  /*
 		   * If the current token was never found, parsing is complete ...
 		   */
			if (entry_index < 0)
			  complete = 1;
			else if (*current_addr == '\0' || iter == TKIP_AND_AES_ENTRY_INDEX)
			  complete = 1;

			if (entry_index == TKIP_AND_AES_ENTRY_INDEX)
			  pairwise_modes_found = (FOUND_TKIP | FOUND_CCMP);
			else if (entry_index == TKIP_ENTRY_INDEX)
			  pairwise_modes_found |= FOUND_TKIP;
			else if (entry_index == AES_ENTRY_INDEX)
			  pairwise_modes_found |= FOUND_CCMP;
		}
	}
	while (complete == 0);

	if (pairwise_modes_found == (FOUND_TKIP | FOUND_CCMP))
	  retaddr = encryption_mode_table[ TKIP_AND_AES_ENTRY_INDEX ].qcsapi_value;
	else if (pairwise_modes_found == FOUND_TKIP)
	  retaddr = encryption_mode_table[ TKIP_ENTRY_INDEX ].qcsapi_value;
	else if (pairwise_modes_found == FOUND_CCMP)
	  retaddr = encryption_mode_table[ AES_ENTRY_INDEX ].qcsapi_value;

	return( retaddr );
}

/*
 * get and set WPA APIs are restricted to the Access Point.
 * Because now only hostapd.conf supports a single Service Set configuration.
 * Corresponding Station file, wpa_supplicant.conf, can include multiple Service Set configurations.
 * So on a Station, corresponding SSID APIs must be used.
 */

int
qcsapi_wifi_get_WPA_encryption_modes( const char *ifname, string_32 encryption_modes )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (encryption_modes == NULL)
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
	  /*
 	   * local buffer for "pairwise" value is NOT a string32
 	   * It contains the value found in hostapd.conf, different (and shorter in length)
 	   * than the TR-069 / TR-098 spec for the encryption mode.
 	   */
		char		 pairwise[ 32 ];
		const char	*actual_param = "wpa_pairwise";
	  /*
	   * Since get_WPA_encryption_modes now only works on an AP (hostapd.conf), no SSID is required
	   * and the parameter name is wpa_pairwise.
	   */
		retval = lookup_ap_security_parameter( ifname, wifi_mode, actual_param, &pairwise[ 0 ], sizeof( pairwise ) );
		if (retval >= 0)
		{
			const char	*proposed_return_string = local_parse_wpa_pairwise( &pairwise[ 0 ] );

			if (proposed_return_string != NULL)
			  strcpy( encryption_modes, proposed_return_string );
			else
			  retval = -ENXIO;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

/* encryption mode and authorization mode are the same lengths */

#define QCSAPI_WPA_SECURITY_MODE_MAX_SIZE	31

int
qcsapi_wifi_set_WPA_encryption_modes( const char *ifname, const string_32 encryption_modes )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;
	const char		*new_internal_value = NULL;

	enter_qcsapi();

	if (encryption_modes == NULL)
	  retval = -EFAULT;
	else if (strnlen( encryption_modes, QCSAPI_WPA_SECURITY_MODE_MAX_SIZE + 1 ) > QCSAPI_WPA_SECURITY_MODE_MAX_SIZE)
	  retval = -EINVAL;
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
		unsigned int	iter;

		for (iter = 0; encryption_mode_table[ iter ].internal_value != NULL && new_internal_value == NULL; iter++)
		{
			if (strcmp( encryption_modes, encryption_mode_table[ iter ].qcsapi_value ) == 0)
			  new_internal_value = encryption_mode_table[ iter ].internal_value;
		}

		if (new_internal_value == NULL)
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		retval = update_security_parameter(
				 ifname,
				 NULL,
				"wpa_pairwise",
				 new_internal_value,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_WPA_authentication_mode( const char *ifname, string_32 authentication_mode )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (authentication_mode == NULL)
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
		char		 key_mgmt[ 32 ];
		const char	*actual_param = "wpa_key_mgmt";

		retval = lookup_ap_security_parameter( ifname, wifi_mode, actual_param, &key_mgmt[ 0 ], sizeof( key_mgmt ) );
		if (retval >= 0)
		{
			unsigned int	iter;
			int		found_entry = 0;

			for (iter = 0; authentication_mode_table[ iter ].internal_value != NULL && found_entry == 0; iter++)
			{
				const parameter_translation_entry	*p_pte = &authentication_mode_table[ iter ];
				unsigned int				 internal_length = strlen( p_pte->internal_value );

				if (strncmp( p_pte->internal_value, &key_mgmt[ 0 ], internal_length ) == 0)
			  	{
					found_entry = 1;
					strcpy( authentication_mode, authentication_mode_table[ iter ].qcsapi_value );
			  	}
			}

			if (found_entry == 0)
			  retval = -ENXIO;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_WPA_authentication_mode( const char *ifname, const string_32 authentication_mode )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;
	const char		*new_internal_value = NULL;
	char                    eap_server[2];
	char                    eap_key_index_workaround[2];
	char                    ieee8021x[2];

	enter_qcsapi();

	if (authentication_mode == NULL)
	  retval = -EFAULT;
	else if (strnlen( authentication_mode, QCSAPI_WPA_SECURITY_MODE_MAX_SIZE + 1 ) > QCSAPI_WPA_SECURITY_MODE_MAX_SIZE)
	  retval = -EINVAL;
	else
	{
		unsigned int	iter;

		for (iter = 0; authentication_mode_table[ iter ].internal_value != NULL && new_internal_value == NULL; iter++)
		{
			if (strcmp( authentication_mode, authentication_mode_table[ iter ].qcsapi_value ) == 0)
			  new_internal_value = authentication_mode_table[ iter ].internal_value;
		}

		if (new_internal_value == NULL)
		  retval = -EINVAL;
	}

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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		if (strcmp(new_internal_value, "NONE") == 0)
			retval = -EINVAL;
	}

	if (retval >= 0)
	{
                int use_dot1x = 0;
		retval = update_security_parameter(
				 ifname,
				 NULL,
				"wpa_key_mgmt",
				 new_internal_value,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);

                if (retval >= 0 ) {
                        if ((strcmp(new_internal_value, "WPA-EAP") == 0)) {
                                use_dot1x = 1;
                        }

                        snprintf(ieee8021x, sizeof(ieee8021x), "%d", use_dot1x);
                        snprintf(eap_key_index_workaround, sizeof(eap_key_index_workaround), "%d", use_dot1x);
                        snprintf(eap_server, sizeof(eap_server), "%d", !use_dot1x);
                }

                if (retval >= 0) {
                        retval = update_security_parameter(
                                        ifname,
                                        NULL,
                                        "ieee8021x",
                                        ieee8021x,
                                        wifi_mode,
                                        QCSAPI_TRUE,
                                        qcsapi_bare_string,
                                        security_update_complete
                                        );
                }

                if (retval >= 0) {
                        retval = update_security_parameter(
                                        ifname,
                                        NULL,
                                        "eapol_key_index_workaround",
                                        eap_key_index_workaround,
                                        wifi_mode,
                                        QCSAPI_TRUE,
                                        qcsapi_bare_string,
                                        security_update_complete
                                        );
                }

                if (retval >= 0) {
                        retval = update_security_parameter(
                                        ifname,
                                        NULL,
                                        "eap_server",
                                        eap_server,
                                        wifi_mode,
                                        QCSAPI_TRUE,
                                        qcsapi_bare_string,
                                        security_update_complete
                                        );
                }
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_interworking( const char *ifname, string_32 p_interworking )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_HS20);

	if (retval >= 0) {
		if (p_interworking == NULL)
			retval = -EFAULT;
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		char		 interworking[2];
		const char	*actual_param = "interworking";

		retval = lookup_ap_security_parameter( ifname,
							wifi_mode,
							actual_param,
							&interworking[0],
							sizeof( interworking ) );
		if (retval >= 0)
			strcpy( p_interworking, interworking );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_interworking( const char *ifname, const string_32 interworking_value )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_HS20);

	if (retval >= 0) {
		if (interworking_value == NULL)
			retval = -EFAULT;
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = update_security_parameter(
				 ifname,
				 NULL,
				"interworking",
				 interworking_value,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_80211u_params( const char *ifname, const string_32 param, string_256 p_value )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_HS20);

	if (retval >= 0) {
		if (p_value == NULL)
			retval = -EFAULT;
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		string_256	value;
		const char	*actual_param = param;

		retval = lookup_ap_security_parameter( ifname,
							wifi_mode,
							actual_param,
							&value[ 0 ],
							sizeof( value ) );
		if (retval >= 0)
			strcpy( p_value, value );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

static int verify_3gpp_cell_net_value( const char *value)
{
	const char *ptr = value;
	int count = 0;
	int mcc_len;
	int mnc_len;

	while (*ptr) {
		mcc_len = 0;
		mnc_len = 0;

		/* Validate MCC */
		while (*ptr && *ptr != ',') {
			if (*ptr < '0' || *ptr > '9')
				return -EINVAL;
			ptr++;
			mcc_len++;
		}

		if (*ptr == '\0' || mcc_len != IEEE80211U_MCC_LEN)
			return -EINVAL;

		ptr++;
		/* Validate MNC */
		while (*ptr && *ptr != ';') {
			if (*ptr < '0' || *ptr > '9')
				return -EINVAL;
			ptr++;
			mnc_len++;
		}

		if (mnc_len > IEEE80211U_MNC_LEN_MAX || mnc_len < IEEE80211U_MNC_LEN_MIN)
			return -EINVAL;

		if (*ptr)
			ptr++;

		count++;
	}

	if (count > IEEE80211U_3GPP_CELL_NET_MAX)
		return -qcsapi_param_count_exceeded;

	return 0;
}

int
qcsapi_wifi_set_80211u_params( const char *ifname, const string_32 param, const string_256 value1,
				const string_32 value2 )
{
	int			 retval = 0;
	int			 ipv4_type = 0;
	int			 ipv6_type= 0;
	int			 ipaddr_type = 0;
	int			 skfd = -1;
	string_256		 param_value;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	retval = local_swfeat_check_supported(SWFEAT_ID_HS20);

	if (retval >= 0) {
		if (value1 == NULL)
			retval = -EFAULT;
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		if (!strcmp(param, "ipaddr_type_availability")) {
			if (qcsapi_verify_numeric(value1) < 0) {
				printf("Invalid parameter %s - must be an unsigned integer\n",
					value1);
				retval = -EINVAL;
			}

			if (retval >= 0) {
				if (qcsapi_verify_numeric(value2) < 0) {
					printf("Invalid parameter %s - must be an "
						"unsigned integer\n", value2);
					retval = -EINVAL;
				}
			}

			if (retval >= 0) {
				ipv4_type = atoi(value1);
				ipv6_type = atoi(value2);
				if (ipv4_type > IEEE80211U_PARAM_IPV4ADDRTYPE_MAX ||
					ipv4_type < IEEE80211U_PARAM_IPV4ADDRTYPE_MIN) {
					printf("ipv4 type must be between %u and %u\n",
						IEEE80211U_PARAM_IPV4ADDRTYPE_MAX,
						IEEE80211U_PARAM_IPV4ADDRTYPE_MIN);
					retval = -EINVAL;
				}
			}

			if (retval >= 0) {
				if (ipv6_type > IEEE80211U_PARAM_IPV6ADDRTYPE_MAX ||
					ipv6_type < IEEE80211U_PARAM_IPV6ADDRTYPE_MIN) {
					printf("ipv6 type must be between %u and %u\n",
						IEEE80211U_PARAM_IPV6ADDRTYPE_MAX,
						IEEE80211U_PARAM_IPV6ADDRTYPE_MIN);
					retval = -EINVAL;
				}
			}

			if (retval >= 0) {
				ipaddr_type = (ipv4_type & 0x3f) << 2 | (ipv6_type & 0x3);
				sprintf(param_value, "%02x", ipaddr_type);
			}
		} else if (!strcmp(param, "anqp_3gpp_cell_net")) {
			retval = verify_3gpp_cell_net_value(value1);

			if (retval >= 0)
				strcpy(param_value, value1);
		} else if (!strcmp(param, "gas_comeback_delay")) {
			if (verify_numeric_range(value1, 0, USHRT_MAX) == 0)
				retval = -EINVAL;
			else
				strcpy(param_value, value1);
		} else {
			strcpy(param_value, value1);
		}
	}

	if (retval >= 0) {
		retval = update_security_parameter(
				 ifname,
				 NULL,
				 param,
				 param_value,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_security_get_nai_realms( const char *ifname, string_4096 p_value )
{
	if (ifname == NULL || p_value == NULL)
		return -EFAULT;

	return local_security_get_multi_entry_param( ifname, NAI_REALM_PARAM, p_value,
								sizeof(string_4096) );
}

int
qcsapi_security_add_nai_realm( const char *ifname, const int encoding, const char *nai_realm,
					const char *eap_method)
{
	string_512	value;

	if (encoding != 1 && encoding != 0)
		return -EINVAL;

	if (nai_realm == NULL || eap_method == NULL)
		return -EFAULT;

	if ((strchr(nai_realm, ',') != NULL) || (strlen(nai_realm) > HS20_MAX_NAI_REALM_LEN))
		return -EINVAL;

	sprintf(value, "%d,%s,%s", encoding, nai_realm, eap_method);

	return local_security_update_multi_entry_param( ifname, NAI_REALM_PARAM, value, 0 );
}

int
qcsapi_security_del_nai_realm( const char *ifname, const char *nai_realm )
{
	if (nai_realm == NULL)
		return -EFAULT;

	if ((strchr(nai_realm, ',') != NULL) || (strlen(nai_realm) > HS20_MAX_NAI_REALM_LEN))
		return -EINVAL;

	return local_security_update_multi_entry_param( ifname, NAI_REALM_PARAM, nai_realm, 1 );
}

int
qcsapi_security_get_roaming_consortium( const char *ifname, string_1024 p_value )
{
	if (ifname == NULL || p_value == NULL)
		return -EFAULT;

	return local_security_get_multi_entry_param( ifname, "roaming_consortium", p_value,
									sizeof(string_1024) );
}

static int is_roaming_consortium(const char *p_value)
{
	int len = 0;

	while(*p_value != '\0') {
		if (!isxdigit(*p_value))
			return 0;
		p_value++;
		len++;
	}

	if ((len & 1) || (len < HS20_MIN_ROAMING_CONSORTIUM_LEN) || (len > HS20_MAX_ROAMING_CONSORTIUM_LEN))
		return 0;

	return 1;
}

int
qcsapi_security_add_roaming_consortium( const char *ifname, const char *p_value )
{
	if (p_value == NULL)
		return -EFAULT;

	if (!is_roaming_consortium(p_value))
		return -EINVAL;

	return local_security_update_multi_entry_param( ifname, "roaming_consortium", p_value, 0 );
}

int
qcsapi_security_del_roaming_consortium( const char *ifname, const char *p_value )
{
	if (p_value == NULL)
		return -EFAULT;

	if (!is_roaming_consortium(p_value))
		return -EINVAL;

	return local_security_update_multi_entry_param( ifname, "roaming_consortium", p_value, 1 );
}

int
qcsapi_security_get_venue_name( const char *ifname, string_4096 p_value )
{
	if (ifname == NULL || p_value == NULL)
		return -EFAULT;

	return local_security_get_multi_entry_param( ifname, "venue_name", p_value,
								sizeof(string_4096) );
}

static int is_lang_code(const char *lang_code)
{
	int len = 0;

	while (*lang_code != '\0') {
		if (!isalpha(*lang_code))
			return 0;
		lang_code++;
		len++;
	}

	if (len > ISO639_LANG_CODE_LEN_MAX)
		return 0;

	return 1;
}

int
qcsapi_security_add_venue_name( const char *ifname, const char *lang_code, const char *venue_name )
{
	string_512	value;

	if ( lang_code == NULL  || venue_name == NULL)
		return -EFAULT;

	if (!is_lang_code(lang_code) || (strlen(venue_name) > IEEE80211U_VENUE_NAME_LEN_MAX))
		return -EINVAL;

	sprintf(value, "P\"%s:%s\"", lang_code, venue_name);

	return local_security_update_multi_entry_param( ifname, "venue_name", value, 0 );
}

int
qcsapi_security_del_venue_name( const char *ifname, const char *lang_code, const char *venue_name )
{
	string_512	value;

	if ( lang_code == NULL  || venue_name == NULL)
		return -EFAULT;

	if (!is_lang_code(lang_code) || (strlen(venue_name) > IEEE80211U_VENUE_NAME_LEN_MAX))
		return -EINVAL;

	sprintf(value, "P\"%s:%s\"", lang_code, venue_name);

	return local_security_update_multi_entry_param( ifname, "venue_name", value, 1 );
}

int
qcsapi_security_get_oper_friendly_name( const char *ifname, string_4096 p_value )
{
	if (ifname == NULL || p_value == NULL)
		return -EFAULT;

	return local_security_get_multi_entry_param( ifname, "hs20_oper_friendly_name", p_value,
									sizeof(string_4096) );
}

int
qcsapi_security_add_oper_friendly_name( const char *ifname, const char *lang_code,
						const char *oper_friendly_name )
{
	string_512	value;

	if ( lang_code == NULL  || oper_friendly_name == NULL)
		return -EFAULT;

	if (!is_lang_code(lang_code) || (strlen(oper_friendly_name) > HS20_OPER_FRIENDLY_NAME_LEN_MAX))
		return -EINVAL;

	sprintf(value, "%s:%s", lang_code, oper_friendly_name);

	return local_security_update_multi_entry_param( ifname,  "hs20_oper_friendly_name", value, 0 );
}

int
qcsapi_security_del_oper_friendly_name( const char *ifname, const char *lang_code, const char *oper_friendly_name )
{
	string_512	value;

	if ( lang_code == NULL  || oper_friendly_name == NULL)
		return -EFAULT;

	if (!is_lang_code(lang_code) || (strlen(oper_friendly_name) > HS20_OPER_FRIENDLY_NAME_LEN_MAX))
		return -EINVAL;

	sprintf(value, "%s:%s", lang_code, oper_friendly_name);

	return local_security_update_multi_entry_param( ifname,  "hs20_oper_friendly_name", value, 1 );
}

int
qcsapi_security_get_hs20_conn_capab( const char *ifname, string_4096 p_value )
{
	if (ifname == NULL || p_value == NULL)
		return -EFAULT;

	return local_security_get_multi_entry_param( ifname, "hs20_conn_capab", p_value,
									sizeof(string_4096) );
}

int
qcsapi_security_add_hs20_conn_capab(const char *ifname, const char *ip_proto, const char *port_num,
					const char *status)
{
	string_64               param_value;

	if (ip_proto == NULL || port_num == NULL || status == NULL) {
		return -EFAULT;
	}

	if (verify_numeric_range(ip_proto, 0, IPPROTO_MAX) == 0) {
		return -EINVAL;
	}

	if (verify_numeric_range(port_num, 0, USHRT_MAX) == 0) {
		return -EINVAL;
	}

	if (verify_numeric_range(status, 0, IEEE80211U_PARAM_IP_STATUS_MAX) == 0) {
		return -EINVAL;
	}

	snprintf(param_value, sizeof(param_value), "%s:%s:%s", ip_proto, port_num, status);

	return local_security_update_multi_entry_param( ifname, "hs20_conn_capab", param_value, 0 );
}

int
qcsapi_security_del_hs20_conn_capab(const char *ifname, const char *ip_proto, const char *port_num,
					const char *status)
{
	string_64               param_value;

	if (ip_proto == NULL || port_num == NULL || status == NULL) {
		return -EFAULT;
	}

	snprintf(param_value, sizeof(param_value), "%s:%s:%s", ip_proto, port_num, status);

	return local_security_update_multi_entry_param( ifname, "hs20_conn_capab", param_value, 1 );
}

int
qcsapi_wifi_get_hs20_status( const char *ifname, string_32 p_hs20 )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (p_hs20 == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		char		 hs20[2];
		const char	*actual_param = "hs20";

		retval = lookup_ap_security_parameter( ifname,
						       wifi_mode,
						       actual_param,
						       &hs20[0],
						       sizeof( hs20 ) );
		if (retval >= 0)
			strcpy( p_hs20, hs20 );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_hs20_status( const char *ifname, const string_32 hs20_val )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (hs20_val == NULL) {
		retval = -EFAULT;
	}

	if (retval >= 0) {
		if (verify_value_one_or_zero(hs20_val))
			retval = -EINVAL;
	}

	if (retval >= 0) {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = update_security_parameter(
				 ifname,
				 NULL,
				"hs20",
				 hs20_val,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_proxy_arp( const char *ifname, const string_32 proxy_arp_val )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (proxy_arp_val == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = update_security_parameter(
				 ifname,
				 NULL,
				"proxy_arp",
				 proxy_arp_val,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_proxy_arp( const char *ifname, string_32 p_proxy_arp )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (p_proxy_arp == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		char		 proxy_arp[2];
		const char	*actual_param = "proxy_arp";

		retval = lookup_ap_security_parameter( ifname,
						       wifi_mode,
						       actual_param,
						       proxy_arp,
						       sizeof( proxy_arp ) );
		if (retval >= 0)
			strcpy( p_proxy_arp, proxy_arp );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_l2_ext_filter(const char *ifname, const string_32 param, string_32 value )
{
	int retval = 0;
	int skfd = -1;
	char setparam_code[QCSAPI_IOCTL_BUFSIZE];
	char *argv[] = { &setparam_code[0] };
	int argc = ARRAY_SIZE(argv);
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	uint32_t param_value;

	if (ifname == NULL || param == NULL || value == NULL)
		return -EFAULT;

	enter_qcsapi();

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_invalid_wifi_mode;
			}
		}
	}

	if (retval >= 0) {
		if (!strcmp(param, "status")) {
			snprintf(setparam_code, sizeof(setparam_code), "%u",
							IEEE80211_PARAM_L2_EXT_FILTER);
		} else if (!strcmp(param, "port")) {
			snprintf(setparam_code, sizeof(setparam_code), "%u",
							IEEE80211_PARAM_L2_EXT_FILTER_PORT);
		} else {
			retval = -EINVAL;
		}
	}

	if (retval >= 0) {
		retval = call_private_ioctl(
				skfd,
				argv,
				argc,
				ifname,
				"getparam",
				(void *)&param_value,
				sizeof(param_value)
		);

		if (retval >= 0) {
			if (!strcmp(param, "port")) {
				if (param_value ==  L2_EXT_FILTER_EMAC_0_PORT) {
					strcpy(value,"emac0");
				} else if (param_value ==  L2_EXT_FILTER_EMAC_1_PORT) {
					strcpy(value,"emac1");
				}
			} else if (!strcmp(param, "status")) {
				sprintf(value, "%d", param_value);
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
local_wifi_set_l2_ext_filter( const int skfd, const char *ifname, const string_32 param,
					const string_32 value )
{
	char setparam_index[ 4 ] = { 0 };
	char setparam_value[ 4 ] = { 0 };
	char *argv[] = { &setparam_index[ 0 ], &setparam_value[ 0 ] };
	const int argc = sizeof( argv ) / sizeof( argv[ 0 ] );
	uint32_t param_value = 0;
	int retval = 0;

	if (strcmp(param, "status") == 0) {
		if (verify_value_one_or_zero(value))
			return -EINVAL;
		param_value = atoi(value);
		snprintf( &setparam_index[ 0 ], sizeof(setparam_index), "%d",
							IEEE80211_PARAM_L2_EXT_FILTER);
	} else if (strcmp(param, "port") == 0) {
		if (strcmp(value, "emac0") == 0) {
			param_value =  L2_EXT_FILTER_EMAC_0_PORT;
		} else if (strcmp(value, "emac1") == 0) {
			param_value =  L2_EXT_FILTER_EMAC_1_PORT;
		} else {
			return -EINVAL;
		}
		snprintf( &setparam_index[ 0 ], sizeof(setparam_index), "%d",
							IEEE80211_PARAM_L2_EXT_FILTER_PORT);
	} else {
		return -EINVAL;
	}

	snprintf( &setparam_value[ 0 ], sizeof(setparam_value), "%u", param_value );

	retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"setparam",
			NULL,
			0);

	return ( retval );
}

int
qcsapi_wifi_set_l2_ext_filter( const char *ifname, const string_32 param,
				const string_32 value )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	if (ifname == NULL || param == NULL || value == NULL)
		return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if(retval >= 0) {
		retval = local_wifi_set_l2_ext_filter( skfd, ifname, param, value );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_hs20_params( const char *ifname, const string_32 param, string_32 p_buffer )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (p_buffer == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		string_32	 value;
		const char	*actual_param = param;

		retval = lookup_ap_security_parameter( ifname,
						       wifi_mode,
                                                       actual_param,
				                       &value[ 0 ],
						       sizeof( string_32 ) );
		if (retval >= 0)
			strcpy( p_buffer, value );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_hs20_params( const char *ifname, const string_32 param,
				const string_64 value1, const string_64 value2,
				const string_64 value3, const string_64 value4,
				const string_64 value5, const string_64 value6 )
{
	int			retval = 0;
	int			skfd = -1;
	string_256		param_value;
	uint8_t			band1 = 0;
	uint8_t			band2 = 0;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (value1 == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		if (!strcmp(param, "hs20_wan_metrics")) {
			if (!value2 || !value3 || !value4 || !value5 || !value6) {
				retval = -EFAULT;
			}
			if (retval >= 0) {
				if (verify_hexstring(value1, 1) ||
						!verify_numeric_range(value2, 0, ULONG_MAX) ||
						!verify_numeric_range(value3, 0, ULONG_MAX) ||
						!verify_numeric_range(value4, 0, (uint8_t) (~0)) ||
						!verify_numeric_range(value5, 0, (uint8_t) (~0)) ||
						!verify_numeric_range(value6, 0, USHRT_MAX)) {
					retval = -EINVAL;
				} else {
					sprintf(param_value, "%s:%s:%s:%s:%s:%s", value1, value2,
							value3, value4, value5, value6);
				}
			}
		} else if (!strcmp(param, "disable_dgaf")) {
			if (verify_value_one_or_zero(value1))
				retval = -EINVAL;
			if (retval >= 0)
				strcpy(param_value, value1);
		} else if (!strcmp(param, "hs20_operating_class")) {
			if (verify_numeric_range(value1, 0, (uint8_t) (~0)) == 0)
				retval = -EINVAL;
			if (retval >= 0) {
				band1 = atoi(value1);
				if (value2) {
					if (verify_numeric_range(value2, 0, (uint8_t) (~0)) == 0)
						retval = -EINVAL;
					if (retval >= 0) {
						band2 = atoi(value2);
						sprintf(param_value, "%02x%02x", band1, band2);
					}
				} else {
					sprintf(param_value, "%02x", band1);
				}
			}
		}
	}

	if (retval >= 0) {
		retval = update_security_parameter(
				 ifname,
				 NULL,
				 param,
				 param_value,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

static int
locate_ap_parameter_for_remove(
	const char *ifname,
	const char *parameter,
	FILE *config_fh,
	FILE *temp_fh,
	char *config_buffer,
	const unsigned int sizeof_buffer
)
{
	int		retval = E_PARAMETER_INVALID;
	string_32	param;
	int		param_length;

	if (ifname == NULL) {
		retval = -EFAULT;
	}
	if (retval >= 0) {
		param_length = sprintf(param, "%s", parameter);
		while (fgets( config_buffer, sizeof_buffer, config_fh ) != NULL) {
			if ((strncmp(config_buffer, parameter, param_length) == 0)) {
				retval = E_PARAMETER_FOUND;
			} else {
				fprintf( temp_fh, "%s", config_buffer );
			}
		}
	}

	return( retval );
}


static int
update_security_parameter_aft_remove(
	const char *ifname,
	const char *parameter,
	const qcsapi_wifi_mode wifi_mode,
	const int update_flag,
	const int quote_flag,
	const int complete_update)
{
	int		 retval = 0;
	char		 configuration_file[MAX_SECURITY_CONFIG_LENGTH];
	char		 qcsapi_temporary_conf[MAX_SECURITY_CONFIG_LENGTH];
	const char	*configuration_program = NULL;
	FILE		*config_fh = NULL, *temp_fh = NULL;
	int update_mode = local_wifi_security_update_mode();

	if (update_mode == security_update_complete)
		update_mode = complete_update;

	/*
	* If the real User ID is not root, then abort now.
	*/
	if (getuid() != 0) {
		retval = -EPERM;
	} else {
		retval = locate_configuration_file( wifi_mode, &configuration_file[ 0 ],
							sizeof( configuration_file ) );
		configuration_program = (wifi_mode == qcsapi_access_point) ?
					HOST_APD_PROCESS : WPA_SUPPLICANT_PROCESS;
	}

	if (retval >= 0) {
		config_fh = fopen( configuration_file, "r" );
		if (config_fh == NULL) {
			retval = -errno;
			if (retval >= 0)
			  retval =  -ENOENT;
		}
	}

	if (retval >= 0) {
		retval = local_lookup_file_path_config(
				 qcsapi_security_configuration_path,
				&qcsapi_temporary_conf[ 0 ],
				 sizeof( qcsapi_temporary_conf ) - (strlen( QCSAPI_TEMPORARY_CONF ) + 1)
		);
	}

	if (retval >= 0) {
		strcat( &qcsapi_temporary_conf[ 0 ], "/" );
		strcat( &qcsapi_temporary_conf[ 0 ], QCSAPI_TEMPORARY_CONF );

		temp_fh = fopen( &qcsapi_temporary_conf[ 0 ], "w" );
		if (temp_fh == NULL) {
			retval = -errno;
			if (retval >= 0)
			  retval =  -EACCES;

			if (config_fh != NULL)
			  fclose( config_fh );
			config_fh = NULL;
		}
	}

	if (retval >= 0) {
		int		ival;
		char		config_buffer[MAX_SECURITY_CONFIG_LENGTH];
		unsigned int	sizeof_buffer = sizeof( config_buffer );

		if (wifi_mode == qcsapi_access_point) {
			ival = locate_ap_parameter_for_remove(ifname, parameter, config_fh,
					temp_fh, &config_buffer[0], sizeof_buffer);

			if (ival > 0) {
				complete_security_file_xfer(config_fh, temp_fh,
					&config_buffer[0], sizeof_buffer, 0);
			}
		}

		fclose( config_fh );
		config_fh = NULL;
		fclose( temp_fh );

		if (retval >= 0) {
			ival = unlink( configuration_file );
			if (ival < 0) {
				retval = -errno;
				if (retval >= 0)
				  retval = ival;
			}
		}
	}

	if (retval >= 0) {
		int	ival = rename( qcsapi_temporary_conf, configuration_file );

		if (ival < 0) {
			retval = -errno;
			if (retval >= 0)
			  retval = ival;
		}
	}

	if (retval >= 0 && update_mode != security_update_pending) {
		if (wifi_mode == qcsapi_access_point)
			retval = update_security_bss_configuration( ifname );
	}

	if (config_fh != NULL)
		fclose( config_fh );

	return( retval );
}

int
qcsapi_remove_11u_param( const char *ifname, const string_64 param )
{
	int                      retval = 0;
        int                      skfd = -1;
        qcsapi_wifi_mode         wifi_mode = qcsapi_nosuch_mode;

        enter_qcsapi();

        if (param == NULL) {
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
                retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
                if (retval >= 0) {
                        if (wifi_mode != qcsapi_access_point)
                                retval = -qcsapi_only_on_AP;
                }
        }
	if (retval >= 0) {
                retval = update_security_parameter_aft_remove(
                                 ifname,
                                 param,
                                 wifi_mode,
                                 QCSAPI_TRUE,
                                 qcsapi_bare_string,
                                 security_update_complete
                );
        }

        if (skfd >= 0) {
                local_close_iw_sockets( skfd );
        }

        leave_qcsapi();

        return( retval );
}

int
qcsapi_remove_hs20_param( const char *ifname, const string_64 param )
{
		int                      retval = 0;
        int                      skfd = -1;
        qcsapi_wifi_mode         wifi_mode = qcsapi_nosuch_mode;

        enter_qcsapi();

        if (param == NULL) {
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
                retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
                if (retval >= 0) {
                        if (wifi_mode != qcsapi_access_point)
                                retval = -qcsapi_only_on_AP;
                }
        }
	if (retval >= 0) {
                retval = update_security_parameter_aft_remove(
                                 ifname,
                                 param,
                                 wifi_mode,
                                 QCSAPI_TRUE,
                                 qcsapi_bare_string,
                                 security_update_complete
                );
        }

        if (skfd >= 0) {
                local_close_iw_sockets( skfd );
        }

        leave_qcsapi();

        return( retval );
}

/*
 * Same restriction apply to the PSK and passphrase APIs that apply to the WPA APIs.
 *
 * For a station, the corresponding SSID APIs must be used.
 */

int
qcsapi_wifi_get_pre_shared_key( const char *ifname, const qcsapi_unsigned_int key_index, string_64 pre_shared_key )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;

	(void) key_index;

	enter_qcsapi();

	if (pre_shared_key == NULL)
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
	  /*
 	   * sizeof operator needs the type name, not its instantiation.
 	   * For string_64 is an array of chars, and C-syntax is such that an instantiation
 	   * of string_64 is actually an address - with sizeof equal to 4 (8 if addresses have 64 bits).
 	   */
		retval = lookup_ap_security_parameter( ifname, wifi_mode, "wpa_psk", pre_shared_key, sizeof( string_64 ) );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_pre_shared_key( const char *ifname, const qcsapi_unsigned_int key_index, const string_64 pre_shared_key )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	(void) key_index;

	enter_qcsapi();

	if (pre_shared_key == NULL)
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
		if (verify_PSK( pre_shared_key ) == 0)
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
		retval = update_security_parameter(
				 ifname,
				 NULL,
				"wpa_psk",
				 pre_shared_key,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_pending
		);
		if (retval >= 0)
		  retval = update_security_parameter(
				 ifname,
				 NULL,
				"wpa_passphrase",
				"",
				 wifi_mode,
				 QCSAPI_FALSE,
				 qcsapi_bare_string,
				 security_update_pending
		  );

		update_security_bss_configuration( ifname );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_add_radius_auth_server_cfg( const char *ifname, const char *radius_auth_server_ipaddr,
		const char *radius_auth_server_port, const char *radius_auth_server_sh_key)
{
	int			retval = 0;
	int			skfd = -1;
	string_256  values_str;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (radius_auth_server_ipaddr == NULL || radius_auth_server_port == NULL ||
						 radius_auth_server_sh_key == NULL) {
		retval = -EFAULT;
	} else {
		if (verify_value_ipaddr(radius_auth_server_ipaddr) == 0)
			return -EINVAL;

		if (verify_numeric_range(radius_auth_server_port, 1, USHRT_MAX) == 0)
			return -EINVAL;

		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	sprintf(values_str, "%s,%s,%s", radius_auth_server_ipaddr, radius_auth_server_port,
					radius_auth_server_sh_key);

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = update_security_parameter_i(
				 ifname,
				 NULL,
				 "auth_server_addr",
				 values_str,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete,
				 0,
				 1
			);

		update_security_bss_configuration( ifname );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_del_radius_auth_server_cfg( const char *ifname, const char *radius_auth_server_ipaddr,
		const char *radius_auth_server_port)
{
	int			retval = 0;
	int			skfd = -1;
	string_32  values_str;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (radius_auth_server_ipaddr == NULL || radius_auth_server_port == NULL) {
		retval = -EFAULT;
	} else {
		if (verify_value_ipaddr(radius_auth_server_ipaddr) == 0)
			return -EINVAL;

		if (verify_numeric_range(radius_auth_server_port, 1, USHRT_MAX) == 0)
			return -EINVAL;

		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0)
				retval = skfd;
		}
	}

	sprintf(values_str, "%s,%s", radius_auth_server_ipaddr, radius_auth_server_port);

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = update_security_parameter_i(
				 ifname,
				 NULL,
				 "auth_server_addr",
				 values_str,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete,
				 1,
				 1
			);

		update_security_bss_configuration( ifname );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_radius_auth_server_cfg( const char *ifname, string_1024 radius_auth_server_cfg)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0)
			retval = skfd;
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		string_1024       value;
		retval = local_security_get_multi_parameter(ifname,
							wifi_mode,
							"auth_server_addr",
							value,
							sizeof(string_1024),
							1);
		if (retval >= 0) {
			strncpy(radius_auth_server_cfg, value, sizeof(string_1024));
			radius_auth_server_cfg[sizeof(string_1024) - 1] = '\0';
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_set_own_ip_addr( const char *ifname, const string_16 own_ip_addr )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (own_ip_addr == NULL)
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
				retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
		retval = update_security_parameter(
				 ifname,
				 NULL,
				"own_ip_addr",
				 own_ip_addr,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_pending
		);

		update_security_bss_configuration( ifname );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

#define PSK_AUTH_FAILURE_BUF_LEN	8
int
qcsapi_wifi_get_psk_auth_failures(const char *ifname, qcsapi_unsigned_int *count)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char buf[PSK_AUTH_FAILURE_BUF_LEN] = {0};
	char cmd_buf[64] = {0};
	char primary_interface[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL || count == NULL) {
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
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	}

	if (retval >= 0) {
		if (wifi_mode == qcsapi_access_point)
			retval = local_get_primary_ap_interface(&primary_interface[0], sizeof(primary_interface) - 1);
		else if (wifi_mode == qcsapi_station)
			strncpy(primary_interface, ifname, sizeof(primary_interface) - 1);
		else
			retval = -EFAULT;
	}

	if (retval >= 0) {
		sprintf(cmd_buf, "%s %s", "GET_PSK_AUTH_FAILURE", ifname);
		retval = send_message_security_daemon(primary_interface,
					wifi_mode,
					cmd_buf,
					buf,
					PSK_AUTH_FAILURE_BUF_LEN);
		if (retval >= 0) {
			if (sscanf(buf, "%u", count) != 1)
				retval = -EFAULT;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_key_passphrase( const char *ifname, const qcsapi_unsigned_int key_index, string_64 passphrase )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	(void) key_index;

	enter_qcsapi();

	if (passphrase == NULL)
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

  /*
   * Standard (TR-069, TR-098) states an attempt to get a passphrase key shall return the 0-length string.
   * But this program does return the passphrase.
   * Let the calling application enforce the standard, should this be desired.
   */

	if (retval >= 0)
	{
		const char	*actual_param = "wpa_passphrase";
	  /*
 	   * sizeof operator needs the type name, not its instantiation.
 	   * For string_64 is an array of chars, and C-syntax is such that an instantiation
 	   * of string_64 is actually an address - with sizeof equal to 4 (8 if addresses have 64 bits).
 	   */
		retval = lookup_ap_security_parameter( ifname, wifi_mode, actual_param, passphrase, sizeof( string_64 ) );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}


	leave_qcsapi();

	return( retval );
}

/*
	ASCII Key Length <8-63>
	Hex Key Length - 64
*/
#define QCSAPI_WPA_PASSPHRASE_MIN_SIZE	8
#define QCSAPI_WPA_PASSPHRASE_MAX_SIZE	63

int
qcsapi_wifi_set_key_passphrase( const char *ifname, const qcsapi_unsigned_int key_index, const string_64 passphrase )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;

	(void) key_index;

	enter_qcsapi();

	if (passphrase == NULL)
	  retval = -EFAULT;
	else
	{
		size_t	passphrase_len = strnlen( passphrase, QCSAPI_WPA_PASSPHRASE_MAX_SIZE + 1 );

		if (passphrase_len > QCSAPI_WPA_PASSPHRASE_MAX_SIZE || passphrase_len < QCSAPI_WPA_PASSPHRASE_MIN_SIZE)
		  retval = -EINVAL;
	}

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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
		retval = update_security_parameter(
				 ifname,
				 NULL,
				"wpa_passphrase",
				 passphrase,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_pending
		);
		if (retval >= 0)
		  retval = update_security_parameter(
				 ifname,
				 NULL,
				"wpa_psk",
				"",
				 wifi_mode,
				 QCSAPI_FALSE,
				 qcsapi_bare_string,
				 security_update_pending
		  );

		update_security_bss_configuration( ifname );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_get_group_key_interval( const char *ifname, string_16 group_key_interval )
{
        int                      retval = 0;
        int                      skfd = -1;
        qcsapi_wifi_mode         wifi_mode = qcsapi_nosuch_mode;

        enter_qcsapi();

        if (group_key_interval == NULL)
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
                retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
                if (retval >= 0)
                {
                        if (wifi_mode != qcsapi_access_point)
                                retval = -qcsapi_only_on_AP;
                }
        }

        if (retval >= 0)
        {
                retval = lookup_ap_security_parameter( ifname,
                                                       wifi_mode,
                                                       "wpa_group_rekey",
                                                       group_key_interval,
                                                       sizeof( string_64 ) );
        }

        if (skfd >= 0) {
                local_close_iw_sockets( skfd );
        }

        leave_qcsapi();

        return( retval );
}

int
qcsapi_wifi_set_group_key_interval( const char *ifname, const string_16 group_key_interval )
{
        int                     retval = 0;
        int                     skfd = -1;
        qcsapi_wifi_mode        wifi_mode = qcsapi_nosuch_mode;

        enter_qcsapi();

        if (group_key_interval == NULL)
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
                retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
                if (retval >= 0)
                {
                        if (wifi_mode != qcsapi_access_point)
                                retval = -qcsapi_only_on_AP;
                }
        }

	if (retval >= 0)
        {
                retval = update_security_parameter(
                                 ifname,
                                 NULL,
                                "wpa_group_rekey",
                                 group_key_interval,
                                 wifi_mode,
                                 QCSAPI_TRUE,
                                 qcsapi_bare_string,
                                 security_update_pending
                );

                update_security_bss_configuration( ifname );
        }

        if (skfd >= 0) {
                local_close_iw_sockets( skfd );
        }

        leave_qcsapi();

        return( retval );
}


int
qcsapi_wifi_get_pmf( const char *ifname, int *p_pmf_cap )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char pmf_cap_string[3] = {0};


	if (p_pmf_cap == NULL)
	  return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0)
	{
		retval = -errno;
		if (retval >= 0)
		  retval = skfd;
	}

	if (retval >= 0)
	{
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}


	if (retval >= 0)
	{
		const char	*actual_param = "ieee80211w";

		retval = lookup_ap_security_parameter( ifname, wifi_mode, actual_param, &pmf_cap_string[0], sizeof( pmf_cap_string ) );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	(*p_pmf_cap) = atoi(pmf_cap_string);

	leave_qcsapi();

	return( retval );
}

int
local_wifi_option_set_pmf( const int skfd, const char *ifname, const int pmf_cap )
{
	char setparam_index[ 4 ] = { 0 };
	char setparam_value[ 4 ] = { 0 };
	char *argv[] = { &setparam_index[ 0 ], &setparam_value[ 0 ] };
	const int argc = sizeof( argv ) / sizeof( argv[ 0 ] );
	int retval = 0;

	snprintf( &setparam_index[ 0 ], sizeof(setparam_index), "%d", IEEE80211_PARAM_CONFIG_PMF);
	if (pmf_cap == qcsapi_pmf_required)
		strcpy( &setparam_value[ 0 ], "3" );
	else if	(pmf_cap == qcsapi_pmf_optional)
		strcpy( &setparam_value[ 0 ], "2" );
	else if (pmf_cap == qcsapi_pmf_disabled)
		strcpy( &setparam_value[ 0 ], "0" );
	else
		return -EFAULT;

	retval = call_private_ioctl(
			skfd,
			argv, argc,
			ifname,
			"setparam",
			NULL,
			0);

	return( retval );
}

int
qcsapi_wifi_set_pmf( const char *ifname, int pmf_cap)
{
	int			 retval = 0;
	int			 skfd = -1;
	char pmf_cap_string[2];
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0)
	{
		retval = -errno;
		if (retval >= 0)
		  retval = skfd;
	}

	if (retval >= 0)
	{
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (!((pmf_cap == qcsapi_pmf_required) ||
		(pmf_cap == qcsapi_pmf_optional) ||
		(pmf_cap == qcsapi_pmf_disabled))) {
		retval = -EINVAL;
	}

	if (retval >= 0)
	{
		snprintf(pmf_cap_string, sizeof(pmf_cap_string), "%d", pmf_cap);
		retval = update_security_parameter(
				 ifname,
				 NULL,
				"ieee80211w",
				 pmf_cap_string,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);

		retval = update_security_bss_configuration( ifname );
	}

	if(retval >= 0)
	{
		retval = local_wifi_option_set_pmf( skfd, ifname, pmf_cap );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}


/*
 * The IEEE (802.)11i QCS APIs just call the corresponding WPA QCS APIs
 *
 * For this reason they are exceptions to the rule for all top-level QCS APIs that the
 * 1st executable statement is enter_qcsapi() and the last last executable statement is leave_qcsapi().
 */

int
qcsapi_wifi_get_IEEE11i_encryption_modes( const char *ifname, string_32 encryption_modes )
{
	return( qcsapi_wifi_get_WPA_encryption_modes(  ifname, encryption_modes ) );
}

int
qcsapi_wifi_set_IEEE11i_encryption_modes( const char *ifname, const string_32 encryption_modes )
{
	return( qcsapi_wifi_set_WPA_encryption_modes(  ifname, encryption_modes ) );
}

int
qcsapi_wifi_get_IEEE11i_authentication_mode( const char *ifname, string_32 authentication_mode )
{
	return( qcsapi_wifi_get_WPA_authentication_mode(  ifname, authentication_mode ) );
}

int
qcsapi_wifi_set_IEEE11i_authentication_mode( const char *ifname, const string_32 authentication_mode )
{
	return( qcsapi_wifi_set_WPA_authentication_mode(  ifname, authentication_mode ) );
}

int
qcsapi_wifi_get_michael_errcnt(const char *ifname, uint32_t *errcount)
{
	int retval = 0;
	int skfd = -1;
	char setparam_code[QCSAPI_IOCTL_BUFSIZE];
	char *argv[] = { &setparam_code[0] };
	int argc = ARRAY_SIZE(argv);
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	if (ifname == NULL || errcount == NULL)
		return -EFAULT;

	enter_qcsapi();

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if ((wifi_mode != qcsapi_station) && (wifi_mode != qcsapi_access_point)) {
		retval = -qcsapi_invalid_wifi_mode;
		goto ready_to_return;
	}

	snprintf(setparam_code, sizeof(setparam_code), "%u", IEEE80211_PARAM_MICHAEL_ERR_CNT);
	retval = call_private_ioctl(
			skfd,
			argv,
			argc,
			ifname,
			"getparam",
			(void *)errcount,
			sizeof(*errcount)
	);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

static int
local_wps_is_bssid_selected( const qcsapi_mac_addr bssid )
{
	int	bssid_is_selected = 1;

	if (bssid == NULL) {
		bssid_is_selected = 0;
	} else {
		qcsapi_mac_addr	all_zeros = { 0, 0, 0, 0, 0, 0 };

		if (memcmp( bssid, all_zeros, sizeof( all_zeros ) ) == 0) {
			bssid_is_selected = 0;
		}
	}

	return( bssid_is_selected );
}

static int local_wps_validate_pin(const char *wps_pin) {
	int count = 0;
	const char *iter;
	unsigned long int ul_pin;
	unsigned long int accum;

	if (NULL == wps_pin)
		return -EINVAL;

	iter = wps_pin;

	while((*iter != '\0')) {
		if (isdigit(*iter) == 0)
			return -EINVAL;
		iter++;
		count++;
	}

	if ((count != QCSAPI_WPS_MAX_PIN_LEN) && (count != QCSAPI_WPS_SHORT_PIN_LEN))
		return -EINVAL;

	if (count == QCSAPI_WPS_MAX_PIN_LEN) {
		ul_pin = strtoul(wps_pin, NULL, 10);
		accum = 0;
		accum += 3 * ((ul_pin / 10000000) % 10);
		accum += 1 * ((ul_pin / 1000000) % 10);
		accum += 3 * ((ul_pin / 100000) % 10);
		accum += 1 * ((ul_pin / 10000) % 10);
		accum += 3 * ((ul_pin / 1000) % 10);
		accum += 1 * ((ul_pin / 100) % 10);
		accum += 3 * ((ul_pin / 10) % 10);
		accum += 1 * ((ul_pin / 1) % 10);
		if (0 != (accum % 10))
			return -EINVAL;
	}

	return 0;
}

int
qcsapi_wps_registrar_report_button_press( const char *ifname )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			primary_interface[IFNAMSIZ] = {0};
	char			cmd_buf[128];
	char			reply_buf[32];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	}
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			}
		}
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(&primary_interface[0], sizeof(primary_interface) - 1);
		if (retval < 0)
		      retval = -qcsapi_only_on_AP;
	}

	if (retval >= 0) {
		snprintf(cmd_buf, sizeof(cmd_buf), "WPS_PBC %s", ifname);
		retval = send_message_security_daemon(primary_interface,
						      wifi_mode,
						      cmd_buf,
						      reply_buf,
						      sizeof(reply_buf));
	}

	if (strncmp(reply_buf, "FAIL", sizeof(reply_buf)) == 0)
		retval = -qcsapi_param_value_invalid;
	else if (strncmp(reply_buf, "WPS overlap", sizeof(reply_buf)) == 0)
		retval = -qcsapi_wps_overlap_detected;

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
get_conf_ssid_list( const char *ifname, const unsigned int arrayc, char *list_SSID[] )
{
	int			 retval = 0;
	int			 skfd = -1;
	int			 local_error_val = 0;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;
	char			 config_file_path[MAX_SECURITY_CONFIG_LENGTH];
	FILE			*config_fh = NULL;
	char			 config_line[MAX_SECURITY_CONFIG_LENGTH];
	const char		*ssid_addr;
	SSID_parsing_state	 e_parse_state = e_searching_for_network;
	unsigned int		 index_list = 0;

	if (ifname == NULL || list_SSID == NULL) {
		retval = -EFAULT;
	} else if (arrayc < 1) {
		retval = -EINVAL;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0)
		{
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	if (retval >= 0) {
		if (wifi_mode != qcsapi_station) {
			retval = -qcsapi_only_on_STA;
		}
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	local_error_val = locate_configuration_file( wifi_mode, &config_file_path[ 0 ], sizeof( config_file_path ) );
	if (local_error_val >= 0) {
		  config_fh = fopen( &config_file_path[ 0 ], "r" );
	}

	if (config_fh == NULL) {
		if (local_error_val < 0) {
			retval = local_error_val;
		} else {
			retval = -errno;
			if (retval >= 0) {
				retval = -ENOENT;
			}
		}

		goto ready_to_return;
	}

	while (read_to_eol(&config_line[0], sizeof(config_line), config_fh) != NULL) {
		process_SSID_config_line( "", &e_parse_state, "ssid", &config_line[ 0 ] );

		if ((e_parse_state == e_found_network_token) &&
		    ((ssid_addr = locate_parameter_line( "ssid", &config_line[ 0 ] )) != NULL)) {
			char		*dest_SSID = list_SSID[ index_list ];

			while (isspace( *ssid_addr ))
			 ssid_addr++;
			if (*ssid_addr == '=')
			 ssid_addr++;
			while (isspace( *ssid_addr ))
			 ssid_addr++;
			if (*ssid_addr == '"')
			 ssid_addr++;

			if (dest_SSID == NULL) {
				retval = -EFAULT;
				break;
			} else {
					unsigned int	 copy_count = 0;

					while (*ssid_addr != '"' &&
					       *ssid_addr != '\n' &&
					       *ssid_addr != '\0' &&
					       copy_count < IW_ESSID_MAX_SIZE) {
					*(dest_SSID++) = *(ssid_addr++);
					copy_count++;
				}

				*dest_SSID = '\0';
			}

			index_list++;
			if (index_list >= arrayc) {
				break;
			}
		}
	}

  ready_to_return:
	if (config_fh != NULL)
	  fclose( config_fh );

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	return( retval );
}

#define MAX_NETWORKID_LEN 4
int qcsapi_wifi_associate(const char *ifname, const qcsapi_SSID join_ssid)
{
	int	retval = 0;
	int	skfd = -1;
	unsigned int iter;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char wps_message[QCSAPI_SSID_MAXLEN + MAX_NETWORKID_LEN] = "";
	char wps_ssid[QCSAPI_SSID_MAXLEN + 1] = {0};
	/*
	 * Increase length of 'wps_ssid' by 1, because the security daemon
	 * encloses the name of the SSID in double quotes.  Thus if the
	 * SSID is the maximum legal length, the last character in its
	 * name would be truncated if this extension were not present.
	 */
	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
		if (retval >= 0 && wifi_mode != qcsapi_station) {
			retval = -qcsapi_only_on_STA;
		}
	}

	/* See if the network we want to join is in the list and if so select it. */
	if (retval >= 0) {
		int complete = 0;
		for (iter = 0; iter < QCSAPI_SSID_MAXNUM && complete == 0; iter++) {

			snprintf(&wps_message[0], sizeof(wps_message),
				 "GET_NETWORK %d ssid", iter);
			memset(wps_ssid, 0, sizeof(wps_ssid));
			retval = send_message_security_daemon(ifname, wifi_mode,
							      &wps_message[0],
							      wps_ssid, sizeof(wps_ssid));
			if (retval >= 0) {
				retval = -qcsapi_SSID_not_found;

				if (strcmp(wps_ssid, "FAIL") == 0) {
					complete = 1;
				} else if (strncmp(wps_ssid, join_ssid, QCSAPI_SSID_MAXLEN) == 0) {
					snprintf(wps_message, sizeof(wps_message),
						 "SELECT_NETWORK %d", iter);
					retval = send_message_security_daemon(ifname, wifi_mode,
									      &wps_message[ 0 ],
									      NULL, 0);
					complete = 1;
				}
			}
		}
	}

	/* Force association to the particular network */
	if (retval >= 0) {
		retval = send_message_security_daemon(ifname,
						      wifi_mode,
						      "REASSOCIATE",
						      NULL, 0);
	}


	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

static int local_sta_set_wps_state(const char *ifname, int state)
{
	int retval = 0;
	int skfd = -1;
	char state_string[2];
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	if (state < 0 || state > 1)
		return -EINVAL;

	if (ifname == NULL)
		return -EFAULT;

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		return retval;

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if (wifi_mode == qcsapi_station) {
		snprintf(state_string, sizeof(state_string), "%d", state);
		retval = update_security_parameter(ifname,
				NULL,
				"wps_state",
				state_string,
				qcsapi_station,
				QCSAPI_TRUE,
				qcsapi_bare_string,
				security_update_complete);
	} else if (wifi_mode == qcsapi_access_point) {
		retval = -qcsapi_only_on_STA;
	} else {
		retval = -qcsapi_invalid_wifi_mode;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	return retval;
}

static int local_wps_set_configured_state(const char *ifname, int state)
{
	int retval = 0;
	int skfd = -1;
	char state_string[2];
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	if (state < 0 || state > 2)
		return -EINVAL;

	if (ifname == NULL)
		return -EFAULT;

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		return retval;

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if (wifi_mode == qcsapi_access_point) {
		snprintf(state_string, sizeof(state_string), "%d", state);
		retval = update_security_parameter(ifname,
				NULL,
				"wps_state",
				state_string,
				qcsapi_access_point,
				QCSAPI_TRUE,
				qcsapi_bare_string,
				security_update_complete);
	} else if (wifi_mode == qcsapi_station) {
		retval = -qcsapi_only_on_AP;
	} else {
		retval = -qcsapi_invalid_wifi_mode;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	return retval;
}

static int local_wps_set_param(const char *ifname, const char *param_type, const char *param_value,
				qcsapi_wifi_mode wifi_mode)
{
	int retval = 0;
	int remove_param = 0;

	if (!ifname || !param_type || !param_value)
		return -EFAULT;

	/* skip primary interface check for MBSS in AP mode */
	if (wifi_mode != qcsapi_access_point) {
		retval = local_verify_interface_is_primary(ifname);
		if (retval < 0)
			return retval;
	}

	if (strcmp(param_value, "NULL") == 0 ||
			strcmp(param_value, "null") == 0)
		remove_param = 1;

	retval = update_security_parameter_i(ifname,
			NULL,
			param_type,
			param_value,
			wifi_mode,
			QCSAPI_TRUE,
			qcsapi_bare_string,
			security_update_complete,
			remove_param,
			0);

	return retval;
}

static int local_wps_set_param_ap_dynamic(const char *ifname, const char *param_type, const char *param_value,
				qcsapi_wifi_mode wifi_mode)
{
	int retval = 0;
	char cmd_buf[128];
	char reply_buf[64];
	char primary_interface[IFNAMSIZ] = {0};

	retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);

	if (retval >= 0) {
		snprintf(cmd_buf, sizeof(cmd_buf), "BSS_SET %s %s %s", param_type, ifname, param_value);
		retval = send_message_security_daemon(primary_interface, qcsapi_access_point, cmd_buf, reply_buf, sizeof(reply_buf));
	}

	if (retval >= 0) {
		if (strncmp(reply_buf, "FAIL", sizeof(reply_buf) - 1) == 0)
			retval = -qcsapi_parameter_not_found;
	}

	return retval;
}


static int verify_wps_model_name_serial(const char* value)
{
	return (strlen(value) > 32 ? -EINVAL : 0);
}

static int verify_wps_manufacturer(const char* value)
{
	return (strlen(value) > 64 ? -EINVAL : 0);
}

static int verify_zero_or_one(const char* value)
{
	int flag;

	if (value == NULL) {
		return -EINVAL;
	}

	if (strlen(value) > 1) {
		return -EINVAL;
	}

	if (!isdigit(*value)) {
		return -EINVAL;
	}

	flag = atoi(value);

	if (flag != 0 && flag != 1) {
		return -EINVAL;
	}

	return 0;
}

static int verify_wps_pbc_m1(const char* value)
{
	return verify_zero_or_one(value);
}

static int verify_force_broadcast_ssid(const char *value)
{
	return verify_zero_or_one(value);
}

static int verify_ap_pin_fail_method(const char *value)
{
	int method_valid = 0;

	if (value == NULL)
		return -EINVAL;

	if (strcmp(value, "default") == 0)
		method_valid = 1;

	if (strcmp(value, "auto_lockdown") == 0)
		method_valid = 1;

	if (!method_valid)
		return -EINVAL;

	return 0;
}


static int verify_auto_lockdown_max_retry(const char *value)
{
	int val;

	val = atoi(value);
	while (*value != '\0') {
		if (!isdigit(*value))
			return -EINVAL;
		value++;
	}

	if (val < 0)
		return -EINVAL;

	return 0;
}

int verify_wps_vendor_spec(const char *value)
{
	if (value == NULL)
		return 0;

	if (strcmp(value, WPS_VENDOR_NETGEAR) == 0 ||
			strcmp(value, "NULL") == 0 ||
			strcmp(value, "null") == 0)
		return 0;

	return -EINVAL;
}

#define BSS_GET_MESSAGE_LEN 64
#define BSS_GET_REPLY_LEN 16

int local_ap_setup_locked(const char *ifname, const char *param_type,
				const char *param_value,
				qcsapi_wifi_mode wifi_mode)
{
	int retval = 0;
	int remove_param = 0;
	char message[BSS_GET_MESSAGE_LEN];
	char reply[BSS_GET_REPLY_LEN];
	char primary_ifname[IFNAMSIZ] = {0};

	if (!ifname || !param_type || !param_value)
		return -EFAULT;

	if (strcmp(param_value, "NULL") == 0 ||
			strcmp(param_value, "null") == 0)
		remove_param = 1;

	retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
	if (retval >= 0) {
		/* Verify if ap_pin_fail_method is set to auto_lockdown or not */
		snprintf(message, sizeof(message),
				"BSS_GET ap_pin_fail_method %s", ifname);
		retval = send_message_security_daemon(primary_ifname, wifi_mode,
						message, reply, sizeof(reply));
		if (strcmp(reply, "auto_lockdown") != 0) {
			retval = -qcsapi_configuration_error;
		}
	}

	if (retval >= 0)
		retval = update_security_parameter_i(ifname,
				NULL,
				param_type,
				param_value,
				wifi_mode,
				QCSAPI_TRUE,
				qcsapi_bare_string,
				security_update_complete,
				remove_param,
				0);

	if (retval >= 0 && !remove_param)
		retval = local_wps_set_param_ap_dynamic(ifname,
							param_type,
							param_value,
							wifi_mode);

	return retval;
}

static const struct {
	qcsapi_wps_param_type wps_param_type;
	char *wps_param_name;
	int (*verify_value)(const char *value);
	qcsapi_wifi_mode mode_limit;
	int (*set_wps_param)(const char *ifname, const char *param_type, const char *param_value,
				qcsapi_wifi_mode wifi_mode);
} wps_set_param_str[] = {
	{
		qcsapi_wps_uuid,
		"uuid",
		verify_uuid_value,
		qcsapi_mode_not_defined,
		local_wps_set_param
	},
	{
		qcsapi_wps_os_version,
		"os_version",
		NULL,
		qcsapi_mode_not_defined,
		local_wps_set_param
	},
	{
		qcsapi_wps_device_name,
		"device_name",
		NULL,
		qcsapi_mode_not_defined,
		local_wps_set_param
	},
	{
		qcsapi_wps_config_methods,
		"config_methods",
		verify_wps_methods_value,
		qcsapi_mode_not_defined,
		local_wps_set_param
	},
	{
		qcsapi_wps_ap_setup_locked,
		"ap_setup_locked",
		NULL,
		qcsapi_access_point,
		local_ap_setup_locked
	},
	{
		qcsapi_wps_ap_pin,
		"ap_pin",
		local_wps_validate_pin,
		qcsapi_access_point,
		local_wps_set_param
	},
	{
		qcsapi_wps_force_broadcast_uuid,
		"force_broadcast_uuid",
		verify_force_broadcast_ssid,
		qcsapi_access_point,
		local_wps_set_param_ap_dynamic
	},
	{
		qcsapi_wps_ap_pin_fail_method,
		"ap_pin_fail_method",
		verify_ap_pin_fail_method,
		qcsapi_access_point,
		local_wps_set_param
	},
	{
		qcsapi_wps_auto_lockdown_max_retry,
		"auto_lockdown_max_retry",
		verify_auto_lockdown_max_retry,
		qcsapi_access_point,
		local_wps_set_param
	},
	{
		qcsapi_wps_vendor_spec,
		"wps_vendor_spec",
		verify_wps_vendor_spec,
		qcsapi_access_point,
		local_wps_set_param
	},
	{
		qcsapi_wps_serial_number,
		"serial_number",
		verify_wps_model_name_serial,
		qcsapi_mode_not_defined,
		local_wps_set_param
	},
	{
		qcsapi_wps_manufacturer,
		"manufacturer",
		verify_wps_manufacturer,
		qcsapi_mode_not_defined,
		local_wps_set_param
	},
	{
		qcsapi_wps_model_name,
		"model_name",
		verify_wps_model_name_serial,
		qcsapi_mode_not_defined,
		local_wps_set_param
	},
	{
		qcsapi_wps_model_number,
		"model_number",
		verify_wps_model_name_serial,
		qcsapi_mode_not_defined,
		local_wps_set_param
	},
	{
		qcsapi_wps_pbc_in_m1,
		"pbc_in_m1",
		verify_wps_pbc_m1,
		qcsapi_access_point,
		local_wps_set_param
	},
	{
		qcsapi_wps_param_end,
		NULL,
		NULL,
		qcsapi_mode_not_defined,
		NULL
	}
};

int qcsapi_wps_set_param(const char *ifname, const qcsapi_wps_param_type param_type, const char *param_value)
{
	int retval = 0;
	int find_entry = -1;
	int iter;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char primary_ifname[IFNAMSIZ] = {0};
	char all_ifnames[MAX_BSSID][IFNAMSIZ];
	int ifname_count;
	char *ifname_each;

	if (!ifname || !param_value) {
		return -EFAULT;
	}

	enter_qcsapi();

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	/* call_qcsapi set_wps_param all xxx xxx can be used in MBSS situation
	 * to set specified item from all BSSes to the same value
	 * */
	ifname_count = 0;
	if (strcmp(ifname, "all") == 0) {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
		if (retval < 0) {
			retval = -qcsapi_only_on_AP;
			printf("paramter \"all\" could only be used in AP mode\n");
			goto ready_to_return;
		}

		for (iter = 0; iter < MAX_BSSID; iter++) {
			retval = lookup_ap_ifname_by_index(iter, all_ifnames[ifname_count], IFNAMSIZ);
			if (retval < 0)
				break;
			ifname_count++;
		}
	} else {
		strcpy(all_ifnames[ifname_count], ifname);
		ifname_count++;
	}

	for (iter=0; wps_set_param_str[iter].wps_param_type < qcsapi_wps_param_end; iter++) {
		if (wps_set_param_str[iter].wps_param_type == param_type &&
				wps_set_param_str[iter].wps_param_name != NULL) {
			find_entry = iter;
			break;
		}
	}
	if (find_entry < 0) {
		printf("wps param (id = %d) not found\n", param_type);
		retval = -EFAULT;
		goto ready_to_return;
	}

	if (wps_set_param_str[find_entry].verify_value != NULL) {
		retval = wps_set_param_str[find_entry].verify_value(param_value);
		if (retval < 0)
			goto ready_to_return;
	}

	for (iter = 0; iter < ifname_count; iter++) {
		ifname_each = all_ifnames[iter];

		if (wps_set_param_str[find_entry].mode_limit !=	qcsapi_mode_not_defined) {
			retval = local_verify_wifi_mode(skfd, ifname_each,
					wps_set_param_str[find_entry].mode_limit, &wifi_mode);
			if (retval < 0)
				goto ready_to_return;
		}

		if (wifi_mode == qcsapi_nosuch_mode) {
			retval = local_wifi_get_mode(skfd, ifname_each, &wifi_mode);
			if (retval < 0)
				goto ready_to_return;
		}

		retval = wps_set_param_str[find_entry].set_wps_param(ifname_each,
				wps_set_param_str[find_entry].wps_param_name,
				param_value,
				wifi_mode);
		if (retval < 0)
			goto ready_to_return;
	}

ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

#define WPS_STATE_DISABLED 0
#define WPS_STATE_ENABLED 1
#define WPS_STATE_CONFIGURED 2
int qcsapi_wifi_disable_wps(const char *ifname, int disable_wps)
{
	int retval = 0;
	int state = -1;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if ((wifi_mode != qcsapi_station) && (wifi_mode != qcsapi_access_point)) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	if (disable_wps == 1) {
		state = WPS_STATE_DISABLED;
	} else if (disable_wps == 0) {
		if (wifi_mode == qcsapi_station)
			state = WPS_STATE_ENABLED;
		else if (wifi_mode == qcsapi_access_point)
			state = WPS_STATE_CONFIGURED;
	} else {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		if (wifi_mode == qcsapi_station) {
			retval = local_sta_set_wps_state(ifname, state);
		} else if (wifi_mode == qcsapi_access_point) {
			retval = local_wps_set_configured_state(ifname, state);
		}
	}

  ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_disassociate(const char *ifname)
{
	int	retval = 0;
	int	skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
		if (retval >= 0 && wifi_mode != qcsapi_station) {
			retval = -qcsapi_only_on_STA;
		}
	}


	if (retval >= 0) {
		retval = send_message_security_daemon(ifname,
						      wifi_mode,
						      "DISCONNECT",
						      NULL, 0);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

#define DISASSOCIATE_MESSAGE_LEN 64
int qcsapi_wifi_disassociate_sta(const char *ifname, qcsapi_mac_addr mac)
{
	int  retval       = 0;
	int  skfd         = -EFAULT;
	bool associated   = false;

	qcsapi_wifi_mode  mode;

	char message[DISASSOCIATE_MESSAGE_LEN] = {0};
	char primary_interface[IFNAMSIZ] = {0};

	enter_qcsapi();

	if ((ifname == NULL) || (mac == NULL)) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_generic_verify_mac_addr_valid(mac);
	if (retval < 0) {
		goto ready_to_return;
	}

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &mode);
	if (retval < 0) {
		goto ready_to_return;
	}
	if (mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);
	if (retval < 0) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval =  local_is_mac_associated(skfd, ifname, mac, &associated);
	if (retval < 0) {
		goto ready_to_return;
	}
	if (!associated) {
		retval = -qcsapi_mac_not_in_assoc_list;
		goto ready_to_return;
	}

	snprintf(message, sizeof(message), "DISASSOCIATE "MACFILTERINGMACFMT,
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	retval = send_message_security_daemon(primary_interface, mode, message, NULL,0);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}
	leave_qcsapi();

	return retval;
}


int
qcsapi_wps_registrar_report_pin( const char *ifname, const char *wps_pin )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			primary_interface[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL || wps_pin == NULL) {
		retval = -EFAULT;
	}
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wps_validate_pin( wps_pin );
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);
		if (retval < 0) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		char	wps_message[ QCSAPI_WPS_MAX_PIN_LEN + 24 ] = "";

		snprintf( &wps_message[ 0 ],
			   sizeof( wps_message ),
			  "WPS_PIN_BSS %s any %s",
			   ifname,
			   wps_pin );
		retval = send_message_security_daemon(primary_interface,
						      wifi_mode,
						     &wps_message[ 0 ],
						      NULL,
						      0);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wps_registrar_get_pp_devname(const char *ifname, int blacklist, string_128 pp_devname)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			*pp_section = NULL;

	enter_qcsapi();

	if (ifname == NULL || pp_devname == NULL) {
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

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	if (retval >= 0) {
		if (wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
			goto ready_to_return;
		}
	} else {
		goto ready_to_return;
	}

	if (blacklist)
		pp_section = "wps_pp_devname_blacklist";
	else
		pp_section = "wps_pp_devname";

	retval = lookup_ap_security_parameter(ifname,
					      wifi_mode,
					      pp_section,
					      pp_devname,
					      sizeof(string_128));

  ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	leave_qcsapi();

	return retval;
}

int
qcsapi_wps_registrar_set_pp_devname( const char *ifname, int update_blacklist, const string_256 pp_devname )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			*pp_section = NULL;
	char			*pp_value = NULL;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	} else if (pp_devname != NULL && strnlen(pp_devname, sizeof(string_256)) >= sizeof(string_256)) {
		retval = -EINVAL;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	if (retval >= 0) {
		if (wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
			goto ready_to_return;
		}
	} else {
		goto ready_to_return;
	}

	if (update_blacklist)
		pp_section = "wps_pp_devname_blacklist";
	else
		pp_section = "wps_pp_devname";

	if (pp_devname == NULL)
		pp_value = "";
	else
		pp_value = (char *)pp_devname;

	retval = update_security_parameter(
			 ifname,
			 NULL,
			 pp_section,
			 pp_value,
			 qcsapi_access_point,
			 QCSAPI_TRUE,
			 qcsapi_bare_string,
			 security_update_complete
	);

  ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	leave_qcsapi();

	return retval;
}

/*
 * At this time the WPS Enrollee APIs only work on a STA.
 * There is no absolute requirement to limit WPS Enrollees to STAs though.
 */

int
qcsapi_wps_enrollee_report_button_press( const char *ifname, const qcsapi_mac_addr bssid )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	}
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_station) {
				retval = -qcsapi_only_on_STA;
			}
		}
	}

	if (retval >= 0) {
		char	wps_message[ MAC_ADDR_STRING_LENGTH + 10 ] = "";
		char	mac_addr[ MAC_ADDR_STRING_LENGTH ] = "";

		if (local_wps_is_bssid_selected( bssid )) {
			snprintf( &mac_addr[ 0 ],
				   sizeof( mac_addr),
				   MACFILTERINGMACFMT,
				   bssid[ 0 ],
				   bssid[ 1 ],
				   bssid[ 2 ],
				   bssid[ 3 ],
				   bssid[ 4 ],
				   bssid[ 5 ] );
		} else {
			strcpy( &mac_addr[ 0 ], "any" );
		}

		snprintf( &wps_message[ 0 ],
			   sizeof( wps_message ),
			  "WPS_PBC %s",
			  &mac_addr[ 0 ] );

		retval = send_message_security_daemon(ifname,
						      wifi_mode,
						     &wps_message[ 0 ],
						      NULL,
						      0);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wps_enrollee_report_pin( const char *ifname, const qcsapi_mac_addr bssid, const char *wps_pin )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || wps_pin == NULL) {
		retval = -EFAULT;
	}
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_station) {
				retval = -qcsapi_only_on_STA;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wps_validate_pin( wps_pin );
	}

	if (retval >= 0) {
		char	wps_message[ QCSAPI_WPS_MAX_PIN_LEN + MAC_ADDR_STRING_LENGTH + 2 ] = "";
		char	mac_addr[ MAC_ADDR_STRING_LENGTH ] = "";

		if (local_wps_is_bssid_selected( bssid )) {
			snprintf( &mac_addr[ 0 ],
				   sizeof( mac_addr),
				   MACFILTERINGMACFMT,
				   bssid[ 0 ],
				   bssid[ 1 ],
				   bssid[ 2 ],
				   bssid[ 3 ],
				   bssid[ 4 ],
				   bssid[ 5 ] );
		} else {
			strcpy( &mac_addr[ 0 ], "any" );
		}

		snprintf( &wps_message[ 0 ],
			   sizeof( wps_message ),
			  "WPS_PIN %s %s",
			  &mac_addr[ 0 ],
			   wps_pin );

		retval = send_message_security_daemon(ifname,
						      wifi_mode,
						     &wps_message[ 0 ],
						      NULL,
						      0);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wps_enrollee_generate_pin( const char *ifname, const qcsapi_mac_addr bssid, char *wps_pin )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || wps_pin == NULL) {
		retval = -EFAULT;
	}
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_station) {
				retval = -qcsapi_only_on_STA;
			}
		}
	}

	if (retval >= 0) {
		char	wps_message[ MAC_ADDR_STRING_LENGTH + 10 ] = "";
		char	mac_addr[ MAC_ADDR_STRING_LENGTH ] = "";

		if (local_wps_is_bssid_selected( bssid )) {
			snprintf( &mac_addr[ 0 ],
				   sizeof( mac_addr),
				   MACFILTERINGMACFMT,
				   bssid[ 0 ],
				   bssid[ 1 ],
				   bssid[ 2 ],
				   bssid[ 3 ],
				   bssid[ 4 ],
				   bssid[ 5 ] );
		} else {
			strcpy( &mac_addr[ 0 ], "any" );
		}

		snprintf( &wps_message[ 0 ],
			   sizeof( wps_message ),
			  "WPS_PIN %s",
			  &mac_addr[ 0 ] );

		retval = send_message_security_daemon(ifname,
						      wifi_mode,
						     &wps_message[ 0 ],
						      wps_pin,
						      QCSAPI_WPS_MAX_PIN_LEN + 1);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wps_get_ap_pin(const char *ifname, char *wps_pin, const int force_regenerate)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char cmd[128];
	char primary_interface[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL || wps_pin == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (retval >= 0) {
		snprintf(cmd, sizeof(cmd), "WPS_AP_PIN_BSS %s get", ifname);
		retval = send_message_security_daemon(primary_interface,
						      wifi_mode,
						      cmd,
						      wps_pin,
						      QCSAPI_WPS_MAX_PIN_LEN + 1);
		if (retval < 0) {
			goto ready_to_return;
		}
	}

	if (force_regenerate || strncmp(wps_pin, "FAIL", QCSAPI_WPS_MAX_PIN_LEN) == 0) {
		snprintf(cmd, sizeof(cmd), "WPS_AP_PIN_BSS %s random", ifname);
		retval = send_message_security_daemon(primary_interface,
						      wifi_mode,
						      cmd,
						      wps_pin,
						      QCSAPI_WPS_MAX_PIN_LEN + 1);
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();
	return retval;
}

int qcsapi_wps_set_ap_pin(const char *ifname, const char *wps_pin)
{
	int retval = 0;
	int skfd = -1;
	char tmp[128];
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char primary_interface[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL || wps_pin == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wps_validate_pin(wps_pin);
	if (retval < 0) {
		goto ready_to_return;
	}

	snprintf(tmp, sizeof(tmp), "WPS_AP_PIN_BSS %s set %s", ifname, wps_pin);

	if (retval >= 0) {
		retval = send_message_security_daemon(primary_interface,
						      wifi_mode,
						      tmp,
						      NULL,
						      0);
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_wps_enable_ap_pin(const char *ifname, int enable)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char wps_pin[QCSAPI_WPS_MAX_PIN_LEN + 1];
	char primary_interface[IFNAMSIZ] = {0};
	char cmd[128];
	int update_mode = local_wifi_security_update_mode();

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (update_mode == security_update_pending) {
		/* In security defer mode */
		retval = -qcsapi_not_supported;
		goto ready_to_return;
	}

	if (enable)
		snprintf(cmd, sizeof(cmd), "WPS_AP_PIN_BSS %s enable", ifname);
	else
		snprintf(cmd, sizeof(cmd), "WPS_AP_PIN_BSS %s disable", ifname);
	retval = send_message_security_daemon(primary_interface,
					      wifi_mode,
					      cmd,
					      wps_pin,
					      QCSAPI_WPS_MAX_PIN_LEN + 1);
	if (retval < 0) {
		goto ready_to_return;
	}

	snprintf(cmd, sizeof(cmd), "BSS_SET auto_lockdown_fail_count %s 0", ifname);
	retval = send_message_security_daemon(primary_interface,
					      wifi_mode,
					      cmd,
					      wps_pin,
					      QCSAPI_WPS_MAX_PIN_LEN + 1);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_wps_save_ap_pin(const char *ifname)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char wps_pin[QCSAPI_WPS_MAX_PIN_LEN + 1];
	char primary_interface[IFNAMSIZ] = {0};
	char cmd[128];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (wifi_mode != qcsapi_access_point) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (retval >= 0) {
		snprintf(cmd, sizeof(cmd), "WPS_AP_PIN_BSS %s get", ifname);
		retval = send_message_security_daemon(primary_interface,
						      wifi_mode,
						      cmd,
						      wps_pin,
						      QCSAPI_WPS_MAX_PIN_LEN + 1);
		if (retval < 0) {
			goto ready_to_return;
		}
	}

	if (strncmp(wps_pin, "FAIL", QCSAPI_WPS_MAX_PIN_LEN) == 0) {
		retval = -qcsapi_parameter_not_found;
		goto ready_to_return;
	}


	retval = update_security_parameter(
			 ifname,
			 NULL,
			 "ap_pin",
			 wps_pin,
			 qcsapi_access_point,
			 QCSAPI_TRUE,
			 qcsapi_bare_string,
			 security_update_complete
	);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_wps_get_sta_pin(const char *ifname, char *wps_pin)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || wps_pin == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_verify_interface_is_primary(ifname);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0) {
		goto ready_to_return;
	}

	if (wifi_mode != qcsapi_station) {
		retval = -qcsapi_only_on_STA;
		goto ready_to_return;
	}

	retval = send_message_security_daemon(ifname,
			wifi_mode,
			"WPS_PIN get",
			wps_pin,
			QCSAPI_WPS_MAX_PIN_LEN + 1);

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();
	return retval;
}

#define WPS_GET_STATE_MIN_LEN	3

int
qcsapi_wps_get_state( const char *ifname, char *wps_state, const qcsapi_unsigned_int max_len )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			cmd[128];
	char			primary_interface[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL || wps_state == NULL) {
		retval = -EFAULT;
	}
	else if (max_len < WPS_GET_STATE_MIN_LEN) {
		retval = -qcsapi_buffer_overflow;
	}
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
		  /*
		   * Sanity check - should not happen ...
		   */
			if (wifi_mode != qcsapi_station && wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_invalid_wifi_mode;
			}
		}
	}

	if (retval >= 0) {
		if (wifi_mode == qcsapi_access_point) {
			snprintf(cmd, sizeof(cmd), "WPS_STATUS %s", ifname);
			retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);
		} else {
			snprintf(cmd, sizeof(cmd), "WPS_STATUS");
			strncpy(primary_interface, ifname, sizeof(primary_interface) - 1);
		}
	}

	if (retval >= 0) {
		retval = send_message_security_daemon(primary_interface,
						      wifi_mode,
						      cmd,
						      wps_state,
						      max_len);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wps_get_configured_state(const char *ifname, char *wps_state, const qcsapi_unsigned_int max_len)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char state_string[8];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if (wifi_mode == qcsapi_access_point) {
		retval = lookup_ap_security_parameter(ifname,
					qcsapi_access_point,
					"wps_state",
					state_string,
					sizeof(state_string));
		if (retval >= 0) {
			if (strcmp(state_string, "0") == 0) {
				snprintf(wps_state, max_len, "%s", "disabled");
			} else if (strcmp(state_string, "1") == 0) {
				snprintf(wps_state, max_len, "%s", "not configured");
			} else if (strcmp(state_string, "2") == 0) {
				snprintf(wps_state, max_len, "%s", "configured");
			} else {
				snprintf(wps_state, max_len, "%s", "invalid value");
			}
		}
	} else if (wifi_mode == qcsapi_station) {
		retval = -qcsapi_only_on_AP;
	} else {
		retval = -qcsapi_invalid_wifi_mode;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_wps_get_runtime_state(const char *ifname, char *state, int max_len)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char primary_ifname[IFNAMSIZ] = {0};
	char message[64];
	char state_string[64];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if (wifi_mode == qcsapi_access_point) {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
		if (retval < 0) {
			goto ready_to_return;
		}

		snprintf(message, sizeof(message), "WPS_CONFIGURED_STATE %s", ifname);
		retval = send_message_security_daemon(primary_ifname, wifi_mode, message, state_string, sizeof(state_string));
		if (retval >= 0) {
			snprintf(state, max_len, "%s", state_string);
		}
	} else if (wifi_mode == qcsapi_station) {
		retval = -qcsapi_only_on_AP;
	} else {
		retval = -qcsapi_invalid_wifi_mode;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

int
qcsapi_wps_set_configured_state(const char *ifname, const qcsapi_unsigned_int state)
{
	int retval = 0;

	enter_qcsapi();
	retval = local_wps_set_configured_state(ifname, state);
	leave_qcsapi();
	return retval;
}

int qcsapi_wps_set_timeout(const char *ifname, const int value)
{
	int			retval = 0;
	int			skfd = -1;
	char			wps_message[32];
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			primary_ifname[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if ((wifi_mode != qcsapi_station) && (wifi_mode != qcsapi_access_point)) {
				retval = -qcsapi_invalid_wifi_mode;
			}
		}
	}

	if (retval >= 0) {
		if (wifi_mode == qcsapi_station)
		      strncpy(primary_ifname, ifname, sizeof(primary_ifname) - 1);
		else
		      retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
	}

	if (retval >= 0) {
		snprintf(wps_message, sizeof(wps_message), "WPS_TIMEOUT %d", value);
		retval = send_message_security_daemon(primary_ifname, wifi_mode, wps_message, NULL, 0);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wps_on_hidden_ssid(const char *ifname, const int value)
{
	int			retval = 0;
	int			skfd = -1;
	char			wps_message[64];
	char			primary_ifname[IFNAMSIZ] = {0};
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			}
		}
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
	}

	if (retval >= 0) {
		snprintf(wps_message, sizeof(wps_message), "BSS_SET wps_on_hidden_ssid %s %d", ifname, value);
		retval = send_message_security_daemon(primary_ifname, wifi_mode, wps_message, NULL, 0);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wps_on_hidden_ssid_status(const char *ifname, char *state, int max_len)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char primary_ifname[IFNAMSIZ] = {0};
	char message[64];
	char state_string[8];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if (wifi_mode == qcsapi_access_point) {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
		if (retval < 0) {
			goto ready_to_return;
		}

		snprintf(message, sizeof(message), "BSS_GET wps_on_hidden_ssid %s", ifname);
		retval = send_message_security_daemon(primary_ifname,
					wifi_mode,
					message,
					state_string,
					sizeof(state_string));
		if (retval >= 0) {
			snprintf(state, max_len, "%s", state_string);
		}
	} else if (wifi_mode == qcsapi_station) {
		retval = -qcsapi_only_on_AP;
	} else {
		retval = -qcsapi_invalid_wifi_mode;
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();
	return retval;
}

int qcsapi_wps_upnp_enable(const char *ifname, const int value)
{
	int			retval = 0;
	int			skfd = -1;
	char			wps_message[32];
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			primary_ifname[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			}
		}
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
	}

	if (retval >= 0) {
		snprintf(wps_message, sizeof(wps_message), "WPS_UPNP_ENABLE %d", value);
		retval = send_message_security_daemon(primary_ifname, wifi_mode, wps_message, NULL, 0);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int qcsapi_wps_upnp_status(const char *ifname, char *reply, int reply_len)
{
	int			retval = 0;
	int			skfd = -1;
	char			wps_message[32];
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			primary_ifname[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			}
		}
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
	}

	if (retval >= 0) {
		snprintf(wps_message, sizeof(wps_message), "WPS_UPNP_STATUS");
		retval = send_message_security_daemon(primary_ifname, wifi_mode, wps_message, reply, reply_len);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_wps_allow_pbc_overlap(const char *ifname, const qcsapi_unsigned_int allow)
{
	int retval = 0;
	int skfd = -1;
	char state_string[2];
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	if ((allow != 0) && (allow != 1)) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if ((wifi_mode != qcsapi_station) && (wifi_mode != qcsapi_access_point)) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	if (retval >= 0) {
		snprintf(state_string, sizeof(state_string), "%d", allow);
		retval = update_security_parameter_i(ifname,
				NULL,
				"wps_allow_pbc_overlap",
				state_string,
				wifi_mode,
				QCSAPI_TRUE,
				qcsapi_bare_string,
				security_update_complete,
				(allow ? 0 : 1),
				0);
	}

ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();
	return retval;
}


int
qcsapi_wps_get_allow_pbc_overlap_status(const char *ifname, int *status)
{
	int		retval = 0;
	int		skfd = -1;
	char	value[2];
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if ((wifi_mode != qcsapi_station) && (wifi_mode != qcsapi_access_point)) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	if (wifi_mode == qcsapi_access_point) {
		retval = lookup_ap_security_parameter(ifname,
					      qcsapi_access_point,
					      "wps_allow_pbc_overlap",
					      value,
					      2);
	} else if (wifi_mode == qcsapi_station) {
		retval = lookup_SSID_parameter(
						 NULL,
						 qcsapi_station,
						 "wps_allow_pbc_overlap",
						 value,
						 2);
	}

	if (retval == -qcsapi_parameter_not_found) {
		value[0] = '0';
		value[1] = '\0';
		retval = 0;
	}

	*status = atoi(value);

ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	leave_qcsapi();

	return retval;
}

static const struct{
	qcsapi_wps_param_type wps_param_type;
	const char *param_name;
	qcsapi_wifi_mode mode_limit;
	int dynamic;
} wps_get_cmd_str[] = {
	{qcsapi_wps_uuid, "uuid", qcsapi_mode_not_defined, QCSAPI_TRUE},
	{qcsapi_wps_os_version, "os_version", qcsapi_mode_not_defined, QCSAPI_TRUE},
	{qcsapi_wps_device_name, "device_name", qcsapi_mode_not_defined, QCSAPI_TRUE},
	{qcsapi_wps_config_methods, "config_methods", qcsapi_mode_not_defined, QCSAPI_TRUE},
	{qcsapi_wps_ap_setup_locked, "ap_setup_locked", qcsapi_access_point, QCSAPI_TRUE},
	{qcsapi_wps_force_broadcast_uuid, "force_broadcast_uuid", qcsapi_access_point, QCSAPI_TRUE},
	{qcsapi_wps_ap_pin_fail_method, "ap_pin_fail_method", qcsapi_access_point, QCSAPI_TRUE},
	{qcsapi_wps_auto_lockdown_max_retry, "auto_lockdown_max_retry", qcsapi_access_point, QCSAPI_TRUE},
	{qcsapi_wps_auto_lockdown_fail_num, "auto_lockdown_fail_count", qcsapi_access_point, QCSAPI_TRUE},
	{qcsapi_wps_vendor_spec, "wps_vendor_spec", qcsapi_access_point, QCSAPI_TRUE},
	{qcsapi_wps_last_successful_client, "last_wps_client", qcsapi_access_point, QCSAPI_TRUE},
	{qcsapi_wps_last_successful_client_devname, "last_wps_client_devname", qcsapi_access_point, QCSAPI_TRUE},
	{qcsapi_wps_serial_number, "serial_number", qcsapi_mode_not_defined, QCSAPI_FALSE},
	{qcsapi_wps_manufacturer, "manufacturer", qcsapi_mode_not_defined, QCSAPI_FALSE},
	{qcsapi_wps_model_name, "model_name", qcsapi_mode_not_defined, QCSAPI_FALSE},
	{qcsapi_wps_model_number, "model_number", qcsapi_mode_not_defined, QCSAPI_FALSE},
	{qcsapi_wps_pbc_in_m1, "pbc_in_m1", qcsapi_access_point, QCSAPI_FALSE},
	{qcsapi_wps_param_end, NULL, qcsapi_mode_not_defined, QCSAPI_FALSE}
};

int
qcsapi_wps_get_param(const char *ifname, qcsapi_wps_param_type wps_type,
		char *wps_str, const qcsapi_unsigned_int max_len)
{
	int retval = 0;
	int skfd = -1;
	int iter;
	char cmd[128];
	char primary_interface[IFNAMSIZ] = {0};
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	if (ifname == NULL) {
		return -EFAULT;
	}

	if (wps_type >= qcsapi_wps_last_config_error) {
		return -EOPNOTSUPP;
	}

	enter_qcsapi();

	retval = local_open_iw_socket_with_error(&skfd);
	if (retval < 0)
		goto ready_to_return;

	retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);
	if (retval < 0)
		goto ready_to_return;

	if (wifi_mode != qcsapi_access_point) {
		retval = local_verify_interface_is_primary(ifname);
		if (retval < 0) {
			goto ready_to_return;
		}
	}

	for(iter=0; wps_get_cmd_str[iter].wps_param_type != qcsapi_wps_param_end; iter++) {
		if (wps_get_cmd_str[iter].wps_param_type == wps_type) {
			break;
		}
	}

	if (wps_get_cmd_str[iter].wps_param_type == qcsapi_wps_param_end) {
		retval = -EINVAL;
		goto ready_to_return;
	}

	if (wps_get_cmd_str[iter].mode_limit !=	qcsapi_mode_not_defined) {
		retval = local_verify_wifi_mode(skfd, ifname,
				wps_get_cmd_str[iter].mode_limit, &wifi_mode);
		if (retval < 0)
			goto ready_to_return;
	}

	if (wps_get_cmd_str[iter].dynamic) {
		if (wifi_mode == qcsapi_access_point) {
			snprintf(cmd, sizeof(cmd), "BSS_GET %s %s",
				 wps_get_cmd_str[iter].param_name, ifname);
			retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);
			if (retval < 0) {
				retval = -qcsapi_only_on_AP;
				goto ready_to_return;
			}
		} else {
			snprintf(cmd, sizeof(cmd), "GET %s", wps_get_cmd_str[iter].param_name);
			strcpy(primary_interface, ifname);
		}

		retval = send_message_security_daemon(primary_interface, wifi_mode,
						      cmd,wps_str, max_len);
	}
	else {
		if (wifi_mode == qcsapi_access_point) {
			retval =  lookup_ap_security_parameter(ifname, wifi_mode,
							       wps_get_cmd_str[iter].param_name,
							       wps_str, max_len);
		}
		else {
			retval = lookup_SSID_parameter(NULL, wifi_mode,
						       wps_get_cmd_str[iter].param_name,
						       wps_str, max_len);
		}
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

#define WPA_GET_STATUS_MIN_LEN	12
#define WPA_STATUS_CMD_LEN 32
int
qcsapi_wifi_get_wpa_status( const char *ifname, char *wpa_status, const char *mac_addr,
		const qcsapi_unsigned_int max_len )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			wpa_status_cmd_str[WPA_STATUS_CMD_LEN] = {0};
	char			primary_interface[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL || wpa_status == NULL) {
		retval = -EFAULT;
	}
	else if (max_len < WPA_GET_STATUS_MIN_LEN) {
		retval = -qcsapi_buffer_overflow;
	}
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {

			if (wifi_mode != qcsapi_station && wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_invalid_wifi_mode;
			}
		}
	}

	if (wifi_mode == qcsapi_station) {
		retval = -qcsapi_only_on_AP;
	} else {
		sprintf(wpa_status_cmd_str, "STATUS %s", mac_addr);
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);
	}

	if (retval >= 0) {
		retval = send_message_security_daemon(primary_interface,
						      wifi_mode,
						      wpa_status_cmd_str,
						      wpa_status,
						      max_len);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );

}

int
qcsapi_wifi_get_auth_state(const char *ifname, const char *mac_addr, int *auth_state)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	local_wifi_mode = qcsapi_nosuch_mode;
	char			wpa_status_str[GET_WPA_STATUS_STR_LEN + 1] = {0};
	char			wpa_status_cmd_str[WPA_STATUS_CMD_LEN] = {0};
	char			primary_interface[IFNAMSIZ] = {0};


	if(!ifname || !mac_addr) {
		return -EINVAL;
	}

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = (errno > 0) ? -errno : skfd;
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &local_wifi_mode );
	}

	if (local_wifi_mode == qcsapi_station) {
		retval = -qcsapi_only_on_AP;
	} else {
		snprintf(wpa_status_cmd_str, WPA_STATUS_CMD_LEN, "STATUS %s", mac_addr);
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(primary_interface, sizeof(primary_interface) - 1);
	}

	if (retval >= 0 ) {
		*auth_state = 0;
		retval = send_message_security_daemon(primary_interface,
						      local_wifi_mode,
						      wpa_status_cmd_str,
						      wpa_status_str,
						      GET_WPA_STATUS_STR_LEN);
	}

	if(retval >= 0) {
		if (!strncmp(wpa_status_str, "WPA_SUCCESS", strlen("WPA_SUCCESS"))) {
			*auth_state = 1;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}
/* programs relating to MAC address filtering */

int
qcsapi_wps_cancel(const char *ifname)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char primary_ifname[IFNAMSIZ] = {0};
	char cmd[256];

	enter_qcsapi();

	if (ifname == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}

	if (retval >= 0) {
		if (wifi_mode == qcsapi_station) {
			retval = send_message_security_daemon(ifname,
							      wifi_mode,
							      "WPS_CANCEL",
							      NULL,
							      0);
		} else if (wifi_mode == qcsapi_access_point) {
			retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
			if (retval >= 0) {
				snprintf(cmd, sizeof(cmd), "WPS_CANCEL %s", ifname);
				/*
				 * Use the primary interface name as parameter
				 * Keep consistency with fix of hostapd_cli reconfigure for MBSS support
				 */
				retval = send_message_security_daemon(primary_ifname,
								      wifi_mode,
								      cmd,
								      NULL,
								      0);
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return (retval);
}

int qcsapi_wps_set_pbc_in_srcm(const char *ifname, const qcsapi_unsigned_int enabled)
{
	int retval = 0;
	int skfd = -1;
	char cmd[64] = {0};
	char primary_ifname[IFNAMSIZ] = {0};
	int update_mode = local_wifi_security_update_mode();

	if (ifname == NULL)
		return -EFAULT;

	enter_qcsapi();

	retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
	if (retval < 0) {
		retval = -qcsapi_only_on_AP;
	}

	if (retval >= 0)
		retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0 && update_mode == security_update_pending) {
		/* In security defer mode */
		retval = -qcsapi_not_supported;
	}

	if (retval >= 0) {
		snprintf(cmd, sizeof(cmd), "WPS_PBC_IN_SRCM %d", !!enabled);
		retval = send_message_security_daemon(primary_ifname,
					qcsapi_access_point,
					cmd,
					NULL,
					0);
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int qcsapi_wps_get_pbc_in_srcm(const char *ifname, qcsapi_unsigned_int *p_enabled)
{
	int retval = 0;
	int skfd = -1;
	char msg[64] = {0};
	char primary_ifname[IFNAMSIZ] = {0};

	if (ifname == NULL || p_enabled == NULL)
		return -EFAULT;

	enter_qcsapi();

	retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
	if (retval < 0) {
		retval = -qcsapi_only_on_AP;
	}

	if (retval >= 0)
		retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0) {
		retval = send_message_security_daemon(primary_ifname,
					qcsapi_access_point,
					"GET_PBC_IN_SRCM",
					msg,
					sizeof(msg));
		if (retval >= 0)
			if (sscanf(msg, "%u", p_enabled) != 1)
				retval = -EFAULT;
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	leave_qcsapi();

	return retval;
}

int qcsapi_registrar_set_default_pbc_bss(const char *ifname)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			primary_ifname[IFNAMSIZ] = {0};
	char			cmd[32];
	char			reply[32];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
		if (retval < 0) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		if (strcmp(ifname, "null") == 0)
		      retval = local_wifi_get_mode( skfd, primary_ifname, &wifi_mode );
		else
		      retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}

	if (retval >= 0) {
		if (wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		snprintf(cmd, sizeof(cmd), "SET default_pbc_bss %s", ifname);
		retval = send_message_security_daemon(primary_ifname,
						      qcsapi_access_point,
						      &cmd[0],
						      reply,
						      sizeof(reply));

		if (retval >= 0) {
			if (strncmp(reply, "FAIL", sizeof(reply)) == 0)
				retval = -ENODEV;
		}
	}

	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	leave_qcsapi();

	return retval;
}

int qcsapi_registrar_get_default_pbc_bss(char *default_bss, int len)
{
	int			retval = 0;
	int			skfd = -1;
	char			primary_interface[IFNAMSIZ] = {0};

	if (default_bss == NULL)
		return -EFAULT;

	enter_qcsapi();

	skfd = local_open_iw_sockets();
	if (skfd < 0) {
		retval = -errno;
		if (retval >= 0) {
			retval = skfd;
		}
	}

	if (retval >= 0) {
		retval = local_get_primary_ap_interface(&primary_interface[0], sizeof(primary_interface) - 1);
		if (retval < 0) {
			retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0) {
		retval = send_message_security_daemon(primary_interface,
						      qcsapi_access_point,
						      "GET default_pbc_bss",
						      default_bss,
						      len);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

static int
create_deny_mac_addr_file( const char *path_deny_mac_addr_file )
{
	int	retval = 0;

	local_write_string_to_file(
		&path_deny_mac_addr_file[ 0 ],
		"# Deny MAC address file created by QCSAPI\n"
	);

	return( retval );
}

static int
create_accept_mac_addr_file( const char *path_accept_mac_addr_file )
{
	int	retval = 0;

	local_write_string_to_file(
		&path_accept_mac_addr_file[ 0 ],
		"# Accept MAC address file created by QCSAPI\n"
	);

	return( retval );
}

static int
create_accept_oui_file( const char *path_accept_oui_file )
{
	int	retval = 0;

	local_write_string_to_file(
		&path_accept_oui_file[ 0 ],
		"# Accept OUI file created by QCSAPI\n"
	);

	return( retval );
}

int
local_parse_mac_addr( const char *mac_addr_as_str, qcsapi_mac_addr mac_addr )
{
	int		retval = 0;

	if (mac_addr_as_str == NULL)
	  retval = -EFAULT;
	else
	{
		unsigned int	tmparray[ sizeof( qcsapi_mac_addr ) ];
		int		ival = sscanf( mac_addr_as_str, "%2x:%2x:%2x:%2x:%2x:%2x",
					&tmparray[ 0 ],
					&tmparray[ 1 ],
					&tmparray[ 2 ],
					&tmparray[ 3 ],
					&tmparray[ 4 ],
					&tmparray[ 5 ]
		);

		if (ival == (int) sizeof( qcsapi_mac_addr ))
		{
			mac_addr[ 0 ] = (uint8_t) tmparray[ 0 ];
			mac_addr[ 1 ] = (uint8_t) tmparray[ 1 ];
			mac_addr[ 2 ] = (uint8_t) tmparray[ 2 ];
			mac_addr[ 3 ] = (uint8_t) tmparray[ 3 ];
			mac_addr[ 4 ] = (uint8_t) tmparray[ 4 ];
			mac_addr[ 5 ] = (uint8_t) tmparray[ 5 ];

			retval = 0;
		}
		else
		  retval = -EINVAL;
	}

	return( retval );
}

static int
read_mac_addr_file(
	const char *mac_addr_file,
	mac_addr_file_cb the_callback,
	void *arg1,
	void *arg2
)
{
	int	 retval = 0;
	FILE	*mac_addr_fh = NULL;

	if (mac_addr_file == NULL)
	  retval = -EFAULT;
	else
	{

		mac_addr_fh = fopen( mac_addr_file, "r" );
		if (mac_addr_fh == NULL)
		{
			if (errno > 0)
			  retval = -errno;
			else
			  retval = -ENOENT;
		}
	}

	if (retval >= 0)
	{
		char	mac_addr_line[ 32 ];
		int	complete = 0;

		while (fgets( &mac_addr_line[ 0 ], sizeof( mac_addr_line ), mac_addr_fh ) != NULL &&
		       complete == 0)
		{
			char	*tmpaddr = &mac_addr_line[ 0 ];

			while (*tmpaddr != '\0' && isspace( *tmpaddr ))
			  tmpaddr++;

			if (*tmpaddr != '\0' && *tmpaddr != '#')
			{
				qcsapi_mac_addr	mac_addr;
				int		ival = local_parse_mac_addr( tmpaddr, mac_addr );

				if (ival >= 0)
				{
					ival = (*the_callback)( mac_addr, arg1, arg2 );
					if (ival < 0)
					{
						retval = ival;
						complete = 1;
					}
					else if (ival > 0)
					  complete = 1;
				}
			}
		}
	}

	if (mac_addr_fh != NULL)
	  fclose( mac_addr_fh );

	return( retval );
}

int
local_security_get_mac_address_filtering(
	const char *ifname,
	qcsapi_mac_address_filtering *current_mac_address_filtering
)
{
	int				retval = 0;
	int				skfd = -1;
	char				param_buffer[ 80 ];
	int				macaddr_acl = -1;
	qcsapi_wifi_mode		wifi_mode = qcsapi_nosuch_mode;
	qcsapi_mac_address_filtering	current_filtering = qcsapi_nosuch_mac_address_filtering;

	if (current_mac_address_filtering == NULL || ifname == NULL)
	  retval = -EFAULT;
	else
	  retval = local_open_iw_socket_with_error( &skfd );

	if (retval >= 0)
	{
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
		if (get_count_calls_qcsapi_init() < 1)
		  retval = -qcsapi_not_initialized;
	}

	if (retval >= 0)
	{
		int	ival;

		ival = lookup_ap_security_parameter(
			 ifname,
			 wifi_mode,
			"macaddr_acl",
			&param_buffer[ 0 ],
			 sizeof( param_buffer )
		);

		if (ival != 0)
		  current_filtering = qcsapi_disable_mac_address_filtering;
		else
		{
			sscanf( &param_buffer[ 0 ], "%d", &macaddr_acl );

			if (macaddr_acl == 1)
			  current_filtering = qcsapi_deny_mac_address_unless_authorized;
			else if (macaddr_acl == 0)
			  current_filtering = qcsapi_accept_mac_address_unless_denied;
			else
			  current_filtering = qcsapi_disable_mac_address_filtering;
		}

	  /* current filtering is no longer qcsapi_nosuch_mac_address_filtering */
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	if (retval >= 0)
	  *current_mac_address_filtering = current_filtering;

	return( retval );
}

int
qcsapi_wifi_get_mac_address_filtering(
	const char *ifname,
	qcsapi_mac_address_filtering *current_mac_address_filtering
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_security_get_mac_address_filtering( ifname, current_mac_address_filtering );

	leave_qcsapi();

	return( retval );
}

int
local_security_build_mac_filter_file(
	const char *base_file,
	char *full_path,
	const unsigned int size_file_path,
	const char *ifname
)
{
	unsigned int if_len;
	int retval;

	if (ifname == NULL)
		return -EFAULT;

	if_len = strlen(ifname) + 1; /* +1 : "." */
	if (size_file_path <= if_len)
		return -EFAULT;

	retval = locate_security_file(base_file, full_path, size_file_path - if_len);

	if (retval >= 0) {
		strcat(full_path, ".");
		strcat(full_path, ifname);
	}

	return retval;
}

int
local_security_set_mac_address_filtering(
	const char *ifname,
	const qcsapi_mac_address_filtering new_mac_address_filtering
)
{
	int				retval = 0;
	int				skfd = -1;
	qcsapi_wifi_mode		wifi_mode = qcsapi_nosuch_mode;
	char				path_mac_addr_file[ 80 ];
	int				call_reload_security_configuration = 0;

	if (ifname == NULL)
	  retval = -EFAULT;
	else
	  retval = local_open_iw_socket_with_error( &skfd );

	if (retval >= 0)
	{
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0)
		{
			if (wifi_mode != qcsapi_access_point)
			  retval = -qcsapi_only_on_AP;
		}
	}

	if (retval >= 0)
	{
		if (get_count_calls_qcsapi_init() < 1)
		  retval = -qcsapi_not_initialized;
	}

	if (retval >= 0)
	{
		if (new_mac_address_filtering == qcsapi_disable_mac_address_filtering ||
		    new_mac_address_filtering == qcsapi_accept_mac_address_unless_denied)
		  retval = local_security_build_mac_filter_file(HOSTAPD_DENY, &path_mac_addr_file[ 0 ], sizeof(path_mac_addr_file), ifname);
		else if (new_mac_address_filtering == qcsapi_deny_mac_address_unless_authorized)
		  retval = local_security_build_mac_filter_file(HOSTAPD_ACCEPT, &path_mac_addr_file[ 0 ], sizeof(path_mac_addr_file), ifname);
		else
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		int	current_macaddr_acl = -1, expected_macaddr_acl = -1;
		int	ival_macaddr_file = -1;
		char	param_buffer[ 80 ];
		int	ival_macaddr_acl = lookup_ap_security_parameter(
				 ifname,
				 wifi_mode,
				"macaddr_acl",
				&param_buffer[ 0 ],
				 sizeof( param_buffer )
			);

		if (ival_macaddr_acl >= 0)
		{
			sscanf( &param_buffer[ 0 ], "%d", &current_macaddr_acl );
		}

		switch (new_mac_address_filtering)
		{
		  case qcsapi_disable_mac_address_filtering:
		  case qcsapi_accept_mac_address_unless_denied:

			if (new_mac_address_filtering == qcsapi_disable_mac_address_filtering) {
				/* For disable, we always want to remove the macaddr_acl parameter */
				expected_macaddr_acl = -1;
			} else {
				expected_macaddr_acl = 0;
			}

			if (ival_macaddr_acl < 0 || current_macaddr_acl != expected_macaddr_acl)
			{
				/*
				 * For disabled, clear the parameter so we can reliably read it back,
				 * even when the deny list is empty.
				 */
				if (new_mac_address_filtering == qcsapi_disable_mac_address_filtering) {
					update_security_parameter_i(
							ifname,
							NULL,
							"macaddr_acl",
							"0",
							wifi_mode,
							QCSAPI_TRUE,
							qcsapi_bare_string,
							security_update_pending,
							1,
							0);

				} else {
					update_security_parameter(
							ifname,
							NULL,
							"macaddr_acl",
							"0",
							wifi_mode,
							QCSAPI_TRUE,
							qcsapi_bare_string,
							security_update_pending
							);
				}

				call_reload_security_configuration = 1;
			}

			ival_macaddr_file = lookup_ap_security_parameter(
				 ifname,
				 wifi_mode,
				"deny_mac_file",
				&param_buffer[ 0 ],
				 sizeof( param_buffer )
			);

			if (ival_macaddr_file < 0 ||
			    strcmp( &param_buffer[ 0 ], &path_mac_addr_file[ 0 ] ) != 0)
			{
				update_security_parameter(
					 ifname,
					 NULL,
					"deny_mac_file",
					&path_mac_addr_file[ 0 ],
					 wifi_mode,
			 		 QCSAPI_TRUE,
			 		 qcsapi_bare_string,
					 security_update_pending
				);

				call_reload_security_configuration = 1;
			}
		  /*
		   * If 1) the file does not exist or
		   *    2) MAC address filtering is now disabled
		   * then use local_write_string_to_file to create / reset
		   * the Deny MAC address file.
		   */
			if (access( &path_mac_addr_file[ 0 ], F_OK ) < 0 ||
			    new_mac_address_filtering == qcsapi_disable_mac_address_filtering)
			{
				create_deny_mac_addr_file( &path_mac_addr_file[ 0 ] );
				call_reload_security_configuration = 1;
			}

			break;

		  case qcsapi_deny_mac_address_unless_authorized:

			expected_macaddr_acl = 1;

			if (ival_macaddr_acl < 0 || current_macaddr_acl != expected_macaddr_acl)
			{
				update_security_parameter(
					 ifname,
					 NULL,
					"macaddr_acl",
					"1",
					 wifi_mode,
			 		 QCSAPI_TRUE,
			 		 qcsapi_bare_string,
					 security_update_pending
				);

				call_reload_security_configuration = 1;
			}

			ival_macaddr_file = lookup_ap_security_parameter(
				 ifname,
				 wifi_mode,
				"accept_mac_file",
				&param_buffer[ 0 ],
				 sizeof( param_buffer )
			);

			if (ival_macaddr_file < 0 ||
			    strcmp( &param_buffer[ 0 ], &path_mac_addr_file[ 0 ] ) != 0)
			{
				update_security_parameter(
					 ifname,
					 NULL,
					"accept_mac_file",
					&path_mac_addr_file[ 0 ],
					 wifi_mode,
			 		 QCSAPI_TRUE,
					 qcsapi_bare_string,
					 security_update_pending
				);

				if (access( &path_mac_addr_file[ 0 ], F_OK ) < 0)
				{
					create_accept_mac_addr_file( &path_mac_addr_file[ 0 ] );
				}

				call_reload_security_configuration = 1;
			}

			ival_macaddr_file = lookup_ap_security_parameter(
					ifname,
					wifi_mode,
					"accept_oui_file",
					&param_buffer[0],
					sizeof( param_buffer ));

			if (ival_macaddr_file < 0 || strcmp(&param_buffer[0], &path_mac_addr_file[0]) != 0)
			{
				retval = local_security_build_mac_filter_file(HOSTAPD_ACCEPT_OUI, &path_mac_addr_file[0],
						sizeof(path_mac_addr_file), ifname);
				if (retval >= 0) {
					update_security_parameter(
							ifname,
							NULL,
							"accept_oui_file",
							&path_mac_addr_file[0],
							wifi_mode,
							QCSAPI_TRUE,
							qcsapi_bare_string,
							security_update_pending);

					if (access(&path_mac_addr_file[0], F_OK) < 0)
					{
						create_accept_oui_file(&path_mac_addr_file[0]);
					}

					call_reload_security_configuration = 1;
				}
			}
			break;
		  /*
		   * Sanity check - should have been caught when we located the MAC addres file (accept or deny).
		   */
		  default:
			retval = -EINVAL;
			break;
		}
	}

	if (call_reload_security_configuration)
		update_security_bss_configuration( ifname );

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	return( retval );
}

int
qcsapi_wifi_set_mac_address_filtering(
	const char *ifname,
	const qcsapi_mac_address_filtering new_mac_address_filtering
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_security_set_mac_address_filtering(ifname, new_mac_address_filtering );

	leave_qcsapi();

	return( retval );
}

static int
local_security_clear_mac_filter_lists(const char *ifname)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			path_mac_addr_file[ 80 ];
	char			param_buffer[ 80 ];
	int			ival_macaddr_acl;
	int			ival_macaddr_file;
	int			current_macaddr_acl = -1;
	int			reload_sec = 0;

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			}
		}
	}

	if (retval >= 0) {
		if (get_count_calls_qcsapi_init() < 1) {
			retval = -qcsapi_not_initialized;
		}
	}

	if (retval >= 0) {

		ival_macaddr_acl = lookup_ap_security_parameter(
				ifname,
				wifi_mode,
				"macaddr_acl",
				&param_buffer[ 0 ],
				sizeof( param_buffer )
				);

		/*
		 * We read in the macaddr_acl variable to see whether to kick the hostapd
		 * daemon or not.
		 */
		if (ival_macaddr_acl >= 0) {
			sscanf( &param_buffer[ 0 ], "%d", &current_macaddr_acl );
		}

		/* Clear the accept file first */
		ival_macaddr_file = lookup_ap_security_parameter(
				ifname,
				wifi_mode,
				"accept_mac_file",
				&param_buffer[ 0 ],
				sizeof( param_buffer )
				);

		if (ival_macaddr_file >= 0) {
			int ival_sec_path;
			ival_sec_path = local_security_build_mac_filter_file(HOSTAPD_ACCEPT, &path_mac_addr_file[ 0 ], sizeof(path_mac_addr_file), ifname);
			if (ival_sec_path >= 0) {
				if (access( &path_mac_addr_file[ 0 ], F_OK ) >= 0) {
					create_accept_mac_addr_file( &path_mac_addr_file[ 0 ] );
					reload_sec = 1;
				}
			}
		}
		/* Clear the accept oui file */
		ival_macaddr_file = lookup_ap_security_parameter(
				ifname,
				wifi_mode,
				"accept_oui_file",
				&param_buffer[0],
				sizeof(param_buffer));

		if (ival_macaddr_file >= 0) {
			int ival_sec_path;
			ival_sec_path = local_security_build_mac_filter_file(HOSTAPD_ACCEPT_OUI, &path_mac_addr_file[0],
					sizeof(path_mac_addr_file), ifname);
			if (ival_sec_path >= 0) {
				if (access(&path_mac_addr_file[0], F_OK) >= 0) {
					create_accept_oui_file(&path_mac_addr_file[0]);
					reload_sec = 1;
				}
			}
		}
		/* Now clear the deny file */
		ival_macaddr_file = lookup_ap_security_parameter(
				ifname,
				wifi_mode,
				"deny_mac_file",
				&param_buffer[ 0 ],
				sizeof( param_buffer )
				);

		if (ival_macaddr_file >= 0) {
			int ival_sec_path;
			ival_sec_path = local_security_build_mac_filter_file(HOSTAPD_DENY, &path_mac_addr_file[ 0 ], sizeof(path_mac_addr_file), ifname);
			if (ival_sec_path >= 0) {
				if (access( &path_mac_addr_file[ 0 ], F_OK ) >= 0) {
					create_deny_mac_addr_file( &path_mac_addr_file[ 0 ] );
					reload_sec = 1;
				}
			}
		}
		/* We only reload if one or more of the files was cleared and macaddr_acl is set to something */
		if (reload_sec && (current_macaddr_acl != -1)) {
			update_security_bss_configuration( ifname );
		}

	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	return retval;
}

int
qcsapi_wifi_clear_mac_address_filters(
	const char *ifname
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_security_clear_mac_filter_lists(ifname);

	leave_qcsapi();

	return( retval );
}

static int
append_mac_addr_string( qcsapi_mac_addr current_mac_addr, void *arg1, void *arg2 )
{
	int			 retval = 0;
	char			*base_list_mac_addresses = (char *) arg1;
	const unsigned int	 sizeof_list = (unsigned int) arg2;
	unsigned int		 current_length = strnlen( base_list_mac_addresses, sizeof_list );
	unsigned int		 incremental_length = 0;
	char			 current_mac_addr_string[ 20 ];

	sprintf( &current_mac_addr_string[ 0 ], MACFILTERINGMACFMT,
		  current_mac_addr[ 0 ],
		  current_mac_addr[ 1 ],
		  current_mac_addr[ 2 ],
		  current_mac_addr[ 3 ],
		  current_mac_addr[ 4 ],
		  current_mac_addr[ 5 ]
	);

	incremental_length = strnlen( &current_mac_addr_string[ 0 ], sizeof( current_mac_addr_string ) );
	if (incremental_length + current_length + 1 > sizeof_list - 1)
	  retval = -qcsapi_buffer_overflow;
	else
	{
		if (current_length > 0)
		  strcat( base_list_mac_addresses + current_length, "," );
		strcat( base_list_mac_addresses + current_length, &current_mac_addr_string[ 0 ] );
	}

	return( retval );
}

int
local_security_get_authorized_mac_addresses( const char *ifname, char *list_mac_addresses, const unsigned int sizeof_list )
{
	int				retval = 0;
	qcsapi_mac_address_filtering	current_mac_address_filtering = qcsapi_nosuch_mac_address_filtering;
/*
 * Last test insures there is at least room for 1 MAC address.
 *
 * And local_security_get_mac_address_filtering restricts the API to an AP, as required.
 */
	if (ifname == NULL || list_mac_addresses == NULL)
	  retval = -EFAULT;
	else if (sizeof_list < 20)
	  retval = -qcsapi_buffer_overflow;
	else
	  retval = local_security_get_mac_address_filtering( ifname, &current_mac_address_filtering );

	if (retval >= 0)
	{
		if ((current_mac_address_filtering != 0) &&
		    (current_mac_address_filtering != qcsapi_deny_mac_address_unless_authorized))
		  retval = -qcsapi_configuration_error;
	}

	if (retval >= 0)
	{
		char	path_mac_addr_file[ 80 ];

		retval = local_security_build_mac_filter_file(
			 HOSTAPD_ACCEPT,
			&path_mac_addr_file[ 0 ],
			 sizeof( path_mac_addr_file ),
			 ifname
		);

		if (retval >= 0)
		{
		  /*
		   * local_sizeof_list avoids arguments with the compiler
		   * about the const nature of sizeof_list.
		   */
			unsigned int	local_sizeof_list = sizeof_list;

			*list_mac_addresses = '\0';

			retval = read_mac_addr_file(
					&path_mac_addr_file[ 0 ],
					 append_mac_addr_string,
					 list_mac_addresses,
				(void *) local_sizeof_list
			);
		}
	}

	return( retval );
}

int
qcsapi_wifi_get_authorized_mac_addresses( const char *ifname, char *list_mac_addresses, const unsigned int sizeof_list )
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_security_get_authorized_mac_addresses(ifname, list_mac_addresses, sizeof_list );

	leave_qcsapi();

	return( retval );
}

int
local_security_get_denied_mac_addresses( const char *ifname, char *list_mac_addresses, const unsigned int sizeof_list )
{
	int				retval = 0;
	qcsapi_mac_address_filtering	current_mac_address_filtering = qcsapi_nosuch_mac_address_filtering;
/*
 * Last test insures there is at least room for 1 MAC address.
 *
 * And local_security_get_mac_address_filtering restricts the API to an AP, as required.
 */
	if (ifname == NULL || list_mac_addresses == NULL)
	  retval = -EFAULT;
	else if (sizeof_list < 20)
	  retval = -qcsapi_buffer_overflow;
	else
	  retval = local_security_get_mac_address_filtering( ifname, &current_mac_address_filtering );

	if (retval >= 0)
	{
		if (current_mac_address_filtering != qcsapi_disable_mac_address_filtering &&
		    current_mac_address_filtering != qcsapi_accept_mac_address_unless_denied)
		  retval = -qcsapi_configuration_error;
	}

	if (retval >= 0)
	{
		if (current_mac_address_filtering == qcsapi_disable_mac_address_filtering)
		{
			*list_mac_addresses = '\0';	/* No addresses are denied */
		}
		else
		{
			char	path_mac_addr_file[ 80 ];

			retval = local_security_build_mac_filter_file(
				 HOSTAPD_DENY,
				&path_mac_addr_file[ 0 ],
				 sizeof( path_mac_addr_file ),
				 ifname
			);

			if (retval >= 0)
			{
			  /*
			   * local_sizeof_list avoids arguments with the compiler
			   * about the const nature of sizeof_list.
			   */
				unsigned int	local_sizeof_list = sizeof_list;

				*list_mac_addresses = '\0';

				retval = read_mac_addr_file(
						&path_mac_addr_file[ 0 ],
						 append_mac_addr_string,
						 list_mac_addresses,
					(void *) local_sizeof_list
				);
			}
		}
	}

	return( retval );
}

int
qcsapi_wifi_get_denied_mac_addresses( const char *ifname, char *list_mac_addresses, const unsigned int sizeof_list )
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_security_get_denied_mac_addresses(ifname, list_mac_addresses, sizeof_list );

	leave_qcsapi();

	return( retval );
}

static int
search_for_mac_addr( qcsapi_mac_addr current_mac_addr, void *arg1, void *arg2 )
{
	int	 retval = 0;
	uint8_t	*target_mac_addr = (uint8_t *) arg1;
	int	*retarg = (int *) arg2;

	if (retarg == NULL)
	  retval = -EFAULT;
	else
	{
	  /*
	   * 1 if they match, 0 if not a match
	   */
		int	ival = memcmp( current_mac_addr, target_mac_addr, sizeof( qcsapi_mac_addr ) );

		if (ival == 0)
		{
			*retarg = 1;
			retval = 1;
		}
		else
		  *retarg = 0;
	}

	return( retval );
}

int
local_security_is_mac_address_authorized(
	const char *ifname,
	const qcsapi_mac_addr address_to_verify,
	int *p_mac_address_authorized
)
{
	int				retval = 0;
	qcsapi_mac_address_filtering	current_mac_address_filtering = qcsapi_nosuch_mac_address_filtering;
/*
 * local_security_get_mac_address_filtering restricts the API to an AP, as required.
 */
	if (ifname == NULL || address_to_verify == NULL || p_mac_address_authorized == NULL)
	  retval = -EFAULT;
	else
	  retval = local_security_get_mac_address_filtering( ifname, &current_mac_address_filtering );

	if (retval >= 0)
	{
		retval = local_generic_verify_mac_addr_valid( address_to_verify );
	}

	if (retval >= 0)
	{
		if (current_mac_address_filtering == qcsapi_disable_mac_address_filtering)
		  *p_mac_address_authorized = 1;
		else
		{
			char	 path_mac_addr_file[ 80 ];
			char	*base_mac_file = HOSTAPD_DENY;

			if (current_mac_address_filtering == qcsapi_deny_mac_address_unless_authorized)
			  base_mac_file = HOSTAPD_ACCEPT;

			retval = local_security_build_mac_filter_file(
				 base_mac_file,
				&path_mac_addr_file[ 0 ],
				 sizeof( path_mac_addr_file ),
				 ifname
			);

			if (retval >= 0)
			{
				qcsapi_mac_addr	local_address_to_verify;
				int		found_mac_address = 0;

				memcpy( local_address_to_verify, address_to_verify, sizeof( qcsapi_mac_addr ) );

				retval = read_mac_addr_file(
						&path_mac_addr_file[ 0 ],
						 search_for_mac_addr,
						 local_address_to_verify,
						&found_mac_address
				);

				if (retval >= 0)
				{
					if (found_mac_address > 1)	/* force it to be either 0 or 1 */
					  found_mac_address = 1;

					if (current_mac_address_filtering == qcsapi_accept_mac_address_unless_denied)
					{
						if (found_mac_address)
						  *p_mac_address_authorized = 0;
						else
						  *p_mac_address_authorized = 1;
					}
					else
					  *p_mac_address_authorized = found_mac_address;
				}
			}
		}
	}

	return( retval );
}

int
qcsapi_wifi_is_mac_address_authorized(
	const char *ifname,
	const qcsapi_mac_addr address_to_verify,
	int *p_mac_address_authorized
)
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_security_is_mac_address_authorized( ifname, address_to_verify, p_mac_address_authorized );

	leave_qcsapi();

	return( retval );
}

static int
add_mac_address( const char *path_mac_addr_file, const qcsapi_mac_addr the_mac_addr )
{
	int		retval = 0;
	qcsapi_mac_addr	local_mac_addr;
	int		found_mac_address = 0;

	memcpy( local_mac_addr, the_mac_addr, sizeof( qcsapi_mac_addr ) );

	read_mac_addr_file(
		 path_mac_addr_file,
		 search_for_mac_addr,
		 local_mac_addr,
		&found_mac_address
	);

	if (found_mac_address == 0)
	{
		char	subshell_cmd[ 120 ];

		sprintf( &subshell_cmd[ 0 ], "echo \"" MACFILTERINGMACFMT "\" >>%s",
			  the_mac_addr[ 0 ],
			  the_mac_addr[ 1 ],
			  the_mac_addr[ 2 ],
			  the_mac_addr[ 3 ],
			  the_mac_addr[ 4 ],
			  the_mac_addr[ 5 ],
			  path_mac_addr_file
		);

		system( &subshell_cmd[ 0 ] );
	}

	return( retval );
}

static int
remove_mac_address( const char *path_mac_addr_file, const qcsapi_mac_addr the_mac_addr )
{
	int	retval = 0;
	qcsapi_mac_addr	local_mac_addr;
	int		found_mac_address = 0;

	memcpy( local_mac_addr, the_mac_addr, sizeof( qcsapi_mac_addr ) );

	read_mac_addr_file(
		 path_mac_addr_file,
		 search_for_mac_addr,
		 local_mac_addr,
		&found_mac_address
	);

	if (found_mac_address == 1)
	{
		char	subshell_cmd[ 132 ];

		sprintf( &subshell_cmd[ 0 ], "remove_mac_addr \"" MACFILTERINGMACFMT "\" %s",
			  the_mac_addr[ 0 ],
			  the_mac_addr[ 1 ],
			  the_mac_addr[ 2 ],
			  the_mac_addr[ 3 ],
			  the_mac_addr[ 4 ],
			  the_mac_addr[ 5 ],
			  path_mac_addr_file
		);

		system( &subshell_cmd[ 0 ] );
	}


	return( retval );
}

static int
local_security_update_filtered_mac_address(
	const char *ifname,
	int accept_deny_flag,
	const qcsapi_mac_addr the_mac_addr,
	int flag
)
{
	int	retval = 0, ival = 0;
	qcsapi_mac_address_filtering current_mac_address_filtering = qcsapi_nosuch_mac_address_filtering;
	char path_mac_addr_file[ 80 ];
	int	call_reload_security_configuration = 0;

	if (ifname == NULL || the_mac_addr == NULL)
		retval = -EFAULT;
  /*
   * Return value of -EINVAL represents a programming error.
   */
	else if (accept_deny_flag != accept_mac_address && accept_deny_flag != deny_mac_address
			&& accept_deny_flag != accept_oui)
		retval = -EINVAL;
	else
  /*
   * local_security_get_mac_address_filtering restricts the API to an AP, as required.
   * Here though we ignore the current MAC address filtering.
   */
		retval = local_security_get_mac_address_filtering(ifname, &current_mac_address_filtering);

	if (retval >= 0)
		retval = local_generic_verify_mac_addr_valid(the_mac_addr);

	if (retval >= 0 && accept_deny_flag == deny_mac_address)
	{
	  /*
	   * If blocking a MAC address, insure if macaddr_acl is not defined,
	   * it gets set to 0 (accept unless denied) and insure that deny_mac_file
	   * has the path to the Deny MAC address file.
	   */
		char param_buffer[80];
	  /*
	   * Locating the Deny MAC address file path is expected to work ...
	   */
		if (local_security_build_mac_filter_file(HOSTAPD_DENY, &path_mac_addr_file[ 0 ], sizeof( path_mac_addr_file ), ifname) < 0)
		  return( -qcsapi_programming_error );

		ival = lookup_ap_security_parameter(
			 ifname,
			 qcsapi_access_point,
			"deny_mac_file",
			&param_buffer[ 0 ],
			 sizeof( param_buffer )
		);

		if (ival < 0 || strcmp( &param_buffer[ 0 ], &path_mac_addr_file[ 0 ] ) != 0)
		{
			retval = update_security_parameter(
				 ifname,
				 NULL,
				"deny_mac_file",
				&path_mac_addr_file[ 0 ],
				 qcsapi_access_point,
		 		 QCSAPI_TRUE,
		 		 qcsapi_bare_string,
				 security_update_pending
			);

			call_reload_security_configuration = 1;
		}

		if (retval >= 0)
		{
			ival = lookup_ap_security_parameter(
				 ifname,
				 qcsapi_access_point,
				"macaddr_acl",
				&param_buffer[ 0 ],
				 sizeof( param_buffer )
			);

			if (ival < 0)
			{
				retval = update_security_parameter(
						 ifname,
						 NULL,
						"macaddr_acl",
						"0",
						 qcsapi_access_point,
						 QCSAPI_TRUE,
						 qcsapi_bare_string,
						 security_update_pending
				);

				call_reload_security_configuration = 1;
			}
		}
	} else if (retval >= 0 && accept_deny_flag == accept_mac_address) {
		char	param_buffer[80];
		/*
		* Locating the accpet MAC address file path is expected to work ...
		*/
		if (local_security_build_mac_filter_file(HOSTAPD_ACCEPT, &path_mac_addr_file[0], sizeof(path_mac_addr_file), ifname) < 0)
			return -qcsapi_programming_error;

		ival = lookup_ap_security_parameter(
			 ifname,
			 qcsapi_access_point,
			"accept_mac_file",
			&param_buffer[0],
			 sizeof(param_buffer));

		if (ival < 0 || strcmp(&param_buffer[0], &path_mac_addr_file[0]) != 0) {
			retval = update_security_parameter(
				 ifname,
				 NULL,
				"accept_mac_file",
				&path_mac_addr_file[0],
				 qcsapi_access_point,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_pending);

			call_reload_security_configuration = 1;
		}
	} else if (retval >= 0 && accept_deny_flag == accept_oui) {
		char param_buffer[80];
		if (local_security_build_mac_filter_file(HOSTAPD_ACCEPT_OUI, &path_mac_addr_file[0],
				sizeof(path_mac_addr_file), ifname) < 0)
			return -qcsapi_programming_error;

		ival = lookup_ap_security_parameter(
				ifname,
				qcsapi_access_point,
				"accept_oui_file",
				&param_buffer[0],
				sizeof(param_buffer));

		if (ival < 0 || strcmp(&param_buffer[0], &path_mac_addr_file[0]) != 0) {
			retval = update_security_parameter(
					ifname,
					NULL,
					"accept_oui_file",
					&path_mac_addr_file[0],
					qcsapi_access_point,
					QCSAPI_TRUE,
					qcsapi_bare_string,
					security_update_pending);

			call_reload_security_configuration = 1;
		}
	}

	if (retval >= 0)
	{
		ival = local_security_build_mac_filter_file(
			 HOSTAPD_ACCEPT,
			&path_mac_addr_file[ 0 ],
			 sizeof( path_mac_addr_file ),
			 ifname
		);

		if (ival >= 0)
		{
			if (access( &path_mac_addr_file[ 0 ], F_OK ) < 0)
			{
				create_accept_mac_addr_file( &path_mac_addr_file[ 0 ] );
			}
		  /*
		   * Value of accept_deny_flag has been vetted.
		   */
			if (accept_deny_flag == accept_mac_address)
			{
				add_mac_address( &path_mac_addr_file[ 0 ], the_mac_addr );
			}
			else
			{
				remove_mac_address( &path_mac_addr_file[ 0 ], the_mac_addr );
			}

			call_reload_security_configuration = 1;
		}
	}

	if (retval >= 0)
	{
		ival = local_security_build_mac_filter_file(
					 HOSTAPD_ACCEPT_OUI,
					&path_mac_addr_file[ 0 ],
					 sizeof( path_mac_addr_file ),
					 ifname
				);
		if (ival >= 0)
		{
			if (access(&path_mac_addr_file[0], F_OK) < 0)
			{
				create_accept_oui_file(&path_mac_addr_file[0]);
			}

			if (accept_deny_flag == accept_oui)
			{
				if (flag)
					add_mac_address(&path_mac_addr_file[0], the_mac_addr);
				else
					remove_mac_address(&path_mac_addr_file[0], the_mac_addr);
			}
			call_reload_security_configuration = 1;
		}
	}

	if (retval >= 0)
	{
		ival = local_security_build_mac_filter_file(
			 HOSTAPD_DENY,
			&path_mac_addr_file[ 0 ],
			 sizeof( path_mac_addr_file ),
			 ifname
		);

		if (ival >= 0)
		{
			if (access( &path_mac_addr_file[ 0 ], F_OK ) < 0)
			{
				create_deny_mac_addr_file( &path_mac_addr_file[ 0 ] );
			}
		  /*
		   * Value of accept_deny_flag has been vetted.
		   */
			if (accept_deny_flag == deny_mac_address)
			{
				add_mac_address( &path_mac_addr_file[ 0 ], the_mac_addr );
			}
			else
			{
				remove_mac_address( &path_mac_addr_file[ 0 ], the_mac_addr );
			}

			call_reload_security_configuration = 1;
		}
	}

	if (call_reload_security_configuration)
	{
		update_security_bss_configuration( ifname );
	}

	return( retval );
}

int
qcsapi_wifi_authorize_mac_address( const char *ifname, const qcsapi_mac_addr address_to_authorize )
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_security_update_filtered_mac_address( ifname, accept_mac_address, address_to_authorize, ADD_INTO_LIST );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_wifi_deny_mac_address( const char *ifname, const qcsapi_mac_addr address_to_deny )
{
	int	retval = 0;

	enter_qcsapi();

	retval = local_security_update_filtered_mac_address( ifname, deny_mac_address, address_to_deny, ADD_INTO_LIST );

	leave_qcsapi();

	return( retval );
}

static int
local_security_remove_filtered_mac_address( const char *ifname, const qcsapi_mac_addr the_mac_addr )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			path_mac_addr_file[ 80 ];
	char			param_buffer[ 80 ];
	int			ival_macaddr_acl;
	int			ival_macaddr_file;
	int			current_macaddr_acl = -1;
	int			reload_sec = 0;

	if (ifname == NULL || the_mac_addr == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			}
		}
	}

	if (retval >= 0) {
		if (get_count_calls_qcsapi_init() < 1) {
			retval = -qcsapi_not_initialized;
		}
	}

	if (retval >= 0) {

		ival_macaddr_acl = lookup_ap_security_parameter(
				ifname,
				wifi_mode,
				"macaddr_acl",
				&param_buffer[ 0 ],
				sizeof( param_buffer )
				);

		/*
		 * We read in the macaddr_acl variable to see whether to kick the hostapd
		 * daemon or not.
		 */
		if (ival_macaddr_acl >= 0) {
			sscanf( &param_buffer[ 0 ], "%d", &current_macaddr_acl );
		}

		/* Remove from the accept file first */
		ival_macaddr_file = lookup_ap_security_parameter(
				ifname,
				wifi_mode,
				"accept_mac_file",
				&param_buffer[ 0 ],
				sizeof( param_buffer )
				);

		if (ival_macaddr_file >= 0) {
			int ival_sec_path;
			ival_sec_path = local_security_build_mac_filter_file(HOSTAPD_ACCEPT, &path_mac_addr_file[ 0 ], sizeof(path_mac_addr_file), ifname);
			if (ival_sec_path >= 0) {
				remove_mac_address( &path_mac_addr_file[ 0 ], the_mac_addr );
				reload_sec = 1;
			}
		}

		/* Now remove from the deny file */
		ival_macaddr_file = lookup_ap_security_parameter(
				ifname,
				wifi_mode,
				"deny_mac_file",
				&param_buffer[ 0 ],
				sizeof( param_buffer )
				);

		if (ival_macaddr_file >= 0) {
			int ival_sec_path;
			ival_sec_path = local_security_build_mac_filter_file(HOSTAPD_DENY, &path_mac_addr_file[ 0 ], sizeof(path_mac_addr_file), ifname);
			if (ival_sec_path >= 0) {
				remove_mac_address( &path_mac_addr_file[ 0 ], the_mac_addr );
				reload_sec = 1;
			}
		}

		if (reload_sec && (current_macaddr_acl != -1)) {
			update_security_bss_configuration( ifname );
		}

	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	return retval;
}

int
qcsapi_wifi_remove_mac_address( const char *ifname, const qcsapi_mac_addr address_to_remove )
{
	int retval = 0;

	enter_qcsapi();

	retval = local_security_remove_filtered_mac_address( ifname, address_to_remove );

	leave_qcsapi();

	return( retval );
}

/* Service Set (SSID) QCSAPIs */

/*
 * These currently only work on a Station.
 *
 * Determinant is actually the format of the security configuration file.
 * The one for the station (wpa_supplicant.conf) supports multiple SSID configurations.
 * The one for the access point (hostapd.conf) supports only 1 SSID configuration.
 *
 * The default hostapd.conf (and wpa_supplicant.conf) should only be changed in
 * connection with changes to these programs.
 */

static int
local_SSID_preamble(
	const char *ifname,
	const qcsapi_SSID current_SSID,
	int *p_skfd,
	qcsapi_wifi_mode *p_wifi_mode
)
{
	int	retval = 0;

	if (current_SSID == NULL || ifname == NULL || p_skfd == NULL || p_wifi_mode == NULL)
	  retval = -EFAULT;
	else
	{
		retval = local_security_validate_SSID( current_SSID );
	}

	if (retval >= 0)
	  retval = local_open_iw_socket_with_error( p_skfd );
/*
 * Support for network APIs depends on the format of the security configuration file.
 * Only if this file supports multiple networks are these APIs going to work
 * Currently this file for the Station (wpa_supplicant.conf) DOES support multiple
 * networks; the one for Access Point (hostapd.conf) does not.
 */
	if (retval >= 0)
	{
		retval = local_wifi_get_mode( *p_skfd, ifname, p_wifi_mode );
		if (retval >= 0)
		{
			if (*p_wifi_mode != qcsapi_station)
			  retval = -qcsapi_only_on_STA;
		}
	}

	return( retval );
}

int
qcsapi_SSID_create_SSID( const char *ifname, const qcsapi_SSID new_SSID )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	retval = local_SSID_preamble( ifname, new_SSID, &skfd, &wifi_mode );

	if (retval >= 0)
	{
		retval = instantiate_new_SSID_config( new_SSID, wifi_mode );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	if (retval >= 0) {
		retval = reload_security_configuration( ifname, wifi_mode );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_remove_SSID( const char *ifname, const qcsapi_SSID del_SSID )
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	retval = local_SSID_preamble(ifname, del_SSID, &skfd, &wifi_mode);

	if (retval >= 0) {
		retval = qcsapi_wifi_remove_SSID(del_SSID, wifi_mode);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	if (retval >= 0) {
		retval = reload_security_configuration(ifname, wifi_mode);
	}

	leave_qcsapi();

	return (retval);
}

int
qcsapi_SSID_verify_SSID( const char *ifname, const qcsapi_SSID network_SSID )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	qcsapi_SSID		check_SSID;

	enter_qcsapi();

	retval = local_SSID_preamble( ifname, network_SSID, &skfd, &wifi_mode );

	if (retval >= 0)
	{
		retval = lookup_SSID_parameter( network_SSID, wifi_mode, "ssid", check_SSID, sizeof( check_SSID ) );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_rename_SSID( const char *ifname, const qcsapi_SSID current_SSID, const qcsapi_SSID new_SSID )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (new_SSID == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, current_SSID, &skfd, &wifi_mode );

	if (retval >= 0)
	{
		retval = local_security_validate_SSID( new_SSID );
	}

	if (retval >= 0)
	{
	  /*
 	   * Verify the new SSID is NOT present in the configuration ...
 	   */
		qcsapi_SSID	check_SSID;
		int		ival = lookup_SSID_parameter( new_SSID, wifi_mode, "ssid", check_SSID, sizeof( check_SSID ) );

		if (ival >= 0)
		  retval = -EEXIST;
	}

	if (retval >= 0)
	{
	  /*
 	   * Only update if the SSID actually changed ...
 	   */
		if (strcmp( current_SSID, new_SSID ) != 0)
		  retval = update_security_parameter(
				 ifname,
				 current_SSID,
				"ssid",
				 new_SSID,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_in_quotes,
				 security_update_complete
		  );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_get_SSID_list(const char *ifname, const unsigned int arrayc, char *list_SSID[])
{
	int retval = 0;

	enter_qcsapi();

	retval = get_conf_ssid_list(ifname, arrayc, list_SSID);

	leave_qcsapi();

	return( retval );
}

#define  FOUND_WPA	0x01
#define  FOUND_RSN	0x02

static int
local_parse_SSID_proto( const char *current_proto )
{
	int		 retval = 0;
	int		 complete = 0, proto_modes_found = 0;
	const char	*current_addr = current_proto;

	if (current_proto == NULL)
	  return( -EFAULT );

	do
	{
		int		 expected_length = 0, this_proto_mode = 0;

		while (isspace( *current_addr ))
		  current_addr++;
		complete = (*current_addr == '\0');

		if (complete == 0)
		{
		  /*
		   * check for WPA2 before WPA, since WPA is a substring of WPA2
		   */
			if (strncmp( current_addr, "WPA2", 4 ) == 0)
			{
				this_proto_mode = FOUND_RSN;
				expected_length = 4;
			}
			else if (strncmp( current_addr, "RSN", 3 ) == 0)
			{
				this_proto_mode = FOUND_RSN;
				expected_length = 3;
			}
			else if (strncmp( current_addr, "WPA", 3 ) == 0)
			{
				this_proto_mode = FOUND_WPA;
				expected_length = 3;
			}
			else
			{
				complete = 1;
				retval = -EINVAL;
			}
		}

		if (complete == 0)
		{
			const char	*next_addr = current_addr;
			char	 	 next_char = '\0';

			next_addr = current_addr + expected_length;
			next_char = *next_addr;

			if ((isspace( next_char ) == 0) &&
			    (next_char != '\n') &&
			    (next_char != '\0'))
			{
				complete = 1;
				retval = -EINVAL;
			}
			else
			{
				proto_modes_found |= this_proto_mode;
				current_addr = next_addr;
			}
		}
	} while (complete == 0);

	if (retval >= 0)
	{
		if (proto_modes_found == (FOUND_WPA | FOUND_RSN))
		  retval = index_proto_WPA_11i;
		else if (proto_modes_found == FOUND_WPA)
		  retval = index_proto_WPA_only;
		else if (proto_modes_found == FOUND_RSN)
		  retval = index_proto_11i_only;
	  /*
	   * Come here if the line had no non-whitespace chars ...
	   */
		else
		  retval = -EINVAL;
	}

	return( retval );
}

static int
local_security_is_none_SSID( const qcsapi_SSID SSID_str, const qcsapi_wifi_mode wifi_mode, int *p_security_is_NONE)
{
	int	retval = 0;
	char	key_mgmt[ 32 ];

	retval = lookup_SSID_parameter( SSID_str, wifi_mode, "key_mgmt", key_mgmt, sizeof( key_mgmt ) );

	if (retval >= 0) {
		const parameter_translation_entry	*p_pte = &authentication_mode_table[ AUTH_MODE_TABLE_NONE_INDEX ];
		unsigned int				 internal_length = strlen( p_pte->internal_value );
		if (strncmp( p_pte->internal_value, key_mgmt, internal_length ) == 0) {
			*p_security_is_NONE = 1;
		} else {
			*p_security_is_NONE = 0;
		}
	}

	return retval;
}

int
qcsapi_SSID_get_protocol( const char *ifname, const qcsapi_SSID current_SSID, string_16 current_protocol )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (current_protocol == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, current_SSID, &skfd, &wifi_mode );

	if (retval >= 0) {
		int 		security_is_NONE = 0;
		retval = local_security_is_none_SSID(current_SSID, wifi_mode, &security_is_NONE);
		if (retval >= 0) {
			if (security_is_NONE) {
				retval = -qcsapi_configuration_error;
			}
		}
	}

	if (retval >= 0)
	{
		char		 proto_for_SSID[ 12 ] = { '\0' };

		retval = lookup_SSID_parameter(
			 current_SSID,
			 wifi_mode,
			"proto",
			 proto_for_SSID,
			 sizeof( proto_for_SSID )
		);

		if (retval >= 0)
		{
			int	ival = local_parse_SSID_proto( &proto_for_SSID[ 0 ] );

			if (ival < 0)
			  retval = ival;
			else if (ival > max_SSID_proto_index)
			  retval = -EINVAL;
			else
			{
				strcpy( current_protocol, SSID_proto_table[ ival ].qcsapi_value );
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
qcsapi_SSID_set_protocol( const char *ifname, const qcsapi_SSID current_SSID, const char *new_protocol )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;
	int			 station_protocol_index = -1;

	enter_qcsapi();

	if (new_protocol == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, current_SSID, &skfd, &wifi_mode );

	if (retval >= 0)
	{
		int	beacon_table_index = local_security_search_beacon_table( new_protocol );
	  /*
	   * First search the beacon value table (this is what the get_proto API reports)
	   * Do not allow Basic as a protocol, but continue on if the beacon table search fails.
	   */
		switch (beacon_table_index)
		{
		  case index_beacon_WPA_only:
			station_protocol_index = index_proto_WPA_only;
			break;

		  case index_beacon_11i_only:
			station_protocol_index = index_proto_11i_only;
			break;

		  case index_beacon_WPA_11i:
			station_protocol_index = index_proto_WPA_11i;
			break;

		  case index_beacon_type_basic:
			retval = -EINVAL;
			break;

		  default:
			break;
		}

		if (retval >= 0 && station_protocol_index < 0)
		{
			station_protocol_index = local_parse_SSID_proto( new_protocol );
			if (station_protocol_index < 0 || station_protocol_index > max_SSID_proto_index)
			  retval = -EINVAL;
		}
	}

	if (retval >= 0)
	{
		retval = update_security_parameter(
				 ifname,
				 current_SSID,
				"proto",
				 SSID_proto_table[ station_protocol_index ].internal_value,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);

	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_get_encryption_modes( const char *ifname, const qcsapi_SSID SSID_str, string_32 encryption_modes )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (encryption_modes == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, SSID_str, &skfd, &wifi_mode );

	if (retval >= 0) {
		int 		security_is_NONE = 0;
		retval = local_security_is_none_SSID(SSID_str, wifi_mode, &security_is_NONE);
		if (retval >= 0) {
			if (security_is_NONE) {
				retval = -qcsapi_configuration_error;
			}
		}
	}

	if (retval >= 0)
	{
	  /*
	   * local buffer for "pairwise" value is NOT a string32
	   * It contains the value found in wpa_supplicant.conf, different (and shorter in length)
	   * than the TR-069 / TR-098 spec for the encryption mode.
	   */
		char		 pairwise[ 32 ] = { '\0' };

		retval = lookup_SSID_parameter( SSID_str, wifi_mode, "pairwise", pairwise, sizeof( pairwise ) );
		if (retval >= 0)
		{
			const char	*proposed_return_string = local_parse_wpa_pairwise( &pairwise[ 0 ] );

			if (proposed_return_string != NULL)
			  strcpy( encryption_modes, proposed_return_string );
			else
			  retval = -ENXIO;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_set_encryption_modes( const char *ifname, const qcsapi_SSID SSID_str, const string_32 encryption_modes )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;
	const char		*new_internal_value = NULL;

	enter_qcsapi();

	if (encryption_modes == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, SSID_str, &skfd, &wifi_mode );

	if (retval >= 0)
	{
		if (strnlen( encryption_modes, QCSAPI_WPA_SECURITY_MODE_MAX_SIZE + 1 ) > QCSAPI_WPA_SECURITY_MODE_MAX_SIZE)
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		unsigned int	iter;

		for (iter = 0; encryption_mode_table[ iter ].internal_value != NULL && new_internal_value == NULL; iter++)
		{
			if (strcmp( encryption_modes, encryption_mode_table[ iter ].qcsapi_value ) == 0)
			  new_internal_value = encryption_mode_table[ iter ].internal_value;
		}

		if (new_internal_value == NULL)
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		retval = update_security_parameter(
				 ifname,
				 SSID_str,
				"pairwise",
				 new_internal_value,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_get_group_encryption( const char *ifname, const qcsapi_SSID current_SSID, string_32 group_encryption )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char		 	internal_group_value[ 32 ] = { '\0' };

	enter_qcsapi();

	if (group_encryption == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, current_SSID, &skfd, &wifi_mode );

	if (retval >= 0) {
		int 		security_is_NONE = 0;
		retval = local_security_is_none_SSID(current_SSID, wifi_mode, &security_is_NONE);
		if (retval >= 0) {
			if (security_is_NONE) {
				retval = -qcsapi_configuration_error;
			}
		}
	}

	if (retval >= 0)
	{
		retval = lookup_SSID_parameter(
				 current_SSID,
				 wifi_mode,
				"group",
				 internal_group_value,
				 sizeof( internal_group_value )
		);
	}

	if (retval >= 0)
	{
		int	iter, local_index = -1;

		for (iter = 0; encryption_mode_table[ iter ].internal_value != NULL && local_index < 0; iter++)
		{
			const char	*entry_str = encryption_mode_table[ iter ].internal_value;
			unsigned int	 entry_len = strlen( encryption_mode_table[ iter ].internal_value );

			if (strncmp( internal_group_value, entry_str, entry_len ) == 0)
			{
				local_index = iter;
			}
		}

		if (local_index < 0 || local_index == TKIP_AND_AES_ENTRY_INDEX)
		  retval = -ENXIO;
		else
		  strcpy( group_encryption, encryption_mode_table[ local_index ].internal_value );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_set_group_encryption( const char *ifname, const qcsapi_SSID current_SSID, const string_32 group_encryption )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	int			update_flag = QCSAPI_TRUE;

	enter_qcsapi();

	if (group_encryption == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, current_SSID, &skfd, &wifi_mode );

	if (retval == 0)
	{
		if (strnlen( group_encryption, QCSAPI_WPA_SECURITY_MODE_MAX_SIZE + 1 ) > QCSAPI_WPA_SECURITY_MODE_MAX_SIZE)
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		if (strcmp( group_encryption, "default" ) == 0)
		  update_flag = QCSAPI_FALSE;
		else
		{
			int	iter, local_index = -1;

			for (iter = 0; encryption_mode_table[ iter ].internal_value != NULL && local_index < 0; iter++)
			{
				if (strcmp( group_encryption, encryption_mode_table[ iter ].internal_value ) == 0)
				{
					local_index = iter;
				}
			}

			if (local_index < 0 || local_index == TKIP_AND_AES_ENTRY_INDEX)
			  retval = -EINVAL;
		}
	}

	if (retval >= 0)
	{
		retval = update_security_parameter(
				 ifname,
				 current_SSID,
				"group",
				 group_encryption,
				 wifi_mode,
				 update_flag,
				 qcsapi_bare_string,
	 			 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_get_authentication_mode( const char *ifname, const qcsapi_SSID SSID_str, string_32 authentication_mode )
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (authentication_mode == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, SSID_str, &skfd, &wifi_mode );

	if (retval >= 0)
	{
		char		 key_mgmt[ 32 ];

		retval = lookup_SSID_parameter( SSID_str, wifi_mode, "key_mgmt", key_mgmt, sizeof( key_mgmt ) );
		if (retval >= 0)
		{
			unsigned int	iter;
			int		found_entry = 0;

			for (iter = 0; authentication_mode_table[ iter ].internal_value != NULL && found_entry == 0; iter++)
			{
				const parameter_translation_entry	*p_pte = &authentication_mode_table[ iter ];
				unsigned int				 internal_length = strlen( p_pte->internal_value );

				if (strncmp( p_pte->internal_value, &key_mgmt[ 0 ], internal_length ) == 0)
			  	{
					found_entry = 1;
					strcpy( authentication_mode, authentication_mode_table[ iter ].qcsapi_value );
			  	}
			}

			if (found_entry == 0)
			  retval = -ENXIO;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_set_authentication_mode( const char *ifname, const qcsapi_SSID SSID_str, const string_32 authentication_mode )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;
	const char		*new_internal_value = NULL;

	enter_qcsapi();

	if (authentication_mode == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, SSID_str, &skfd, &wifi_mode );

	if (retval >= 0)
	{
		if (strnlen( authentication_mode, QCSAPI_WPA_SECURITY_MODE_MAX_SIZE + 1 ) > QCSAPI_WPA_SECURITY_MODE_MAX_SIZE)
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		unsigned int	iter;

		for (iter = 0; authentication_mode_table[ iter ].internal_value != NULL && new_internal_value == NULL; iter++)
		{
			if (strcmp( authentication_mode, authentication_mode_table[ iter ].qcsapi_value ) == 0)
			  new_internal_value = authentication_mode_table[ iter ].internal_value;
		}

		if (new_internal_value == NULL)
		  retval = -EINVAL;
	}

	if (retval >= 0)
	{
		retval = update_security_parameter(
				 ifname,
				 SSID_str,
				"key_mgmt",
				 new_internal_value,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_get_pre_shared_key(
			const char *ifname,
			const qcsapi_SSID SSID_str,
			const qcsapi_unsigned_int key_index,
			string_64 pre_shared_key
)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (pre_shared_key == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, SSID_str, &skfd, &wifi_mode );

	if (retval >= 0) {
		int 		security_is_NONE = 0;
		retval = local_security_is_none_SSID(SSID_str, wifi_mode, &security_is_NONE);
		if (retval >= 0) {
			if (security_is_NONE) {
				retval = -qcsapi_configuration_error;
			}
		}
	}

	if (retval >= 0)
	{
	  /*
 	   * sizeof operator needs the type name, not its instantiation.
 	   * For string_64 is an array of chars, and C-syntax is such that an instantiation
 	   * of string_64 is actually an address - with sizeof equal to 4 (8 if addresses have 64 bits).
 	   */
		retval = lookup_SSID_parameter( SSID_str, wifi_mode, "psk", pre_shared_key, sizeof( string_64 ) );
	  /*
 	   * If the value is not a Pre Shared Key, return the 0-length string
 	   */
		if (retval >= 0 && verify_PSK( pre_shared_key ) == 0)
		  *pre_shared_key = '\0';
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_set_pre_shared_key(
			const char *ifname,
			const qcsapi_SSID SSID_str,
			const qcsapi_unsigned_int key_index,
			const string_64 pre_shared_key
)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (pre_shared_key == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, SSID_str, &skfd, &wifi_mode );

	if (retval >= 0)
	{
		if (verify_PSK( pre_shared_key ) == 0)
			retval = -EINVAL;
	}

	if (retval >= 0)
	{
		retval = update_security_parameter(
				 ifname,
				 SSID_str,
				"psk",
				 pre_shared_key,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_get_key_passphrase(
			const char *ifname,
			const qcsapi_SSID SSID_str,
			const qcsapi_unsigned_int key_index,
			string_64 passphrase
)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (passphrase == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, SSID_str, &skfd, &wifi_mode );

	if (retval >= 0) {
		int 		security_is_NONE = 0;
		retval = local_security_is_none_SSID(SSID_str, wifi_mode, &security_is_NONE);
		if (retval >= 0) {
			if (security_is_NONE) {
				retval = -qcsapi_configuration_error;
			}
		}
	}

	if (retval >= 0) {
	  /*
	   * sizeof operator needs the type name, not its instantiation.
	   * For string_64 is an array of chars, and C-syntax is such that an instantiation
	   * of string_64 is actually an address - with sizeof equal to 4 (8 if addresses have 64 bits).
	   */
		retval = lookup_SSID_parameter( SSID_str, wifi_mode, "psk", passphrase, sizeof( string_64 ) );
	  /*
	   * If the value is a Pre Shared Key, return the 0-length string
	   */
		if (retval >= 0 && verify_PSK( passphrase ) != 0)
		  *passphrase = '\0';
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

#define NON_WPS_CONF_FILE	"/mnt/jffs2/wpa_supplicant.conf.pp"
#define NON_WPS_TMP_CONF_FILE	"/tmp/wpa_supplicant.conf.pp"

static int local_clear_wps_ssid(const qcsapi_SSID SSID_str)
{
	int			retval = 0;
	FILE		*stream;
	FILE		*stream_tmp;
	int			dlen;
	char		buf[48];
	int			ssid_find = 0;
	char		*pos;


	stream = fopen(NON_WPS_CONF_FILE, "r");
	if (!stream) {
		return retval;
	}

	stream_tmp = fopen(NON_WPS_TMP_CONF_FILE, "w");
	if (!stream_tmp) {
		fclose(stream);
		printf("can't open /tmp/wpa_supplicant.conf.pp \n");
		return -1;
	}


	while(fgets(buf, sizeof(buf), stream)) {
		buf[sizeof(buf) - 1] = '\0';
		pos = buf;
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}
		if (strncmp(buf, SSID_str, IW_ESSID_MAX_SIZE)) {
			fprintf(stream_tmp, "%s\n", buf);
		} else {
			ssid_find = 1;
		}
	}

	fclose(stream);
	fclose(stream_tmp);

	if (ssid_find) {
		stream = fopen(NON_WPS_CONF_FILE, "w");
		if (!stream) {
			return -1;
		}

		stream_tmp = fopen(NON_WPS_TMP_CONF_FILE, "r");
		if (!stream_tmp) {
			fclose(stream);
			printf("can't open /tmp/wpa_supplicant.conf.pp  \n");
			return -1;
		}

		while ((dlen = fread(buf, 1, sizeof(buf), stream_tmp)) > 0) {
			printf("the len is %d \n", dlen);
			fwrite(buf, 1, dlen, stream);
		}

		fclose(stream);
		fclose(stream_tmp);
	}

	return retval;
}

int
qcsapi_SSID_set_key_passphrase(
			const char *ifname,
			const qcsapi_SSID SSID_str,
			const qcsapi_unsigned_int key_index,
			const string_64 passphrase
)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	size_t	passphrase_len = 0;

	enter_qcsapi();

	if (passphrase == NULL)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, SSID_str, &skfd, &wifi_mode );

	if (retval >= 0) passphrase_len = strnlen(passphrase, QCSAPI_WPA_PASSPHRASE_MAX_SIZE + 1);

	if (retval >= 0) {

		if (passphrase_len > QCSAPI_WPA_PASSPHRASE_MAX_SIZE || passphrase_len < QCSAPI_WPA_PASSPHRASE_MIN_SIZE)
		  retval = -EINVAL;
	}

	if (retval >= 0) {

		local_clear_wps_ssid(SSID_str);

		retval = update_security_parameter(
				 ifname,
				 SSID_str,
				"psk",
				 passphrase,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_in_quotes,
				 security_update_complete
		);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_get_pmf( const char *ifname, const qcsapi_SSID current_SSID, int *p_pmf_cap )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;
	char pmf_cap_string[3] = {0};

	enter_qcsapi();

	if (retval >= 0)
	{
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}

	if (p_pmf_cap == NULL)
		retval = -EFAULT;
	else
		retval = local_SSID_preamble( ifname, current_SSID, &skfd, &wifi_mode );

	if (retval >= 0) {
		int security_is_NONE = 0;
		retval = local_security_is_none_SSID(current_SSID, wifi_mode, &security_is_NONE);
		if (retval >= 0) {
			if (security_is_NONE) {
				retval = -qcsapi_configuration_error;
			}
		}
	}

	if (retval >= 0)
	{
		retval = lookup_SSID_parameter(
			 current_SSID,
			 wifi_mode,
			"ieee80211w",
			 &pmf_cap_string[0],
			 sizeof( pmf_cap_string )
		);

		if (retval >= 0)
		{
			(*p_pmf_cap) = atoi(pmf_cap_string);
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_SSID_set_pmf( const char *ifname, const qcsapi_SSID SSID_str, int pmf_cap )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;
	char pmf_cap_string[2];

	if (retval >= 0)
	{
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}

	if (pmf_cap < 0 || pmf_cap > 2)
	  retval = -EFAULT;
	else
	  retval = local_SSID_preamble( ifname, SSID_str, &skfd, &wifi_mode );


	if (retval >= 0)
	{
		snprintf(pmf_cap_string, sizeof(pmf_cap_string), "%d", pmf_cap);
		retval = update_security_parameter(
				 ifname,
				 SSID_str,
				"ieee80211w",
				 pmf_cap_string,
				 wifi_mode,
				 QCSAPI_TRUE,
				 qcsapi_bare_string,
				 security_update_complete
		);

	}

	if(retval >= 0)
	{
		retval = local_wifi_option_set_pmf( skfd, ifname, pmf_cap );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

static int
local_get_wps_SSID( FILE *config_fh, qcsapi_SSID wps_SSID )
{
	int			retval = 0;
	char			config_line[ 122 ];
	SSID_parsing_state	e_parse_state = e_searching_for_network;
	int			complete = 0;
	qcsapi_SSID		current_ssid = "";
	qcsapi_SSID		local_wps_ssid = "";

	if (config_fh == NULL || wps_SSID == NULL) {
		  return( -qcsapi_programming_error );
	}

	while ((fgets( &config_line[ 0 ], sizeof( config_line ), config_fh ) != NULL) && complete == 0) {
		char	parameter_name[ 122 ], parameter_value[ QCSAPI_SSID_MAXLEN ];

		process_SSID_config_line( "", &e_parse_state, "ssid", &config_line[ 0 ] );

		if (e_parse_state == e_found_network_token) {
			int	ival = parse_config_line(&config_line[ 0 ],
						 &parameter_name[ 0 ],
						  sizeof( parameter_name ),
						 &parameter_value[ 0 ],
						  sizeof( parameter_value ));

			if (ival < 0) {
				complete = 1;
				retval = ival;
			} else if (ival > 0) {
				if (strcmp( &parameter_name[ 0 ], "ssid" ) == 0) {
					strncpy( current_ssid, &parameter_value[ 0 ], QCSAPI_SSID_MAXLEN );
					current_ssid[ QCSAPI_SSID_MAXLEN - 1 ] = '\0';
				} else if (strcmp( &parameter_name[ 0 ], "flags" ) == 0) {
					int	flags_value = atoi( &parameter_value[ 0 ] );

					if ((flags_value & 0x01) != 0) {
						strcpy( local_wps_ssid, current_ssid );
					}
				}
			}
		}
	}

	if (retval >= 0) {
		if (strlen( local_wps_ssid ) > 0) {
			strcpy( wps_SSID, local_wps_ssid );
		}
		else {
			retval = -qcsapi_configuration_error;
		}
	}

	return( retval );
}

int
qcsapi_SSID_get_wps_SSID( const char *ifname, qcsapi_SSID wps_SSID )
{
	int			 retval = 0;
	int			 skfd = -1;
	qcsapi_wifi_mode	 wifi_mode = qcsapi_nosuch_mode;
	FILE			*config_fh = NULL;

	enter_qcsapi();

	if (ifname == NULL || wps_SSID == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_station) {
				retval = -qcsapi_only_on_STA;
			}
		}
	}

	if (retval >= 0) {
		char	config_file_path[ 122 ];

		retval = locate_configuration_file( wifi_mode, &config_file_path[ 0 ], sizeof( config_file_path ) );
		if (retval >= 0) {
			config_fh = fopen( &config_file_path[ 0 ], "r" );
		}
	}

	if (retval >= 0) {
		retval = local_get_wps_SSID( config_fh, wps_SSID );
	}

	if (config_fh != NULL) {
		fclose( config_fh );
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

/*
 * Program fix_macaddr_params only gets called on an AP.  See qcsapi_security_init().
 * Thus fix_macaddr_params will NOT get called if calstate == 1, since in that
 * situation, local_wifi_get_mode (called in qcsapi_security_init()) will fail.
 */

static void
fix_macaddr_params( const char *ifname )
{
  /*
   *  Enforce the following:
   *
   *   Parameter macaddr_acl is either 0 or 1; if some other value, it will be forced to 0.
   *
   *   Parameter accept_mac_file required to be <path to the security configuration file>/hostapd.accept
   *   Parameter accept_oui_file required to be <path to the security configuration file>/hostapd.accept.oui
   *   Parameter deny_mac_file required to be <path to the security configuration file>/hostapd.deny
   *
   *   If any of these three parameters are not defined, no action would be taken for that parameter.
   */
	int	ival, macaddr_acl = -1;
	char	param_buffer[ 80 ];
	int	call_reload_security_configuration = 0;
	char	path_mac_addr_file[ 80 ];

	ival = lookup_ap_security_parameter(
		 ifname,
		 qcsapi_access_point,
		"macaddr_acl",
		&param_buffer[ 0 ],
		 sizeof( param_buffer )
	);

	if (ival >= 0)
	{
		sscanf( &param_buffer[ 0 ], "%d", &macaddr_acl );

		if (macaddr_acl != 0 && macaddr_acl != 1)
		{
			update_security_parameter(
				 ifname,
				 NULL,
				"macaddr_acl",
				"0",
				 qcsapi_access_point,
			 	 QCSAPI_TRUE,
			 	 qcsapi_bare_string,
				 security_update_pending
			);

			call_reload_security_configuration = 1;
		}
	}

	ival = lookup_ap_security_parameter(
		 ifname,
		 qcsapi_access_point,
		"accept_mac_file",
		&param_buffer[ 0 ],
		 sizeof( param_buffer )
	);

	if (ival >= 0)
	{
		local_security_build_mac_filter_file(
			 HOSTAPD_ACCEPT,
			&path_mac_addr_file[ 0 ],
			 sizeof( path_mac_addr_file ),
			 ifname
		);

		if (strcmp( &path_mac_addr_file[ 0 ], &param_buffer[ 0 ] ) != 0)
		{
			update_security_parameter(
				 ifname,
				 NULL,
				"accept_mac_file",
				&path_mac_addr_file[ 0 ],
				 qcsapi_access_point,
			 	 QCSAPI_TRUE,
			 	 qcsapi_bare_string,
				 security_update_pending
			);

			call_reload_security_configuration = 1;
		}
	}

	ival = lookup_ap_security_parameter(
			ifname,
			qcsapi_access_point,
			"accept_oui_file",
			&param_buffer[0],
			sizeof(param_buffer)
			);

	if (ival >= 0)
	{
		local_security_build_mac_filter_file(
				HOSTAPD_ACCEPT_OUI,
				&path_mac_addr_file[0],
				sizeof(path_mac_addr_file),
				ifname
				);

		if (strcmp(&path_mac_addr_file[0], &param_buffer[0]) != 0)
		{
			update_security_parameter(
					ifname,
					NULL,
					"accept_oui_file",
					&path_mac_addr_file[0],
					qcsapi_access_point,
					QCSAPI_TRUE,
					qcsapi_bare_string,
					security_update_pending
					);

			call_reload_security_configuration = 1;
		}
	}

	ival = lookup_ap_security_parameter(
		 ifname,
		 qcsapi_access_point,
		"deny_mac_file",
		&param_buffer[ 0 ],
		 sizeof( param_buffer )
	);

	if (ival >= 0)
	{
		local_security_build_mac_filter_file(
			 HOSTAPD_DENY,
			&path_mac_addr_file[ 0 ],
			 sizeof( path_mac_addr_file ),
			 ifname
		);

		if (strcmp( &path_mac_addr_file[ 0 ], &param_buffer[ 0 ] ) != 0)
		{
			update_security_parameter(
				 ifname,
				 NULL,
				"deny_mac_file",
				&path_mac_addr_file[ 0 ],
				 qcsapi_access_point,
			 	 QCSAPI_TRUE,
			 	 qcsapi_bare_string,
				 security_update_pending
			);

			call_reload_security_configuration = 1;
		}
	}

	if (call_reload_security_configuration)
		update_security_bss_configuration( ifname );
}

static void
fix_macaddr_params_all_bss(void)
{
	int retval;
	unsigned int if_index;
	char if_name[IFNAMSIZ];

	for (if_index = 0; if_index < MAX_BSSID; if_index++) {
		/* The STA mode has been checked by caller, so, call lookup_xxx directly */
		retval = lookup_ap_ifname_by_index(if_index, if_name, IFNAMSIZ);
		if (retval < 0)
			break;

		fix_macaddr_params(if_name);
	}
}

extern char *g_wds_ifname[MAX_WDS_LINKS];

#define	QTN_WDS_CMD_SIZE		(10)
#define	QTN_WDS_KEY_STR_LEN		(QCSAPI_WPA_PSK_MAX_SIZE / 2)

static int wds_delete_psk(
	int skfd,
	const char *wds_ifname,
	const qcsapi_mac_addr peer_address
)
{
	int retval = 0;
	struct ieee80211req_del_key dk;
	unsigned char *p_dk = (unsigned char *)(&dk);
	char subcmd_privacy[QTN_WDS_CMD_SIZE];
	char subcmd_drop[QTN_WDS_CMD_SIZE];
	char *argv1[] = {subcmd_privacy, "0"};
	char *argv2[sizeof(dk) + 1];
	char *argv3[] = {subcmd_drop, "0"};
	int cmd_size;
	char (*argument)[QTN_WDS_CMD_SIZE];
	int i = 0;

	cmd_size = ARRAY_SIZE(argv2) * sizeof(argument[0]);
	argument = malloc(cmd_size);
	if (!argument)
	      return -ENOMEM;

	memset(&dk, 0x00, sizeof(dk));
	memset(argument, 0x00, cmd_size);
	dk.idk_keyix = 0;
	memcpy(dk.idk_macaddr, peer_address, IEEE80211_ADDR_LEN);
	for (i = 0; i < sizeof(dk); i++) {
		sprintf(argument[i], "%d", p_dk[i]);
		argv2[i] = argument[i];
	}

	sprintf(subcmd_privacy, "%d", IEEE80211_PARAM_PRIVACY);

	/* disable privacy */
	retval = call_private_ioctl(skfd, argv1, ARRAY_SIZE(argv1), wds_ifname,
				"setparam", NULL, 0);
	if (retval >= 0) {
		snprintf(subcmd_drop, sizeof(subcmd_drop) - 1, "%d",
					IEEE80211_PARAM_DROPUNENCRYPTED);
		retval = call_private_ioctl(skfd, argv3, ARRAY_SIZE(argv3), wds_ifname,
					"setparam", NULL, 0);
		if (retval >= 0) {
			retval = call_private_ioctl(skfd, argv2, ARRAY_SIZE(argv2),
					wds_ifname, "delkey", NULL, 0);
		}
	}
	free(argument);

	return retval;
}

static int wds_set_psk(
	int skfd,
	const char *wds_ifname,
	const qcsapi_mac_addr peer_address,
	const string_64 pre_shared_key
)
{
	int retval = 0;
	struct ieee80211req_key wk;
	unsigned char *p_wk = (unsigned char*)(&wk);
	unsigned char psk[QTN_WDS_KEY_STR_LEN];
	char subcmd_privacy[QTN_WDS_CMD_SIZE];
	char subcmd_drop[QTN_WDS_CMD_SIZE];
	char *argv1[] = {subcmd_privacy, "1"};
	char *argv2[sizeof(wk) + 1];
	char *argv3[] = {subcmd_drop, "1"};
	int cmd_size;
	char (*argument)[QTN_WDS_CMD_SIZE];
	int i = 0;

	if (verify_PSK(pre_shared_key) == 0)
		return -EINVAL;

	/* Default setting for WDS encryption */
	cmd_size = ARRAY_SIZE(argv2) * sizeof(argument[0]);
	argument = malloc(cmd_size);
	if (!argument)
	      return -ENOMEM;

	memset(&wk, 0x00, sizeof(wk));
	memset(argument, 0x00, cmd_size);
	wk.ik_type = IEEE80211_CIPHER_AES_CCM;
	wk.ik_flags = IEEE80211_KEY_RECV | IEEE80211_KEY_XMIT;
	wk.ik_keyix = 0;
	wk.ik_keylen = sizeof(psk);
	memcpy(wk.ik_macaddr, peer_address, IEEE80211_ADDR_LEN);
	hexstr2bin(pre_shared_key, psk, sizeof(psk));
	memcpy(wk.ik_keydata, psk, sizeof(psk));
	for (i = 0; i < sizeof(wk); i++) {
		sprintf(argument[i], "%d", p_wk[i]);
		argv2[i] = argument[i];
	}

	retval = call_private_ioctl(skfd, argv2, ARRAY_SIZE(argv2), wds_ifname,
				"setkey", NULL, 0);
	if (retval >= 0) {
		/* enable privacy */
		sprintf(subcmd_privacy, "%d", IEEE80211_PARAM_PRIVACY);
		retval = call_private_ioctl(skfd, argv1, ARRAY_SIZE(argv1),
				wds_ifname, "setparam", NULL, 0);
		if (retval >= 0) {
			snprintf(subcmd_drop, sizeof(subcmd_drop) - 1,
				"%d", IEEE80211_PARAM_DROPUNENCRYPTED);
			retval = call_private_ioctl(skfd, argv3,
				ARRAY_SIZE(argv3), wds_ifname, "setparam", NULL, 0);
		}
	}
	free(argument);

	return retval;
}

int
local_wifi_wds_set_psk(
	int skfd,
	const char *wds_ifname,
	const qcsapi_mac_addr peer_address,
	const string_64 pre_shared_key
)
{
	int retval = 0;

	if (pre_shared_key == NULL) {
		retval = wds_delete_psk(skfd, wds_ifname, peer_address);
	} else {
		retval = wds_set_psk(skfd, wds_ifname, peer_address, pre_shared_key);
	}

	return retval;
}


int qcsapi_wds_set_psk(
	const char *ifname,
	const qcsapi_mac_addr peer_address,
	const string_64 pre_shared_key
)
{
	int retval = 0;
	int i = 0;
	int skfd = -1;
	const char *wds_ifname;
	char primary_ifname[IFNAMSIZ] = {0};
	qcsapi_mac_addr temp_peer_address;
	int ival = 0;
	qcsapi_interface_status_code status_code = qcsapi_interface_status_error;

	enter_qcsapi();

	if (ifname == NULL || peer_address == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
	}

	if ((retval = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1)) < 0) {
		retval = -qcsapi_only_on_AP;
		goto ready_to_return;
	}

	/* Check primary interface name */
	if (strcmp(ifname, primary_ifname) != 0) {
		retval = -qcsapi_only_on_primary_interface;
		goto ready_to_return;
	}

	if ((retval = local_open_iw_socket_with_error(&skfd)) < 0) {
		goto ready_to_return;
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
			retval = local_interface_get_status(skfd, wds_ifname, &status_code);

			if (retval >= 0 && status_code == qcsapi_interface_status_running) {
				retval = local_wifi_get_BSSID(skfd, wds_ifname, temp_peer_address);
				if (retval >= 0) {
					if (local_generic_verify_mac_addr_valid(temp_peer_address) >= 0 &&
							memcmp(peer_address, temp_peer_address, sizeof(qcsapi_mac_addr)) == 0) {
						retval = local_wifi_wds_set_psk(skfd, wds_ifname, peer_address, pre_shared_key);
						break;
					}
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

#define PP_STATE_MAX_LEN 5
int qcsapi_wps_set_access_control(const char *ifname, uint32_t ctrl_state)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			config_value[2];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
		goto ready_to_return;
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			}
		}
	} else {
		goto ready_to_return;
	}

	if (retval >= 0) {
		sprintf(config_value, "%d", ctrl_state);
		retval = update_security_parameter(ifname,
				NULL,
				"wps_pp_enable",
				config_value,
				qcsapi_access_point,
				QCSAPI_TRUE,
				qcsapi_bare_string,
				security_update_complete);
	}

ready_to_return:
	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int qcsapi_wps_get_access_control(const char *ifname, uint32_t *ctrl_state)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char pp_state[PP_STATE_MAX_LEN];

	enter_qcsapi();

	if (ifname == NULL) {
		retval = -EFAULT;
	}
	else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
		if (retval >= 0) {
			if (wifi_mode != qcsapi_access_point) {
				retval = -qcsapi_only_on_AP;
			}
		}
	}

	if (retval >= 0) {
		retval = lookup_ap_security_parameter( ifname,
				qcsapi_access_point,
				"wps_pp_enable",
				&pp_state[0],
				sizeof(pp_state));
		if (retval >= 0) {
			if (!strcmp(pp_state, "1") || !strcmp(pp_state, "0")) {
				*ctrl_state = atoi(pp_state);
			} else {
				retval = -qcsapi_parameter_not_found;
			}
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int qcsapi_non_wps_set_pp_enable(const char *ifname, uint32_t ctrl_state)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			security_daemon_message[ 32 ];
	char			reply[ PP_STATE_MAX_LEN ];
	char			primary_interface[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}

	if (retval >= 0) {
		if (wifi_mode == qcsapi_access_point) {
			retval = local_get_primary_ap_interface(&primary_interface[0],
						sizeof(primary_interface) - 1);
			if (retval >= 0) {
				sprintf(security_daemon_message,
							"NON_WPS_PP_ENABLE %s %d",
							ifname,
							(ctrl_state ? 1:0));
				retval = send_message_security_daemon(primary_interface,
							wifi_mode,
							&security_daemon_message[0],
							reply,
							PP_STATE_MAX_LEN);
				if (retval >= 0) {
					if (!strcmp(reply, "FAIL")) {
						retval = -qcsapi_parameter_not_found;
					}
				}
			}
		} else if (wifi_mode == qcsapi_station) {
			sprintf(security_daemon_message, "SET non_wps_pp_enable %d", (ctrl_state ? 1:0));
			retval = send_message_security_daemon(ifname,
							      wifi_mode,
							      &security_daemon_message[0],
							      reply,
							      PP_STATE_MAX_LEN);

			if (retval >= 0) {
				if (!strcmp(reply, "FAIL")) {
					retval = -qcsapi_parameter_not_found;
				}
			}
		} else {
			retval = -qcsapi_invalid_wifi_mode;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int qcsapi_non_wps_get_pp_enable(const char *ifname, uint32_t *ctrl_state)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;
	char			pp_state[PP_STATE_MAX_LEN];
	char			security_daemon_message[ 32 ];
	char			primary_interface[IFNAMSIZ] = {0};

	enter_qcsapi();

	if (ifname == NULL) {
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
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}

	if (retval >= 0) {
		if (wifi_mode == qcsapi_access_point) {
			retval = local_get_primary_ap_interface(&primary_interface[0],
						sizeof(primary_interface) - 1);
			if (retval >= 0) {
				sprintf(security_daemon_message,
							"NON_WPS_PP_STATUS %s",
							ifname);
				retval = send_message_security_daemon(primary_interface,
							wifi_mode,
							security_daemon_message,
							&pp_state[0],
							PP_STATE_MAX_LEN);
				if (retval >= 0) {
					if (!strcmp(pp_state, "1") || !strcmp(pp_state, "0")) {
						*ctrl_state = atoi(pp_state);
					} else {
						retval = -qcsapi_parameter_not_found;
					}
				}
			}
		} else if (wifi_mode == qcsapi_station) {
			sprintf(security_daemon_message, "GET non_wps_pp_enable");
			retval = send_message_security_daemon(ifname,
							      wifi_mode,
							      security_daemon_message,
							      &pp_state[0],
							      PP_STATE_MAX_LEN);
			if (retval >= 0) {
				if (!strcmp(pp_state, "1") || !strcmp(pp_state, "0")) {
					*ctrl_state = atoi(pp_state);
				} else {
					retval = -qcsapi_parameter_not_found;
				}
			}
		} else {
			retval = -qcsapi_invalid_wifi_mode;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

static int local_wifi_set_get_pairing_id(char *pairing_id, int get_set)
{
	int ret = -EFAULT;
	char shell_command[128];
	FILE *fstream;
	char buf[33];
	char *p_buf;

	memset(shell_command, 0, sizeof(shell_command));
	memset(buf, 0, sizeof(buf));

	if ((!!get_set) == SET_PAIRING_ID) {
		snprintf(shell_command, sizeof(shell_command), "/scripts/pairing_id_script set %s", pairing_id);
	} else {
		snprintf(shell_command, sizeof(shell_command), "/scripts/pairing_id_script get");
	}

	fstream = popen(shell_command, "r");

	if(fstream != NULL) {

		if ((!!get_set) == GET_PAIRING_ID) {
			fread(buf, sizeof(char), sizeof(buf) - 1, fstream);
			p_buf = strstr(buf, "\n");
			*p_buf = 0;
			strncpy(pairing_id, buf, sizeof(buf) - 1);
		}

		pclose(fstream);
		ret = 0;
	}

	return ret;
}

int qcsapi_wifi_set_pairing_id(const char *ifname, const char *pairing_id)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	string_32 pairing_id_str = {'\0'};

	enter_qcsapi();

	if (ifname == NULL || pairing_id == NULL) {
		retval = -EFAULT;
	} else if (strnlen(pairing_id, sizeof(string_32)) >= sizeof(string_32)) {
		retval = -EINVAL;
	} else {
		strncpy(pairing_id_str, pairing_id, strlen(pairing_id));
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}
	if (retval >= 0)
		retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);

	if (retval >= 0) {
		if (wifi_mode == qcsapi_access_point) {
			retval = update_security_parameter(
					ifname,
					NULL,
					"pairing_id",
					pairing_id_str,
					wifi_mode,
					QCSAPI_TRUE,
					qcsapi_bare_string,
					security_update_complete);
		} else if(wifi_mode == qcsapi_station) {
			retval = local_wifi_set_get_pairing_id(pairing_id_str, SET_PAIRING_ID);

			if (retval >= 0) {
				retval = reload_security_configuration(ifname, wifi_mode);
			}
		}
	}

	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	leave_qcsapi();

	return retval;

}

int qcsapi_wifi_get_pairing_id(const char *ifname, char *pairing_id)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || pairing_id == NULL) {
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

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	if (retval >= 0) {
		if (wifi_mode == qcsapi_access_point) {
			retval = lookup_ap_security_parameter(ifname,
							      wifi_mode,
							     "pairing_id",
							      pairing_id,
							      sizeof(string_128));
		} else if (wifi_mode == qcsapi_station) {
			retval = local_wifi_set_get_pairing_id(pairing_id, GET_PAIRING_ID);
		}
	}

ready_to_return:

	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	leave_qcsapi();

	return retval;
}

int qcsapi_wifi_set_pairing_enable(const char *ifname, const char *enable)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || enable == NULL) {
		retval = -EFAULT;
	} else if (atoi(enable) < 0 || atoi(enable) > 2) {
		retval = -EINVAL;
	} else {
		skfd = local_open_iw_sockets();
		if (skfd < 0) {
			retval = -errno;
			if (retval >= 0) {
				retval = skfd;
			}
		}
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	if (retval >= 0) {
		if (wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
			goto ready_to_return;
		}
	} else {
		goto ready_to_return;
	}

	retval = update_security_parameter(
			 ifname,
			 NULL,
			"pairing_enable",
			 enable,
			 qcsapi_access_point,
			 QCSAPI_TRUE,
			 qcsapi_bare_string,
			 security_update_complete
	);

ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	leave_qcsapi();

	return retval;

}

int qcsapi_wifi_get_pairing_enable(const char *ifname, char *enable)
{
	int			retval = 0;
	int			skfd = -1;
	qcsapi_wifi_mode	wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	if (ifname == NULL || enable == NULL) {
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

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	if (retval >= 0) {
		if (wifi_mode != qcsapi_access_point) {
			retval = -qcsapi_only_on_AP;
			goto ready_to_return;
		}
	} else {
		goto ready_to_return;
	}

	retval = lookup_ap_security_parameter(ifname,
					      wifi_mode,
					     "pairing_enable",
					      enable,
					      sizeof(string_128));

ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	leave_qcsapi();

	return retval;
}

int
qcsapi_security_init( void )
{
	int			skfd = -1;
	int			ival = local_open_iw_socket_with_error( &skfd );
	char			primary_ifname[IFNAMSIZ] = {0};

	if (ival >= 0) {
		ival = local_get_primary_ap_interface(primary_ifname, sizeof(primary_ifname) - 1);
		if (ival >= 0) {
			fix_macaddr_params_all_bss();
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	return( 0 );
}

int qcsapi_wifi_set_accept_oui_filter(const char *ifname, const qcsapi_mac_addr oui, int flag) {
	int	retval = 0;

	enter_qcsapi();

	retval = local_security_update_filtered_mac_address(ifname, accept_oui, oui, flag);

	leave_qcsapi();
	return retval;
}

int qcsapi_wifi_get_accept_oui_filter(const char *ifname, char *oui_list, const unsigned int sizeof_list) {
	int retval = 0;
	qcsapi_mac_address_filtering current_mac_address_filtering = qcsapi_nosuch_mac_address_filtering;

	enter_qcsapi();

	if (ifname == NULL || oui_list == NULL)
		retval = -EFAULT;
	else if (sizeof_list < 20)
		retval = -qcsapi_buffer_overflow;
	else
		retval = local_security_get_mac_address_filtering(ifname, &current_mac_address_filtering);

	if (retval >= 0)
	{
		if (current_mac_address_filtering != qcsapi_deny_mac_address_unless_authorized)
			retval = -qcsapi_configuration_error;
	}

	if (retval >= 0)
	{
		char path_mac_addr_file[80];

		retval = local_security_build_mac_filter_file(
				HOSTAPD_ACCEPT_OUI,
				&path_mac_addr_file[0],
				sizeof(path_mac_addr_file),
				ifname
				);

		if (retval >= 0)
		{
		  /*
		   * local_sizeof_list avoids arguments with the compiler
		   * about the const nature of sizeof_list.
		   */
			unsigned int local_sizeof_list = sizeof_list;

			*oui_list = '\0';

			retval = read_mac_addr_file(
					&path_mac_addr_file[0],
					append_mac_addr_string,
					oui_list,
					(void *) local_sizeof_list
					);
		}
	}

	leave_qcsapi();
	return retval;
}

