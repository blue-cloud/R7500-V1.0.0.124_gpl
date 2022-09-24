/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2009 Quantenna Communications Inc            **
**                            All Rights Reserved                            **
**                                                                           **
**  File        : qcsapi_rftest.c                                            **
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

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "qcsapi.h"
#include "qcsapi_private.h"

#include "qcsapi_rftest.h"
#include "qcsapi_rfpriv.h"

#ifndef BRIDGE_DEVICE
#define BRIDGE_DEVICE	"br0"
#endif /* BRIDGE_DEVICE */

#ifndef WIFI_DEVICE
#define WIFI_DEVICE	"wifi0"
#endif /* WIFI_DEVICE */

static const struct
{
	const char			*param_name;
	qcsapi_enum_rftest_param	 param_enum;
} rftest_param_table[] =
{
	{ "channel",	e_qcsapi_rftest_chan },
	{ "rftest_chan", e_qcsapi_rftest_chan },
	{ "pktsize",	e_qcsapi_packet_size },
	{ "num_pkt",	e_qcsapi_packet_count },
	{ "legacy",	e_qcsapi_packet_type },
	{ "pkttype",	e_qcsapi_packet_type },
	{ "pkt_type",	e_qcsapi_packet_type },
	{ "pattern",	e_qcsapi_cw_pattern },
	{ "cw_pattern",	e_qcsapi_cw_pattern },
	{ "path_idx",	e_qcsapi_rfpath },
	{ "ssb",	e_qcsapi_SSB_setting },
	{ "tx_power_cal", e_qcsapi_tx_power_cal },
	{ "rftest_bw",	e_qcsapi_rftest_bandwidth },
	{ "bw",		e_qcsapi_rftest_bandwidth },
	{ "tx_power",	e_qcsapi_tx_power },
	{ "antenna",	e_qcsapi_antenna_mask },
	{ "harmonics",	e_qcsapi_harmonics },
	{ "chip_idx",	e_qcsapi_chip_index },
	{ "mcs",	e_qcsapi_rftest_mcs_rate },
	{  NULL,	e_qcsapi_nosuch_rftest_param }
};

static const struct
{
	char				*counter_name;
	qcsapi_rftest_counter_type	 counter_type;
	int				 report_index;
} rftest_counter_table[] =
{
	{ "RF1_TX",	qcsapi_rftest_tx_packets,	0 },
	{ "RF1_RX",	qcsapi_rftest_rx_packets,	0 },
	{ "RF2_TX",	qcsapi_rftest_tx_packets,	1 },
	{ "RF2_RX",	qcsapi_rftest_rx_packets,	1 },
	{  NULL,	qcsapi_nosuch_rftest_counter,	-1 }
};


/*
 * Provide default value for parameters
 * Based on Shilpa G.'s rftest.php
 */

int
qcsapi_rftest_init_params( qcsapi_rftest_params *p_rftest_params )
{
	int	retval = 0;

	if (p_rftest_params != NULL)
	{
		memset( p_rftest_params, 0, sizeof( qcsapi_rftest_params ) );

		p_rftest_params->rftest_magic = 0x1234;
		p_rftest_params->current_test = e_qcsapi_rftest_no_test;
		p_rftest_params->rftest_chan = 36;
		p_rftest_params->packet_size = 400;	/* actual packet size */
		p_rftest_params->packet_count = 0;	/* keep transmitting packets until told to stop */
		p_rftest_params->packet_type = qscapi_packet_802_11n;
		p_rftest_params->cw_pattern = qcscapi_cw_625KHz_0dB;
		p_rftest_params->rfpath = qcsapi_rfpath_chain0_main;
		p_rftest_params->SSB_setting = qcsapi_select_SSB;
		p_rftest_params->tx_power_cal = qcsapi_disable_tx_power_cal;
		p_rftest_params->rftest_bandwidth = qcsapi_bw_20MHz;
		p_rftest_params->antenna_mask = (SPECIAL_ANTENNA_MASK | 0x0f);
		p_rftest_params->harmonics = 1;
		p_rftest_params->chip_index = 0;

		strcpy( &(p_rftest_params->rftest_mcs_rate[ 0 ]), "MCS14" );
	}
	else
	{
		retval = -EFAULT;
	}

	return( retval );
}

/*
 * Written so "channel=100" returns e_qcsapi_rftest_chan
 * But character following "channel" must be '=' or the NUL character.
 * Nothing else.
 */

static qcsapi_enum_rftest_param
name_to_rftest_param_enum( const char *rftest_param )
{
	qcsapi_enum_rftest_param	retval = e_qcsapi_nosuch_rftest_param;
	unsigned int			iter;

	for (iter = 0; retval == e_qcsapi_nosuch_rftest_param && rftest_param_table[ iter ].param_name != NULL; iter++)
	{
		unsigned int	entry_len = strlen( rftest_param_table[ iter ].param_name );

		if (strncasecmp( rftest_param, rftest_param_table[ iter ].param_name, entry_len ) == 0)
		{
			const char	*tmpaddr = rftest_param + entry_len;

			if (*tmpaddr == '\0' || *tmpaddr == '=')
			  retval = rftest_param_table[ iter ].param_enum;
		}
	}

	return( retval );
}

/*
 * Internal program to support qcsapi_rftest_update_params.  Do not confuse with the external API.
 */

static int
qcsapi_update_rftest_param( qcsapi_rftest_params *p_rftest_params, qcsapi_enum_rftest_param e_rftest_param, void *rftest_value )
{
	int	retval = 0;
	int	integer_val = (int) rftest_value;

	switch( e_rftest_param )
	{
	  case e_qcsapi_rftest_chan:
		retval = qcsapi_rftest_set_chan( p_rftest_params, (qcsapi_unsigned_int) rftest_value );
		break;

	  case e_qcsapi_packet_size:
		retval = qcsapi_rftest_set_packet_size( p_rftest_params, (qcsapi_unsigned_int) rftest_value );
		break;

	  case e_qcsapi_packet_count:
		retval = qcsapi_rftest_set_packet_count( p_rftest_params, (qcsapi_unsigned_int) rftest_value );
		break;

	  case e_qcsapi_packet_type:
		retval = qcsapi_rftest_set_packet_type( p_rftest_params, (qcsapi_packet_type) rftest_value );
		break;

	  case e_qcsapi_cw_pattern:
		retval = qcsapi_rftest_set_cw_pattern( p_rftest_params, (qcsapi_cw_pattern) rftest_value );
		break;

	  case e_qcsapi_rfpath:
		retval = qcsapi_rftest_set_rfpath( p_rftest_params, (qcsapi_rfpath) rftest_value );
		break;

	  case e_qcsapi_SSB_setting:
		retval = qcsapi_rftest_set_SSB_setting( p_rftest_params, (qcsapi_SSB_setting) rftest_value );
		break;

	  case e_qcsapi_tx_power_cal:
		retval = qcsapi_rftest_set_tx_power_cal( p_rftest_params, (qcsapi_tx_power_cal) rftest_value );
		break;

	  case e_qcsapi_rftest_bandwidth:
		retval = qcsapi_rftest_set_bandwidth( p_rftest_params, (qcsapi_SSB_setting) rftest_value );
		break;

	  case e_qcsapi_tx_power:
		retval = qcsapi_rftest_set_tx_power( p_rftest_params, (qcsapi_s8) integer_val );
		break;

	  case e_qcsapi_antenna_mask:
		retval = qcsapi_rftest_set_antenna_mask( p_rftest_params, (qcsapi_u8) integer_val );
		break;

	  case e_qcsapi_harmonics:
		retval = qcsapi_rftest_set_harmonics( p_rftest_params, (qcsapi_u8) integer_val );
		break;

	  case e_qcsapi_chip_index:
		retval = qcsapi_rftest_set_chip_index( p_rftest_params, (qcsapi_u8) integer_val );
		break;

	  case e_qcsapi_rftest_mcs_rate:
		retval = qcsapi_rftest_set_integer_mcs_rate( p_rftest_params, (unsigned int) integer_val );
		break;
/*
 * No access to RF test type.  This is deliberate.
 * Calling a start / stop RF test API is the only way to change the test type.
 */  
	  case e_qcsapi_nosuch_rftest_param:
	  default:
		retval = -1;
		break;
	}

	return( retval );
}

int _stdcall
qcsapi_rftest_update_one_param( qcsapi_rftest_params *p_rftest_params, char *param_name_val )
{
	int				 retval = 0;
	qcsapi_enum_rftest_param	 e_current_param = name_to_rftest_param_enum( param_name_val );
	const char			*value_addr = NULL;

	if (e_current_param == e_qcsapi_nosuch_rftest_param)
	{
		retval = -1;
	}
	else
	{
		value_addr = strchr( param_name_val, '=' );
		if (value_addr == NULL)
		  retval = -1;
	  /*
 	   * I.e., it is an error if no equal sign is present in the parameter name=value string.
 	   */
	}

	if (retval == 0)
	{
		int	local_value;

		value_addr++;

		if (e_current_param == e_qcsapi_rftest_mcs_rate && strncasecmp( value_addr, "MCS", 3 ) == 0)
		  value_addr += 3;

		local_value = atoi( value_addr );
		qcsapi_update_rftest_param( p_rftest_params, e_current_param, (void *) local_value );
	}

	return( retval );
}

int
qcsapi_rftest_update_params( qcsapi_rftest_params *p_rftest_params, int argc, char *argv[] )
{
	int				retval = 0;
	int				finished = 0;
	unsigned int			iter = 0;

	while (iter < argc && finished == 0)
	{
		finished = qcsapi_rftest_update_one_param( p_rftest_params, argv[ iter ] );
		if (finished >= 0)
		{
			iter++;
		}
	}

	retval = iter;

	return( retval );
}

int
qcsapi_rftest_dump_params( const qcsapi_rftest_params *p_rftest_params, FILE *fh, const qcsapi_dump_format current_format )
{
	int	retval = 0;

	if (p_rftest_params != NULL)
	{
		if (fh == NULL)
		  fh = stdout;

		if (current_format == qcsapi_dump_HTTP_POST)
		{
			unsigned int	local_mcs;
			int		ival = sscanf( &(p_rftest_params->rftest_mcs_rate[ 0 ]), "MCS%u", &local_mcs );
			
			if (ival != 1)
			  local_mcs = 14;

			fprintf( fh, "channel=%u&", p_rftest_params->rftest_chan );
			fprintf( fh, "bw=%d&", p_rftest_params->rftest_bandwidth );
			fprintf( fh, "pktsize=%u&", p_rftest_params->packet_size );
			fprintf( fh, "num_pkt=%u&", p_rftest_params->packet_count );
			fprintf( fh, "legacy=%u&", p_rftest_params->packet_type );
			fprintf( fh, "pattern=%d&", p_rftest_params->cw_pattern );
			fprintf( fh, "path_idx=%d&", p_rftest_params->rfpath );
			fprintf( fh, "ssb=%d&", p_rftest_params->SSB_setting );
			fprintf( fh, "tx_power=%d&", p_rftest_params->tx_power );
			fprintf( fh, "tx_power_cal=%d&", p_rftest_params->tx_power_cal );
			fprintf( fh, "antenna=%u&", p_rftest_params->antenna_mask );
			fprintf( fh, "harmonics=%u&", p_rftest_params->harmonics );
			fprintf( fh, "chip_idx=%u&", p_rftest_params->chip_index );
			fprintf( fh, "mcs=%u&", local_mcs );

			fprintf( fh, "\n" );
		}
		else
		{
			fprintf( fh, "rftest_chan=%u\n", p_rftest_params->rftest_chan );
			fprintf( fh, "rftest_bw=%d\n", p_rftest_params->rftest_bandwidth );
			fprintf( fh, "pktsize=%u\n", p_rftest_params->packet_size );
			fprintf( fh, "num_pkt=%u\n", p_rftest_params->packet_count );
			fprintf( fh, "pkt_type=%u\n", p_rftest_params->packet_type );
			fprintf( fh, "cw_pattern=%d\n", p_rftest_params->cw_pattern );
			fprintf( fh, "path_idx=%d\n", p_rftest_params->rfpath );
			fprintf( fh, "ssb=%d\n", p_rftest_params->SSB_setting );
			fprintf( fh, "tx_power=%d\n", p_rftest_params->tx_power );
			fprintf( fh, "tx_power_cal=%d\n", p_rftest_params->tx_power_cal );
			fprintf( fh, "antenna=%u\n", p_rftest_params->antenna_mask );
			fprintf( fh, "harmonics=%u\n", p_rftest_params->harmonics );
			fprintf( fh, "chip_idx=%u\n", p_rftest_params->chip_index );

			fprintf( fh, "mcs=%s\n", p_rftest_params->rftest_mcs_rate );
		}
	}
	else
	{
		retval = -EFAULT;
	}

	return( retval );
}

int
qcsapi_rftest_dump_counters( const qcsapi_rftest_packet_report packet_report, FILE *fh, const qcsapi_dump_format the_format )
{
	int	retval = 0;

	if (packet_report == NULL)
	{
		retval = -EFAULT;
	}
	else
	{
		if (fh == NULL)
		  fh = stdout;

		if (the_format == qcsapi_dump_HTTP_POST)
		{
			fprintf( fh, "RF1_TX=%u&", packet_report[ 0 ].tx_packets );
			fprintf( fh, "RF2_TX=%u&", packet_report[ 1 ].tx_packets );
			fprintf( fh, "RF1_RX=%u&", packet_report[ 0 ].rx_packets );
			fprintf( fh, "RF2_RX=%u&", packet_report[ 1 ].rx_packets );
			fprintf( fh, "\n" );
		}
		else
		{
			fprintf( fh, "RF1_TX=%u\n", packet_report[ 0 ].tx_packets );
			fprintf( fh, "RF2_TX=%u\n", packet_report[ 1 ].tx_packets );
			fprintf( fh, "RF1_RX=%u\n", packet_report[ 0 ].rx_packets );
			fprintf( fh, "RF2_RX=%u\n", packet_report[ 1 ].rx_packets );
		}
	}

	return( retval );
}


/*
 * Required to be called before starting any RF test.
 * But do not call until ready to start an RF test.
 *
 * Program equivalent of these 3 Linux user-level commands:
 *      echo "set debug 0x80000000" > /sys/devices/qdrv/control
 *      echo "set level 1" > /sys/devices/qdrv/control
 *      brctl delif br0 wifi0
 */

int
qcsapi_rftest_setup( qcsapi_rftest_params *p_rftest_params )
{
	int	retval = local_wifi_write_to_qdrv( "set debug 0x80000000" );
	int	retval_2 = local_wifi_write_to_qdrv( "set level 1" );

	(void) p_rftest_params;		// RF test parameters not used in this API (yet)
  /*
   * Disable the WiFi - Bridge interface.  Ignore errors.
   */
	local_interface_connect_to_bridge( WIFI_DEVICE, BRIDGE_DEVICE, 0 );

	if (retval_2 < 0)
	  retval = retval_2;

	return( retval );
}

/*
 * Program equivalent of this Linux user-level command:
 *      echo "calcmd 1 0 8 0 1 1 2 $channel" > /sys/devices/qdrv/control
 *
 * with channel obtained from the program's argument.
 */

int
local_rftest_set_channel( qcsapi_unsigned_int rftest_chan )
{
	char	set_channel[ 30 ];

	sprintf( &set_channel[ 0 ], "calcmd 1 0 8 0 1 1 2 %u", rftest_chan );
#ifdef DEBUG_CALCMD
    printf( "set channel: %s\n", &set_channel[ 0 ] );
#endif
	return( local_wifi_write_to_qdrv( &set_channel[ 0 ] ) );
}

/*
 * Program equivalent of these Linux user-level commands:
 *      echo "calcmd 1 0 8 0 1 1 2 $channel" > /sys/devices/qdrv/control
 *      echo "calcmd 12 0 14 0 1 $antenna 2 $mcs 3 $bw 4 $pktsize 5 $legacy" > /sys/devices/qdrv/control
 *
 * with parameters obtained from the RF test params.
 */

static int
local_rftest_setup_packet_test( qcsapi_rftest_params *p_rftest_params )
{
	int		retval = 0;

	if (p_rftest_params == NULL)
	{
		retval = -EFAULT;
	}
	else if (p_rftest_params->current_test != e_qcsapi_rftest_no_test)
	{
		retval = -EBUSY;
	}
	else
	{
		char		start_pkt_test[ 70 ];
		unsigned int	local_mcs = 14;
		unsigned int	calcmd_packet_size = p_rftest_params->packet_size;
		int		retval_2;

		retval = local_rftest_set_channel( p_rftest_params->rftest_chan );
	/*
	 * Packet size at the CALCMD level is the actual size / 100
	 * If the packet size is from 1 to 50, set the CALCMD packet size to 1
	 * Otherwise, round to the nearest multiple of 100
	 */
		if (calcmd_packet_size > 0 && calcmd_packet_size < 50)
		  calcmd_packet_size = 1;
		else
		  calcmd_packet_size = (calcmd_packet_size + 50) / 100;

		sscanf( p_rftest_params->rftest_mcs_rate, "MCS%u", &local_mcs );
		sprintf( &start_pkt_test[ 0 ], "calcmd 12 0 14 0 1 %u 2 %u 3 %d 4 %u 5 %d",
			  p_rftest_params->antenna_mask,
			  local_mcs,
			  p_rftest_params->rftest_bandwidth,
			  calcmd_packet_size,
			  p_rftest_params->packet_type
		);
#ifdef DEBUG_CALCMD
	    printf( "start packet xmit: %s\n", &start_pkt_test[ 0 ] );
#endif
		retval_2 = local_wifi_write_to_qdrv( &start_pkt_test[ 0 ] );

		if (retval_2 < 0)
		  retval = retval_2;
	}

	return( retval );
}

/*
 * Program equivalent of these Linux user-level commands:
 *      echo "calcmd 1 0 8 0 1 1 2 $channel" > /sys/devices/qdrv/control
 *      echo "calcmd 12 0 14 0 1 $antenna 2 $mcs 3 $bw 4 $pktsize 5 $legacy" > /sys/devices/qdrv/control
 *
 * with parameters obtained from the RF test params.
 */

int
qcsapi_rftest_start_packet_receive( qcsapi_rftest_params *p_rftest_params )
{
	int	retval = local_rftest_setup_packet_test( p_rftest_params );

	if (retval >= 0)
	  p_rftest_params->current_test = e_qcsapi_rftest_packet_test;

	return( retval );
}

/*
 * Program equivalent of these Linux user-level commands:
 *      echo "calcmd 1 0 8 0 1 1 2 $channel" > /sys/devices/qdrv/control
 *      echo "calcmd 12 0 14 0 1 $antenna 2 $mcs 3 $bw 4 $pktsize 5 $legacy" > /sys/devices/qdrv/control
 *	echo "calcmd 8 0 6 0 1 $num_pkt" > /sys/devices/qdrv/control
 *
 * with parameters obtained from the RF test params.
 *
 * Combines /scripts/set_test_mode and /scripts/send_test_packet.
 */

int
qcsapi_rftest_start_packet_xmit( qcsapi_rftest_params *p_rftest_params )
{
	int		retval = local_rftest_setup_packet_test( p_rftest_params );

	if (retval >= 0)
	{
		unsigned int	calcmd_packet_count = p_rftest_params->packet_count;
		int		retval_2;
		char		start_pkt_test[ 28 ];
	/*
	 * Packet count at the CALCMD level is the actual count / 1000
	 * If the packet count is from 1 to 500, set the CALCMD packet count to 1
	 * Otherwise, round to the nearest multiple of 1000
	 */
		if (calcmd_packet_count > 0 && calcmd_packet_count < 500)
		  calcmd_packet_count = 1;
		else
		  calcmd_packet_count = (calcmd_packet_count + 500) / 1000;

		sprintf( &start_pkt_test[ 0 ], "calcmd 8 0 6 0 1 %u", calcmd_packet_count );
#ifdef DEBUG_CALCMD
	    printf( "start packet xmit: %s\n", &start_pkt_test[ 0 ] );
#endif
		retval_2 = local_wifi_write_to_qdrv( &start_pkt_test[ 0 ] );

		if (retval_2 < 0)
		  retval = retval_2;

		if (retval >= 0)
		  p_rftest_params->current_test = e_qcsapi_rftest_packet_test;
	}

	return( retval );
}

static void
local_rftest_parse_packet_report_line( const char *packet_report_line, qcsapi_rftest_packet_report packet_report )
{
	const char	*packet_report_addr = packet_report_line;
	int		 complete = 0;

	while (complete == 0)
	{
		int		index_entry = -1;
		unsigned int	iter;

		while (isspace( *packet_report_addr ))
		 packet_report_addr++;

		for (iter = 0; rftest_counter_table[ iter ].counter_name != NULL && index_entry < 0; iter++)
		{
			unsigned int	length_entry_name = strlen( rftest_counter_table[ iter ].counter_name );

			if (strncasecmp( packet_report_addr, rftest_counter_table[ iter ].counter_name, length_entry_name ) == 0)
			{
				index_entry = (int) iter;
				packet_report_addr += length_entry_name;
			}
		}

		if (index_entry < 0)
		{
			complete = 1;
		}
		else
		{
			while (isspace( *packet_report_addr ))
			  packet_report_addr++;

			if (*packet_report_addr != '=')
			  complete = 1;
			else
			  packet_report_addr++;
		}

		if (complete == 0)
		{
			int				 counter_value = atoi( packet_report_addr );
			qcsapi_rftest_packet_counters	*p_packet_counters = &(packet_report[ rftest_counter_table[ index_entry ].report_index ]);

			switch (rftest_counter_table[ index_entry ].counter_type)
			{
			  case qcsapi_rftest_tx_packets:
				p_packet_counters->tx_packets = (qcsapi_unsigned_int) counter_value;
				break;

			  case qcsapi_rftest_rx_packets:
				p_packet_counters->rx_packets = (qcsapi_unsigned_int) counter_value;
				break;

			  case qcsapi_nosuch_rftest_counter:
			  default:
				break;
			}

			while ( *packet_report_addr != ',' &&
				*packet_report_addr != '&' &&
				*packet_report_addr != '\0')
			  packet_report_addr++;

			if (*packet_report_addr != ',' && *packet_report_addr != '&' )
			  complete = 1;
			else
			  packet_report_addr++;
		}
	}
}

/*
 * Program equivalent of this Linux user-level command:
 *      echo "calcmd 15 0 4 0" > /sys/devices/qdrv/control
 */

int
qcsapi_rftest_get_pkt_counters( qcsapi_rftest_params *p_rftest_params, qcsapi_rftest_packet_report packet_report )
{
	int	retval = 0;

	(void) p_rftest_params;

	if (packet_report == NULL)
	{
		retval = -EFAULT;
	}
	else
	{
		retval = local_wifi_write_to_qdrv( "calcmd 15 0 4 0" );

		if (retval >= 0)
		{
			FILE		*qdrv_fh = fopen( QDRV_RESULTS, "r" );
			char		 qdrv_output[ 122 ];

			while (fgets( &qdrv_output[ 0 ], sizeof( qdrv_output ), qdrv_fh ) != NULL)
			{
				local_rftest_parse_packet_report_line( &qdrv_output[ 0 ], packet_report );
			}

			fclose( qdrv_fh );
		}
	}

	return( retval );
}

/*
 * Program equivalent of these Linux user-level commands:
 *      echo "calcmd 1 0 8 0 1 1 2 $channel" > /sys/devices/qdrv/control
 *      echo "calcmd 9 0 14 0 1 $chip_idx 2 $path_idx 3 $pattern 4 $harmonics 5 $singleside" > /sys/devices/qdrv/control
 *
 * with parameters obtained from the RF test params.
 */

int
qcsapi_rftest_start_send_cw( qcsapi_rftest_params *p_rftest_params )
{
	int	retval, retval_2;
	char	start_cw_test[ 50 ];

	if (p_rftest_params == NULL)
	{
		retval = -EFAULT;
	}
	else if (p_rftest_params->current_test != e_qcsapi_rftest_no_test)
	{
		retval = -EBUSY;
	}
	else
	{
		retval = local_rftest_set_channel( p_rftest_params->rftest_chan );
		sprintf( &start_cw_test[ 0 ], "calcmd 9 0 14 0 1 %u 2 %d 3 %d 4 %u 5 %d",
			  p_rftest_params->chip_index,
			  p_rftest_params->rfpath,
			  p_rftest_params->cw_pattern,
			  p_rftest_params->harmonics,
			  p_rftest_params->SSB_setting
		);
#ifdef DEBUG_CALCMD
	    printf( "start CW test 2: %s\n", &start_cw_test[ 0 ] );
#endif
		retval_2 = local_wifi_write_to_qdrv( &start_cw_test[ 0 ] );

		if (retval_2 < 0)
		  retval = retval_2;
	}

	if (retval >= 0)
	  p_rftest_params->current_test = e_qcsapi_rftest_send_cw;

	return( retval );
}

/*
 * Program equivalent of this Linux user-level command:
 *      echo "calcmd 16 0 4 0" > /sys/devices/qdrv/control
 */

int
qcsapi_rftest_stop_packet_test( qcsapi_rftest_params *p_rftest_params )
{
	int	retval = 0;

	if (p_rftest_params == NULL)
	{
		retval = -EFAULT;
	}
	else
	{
		retval = local_wifi_write_to_qdrv( "calcmd 16 0 4 0" );

		if (retval >= 0)
		  p_rftest_params->current_test = e_qcsapi_rftest_no_test;
	}

	return( retval );
}

/*
 * Program equivalent of this Linux user-level command:
 *      echo "calcmd 13 0 6 0 1 $chip_idx" > /sys/devices/qdrv/control
 *
 * with chip index obtained from the program's argument.
 */

static int
local_rftest_stop_send_cw( qcsapi_u8 chip_index )
{
	char	stop_cw_test[ 24 ];

	sprintf( &stop_cw_test[ 0 ], "calcmd 13 0 6 0 1 %d", chip_index );
	return( local_wifi_write_to_qdrv( &stop_cw_test[ 0 ] ) );
}

int
qcsapi_rftest_stop_send_cw( qcsapi_rftest_params *p_rftest_params )
{
	int	retval = 0;

	if (p_rftest_params == NULL)
	{
		retval = -EFAULT;
	}
	else
	{
		retval = local_rftest_stop_send_cw( p_rftest_params->chip_index );
		if (retval >= 0)
		  p_rftest_params->current_test = e_qcsapi_rftest_no_test;
	}

	return( retval );
}

/*
 * Currently just a combination of stop packet transmit and stop send CW,
 * with stop send CW effected against both chip index 0 and 1.
 */

int
qcsapi_rftest_stop_RF_tests( qcsapi_rftest_params *p_rftest_params )
{
	int	retval = qcsapi_rftest_stop_packet_test( p_rftest_params );
	int	retval_2;
  /*
   * Valid chip indexes are 0 and 1
   */
	retval_2 = local_rftest_stop_send_cw( 0 );

	if (retval_2 < 0)
	  retval = retval_2;

	retval_2 = local_rftest_stop_send_cw( 1 );

	if (retval_2 < 0)
	  retval = retval_2;

	return( retval );
}

/*
 * Predicate:
 *   Returns 1 if an RF calibration is in progress,
 *   Returns 0 otherwise
 */

static int
local_rftest_monitor_calibration( void )
{
	int	retval = 1;
	int	ival = local_generic_locate_process( RF_CALIBRATION_PROGRAM );

	if (ival < 0)
	  ival = local_generic_locate_process( RF_CALIBRATION_SCRIPT );

	if (ival < 0)
	  retval = 0;

	return( retval );
}

int
qcsapi_rftest_start_calibration( int wait_flag )
{
	int	retval = 0;

	if (local_rftest_monitor_calibration() != 0)
	  retval = -EALREADY;
	else
	{
		char	rf_calibration_command[ 20 ];

		strcpy( &rf_calibration_command[ 0 ], RF_CALIBRATION_PROGRAM );
		if (wait_flag == 0)
		  strcat( &rf_calibration_command[ 0 ], "&" );

		retval = system( &rf_calibration_command[ 0 ] );
	}

	return( retval );
}

int
qcsapi_rftest_monitor_calibration( qcsapi_rftest_params *p_rftest_params, int *p_test_complete )
{
	int	retval = 0;

	if (p_rftest_params == NULL || p_test_complete == NULL)
	  retval = -EFAULT;
	else
	{
		int	ival = local_rftest_monitor_calibration();

		*p_test_complete = (ival != 0) ? 0 : 1;
	}
	
	return( retval );
}
