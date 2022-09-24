/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2012 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : qcsapi_regulatory.c                                        **
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

#include <arpa/inet.h>
#include <qtn/muc_phy_stats.h>

#include "qcsapi.h"
#include "qcsapi_private.h"

#define CHANNEL_BANDWIDTH_20MHZ_ONLY				BIT(0)
#define CHANNEL_BANDWIDTH_2040MHZ				(BIT(1) | BIT(0))
#define DEFAULT_ANT_NUM						4
#define DEFAULT_ANT_GAIN					(0.0)
#define MAX_REGULATORY_OPTIONS					4
#define QCSAPI_REGULATORY_REGION_NAME_LEN			2
#define QCSAPI_TX_ANTENNAS_MAX					DEFAULT_ANT_NUM

#define QTN_REGULATORY_DB_PATH					"/tmp/qtn_regulatory_db_path"
#define QTN_REGULATORY_DB_PATH_OLD				"/tmp/qtn_regulatory_db_path.old"
#define QTN_REGULATORY_DB_BIN					"/proc/bootcfg/qtn_regulatory_db.bin"
#define QTN_TX_POWER_PATH_BOOTCFG				"/proc/bootcfg/"
#define QTN_TX_POWER_PATH_IMAGE					"/etc/power_tables/"
#define QTN_CAPPED_TX_POWER					"/tmp/qtn_cap_tx_power"

#define TYPE_BAND_INFO						-128
#define TYPE_CHANNEL_INFO					-127
#define TYPE_BAND_UNI_REGULATORY				255

#define TYPE_REGULATORY_DOMAIN_PWR_MAP				0xFFFF
#define TYPE_REGULATORY_DOMAIN_BAND_INFO			0xFFFE
#define TYPE_REGULATORY_DOMAIN_MAX_BAND				0xFFFD
#define TYPE_REGULATORY_DOMAIN_DFS_REGIONS			0xFFFC
#define TYPE_REGULATORY_DOMAIN_VERSION				0xFFFB
#define TYPE_REGULATORY_DOMAIN_NON_PRIMARY			0xFFFA
#define TYPE_REGULATORY_DOMAIN_DFS_MAP				0xFFF9
#define QCSAPI_BAND_NOT_SUPPORTED				(-qcsapi_band_not_supported)
#define QCSAPI_REGION_NOT_SUPPORTED				(-qcsapi_region_not_supported)

/* Keep in sync with same macro in shared_params.h. */
#define HW_OPTION_BONDING_TOPAZ_PROD			0x00000500
#define MAX_5_GHZ_RF_BAND_INDEX		4
#define MAX_2_4_GHZ_RF_BAND_INDEX	5

enum power_table_location {
	POWER_TABLE_LOCATION_BOOTCFG = 0,
	POWER_TABLE_LOCATION_IMAGE = 1,
	POWER_TABLE_LOCATION_TOTAL = POWER_TABLE_LOCATION_IMAGE + 1
};

static struct _tx_power_cfg_fpath_ {
	const char suffix_fpath[32];
} tx_power_cfg_path[POWER_TABLE_LOCATION_TOTAL] = {
	{{QTN_TX_POWER_PATH_BOOTCFG}},
	{{QTN_TX_POWER_PATH_IMAGE}}
};

static struct _tx_power_cfg_fname_ {
	int id;
	const char suffix_fname[32];
} tx_power_cfg_name[] = {
	{HW_OPTION_BONDING_TOPAZ_PROD,	{"tx_power_QSR1000"}},
	{0,				{"tx_power"}}
};

extern int g_filter_DFS;

struct regulatory_non_primary_channel {
	uint8_t channel;
	uint8_t bw;
	uint8_t flags;
};

struct regulatory_non_primary_channel_info {
	struct regulatory_non_primary_channel non_primary_channel;
	struct regulatory_non_primary_channel_info *next;
};

struct regulatory_non_primary_band_info {
	uint8_t band_index;
	char regulatory[4];
	struct regulatory_non_primary_channel_info *channel_info;
};

struct regulatory_channel {
	uint8_t channel;
	uint8_t bw;
#define CHAN_DFS_REQUIRED		(1 << 0)
#define CHAN_WEATHER_RADAR		(1 << 1)
	uint8_t properties;
};

struct regulatory_channel_info {
	struct regulatory_channel regulatory_channel;
	struct regulatory_channel_info *next;
};

struct regulatory_tx_power {
	int8_t ap_pc;
	int8_t ap_pe;
	int8_t sta_pc;
	int8_t sta_pe;
};

struct regulatory_domain_band_info {
	uint8_t band_index;
	char regulatory[4];
	struct regulatory_tx_power regulatory_tx_power;
	struct regulatory_channel_info *channel_info;
};

struct regulatory_dfs_list {
	char dfs_name[4];
	struct regulatory_dfs_list *next;
};

struct l1tlcv {
	uint16_t type;
	uint16_t len;
	uint8_t  cnt;
	char v[0];
}__packed;

struct l2lv {
	uint8_t len;
	char v[0];
}__packed;

struct l3lcv {
	uint16_t len;
	uint8_t cnt;
	char v[0];
}__packed;

struct l4tlv {
	int8_t type;
	uint8_t len;
	char v[0];
}__packed;

struct channel2band {
	uint8_t channel;
	uint8_t band;
} channel2band[] = {
	{ 36,	1},
	{ 40,	1 },
	{ 44,	1 },
	{ 48,	1 },
	{ 52,	2 },
	{ 56,	2 },
	{ 60,	2 },
	{ 64,	2 },
	{ 100,	3 },
	{ 104,	3 },
	{ 108,	3 },
	{ 112,	3 },
	{ 116,	3 },
	{ 120,	3 },
	{ 124,	3 },
	{ 128,	3 },
	{ 132,	3 },
	{ 136,	3 },
	{ 140,	3 },
	{ 144,  3 },
	{ 149,	4 },
	{ 153,	4 },
	{ 157,	4 },
	{ 161,	4 },
	{ 165,	4 },
	{ 169,	4 },
	{ 1,	5},
	{ 2,	5},
	{ 3,	5},
	{ 4,	5},
	{ 5,	5},
	{ 6,	5},
	{ 7,	5},
	{ 8,	5},
	{ 9,	5},
	{ 10,	5},
	{ 11,	5},
	{ 12,	5},
	{ 13,	5},
	{ 14,	5},
};

struct chan_tx_power_data {
	uint8_t channel;
	int power_80M[QCSAPI_POWER_TOTAL];
	int power_40M[QCSAPI_POWER_TOTAL];
	int power_20M[QCSAPI_POWER_TOTAL];
	int valid_index_count;
};

struct band_tx_power_data {
	uint8_t band_index;
	char pwr_regulatory[4];
	char dfs_regulatory[4];
	struct chan_tx_power_data *channels;
	int num_channels;
};

struct tx_power_table {
	string_256 region_by_name;
	char fname[64];
	int status;
	struct band_tx_power_data *bands;
	int num_bands;
};

static void
local_free_regulatory_database(
		char *data
)
{
	if (data != NULL) {
		free(data);
		data = NULL;
	}
}

static char *
local_get_regulatory_database(void)
{
	FILE *fp = NULL;
	char *data = NULL;
	char database_path[256]={0};
	char database_path_old[256]={0};
	char *database_filename = database_path;
	int file_size = 0;
	struct stat file_stat;

	if (stat(QTN_REGULATORY_DB_PATH, &file_stat) == 0) {
		//valid database file's path exists in file QTN_REGULATORY_DB_PATH
		if ((long long)file_stat.st_size < sizeof(database_path)) {
			fp = fopen(QTN_REGULATORY_DB_PATH, "r");
		}

		if (fp != NULL) {
			fscanf(fp, "%s", database_path);
			fclose(fp);
			fp = NULL;

			if (stat(database_path, &file_stat) == 0) {
				fp = fopen(database_path, "rb");
			} else {
				local_generic_syslog("qcsapi_regulatory_database", LOG_ERR,
					"specified database %s not found.\n", database_path);
			}
		}
	}

	if (fp == NULL) {
		//use default database in uboot_env
		database_filename = QTN_REGULATORY_DB_BIN;

		fp = fopen(database_filename, "rb");
		if (fp == NULL) {
			return NULL;
		}

		if (stat(database_filename, &file_stat) != 0) {
			fclose(fp);
			return NULL;
		}
	}

	file_size = (int)file_stat.st_size;
	if (file_size > 0) {
		data = malloc(file_size*(sizeof(*data)));

		if (data == NULL) {
			perror("local_get_regulatory_database");
		} else {
			FILE *fp_old = NULL;

			fp_old = fopen(QTN_REGULATORY_DB_PATH_OLD, "rb");
			if (fp_old != NULL) {
				fscanf(fp_old, "%s", database_path_old);
				fclose(fp_old);
			}

			if (strcmp(database_filename, database_path_old) != 0) {
				fp_old = fopen(QTN_REGULATORY_DB_PATH_OLD, "wb");
				if (fp_old != NULL) {
					fprintf(fp_old, "%s\n", database_filename);
					fclose(fp_old);
				}
			}

			fread(data, 1, file_size, fp);
		}
	}

	fclose(fp);

	return data;
}

int
local_verify_regulatory_regions(
	string_256 list_regulatory_regions, const char *region_in
)
{
	char *pcur;

	if (!list_regulatory_regions || !region_in)
		return -1;

	pcur = list_regulatory_regions;
	while ((pcur = strcasestr(pcur, region_in)) && pcur) {
		if (( ',' == *(pcur + strlen(region_in))) ||
			('\0' == *(pcur + strlen(region_in)))) {
			if (pcur == list_regulatory_regions) {
				return 0;
			} else if (*(pcur - 1) == ',') {
				return 0;
			}
		}
		pcur++;
	}

	return -1;
}

int
local_regulatory_get_list_regulatory_regions(
		string_256 list_regulatory_regions
)
{
	char *ptr = NULL, *region_by_name = NULL, *data = NULL;
	int region_cnt = 0;
	int i = 0;
	struct l1tlcv *l1tlcv = NULL;
	struct l2lv *l2lv = NULL;
	struct l3lcv *l3lcv = NULL;
	int retval = 0;

	data = local_get_regulatory_database();
	*list_regulatory_regions = '\0';

	if (data != NULL) {
		ptr = data + sizeof(uint16_t);
		l1tlcv = (struct l1tlcv *)ptr;

		if (l1tlcv->type == TYPE_REGULATORY_DOMAIN_PWR_MAP) {

			region_cnt = l1tlcv->cnt;

			ptr = l1tlcv->v;

			for (i = 0; i < region_cnt; i++) {

				l2lv = (struct l2lv *)ptr;
				region_by_name = malloc(l2lv->len);
				if (region_by_name == NULL) {
					retval = -1;
					break;
				}

				l3lcv = (struct l3lcv *)(l2lv->v + l2lv->len);

				memset(region_by_name, 0, l2lv->len);
				strncpy(region_by_name, l2lv->v, l2lv->len);

				if (strlen(list_regulatory_regions) + l2lv->len + 1 < sizeof(string_256)) {
					if (i > 0) {
						strcat(list_regulatory_regions, ",");
					}
					strncat(list_regulatory_regions, region_by_name, l2lv->len);
				} else {
					printf("%s:Error out of buffer %ld, some regions will be missing\n", __func__, sizeof(string_256));
				}

				ptr += sizeof(*l2lv) + l2lv->len + sizeof(*l3lcv) + l3lcv->len;

				free(region_by_name);
			}
		} else {
			printf("error regulatory map error\n");
			retval = -1;
		}
		local_free_regulatory_database(data);
	}
	return retval;
}

static int
local_regulatory_get_L1_domain_int(int *p_value, int index, int domain)
{
	char *ptr = NULL, *data = NULL;
	int i = 0, j = 0;
	struct l1tlcv *l1tlcv = NULL;
	uint16_t total_tlv = 0;
	int retval = -2;

	data = local_get_regulatory_database();
	if (data == NULL) {
		return -1;
	}

	total_tlv = *(uint16_t *)data;
	ptr = data + sizeof(uint16_t);

	for (i = 0; i < total_tlv; i++) {
		l1tlcv = (struct l1tlcv *)ptr;

		if (l1tlcv->type == domain) {
			retval = 0;
			int sz = l1tlcv->cnt ? l1tlcv->len / l1tlcv->cnt : l1tlcv->len;
			if (index >= l1tlcv->cnt) {
				retval = -2;
				index = l1tlcv->cnt ? l1tlcv->cnt - 1 : 0;
			}

			uint8_t *p_data=(uint8_t*)&l1tlcv->v[sz * index];

			*p_value = 0;
			for (j = 0; j < MIN(sz, sizeof(*p_value)); j++)
				*p_value += ((unsigned int)p_data[j]) << (j * 8);
			break;
		}

		ptr += sizeof(*l1tlcv) + l1tlcv->len;
	}

	local_free_regulatory_database(data);

	return retval;
}

static int
local_regulatory_get_DFS_regions(
		struct regulatory_dfs_list **p_regulatory_dfs_list
)
{
	char *ptr = NULL, *ptr2 = NULL, *data = NULL;
	int i = 0, j = 0;
	struct l1tlcv *l1tlcv = NULL;
	struct l2lv *l2lv = NULL;
	uint16_t total_tlv = 0;
	int retval = 0;
	struct regulatory_dfs_list *p = NULL, *tail = NULL, *head = NULL;

	data = local_get_regulatory_database();

	if (data != NULL) {
		total_tlv = *(uint16_t *)data;
		ptr = data + sizeof(uint16_t);

		for (i = 0; i < total_tlv; i++) {
			l1tlcv = (struct l1tlcv *)ptr;

			if (l1tlcv->type == TYPE_REGULATORY_DOMAIN_DFS_REGIONS) {

				ptr2 = l1tlcv->v;
				for(j = 0; j < l1tlcv->cnt; j++) {
					l2lv = (struct l2lv *)(ptr2);
					p = malloc(sizeof(struct regulatory_dfs_list));
					if (p == NULL) {
						retval = -1;
						break;
					}

					memset(p->dfs_name, 0, 4);
					sscanf(l2lv->v, "%2s", p->dfs_name);

					if (head == NULL) {
						head = tail = p;
					} else {
						tail->next = p;
						tail = p;
						p->next = NULL;
					}

					ptr2 += sizeof(*l2lv) + l2lv->len;

				}
				*p_regulatory_dfs_list = head;
				break;
			}

			ptr += sizeof(*l1tlcv) + l1tlcv->len;
		}

	} else {
		retval = -1;
	}

	local_free_regulatory_database(data);

	return retval;
}

static void
local_regulatory_free_DFS_regions(
		struct regulatory_dfs_list **p_regulatory_dfs_list
)
{
	while (*p_regulatory_dfs_list != NULL) {
		struct regulatory_dfs_list *p = NULL;
		p = *p_regulatory_dfs_list;
		*p_regulatory_dfs_list = (*p_regulatory_dfs_list)->next;
		free(p);
	}
}

static int
local_regulatory_get_regulatory_map(
		uint16_t tag,
		const char *region_by_name,
		char regulatory_name[][4],
		uint16_t *cnt,
		char *data,
		int band_index
)
{
	char *ptr = NULL, *ptr4 = NULL;
	int region_cnt = 0;
	int i = 0, j = 0, k = 0;
	struct l1tlcv *l1tlcv = NULL;
	struct l2lv *l2lv = NULL;
	struct l3lcv *l3lcv = NULL;
	struct l4tlv *l4tlv = NULL;
	struct l2lv *str = NULL;
	uint8_t map_str_len = 0;
	uint16_t total_tlv;
	int retval = -1;

	if (data == NULL)
		return retval;

	total_tlv = *(uint16_t *)data;
	ptr = data + sizeof(uint16_t);

	while (total_tlv--) {
		l1tlcv = (struct l1tlcv *)ptr;

		if (l1tlcv->type == tag) {
			retval = QCSAPI_REGION_NOT_SUPPORTED;
			break;
		}
		ptr += sizeof(*l1tlcv) + l1tlcv->len;
	}

	if (retval == QCSAPI_REGION_NOT_SUPPORTED) {
		region_cnt = l1tlcv->cnt;
		ptr = l1tlcv->v;

		for (i = 0; i < region_cnt; i++) {
			l2lv = (struct l2lv *)ptr;
			ptr4 = l2lv->v;
			l3lcv = (struct l3lcv *)(ptr4 + l2lv->len);

			if (strncasecmp(region_by_name, l2lv->v, l2lv->len) == 0) {
				retval = QCSAPI_BAND_NOT_SUPPORTED;
				break;
			}

			ptr += sizeof(*l2lv) + l2lv->len + sizeof(*l3lcv) + l3lcv->len;
		}
	}

	if (retval == QCSAPI_BAND_NOT_SUPPORTED) {
		char *ptr2 = l3lcv->v;
		int ic = l3lcv->cnt;

		for (j = 0; j < ic; j++) {
			l4tlv = (struct l4tlv *)ptr2;

			char *ptr3 = l4tlv->v;
			*cnt = MIN(l4tlv->len, MAX_REGULATORY_OPTIONS);
			map_str_len = 0;
			for (k = 0; k < *cnt; k++) {
				str = (struct l2lv *)ptr3;

				if ((l4tlv->type == band_index) ||
						((uint8_t)l4tlv->type == TYPE_BAND_UNI_REGULATORY)) {
					strncpy(regulatory_name[k], str->v, str->len);
					retval = 0;
				}
				ptr3 += str->len + sizeof(*str);
				map_str_len += str->len + sizeof(*str);
			}

			if (retval == 0) {
				break;
			}
			ptr2 += sizeof(*l4tlv) + map_str_len;
		}
	}

	return retval;
}

static int
local_regulatory_apply_tx_power_cap(int capped)
{
	FILE *fp = NULL;

	fp = fopen(QTN_CAPPED_TX_POWER, "w");

	if (fp == NULL) {
		local_generic_syslog(__func__, LOG_WARNING, "TX power is not capped by database!\n");
		return -1;
	}

	fprintf(fp, "%d", capped);

	fclose(fp);

	return 0;
}

static void
local_regulatory_check_tx_power_cap(struct regulatory_tx_power *tx_power)
{
	FILE *fp = NULL;
	int capped = 1;

	fp = fopen(QTN_CAPPED_TX_POWER, "r");

	if (fp == NULL) {
		return;
	}

	if (fscanf(fp, "%d", &capped) == 1 && capped == 0) {
		local_generic_syslog(__func__, LOG_WARNING, "TX power is not capped by database!\n");
		if (tx_power->ap_pc) tx_power->ap_pc = 127;
		if (tx_power->ap_pe) tx_power->ap_pe = 127;
		if (tx_power->sta_pc) tx_power->sta_pc = 127;
		if (tx_power->sta_pe) tx_power->sta_pe = 127;
	}

	fclose(fp);
}

static int
local_regulatory_get_regulatory_domain_band_info(
		char *regulatory_by_name,
		struct regulatory_domain_band_info *regulatory_domain_band_info,
		char *data,
		uint8_t band_index
)
{
	int retval = 0;
	char *ptr = NULL, *ptr1 = NULL;
	struct l4tlv *tlv_band =  NULL, *tlv_channel_info = NULL, *tlv_band_info;
	struct l1tlcv *l1tlcv = NULL;
	struct l2lv *l2lv = NULL;
	struct l3lcv *l3lcv = NULL;
	struct regulatory_channel_info *p_channel = NULL, *p_channel_head = NULL, *p_channel_tail = NULL;
	uint8_t domain_len = 0;
	char regulatory_domain[4];
	int region_len = 0;
	int i = 0, j = 0;

	l1tlcv = (struct l1tlcv *)data;

	if (l1tlcv->type == TYPE_REGULATORY_DOMAIN_BAND_INFO) {

		ptr = data + sizeof(*l1tlcv);
		for (i = 0; i < l1tlcv->cnt; i++) {
			l2lv = (struct l2lv *)ptr;
			domain_len = l2lv->len;
			memset(regulatory_domain, 0, sizeof(regulatory_domain));
			memcpy(regulatory_domain, l2lv->v, domain_len);

			l3lcv = (struct l3lcv *)(ptr + sizeof(*l2lv) + l2lv->len);
			region_len = l3lcv->len;

			if (strncmp(regulatory_domain, regulatory_by_name, region_len) == 0) {
				break;
			}
			ptr += sizeof(*l2lv) + l2lv->len + sizeof(*l3lcv) + l3lcv->len;

		}

		if (i != l1tlcv->cnt) {

			tlv_band = (struct l4tlv *)l3lcv->v;

			for (j = 0; j < l3lcv->cnt; j++){

				if (tlv_band->type == band_index) {
					break;
				}
				tlv_band = (struct l4tlv *)(tlv_band->v + tlv_band->len);
			}

			if (j != l3lcv->cnt) {
				tlv_band_info = (struct l4tlv *)tlv_band->v;

				if (tlv_band_info->type == TYPE_BAND_INFO) {

					regulatory_domain_band_info->band_index = tlv_band->type;

					memcpy(&(regulatory_domain_band_info->regulatory_tx_power),
							(struct regulatory_tx_power *)tlv_band_info->v,
							tlv_band_info->len);
					local_regulatory_check_tx_power_cap(&(regulatory_domain_band_info->regulatory_tx_power));
					strncpy(regulatory_domain_band_info->regulatory, regulatory_by_name, 4);

					tlv_channel_info = (struct l4tlv *)(tlv_band_info->v + tlv_band_info->len);

					ptr1 = tlv_channel_info->v;

					if (tlv_channel_info->type == TYPE_CHANNEL_INFO) {
						for (i = 0;
								i < (tlv_channel_info->len /sizeof(p_channel->regulatory_channel));
								i ++) {
							p_channel = malloc(sizeof(struct regulatory_channel_info));
							if (p_channel == NULL) {
								printf("error: Not enough memory\n");
								retval = -1;
								break;
							}

							memcpy(&(p_channel->regulatory_channel),
									(struct regulatory_channel *)ptr1,
									sizeof(struct regulatory_channel));

							if (p_channel_head == NULL) {
								p_channel_head = p_channel;
								p_channel_tail = p_channel;
							} else {
								p_channel_tail->next = p_channel;
								p_channel_tail = p_channel;
								p_channel->next = NULL;
							}
							ptr1 += sizeof(struct regulatory_channel);
						}
					}
					regulatory_domain_band_info->channel_info = p_channel_head;
				}
			} else {
				retval = QCSAPI_BAND_NOT_SUPPORTED;
			}
		} else {
			printf("error: Region not match\n");
			retval = -1;
		}
	}
	return retval;
}

static int
local_regulatory_get_regulatory_non_primary_band_info(
		const char *regulatory_by_name,
		struct regulatory_non_primary_band_info **non_primary_band_info,
		int band_index
)
{
	char *ptr = NULL, *ptr1 = NULL, *data = NULL;
	struct l1tlcv *l1tlcv = NULL;
	struct l2lv *l2lv = NULL;
	struct l3lcv *l3lcv = NULL;
	struct l4tlv *tlv_band =  NULL, *tlv_channel_info = NULL;
	struct regulatory_non_primary_channel_info *p_channel = NULL, *p_channel_head = NULL, *p_channel_tail = NULL;
	uint16_t total_l1tlv = 0;
	uint8_t domain_len = 0;
	char regulatory_domain[4];
	int region_len = 0;
	int i = 0;
	int retval = -1;

	data = local_get_regulatory_database();
	if (data == NULL) {
		return -1;
	}

	total_l1tlv = *(uint16_t *)data;
	ptr = data + sizeof(uint16_t);

	for (i = 0; i < total_l1tlv; i++) {
		l1tlcv = (struct l1tlcv *)ptr;

		if (l1tlcv->type == TYPE_REGULATORY_DOMAIN_NON_PRIMARY) {
			break;
		}

		ptr += sizeof(*l1tlcv) + l1tlcv->len;
	}
	if (i >= total_l1tlv) {
		goto done;
	}

	ptr += sizeof(*l1tlcv);
	for (i = 0; i < l1tlcv->cnt; i++) {
		l2lv = (struct l2lv *)ptr;
		domain_len = l2lv->len;
		memset(regulatory_domain, 0, sizeof(regulatory_domain));
		memcpy(regulatory_domain, l2lv->v, domain_len);

		l3lcv = (struct l3lcv *)(ptr + sizeof(*l2lv) + l2lv->len);
		region_len = l3lcv->len;

		if (strncmp(regulatory_domain, regulatory_by_name, region_len) == 0) {
			break;
		}

		ptr += sizeof(*l2lv) + l2lv->len + sizeof(*l3lcv) + l3lcv->len;
	}
	if (i >= l1tlcv->cnt) {
		goto done;
	}

	tlv_band = (struct l4tlv *)l3lcv->v;
	for (i = 0; i < l3lcv->cnt; i++){

		if (tlv_band->type == band_index) {
			break;
		}
		tlv_band = (struct l4tlv *)(tlv_band->v + tlv_band->len);
	}
	if (i >= l3lcv->cnt) {
		goto done;
	}

	tlv_channel_info = (struct l4tlv *)tlv_band->v;
	if (tlv_channel_info->type == TYPE_CHANNEL_INFO) {
		*non_primary_band_info = malloc(sizeof(**non_primary_band_info));
		if (*non_primary_band_info == NULL) {
			local_generic_syslog(__func__, LOG_ERR, "Not enough memory\n");
		} else {
			(*non_primary_band_info)->band_index = tlv_band->type;
			strcpy((*non_primary_band_info)->regulatory, regulatory_by_name);

			ptr1 = tlv_channel_info->v;
			for (i = 0; i < (tlv_channel_info->len /sizeof(p_channel->non_primary_channel)); i ++) {
				p_channel = malloc(sizeof(struct regulatory_non_primary_channel_info));
				if (p_channel == NULL) {
					local_generic_syslog(__func__, LOG_ERR, "Not enough memory\n");
					break;
				}

				memcpy(&(p_channel->non_primary_channel),
						(struct regulatory_non_primary_channel *)ptr1,
						sizeof(struct regulatory_non_primary_channel));

				if (p_channel_head == NULL) {
					p_channel_head = p_channel;
					p_channel_tail = p_channel;
				} else {
					p_channel_tail->next = p_channel;
					p_channel_tail = p_channel;
					p_channel->next = NULL;
				}
				ptr1 += sizeof(struct regulatory_non_primary_channel);
			}
			(*non_primary_band_info)->channel_info = p_channel_head;
			retval = 0;
		}
	}

done:
	local_free_regulatory_database(data);
	return retval;
}

static int
local_get_regulatory_domain(const char *region_by_name, const int band_index, char *p_regulatory_name);

static int
local_regulatory_get_wifi_mode(qcsapi_wifi_mode *p_wifi_mode)
{
	int retval;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char primary_ifname[IFNAMSIZ];

	if (p_wifi_mode == NULL) {
		return -1;
	}

	memset(primary_ifname, 0, sizeof(primary_ifname));
	retval = local_get_primary_interface(primary_ifname, IFNAMSIZ - 1);

	if (retval >= 0) {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode(skfd, &primary_ifname[0], &wifi_mode);
	}

	if (retval >= 0) {
		*p_wifi_mode = wifi_mode;
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	return retval;
}

static void
local_generate_tx_power_fname_origin(char *fname, int len, int hw_options, const char *region,
		qcsapi_wifi_mode wifi_mode, uint32_t power_location)
{
	int i = 0;

	if (power_location >= POWER_TABLE_LOCATION_TOTAL) {
		power_location = POWER_TABLE_LOCATION_BOOTCFG;
	}

	for (i = 0; i < sizeof(tx_power_cfg_name)/sizeof(tx_power_cfg_name[0]) - 1; i++) {
		if (hw_options >= tx_power_cfg_name[i].id)
			break;
	}

	if (wifi_mode == qcsapi_station) {
		snprintf(fname,  len - 1, "%s%s_sta_%s.txt",
				tx_power_cfg_path[power_location].suffix_fpath,
				tx_power_cfg_name[i].suffix_fname, region);
	} else {
		snprintf(fname,  len - 1, "%s%s_%s.txt",
				tx_power_cfg_path[power_location].suffix_fpath,
				tx_power_cfg_name[i].suffix_fname, region);
	}
}

static void
local_generate_default_tx_power_fname(char *fname,
		int len, int hw_options, const char *region, uint32_t power_location)
{
	local_generate_tx_power_fname_origin(fname,
			len, hw_options, region, qcsapi_access_point, power_location);
}

static int
local_generate_tx_power_fname_by_mode(char *fname, int len, int hw_options, const char *region,
		qcsapi_wifi_mode wifi_mode, uint32_t power_location)
{
	FILE *fp = NULL;

	local_generate_tx_power_fname_origin(fname,
			len, hw_options, region, wifi_mode, power_location);
	fp = fopen(&fname[0], "r");
	if (fp) {
		fclose(fp);
		return 0;
	}

	/* Try AP mode again since the power table for AP mode can be used for STA mode too */
	if (wifi_mode == qcsapi_station) {
		local_generate_tx_power_fname_origin(fname,
				len, hw_options, region, qcsapi_access_point, power_location);
		fp = fopen(&fname[0], "r");
		if (fp) {
			fclose(fp);
			return 0;
		}
	}

	return -1;
}

static int
local_generate_tx_power_fname_by_region(char *fname, int len, int hw_options, const char *region,
		qcsapi_wifi_mode wifi_mode, uint32_t power_location)
{
	int retval;
	char regulatory_by_name[ 12 ] = { '\0' };

	retval = local_generate_tx_power_fname_by_mode(fname,
			len, hw_options, region, wifi_mode, power_location);
	if (retval >= 0) {
		return 0;
	}

	if (local_get_regulatory_domain(region, TYPE_BAND_UNI_REGULATORY, regulatory_by_name) >= 0) {
		/* To use the first mapped regulatory as default */
		regulatory_by_name[2] = '\0';

		retval = local_generate_tx_power_fname_by_mode(fname,
				len, hw_options, regulatory_by_name, wifi_mode, power_location);
		if (retval >= 0) {
			return 0;
		}
	}

	return -1;
}

static void
local_generate_tx_power_fname(char *fname, int len, int hw_options, const char *region)
{
	int retval;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	uint32_t power_selection = PWR_TABLE_SEL_IMAGE_PRIOR;
	uint8_t location_first;
	uint8_t location_second;
	uint8_t location_default;

	if (fname == NULL) {
		return;
	}

	retval = local_regulatory_get_wifi_mode(&wifi_mode);
	if (retval < 0) {
		goto generate_fname;
	}

	retval = local_wifi_get_power_selection(&power_selection);
	if (retval < 0) {
		goto generate_fname;
	}

generate_fname:

	switch (power_selection)
	{
	case PWR_TABLE_SEL_IMAGE_PRIOR:
		location_first = POWER_TABLE_LOCATION_IMAGE;
		location_second = POWER_TABLE_LOCATION_BOOTCFG;
		location_default = POWER_TABLE_LOCATION_BOOTCFG;
		break;
	case PWR_TABLE_SEL_BOOTCFG_PRIOR:
		location_first = POWER_TABLE_LOCATION_BOOTCFG;
		location_second = POWER_TABLE_LOCATION_IMAGE;
		location_default = POWER_TABLE_LOCATION_BOOTCFG;
		break;
	case PWR_TABLE_SEL_IMAGE_ONLY:
		location_first = POWER_TABLE_LOCATION_IMAGE;
		location_second = POWER_TABLE_LOCATION_TOTAL;
		location_default = POWER_TABLE_LOCATION_IMAGE;
		break;
	case PWR_TABLE_SEL_BOOTCFG_ONLY:
		location_first = POWER_TABLE_LOCATION_BOOTCFG;
		location_second = POWER_TABLE_LOCATION_TOTAL;
		location_default = POWER_TABLE_LOCATION_BOOTCFG;
		break;
	default:
		location_first = POWER_TABLE_LOCATION_BOOTCFG;
		location_second = POWER_TABLE_LOCATION_TOTAL;
		location_default = POWER_TABLE_LOCATION_BOOTCFG;
		break;
	}

	retval = local_generate_tx_power_fname_by_region(fname,
			len, hw_options, region, wifi_mode, location_first);

	if (retval < 0) {
		if (location_second < POWER_TABLE_LOCATION_TOTAL) {
			retval = local_generate_tx_power_fname_by_region(fname,
					len, hw_options, region, wifi_mode, location_second);
		}
	}

	if (retval < 0) {
		local_generate_default_tx_power_fname(fname,
					len, hw_options, region, location_default);
	}
}

enum qtn_reboot_reason_for_power_validation {
	QTN_REASON_NO_INIT_CHECKSUM = 1,
	QTN_REASON_CHECKSUM_MISMATCH,
	QTN_REASON_PWR_TABLE_DELETED,
};

static void local_validate_tx_power_table(char *fname, int hw_options, const char *region)
{
#define QTN_TX_POWER_TMP_CHECKSUM	"/tmp/pwr_csum"
#define	QTN_POWER_TABLE_CHECKSUM_LEN	32	/* MD5 Hex */
	FILE *fp;
	char tmpbuf[128];
	char csum_init[QTN_POWER_TABLE_CHECKSUM_LEN + 4];
	uint32_t count = 0;
	uint32_t power_recheck = 0;
	int retval;
	int reason = 0;

	if (fname == NULL) {
		return;
	}

	retval = local_wifi_get_power_recheck(&power_recheck);
	if (retval < 0 || !power_recheck) {
		return;
	}

	fp = fopen(&fname[0], "r");
	if (fp) {
		fclose(fp);
		/*
		 * power table exist, if it located in image but the checksum doesn't match
		 * the recorded checksum, that means, it is modified, need to reboot the system
		 */
		if (!memcmp(fname, QTN_TX_POWER_PATH_IMAGE, strlen(QTN_TX_POWER_PATH_IMAGE))) {
			retval = local_wifi_get_power_table_checksum(fname, csum_init, sizeof(csum_init));
			if (retval < 0) {
				local_generic_syslog(__func__, LOG_ERR,
					"Failed to get the initial checksum of %s!\n", fname);
				return;
			}

			csum_init[QTN_POWER_TABLE_CHECKSUM_LEN] = '\0';
			if (!strcmp(csum_init, "NA")) {
				local_generic_syslog(__func__, LOG_INFO,
					"The checksum of %s doesn't exist! reboot...\n", fname);
				reason = QTN_REASON_NO_INIT_CHECKSUM;
				goto reboot_system;
			} else {
				/* Remove the old checksum file */
				fp = fopen(QTN_TX_POWER_TMP_CHECKSUM, "r");
				if (fp) {
					fclose(fp);
					remove(QTN_TX_POWER_TMP_CHECKSUM);
				}
				/* Create the new checksum file */
				snprintf(tmpbuf,  sizeof(tmpbuf) - 1, "md5sum %s | cut -d ' ' -f 1 > %s",
						fname, QTN_TX_POWER_TMP_CHECKSUM);
				system(tmpbuf);

				while (count < 1000) {
					fp = fopen(QTN_TX_POWER_TMP_CHECKSUM, "r");
					if (fp) {
						fclose(fp);
						break;
					}
					count++;
				}

				fp = fopen(QTN_TX_POWER_TMP_CHECKSUM, "r");
				if (fp) {
					fgets(tmpbuf, sizeof(tmpbuf), fp);
					fclose(fp);
					tmpbuf[QTN_POWER_TABLE_CHECKSUM_LEN] = '\0';
				} else {
					local_generic_syslog(__func__, LOG_INFO,
							"Failed to create the checksum for %s!\n", fname);
					return;
				}

				if (strcmp(csum_init, tmpbuf)) {
					local_generic_syslog(__func__, LOG_INFO,
						"The checksum of the using power table is incorrect! reboot...\n");
					reason = QTN_REASON_CHECKSUM_MISMATCH;
					goto reboot_system;
				}
			}
		}
	} else {
		qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
		uint32_t power_selection = PWR_TABLE_SEL_IMAGE_PRIOR;

		retval = local_regulatory_get_wifi_mode(&wifi_mode);
		if (retval < 0) {
			return;
		}

		retval = local_wifi_get_power_selection(&power_selection);
		if (retval < 0) {
			return;
		}

		/*
		 * power table doesn't exist, if power table can be retrieved from image, and
		 * there is the record for the power table in the checksum file, that means,
		 * the power table in image is deleted manually, need to reboot system
		 */
		if (power_selection != PWR_TABLE_SEL_BOOTCFG_ONLY) {
			char tmp_fname[64] = {'\0'};

			local_generate_tx_power_fname_origin(tmp_fname,	sizeof(tmp_fname),
					hw_options, region, wifi_mode, POWER_TABLE_LOCATION_IMAGE);
			retval = local_wifi_get_power_table_checksum(tmp_fname, csum_init, sizeof(csum_init));
			if (retval >= 0 && strcmp(csum_init, "NA")) {
				local_generic_syslog(__func__, LOG_INFO,
					"Not find the power table but the checksum for %s does exist! reboot...\n",
					tmp_fname);
				reason = QTN_REASON_PWR_TABLE_DELETED;
				goto reboot_system;
			}

			/* Try AP mode again since the power table for AP mode can be used for STA mode too */
			if (wifi_mode == qcsapi_station) {
				local_generate_tx_power_fname_origin(tmp_fname,	sizeof(tmp_fname),
						hw_options, region, qcsapi_access_point, POWER_TABLE_LOCATION_IMAGE);
				retval = local_wifi_get_power_table_checksum(tmp_fname, csum_init, sizeof(csum_init));
				if (retval >= 0 && strcmp(csum_init, "NA")) {
					local_generic_syslog(__func__, LOG_INFO,
						"Not find the power table but the checksum for %s does exist! reboot...\n",
						tmp_fname);
					reason = QTN_REASON_PWR_TABLE_DELETED;
					goto reboot_system;
				}
			}
		}
	}

	return;

reboot_system:
	switch (reason) {
	case QTN_REASON_NO_INIT_CHECKSUM:
		printf("Invalid power table because no checksum exist, reboot...\n");
		break;
	case QTN_REASON_CHECKSUM_MISMATCH:
		printf("The checksum of the power table is incorrect, reboot...\n");
		break;
	case QTN_REASON_PWR_TABLE_DELETED:
		printf("The power table was deleted, reboot...\n");
		break;
	default:
		break;
	}
	sleep(1); /* delay 1 seconds for log printing */
	system("reboot");
}

static void
local_tx_power_table_fill_band(const char *buf, struct band_tx_power_data *band)
{
	char tmp[4] = {'\0'};
	int id = 0;
	int regulatory_cnt = 0;

	regulatory_cnt = sscanf(buf, "*band %d%s%s", &id, band->pwr_regulatory, tmp);
	band->band_index = id;
	strcpy(band->dfs_regulatory, (regulatory_cnt == 3) ? tmp : band->pwr_regulatory);
	band->channels = NULL;
	band->num_channels = 0;
}

static int
local_tx_power_table_fill_channel(const char *buf,
	int index, int hw_options, int tx_antennas, struct chan_tx_power_data *chan)
{
	int local_channel = 0;
	int ant_idx = 0;
	int ival = 0;
	int pwr_80M[QCSAPI_TX_ANTENNAS_MAX] = {0};
	int pwr_40M[QCSAPI_TX_ANTENNAS_MAX] = {0};
	int pwr_20M[QCSAPI_TX_ANTENNAS_MAX] = {0};

	if (index >= QCSAPI_POWER_TOTAL)
		return 0;

	if (index == 0)
		chan->channel = 0;
	chan->valid_index_count = index;

	if (hw_options >= HW_OPTION_BONDING_TOPAZ_PROD) {
		ival = sscanf(buf,
			"%d%d%d%d%d%d%d%d%d%d%d%d%d",
			&local_channel,
			&pwr_80M[0], &pwr_40M[0], &pwr_20M[0],
			&pwr_80M[1], &pwr_40M[1], &pwr_20M[1],
			&pwr_80M[2], &pwr_40M[2], &pwr_20M[2],
			&pwr_80M[3], &pwr_40M[3], &pwr_20M[3]);

		if (ival < 2) {
			return 0;
		} else if (ival < 3) {
			pwr_40M[0] = pwr_80M[0];
			pwr_20M[0] = pwr_80M[0];
		} else if (ival < 4) {
			pwr_20M[0] = pwr_40M[0];
		}
		if (ival > (3 * (QCSAPI_TX_ANTENNAS_MAX - tx_antennas + 1))) {
			ant_idx = QCSAPI_TX_ANTENNAS_MAX - tx_antennas;
		}
	} else {
		ival = sscanf(buf,
			"%d%d%d",
			&local_channel,
			&pwr_40M[0], &pwr_20M[0]);

		if (ival < 2) {
			return 0;
		} else if (ival < 3) {
			pwr_20M[0] = pwr_40M[0];
		}
	}

	if ((index > 0) && (local_channel != chan->channel))
		return 0;

	chan->channel = local_channel;
	chan->power_80M[index] = pwr_80M[ant_idx];
	chan->power_40M[index] = pwr_40M[ant_idx];
	chan->power_20M[index] = pwr_20M[ant_idx];
	chan->valid_index_count = index + 1;

	return 1;
}

static void
local_init_tx_power_table(const char *region_by_name, struct tx_power_table* power_table)
{
	int hw_options = HW_OPTION_BONDING_TOPAZ_PROD;
	FILE *fp = NULL;
	char tx_power_database_entry[128];
	int tx_antennas = DEFAULT_ANT_NUM;
	int num_tx_ss;
	int num_rx_ss;
	int num_bands = 0, num_channels = 0;
	struct band_tx_power_data *cur_band, *next_band;
	struct chan_tx_power_data *next_channel;
	int index = 0;

	memset(power_table, 0, sizeof(*power_table));

	strncpy(power_table->region_by_name, region_by_name,
		sizeof(power_table->region_by_name) - 1);

	if (power_table->region_by_name[0] == '\0') {
		power_table->status = -ENOENT;
		return;
	}

	local_wifi_get_hw_options(&hw_options);

	local_generate_tx_power_fname(power_table->fname, sizeof(power_table->fname),
		hw_options, region_by_name);
	local_validate_tx_power_table(power_table->fname, hw_options, region_by_name);

	fp = fopen(&power_table->fname[0], "r");
	if (fp == NULL) {
		power_table->status = -ENOENT;
		return;
	}

	if (local_get_supported_spatial_streams(&num_tx_ss, &num_rx_ss) >= 0) {
		if ((num_tx_ss > 0) && (num_tx_ss <= QCSAPI_TX_ANTENNAS_MAX)) {
			tx_antennas = num_tx_ss;
		}
	} else {
		local_generic_syslog(__func__, LOG_ERR,
			"Can't get supported spatial streams\n");
	}

	while (fgets(tx_power_database_entry, sizeof(tx_power_database_entry), fp) != NULL) {
		if (tx_power_database_entry[0] == '#')
			continue;

		if (tx_power_database_entry[0] == '*') {
			++num_bands;
		} else if (num_bands == 0) {
			/*
			 * Channel entry without any band entries
			 * before it, power table format error.
			 */
			local_generic_syslog(__func__, LOG_ERR,
				"Invalid tx power table format\n");
			fclose(fp);
			power_table->status = -EINVAL;
			return;
		} else {
			++num_channels;
		}
	}

	power_table->bands = malloc((sizeof(struct band_tx_power_data) * num_bands) +
		(sizeof(struct chan_tx_power_data) * num_channels));

	if (power_table->bands == NULL) {
		local_generic_syslog(__func__, LOG_ERR, "Not enough memory\n");
		fclose(fp);
		power_table->status = -1;
		return;
	}

	cur_band = next_band = power_table->bands;
	next_channel = (struct chan_tx_power_data *)(cur_band + num_bands);

	rewind(fp);

	while (fgets(tx_power_database_entry, sizeof(tx_power_database_entry), fp) != NULL) {
		if (tx_power_database_entry[0] == '#')
			continue;

		if (tx_power_database_entry[0] == '*') {
			if (index > 0) {
				++cur_band->num_channels;
				++next_channel;
				index = 0;
			}
			local_tx_power_table_fill_band(tx_power_database_entry, next_band);
			next_band->channels = next_channel;
			++power_table->num_bands;
			cur_band = next_band;
			++next_band;
		} else if (local_tx_power_table_fill_channel(tx_power_database_entry,
			index, hw_options, tx_antennas, next_channel)) {
			++index;
		} else if (index > 0) {
			++cur_band->num_channels;
			++next_channel;
			index = 0;

			if (local_tx_power_table_fill_channel(tx_power_database_entry,
				index, hw_options, tx_antennas, next_channel)) {
				++index;
			} else {
				++cur_band->num_channels;
				++next_channel;
			}
		} else {
			++cur_band->num_channels;
			++next_channel;
		}
	}

	if (index > 0) {
		++cur_band->num_channels;
	}

	fclose(fp);
}

static void
local_cleanup_tx_power_table(struct tx_power_table *power_table)
{
	free(power_table->bands);
}

static int
local_get_regulatory_domain_config(
	const struct tx_power_table *power_table,
	uint8_t band_index,
	char *regulatory_by_name,
	char *dfs_regulatory
)
{
	int i;

	if (power_table->status != 0)
		return power_table->status;

	for (i = 0; i < power_table->num_bands; ++i) {
		if (power_table->bands[i].band_index == band_index) {
			if (regulatory_by_name != NULL)
				strcpy(regulatory_by_name, power_table->bands[i].pwr_regulatory);
			if (dfs_regulatory != NULL)
				strcpy(dfs_regulatory, power_table->bands[i].dfs_regulatory);
			return 0;
		}
	}

	return QCSAPI_BAND_NOT_SUPPORTED;
}

static char *
local_regulatory_get_valid_dfs_regulatory(char regulatory_opts[][4], int cnt)
{
	const char const *valid_regulatory_by_radar[]={"us","eu","jp","br","cl","au"};
	int i,j;
	int valid_regulatory_cnt = ARRAY_SIZE(valid_regulatory_by_radar);

	for (i = 0; i < cnt; i++)
	for (j = 0; j < valid_regulatory_cnt; j++) {
		if (strcasecmp(regulatory_opts[i],valid_regulatory_by_radar[j]) == 0)
			return regulatory_opts[i];
	}

	return NULL;
}

static int
local_regulatory_get_regulatory_info(
		const struct tx_power_table *power_table,
		struct regulatory_domain_band_info **regulatory_domain_band_info,
		int band_index,
		char *dfs_regulatory
)
{
	char *data = NULL, *ptr = NULL;
	int retval = 0;
	char pwr_regulatory_opts[MAX_REGULATORY_OPTIONS][4] = {{'\0'},{'\0'},{'\0'},{'\0'}};
	char regulatory_opts[MAX_REGULATORY_OPTIONS][4] = {{'\0'},{'\0'},{'\0'},{'\0'}};
	char pwr_regulatory_opts_str[MAX_REGULATORY_OPTIONS * 4] = {0};
	char dfs_regulatory_opts_str[MAX_REGULATORY_OPTIONS * 4] = {0};
	char (*dfs_regulatory_opts)[4] = pwr_regulatory_opts;
	char select_regulatory[4] = {'\0'};
	char pwr_regulatory[4] = {'\0'};
	struct l1tlcv *l1tlcv = NULL;
	uint16_t cnt_pwr_options = 0;
	uint16_t cnt_dfs_options = 0;
	int pwr_opt_fund = 0;
	int dfs_opt_fund = 0;
	int i;
	char *p_valid_dfs_regulatory = NULL;

	if (strlen(power_table->region_by_name) != QCSAPI_REGULATORY_REGION_NAME_LEN)
		return -EINVAL;

	data = local_get_regulatory_database();

	if (data == NULL)
		return -1;

	retval = local_regulatory_get_regulatory_map(TYPE_REGULATORY_DOMAIN_PWR_MAP,
		power_table->region_by_name, pwr_regulatory_opts,
		&cnt_pwr_options, data, band_index);
	local_regulatory_get_regulatory_map(TYPE_REGULATORY_DOMAIN_DFS_MAP,
		power_table->region_by_name, regulatory_opts, &cnt_dfs_options, data, band_index);
	if (regulatory_opts[0][0]) {
		//separated regulatory map for DFS exist
		dfs_regulatory_opts = regulatory_opts;
	} else if (band_index ==2 || band_index == 3) {
		//use the regulation map of tx power
		dfs_regulatory_opts = pwr_regulatory_opts;
		cnt_dfs_options = cnt_pwr_options;
	} else {
		//no regulation map of DFS for non-DFS channel
		dfs_regulatory = NULL;
	}

	if (retval >= 0) {
		retval = local_get_regulatory_domain_config(power_table, band_index,
			pwr_regulatory, dfs_regulatory);
	}

	for (i = 0; i < cnt_pwr_options; i++) {
		if (strcasecmp(pwr_regulatory_opts[i], pwr_regulatory) == 0) {
			strcpy(select_regulatory, pwr_regulatory_opts[i]);
			pwr_opt_fund = 1;
		}

		if (i > 0) strcat(pwr_regulatory_opts_str, " ");
		strcat(pwr_regulatory_opts_str, pwr_regulatory_opts[i]);
	}
	for (i = 0; i < cnt_dfs_options; i++) {
		if (dfs_regulatory && strcasecmp(dfs_regulatory_opts[i], dfs_regulatory) == 0) {
			dfs_opt_fund = 1;
		}

		if (i > 0) strcat(dfs_regulatory_opts_str, " ");
		strcat(dfs_regulatory_opts_str, dfs_regulatory_opts[i]);
	}

	if (dfs_regulatory)
		p_valid_dfs_regulatory = local_regulatory_get_valid_dfs_regulatory(dfs_regulatory_opts, cnt_dfs_options);

	if (retval >= 0 && pwr_opt_fund == 0) {
		local_generic_syslog(__func__, LOG_ERR,
				"%s incorrect regulation of tx_power %2s, expect %2s\n",
				power_table->fname, pwr_regulatory, pwr_regulatory_opts_str
		);
		local_generic_syslog(__func__, LOG_ERR,
				"Regulation %s is taken for tx_power\n", pwr_regulatory_opts[0]
		);

		strcpy(select_regulatory, pwr_regulatory_opts[0]);
	}

	if (retval >= 0 && dfs_opt_fund == 0 && dfs_regulatory) {
		local_generic_syslog(__func__, LOG_ERR,
				"%s incorrect regulation of DFS %2s, expect %2s\n",
				power_table->fname, dfs_regulatory, dfs_regulatory_opts_str
		);
		local_generic_syslog(__func__, LOG_ERR,
				"Regulation %s is taken for DFS\n", p_valid_dfs_regulatory ? p_valid_dfs_regulatory : "none"
		);

		if (p_valid_dfs_regulatory) {
			strcpy(dfs_regulatory, p_valid_dfs_regulatory);
		}
	}

	if (retval == -ENOENT) {
		retval = 0;
		local_generic_syslog(__func__, LOG_ERR,
				"%s doesn't exist, optional regulations of tx_power in database: %s, %s is taken\n",
				power_table->fname, pwr_regulatory_opts_str, pwr_regulatory_opts[0]
		);
		strcpy(select_regulatory, pwr_regulatory_opts[0]);

		if (dfs_regulatory) {
			local_generic_syslog(__func__, LOG_ERR,
					"%s doesn't exist, DFS optional regulations in database: %s, %s is taken\n",
					power_table->fname, dfs_regulatory_opts_str, p_valid_dfs_regulatory ? p_valid_dfs_regulatory : "none"
			);

			if (p_valid_dfs_regulatory) {
				strcpy(dfs_regulatory, p_valid_dfs_regulatory);
			}
		}
	}

	if (retval >= 0 && regulatory_domain_band_info) {
		*regulatory_domain_band_info = malloc(sizeof(**regulatory_domain_band_info));
		if (*regulatory_domain_band_info == NULL) {
			local_generic_syslog(__func__, LOG_ERR, "Not enough memory\n");
			retval = -1;
		}
	}

	if (regulatory_domain_band_info && *regulatory_domain_band_info) {
		ptr = data + sizeof(uint16_t);
		ptr += sizeof(*l1tlcv) + ((struct l1tlcv*)ptr)->len;
		retval = local_regulatory_get_regulatory_domain_band_info(
					select_regulatory,
					*regulatory_domain_band_info,
					ptr, band_index);

		if (retval == QCSAPI_BAND_NOT_SUPPORTED) {
			free(*regulatory_domain_band_info);
			*regulatory_domain_band_info = NULL;
		}
	}

	local_free_regulatory_database(data);
	return retval;
}

static void
local_regulatory_free_regulatory_info(struct regulatory_domain_band_info **regulatory_domain_band_info)
{
	if (*regulatory_domain_band_info != NULL) {
		if ((*regulatory_domain_band_info)->channel_info != NULL) {
			struct regulatory_channel_info *p1, *p2;

			p1 = (*regulatory_domain_band_info)->channel_info;
			while(p1) {
				p2 = p1;
				p1 = p1->next;
				free(p2);
			}
		}
		free(*regulatory_domain_band_info);
		*regulatory_domain_band_info = NULL;
	}

}

static void
local_regulatory_free_regulatory_non_primary_band_info(
		struct regulatory_non_primary_band_info **regulatory_non_primary_band_info)
{
	if (*regulatory_non_primary_band_info != NULL) {
		if ((*regulatory_non_primary_band_info)->channel_info != NULL) {
			struct regulatory_non_primary_channel_info *p1, *p2;

			p1 = (*regulatory_non_primary_band_info)->channel_info;
			while(p1) {
				p2 = p1;
				p1 = p1->next;
				free(p2);
			}
		}
		free(*regulatory_non_primary_band_info);
		*regulatory_non_primary_band_info = NULL;
	}
}

static int
local_get_regulatory_domain(const char *region_by_name, const int band_index, char *p_regulatory_name)
{
	char regulatory_name[MAX_REGULATORY_OPTIONS][4] = {{'\0'},{'\0'},{'\0'},{'\0'}};
	char *data = NULL;
	uint16_t cnt = 0, i;
	int retval = 0;

	data = local_get_regulatory_database();

	retval = local_regulatory_get_regulatory_map(
			TYPE_REGULATORY_DOMAIN_PWR_MAP,
			region_by_name, regulatory_name,
			&cnt,
			data,
			band_index);

	if (retval >= 0) for (i = 0; i < cnt; i++) {
		if (i > 0) strcat(p_regulatory_name, ",");
		strcat(p_regulatory_name, regulatory_name[i]);
	}

	local_free_regulatory_database(data);

	return retval;
}

static int
local_get_chan_tx_power_data_from_power_table(
		const struct tx_power_table *power_table,
		const uint8_t channel,
		struct chan_tx_power_data *p_data
)
{
	int band, chan;

	if (power_table->status == -ENOENT)
		local_generic_syslog(__func__, LOG_ERR,
			"File %s doesn't exist\n", power_table->fname);

	if (power_table->status != 0)
		return power_table->status;

	for (band = 0; band < power_table->num_bands; ++band) {
		for (chan = 0; chan < power_table->bands[band].num_channels; ++chan) {
			struct chan_tx_power_data *data = &power_table->bands[band].channels[chan];
			if (data->channel == channel) {
				memcpy(p_data, data, sizeof(*data));
				return 0;
			}
		}
	}

	p_data->valid_index_count = 0;

	return 0;
}

/*
 * This mapping table is for backward compatibility issue because the power table
 * formats we have used include 1 line, 2 lines, 4 lines and now we use 8 lines format
 */
static int8_t power_table_mapping[QCSAPI_POWER_TOTAL][QCSAPI_POWER_TOTAL] = {
	{0, 0, 0, 0, 0, 0, 0, 0},	/* 1-line format, line 1 for all bf/ss cases */
	{0, 0, 0, 0, 1, 1, 1, 1},	/* 2-lines format, line 1 for bf off and line 2 for bf on */
	{0, 0, 0, 0, 0, 1, 2, 2},	/* 3-lines, it is possible although we don't release this format */
	{0, 0, 0, 0, -1, 1, 2, 3},	/* 4-lines format, disable bf on 1ss and use bf off 1ss instead */
	{0, 1, 2, 3, 4, 4, 4, 4},	/* 5-lines, it is possible although we don't release this format */
	{0, 1, 2, 3, 4, 5, 5, 5},	/* 6-lines, it is possible although we don't release this format */
	{0, 1, 2, 3, 4, 5, 6, 6},	/* 7-lines, it is possible although we don't release this format */
	{0, 1, 2, 3, 4, 5, 6, 7},	/* 8-lines format */
};

static int
local_regulatory_get_tx_power_info(
	const struct tx_power_table *power_table,
	const uint8_t channel,
	const uint8_t power_index,
	const qcsapi_bw bandwidth,
	int8_t *p_cust_power_80M,
	int8_t *p_cust_power_40M,
	int8_t *p_cust_power_20M,
	int8_t *p_cust_power
)
{
	int retval = 0;
	int index;
	struct chan_tx_power_data tx_power_data;

	if (power_index >= QCSAPI_POWER_TOTAL) {
		local_generic_syslog(__func__, LOG_ERR,
				"Invalid power index %d\n", power_index);
		retval = -ENOENT;
	}

	if (retval >= 0) {
		memset(&tx_power_data, 0, sizeof(tx_power_data));
		retval = local_get_chan_tx_power_data_from_power_table(power_table, channel, &tx_power_data);
	}

	if (retval >= 0) {
		if (tx_power_data.valid_index_count == 0) {
			if (power_index == 0) {
				local_generic_syslog(__func__, LOG_ERR,
						"channel %d doesn't exist in power table\n", channel);
			}
			retval = -ENOENT;
		} else {
			index = power_table_mapping[tx_power_data.valid_index_count - 1][power_index];

			if (p_cust_power_80M) {
				*p_cust_power_80M = (index == -1) ? -1 : tx_power_data.power_80M[index];
			}
			if (p_cust_power_40M) {
				*p_cust_power_40M = (index == -1) ? -1 : tx_power_data.power_40M[index];
			}
			if (p_cust_power_20M) {
				*p_cust_power_20M = (index == -1) ? -1 : tx_power_data.power_20M[index];
			}

			if (p_cust_power) {
				switch (bandwidth) {
				case qcsapi_bw_80MHz:
					*p_cust_power = (index == -1) ? -1 : tx_power_data.power_80M[index];
					break;
				case qcsapi_bw_40MHz:
					*p_cust_power = (index == -1) ? -1 : tx_power_data.power_40M[index];
					break;
				default:
					*p_cust_power = (index == -1) ? -1 : tx_power_data.power_20M[index];
					break;
				}
			}
		}
	}

	return( retval );
}

static int local_regulatory_is_channel_avaliable(
		const struct tx_power_table *power_table,
		const uint8_t channel,
		const qcsapi_bw bandwidth
)
{
	int retval = 0;
	int8_t power = 0;
	retval = local_regulatory_get_tx_power_info(
		power_table,
		channel,
		QCSAPI_POWER_INDEX_BFOFF_1SS,
		bandwidth,
		NULL,
		NULL,
		NULL,
		&power
	);

	if (power == -1) {
		return 0;
	} else {
		return 1;
	}
}

static int local_regulatory_enable_radar(
		char *regulatory_domain
)
{
	int retval =  0;
	char enable_radar_msg[ 32 ] = { '\0' };

	printf( "radar start with regulatory %s\n", regulatory_domain );
	sprintf( &enable_radar_msg[ 0 ], "radar enable %s", regulatory_domain );
	retval = local_wifi_write_to_qdrv( &enable_radar_msg[ 0 ] );
	return retval;
}

static int local_regulatory_setup_radar(
		int skfd,
		const char *ifname,
		char *regulatory_by_name
)
{
	int enable_radar = 0;
	qcsapi_wifi_mode local_wifi_mode = qcsapi_nosuch_mode;
	struct regulatory_dfs_list *regulatory_dfs_list = 0;
	struct regulatory_dfs_list *p;
	int retval = 0;

	retval = local_wifi_get_mode( skfd, ifname, &local_wifi_mode );

	if (retval >= 0) {
		retval = local_regulatory_get_DFS_regions(&regulatory_dfs_list);
	}

	p = regulatory_dfs_list;
	while (p != NULL) {
		if (strcasecmp(regulatory_by_name, p->dfs_name) == 0) {
			enable_radar = 1;
			break;
		}
		p = p->next;
	}

	local_regulatory_free_DFS_regions(&regulatory_dfs_list);

	if (enable_radar) {
		local_regulatory_enable_radar(regulatory_by_name);
	}

	return retval;
}

static uint8_t
local_get_band_index(uint8_t channel)
{
	int i = 0;
	uint8_t band_index = 0;
	for(i = 0; i < ARRAY_SIZE(channel2band); i ++) {
		if (channel2band[i].channel == channel)
			band_index = channel2band[i].band;
	}
	return band_index;
}

static int local_get_antenna_num(int *p_antenna_num)
{
	char antenna_num_value[8] = {'\0'};
	int retval = local_bootcfg_get_parameter(
				"antenna_num",
				&antenna_num_value[ 0 ],
				sizeof( antenna_num_value ));

	if (retval >= 0) {
		*p_antenna_num = atoi(&antenna_num_value[0]);
	} else {
		*p_antenna_num = DEFAULT_ANT_NUM;
		local_generic_syslog(__func__, LOG_WARNING,
				"antenna_num u-boot env doesn't exist, value  %d will be taken as default\n", DEFAULT_ANT_NUM
		);
	}

	return retval;
}

static int local_get_antenna_gain(double *p_antenna_gain)
{
	char antenna_gain_value[8] = {'\0'};
	double antenna_gain = 0.0;
	char buf[10] = {'\0'};
	int retval = local_bootcfg_get_parameter(
				"antenna_gain",
				&antenna_gain_value[ 0 ],
				sizeof( antenna_gain_value ));

	if (retval >= 0) {
		antenna_gain = (double)(atoi(&antenna_gain_value[0]));
		antenna_gain /= 4096.0;
		sprintf(buf, "%.1f", antenna_gain);
		*p_antenna_gain = atof(buf);
	} else {
		*p_antenna_gain = DEFAULT_ANT_GAIN;
		local_generic_syslog(__func__, LOG_WARNING,
				"antenna_gain u-boot env doesn't exist, value %d will be taken as default\n", DEFAULT_ANT_GAIN
		);
	}

	return retval;
}

static int local_regulatory_calculate_tx_power(
	int8_t c_tx_power,
	int8_t e_tx_power
)
{
	int8_t max_tx_power = 0;
	int antenna_num = 0;
	double antenna_gain = 0.0;

	local_get_antenna_gain(&antenna_gain);

	local_get_antenna_num(&antenna_num);

	if (c_tx_power  > 0 && e_tx_power > 0) {
		max_tx_power = MIN((int8_t)(((double)c_tx_power - 10.0*log10((double)antenna_num)) + 0.5),
				((int8_t)((double)e_tx_power - antenna_gain -10.0*log10((double)antenna_num)) + 0.5));
	} else if (c_tx_power  > 0) {
		max_tx_power = (int8_t)((double)c_tx_power - 10.0*log10((double)antenna_num) + 0.5);
	} else if (e_tx_power > 0) {
		max_tx_power = (int8_t)((double)e_tx_power - antenna_gain -10.0*log10((double)antenna_num) + 0.5);
	}

	return max_tx_power;
}

static int
local_get_regulatory_conductive_tx_power(
	qcsapi_wifi_mode wifi_mode,
	struct regulatory_domain_band_info *regulatory_domain_band_info,
	int sta_dfs_en,
	int8_t *p_max_power
)
{
	int retval = 0;
	int8_t c_tx_power = 0, e_tx_power = 0;

	if (regulatory_domain_band_info != NULL) {
		if (regulatory_domain_band_info->regulatory_tx_power.ap_pc > 0) {
			c_tx_power = regulatory_domain_band_info->regulatory_tx_power.ap_pc;
		}

		if (regulatory_domain_band_info->regulatory_tx_power.ap_pe > 0) {
			e_tx_power = regulatory_domain_band_info->regulatory_tx_power.ap_pe;
		}

		/*
		** if regulatory define station mode power we will take it in station mode.
		*/
		if (wifi_mode == qcsapi_station && sta_dfs_en == 0) {
			if (regulatory_domain_band_info->regulatory_tx_power.sta_pc > 0) {
				c_tx_power = regulatory_domain_band_info->regulatory_tx_power.sta_pc;
			}
			if (regulatory_domain_band_info->regulatory_tx_power.sta_pe > 0) {
				e_tx_power = regulatory_domain_band_info->regulatory_tx_power.sta_pe;
			}
		}

		if (c_tx_power == 0 && e_tx_power == 0) {
			printf("Regulatory region domain info error\n");
			retval = -EINVAL;
		}

		if (retval >= 0) {
			*p_max_power = (uint8_t)local_regulatory_calculate_tx_power(c_tx_power, e_tx_power);
		}
	} else {
		printf("Regulatory region domain info ptr is NULL\n");
	}
	return retval;
}

static int
local_get_bit_of_chan_available(const qcsapi_bw bandwidth)
{
	int bit_of_ch_available =0;

	switch (bandwidth) {
	case qcsapi_bw_20MHz:
		bit_of_ch_available = 0;
		break;
	case qcsapi_bw_40MHz:
		bit_of_ch_available = 1;
		break;
	case qcsapi_bw_80MHz:
		bit_of_ch_available = 2;
		break;
	default:
		bit_of_ch_available = 7;
		break;
	}

	return bit_of_ch_available;
}

static inline int
local_regulatory_get_supported_bands(int *first, int *last)
{
	int retval = 0;

	retval = local_regulatory_get_L1_domain_int(last, 0, TYPE_REGULATORY_DOMAIN_MAX_BAND);

	if (retval < 0)
		return -EOPNOTSUPP;

#if QTN_DUAL_BAND_RF
	int rf_chipid = 0;
	retval = local_wifi_get_rf_chipid(&rf_chipid);
	if ((retval >= 0) && rf_chipid == CHIPID_2_4_GHZ) {
		*first = MAX_2_4_GHZ_RF_BAND_INDEX;
	} else if ((retval >= 0) && rf_chipid == CHIPID_5_GHZ) {
		*last = MAX_5_GHZ_RF_BAND_INDEX;
	}
#else
	*last = MAX_5_GHZ_RF_BAND_INDEX;
#endif

	return 0;
}

static void
local_set_active_channel_list_by_bw(int skfd, const char *ifname,
	const struct tx_power_table *power_table, const qcsapi_bw bw)
{
	uint8_t chanlist_array_size = COUNT_802_11_CHANNELS / NBBY;
	int retval = 0;
	int i = 0;
	int max_bands = 0;
	uint8_t chanlist_vals[chanlist_array_size];
	struct regulatory_domain_band_info *p_band_info = NULL;
	struct regulatory_channel_info *p_ch_info = NULL;
	int bit_of_ch_available;
	struct iwreq wrq;
	struct ieee80211_active_chanlist list;

	bit_of_ch_available = local_get_bit_of_chan_available(bw);

	memset(chanlist_vals, 0, sizeof(chanlist_vals));

	retval = local_regulatory_get_supported_bands(&i, &max_bands);

	if (retval < 0)
		return;

	for (; i <= max_bands; i++) {
		retval = local_regulatory_get_regulatory_info(power_table, &p_band_info, i, NULL);

		if (retval == QCSAPI_BAND_NOT_SUPPORTED) {
			retval = 0;
			continue;
		}
		if (retval >= 0) {
			p_ch_info = p_band_info->channel_info;

			while (p_ch_info != NULL) {
				if (isset(&p_ch_info->regulatory_channel.bw, bit_of_ch_available) &&
					local_regulatory_is_channel_avaliable(power_table,
							p_ch_info->regulatory_channel.channel, bw) == 1) {
					setbit(chanlist_vals, p_ch_info->regulatory_channel.channel - 1);
				}
				p_ch_info = p_ch_info->next;
			}
			local_regulatory_free_regulatory_info(&p_band_info);
		}
	}

	if (retval >= 0) {
		list.bw = bw;
		memcpy(list.channels, chanlist_vals, chanlist_array_size);
		memset(&wrq, 0, sizeof(wrq));
		wrq.u.data.flags = SIOCDEV_SUBIO_SET_ACTIVE_CHANNEL_LIST;
		wrq.u.data.pointer = &list;
		wrq.u.data.length = sizeof(list);
		strncpy(wrq.ifr_name, ifname, IFNAMSIZ - 1);
		ioctl(skfd, IEEE80211_IOCTL_EXT, &wrq);
	}
}

static int
local_set_active_channel_lists(int skfd, const char *ifname,
	const struct tx_power_table *power_table)
{
	int retval = 0;

	retval = verify_we_device( skfd, ifname, NULL, 0 );

	if (retval < 0)
		return retval;

	/*
	 * Set the active channel list for 20Mhz, 40Mhz and 80Mhz channels in STA mode
	 */

	local_set_active_channel_list_by_bw(skfd, ifname, power_table, qcsapi_bw_20MHz);
	local_set_active_channel_list_by_bw(skfd, ifname, power_table, qcsapi_bw_40MHz);
	local_set_active_channel_list_by_bw(skfd, ifname, power_table, qcsapi_bw_80MHz);

	return 0;
}

#define MAX_CHAN_CNT	116
static int
local_regulatory_set_chan_list( int skfd, const char *ifname,
	const struct tx_power_table *power_table, const qcsapi_bw bandwidth )
{
	enum {
		chanlist_array_size = COUNT_802_11_CHANNELS / NBBY
	};
	int retval = 0;
	int retval2 = 0;
	int argc = chanlist_array_size;
	uint8_t chanlist_vals[chanlist_array_size];
	int dfs_channel[MAX_CHAN_CNT];
	int dfs_ch_cnt = 0;
	uint8_t non_primary_chanlist_vals[chanlist_array_size];
	char chanlist_strs[chanlist_array_size][4];
	char *chanlist_argv[chanlist_array_size];
	unsigned int iter;
	int i = 0;
	struct regulatory_domain_band_info *p_band_info = NULL;
	struct regulatory_non_primary_band_info *p_non_primary_band_info = NULL;
	struct regulatory_channel_info *p_ch_info= NULL;
	int max_bands = 0;
	int bit_of_ch_available;
	int rf_chipid = 0;
	int weather_radar_chs[MAX_CHAN_CNT];
	int weather_radar_chs_cnt = 0;

	retval = verify_we_device( skfd, ifname, NULL, 0 );

	if (retval < 0)
		return retval;

	retval = local_regulatory_get_L1_domain_int(&max_bands, 0, TYPE_REGULATORY_DOMAIN_MAX_BAND);

	if (retval < 0)
		return -EOPNOTSUPP;

	bit_of_ch_available = local_get_bit_of_chan_available(bandwidth);

	memset( &chanlist_vals[ 0 ], 0, sizeof( chanlist_vals ) );
	memset( &dfs_channel[ 0 ], 0, sizeof( dfs_channel) );
	memset( &non_primary_chanlist_vals[ 0 ], 0, sizeof( non_primary_chanlist_vals ) );

	retval = local_wifi_get_rf_chipid(&rf_chipid);
	if ((retval >= 0) && rf_chipid == CHIPID_2_4_GHZ) {
		/* On 2.4GHz only board RF bands - 5. Start the index from 5 */
		i = MAX_2_4_GHZ_RF_BAND_INDEX;
	} else if ((retval >= 0) && rf_chipid == CHIPID_5_GHZ) {
		/* On 5GHz only board RF bands range <1-4> */
		max_bands = MAX_5_GHZ_RF_BAND_INDEX;
	}

	for (; i <= max_bands; i ++) {
		retval = local_regulatory_get_regulatory_info(power_table, &p_band_info, i, NULL);

		if (retval == QCSAPI_BAND_NOT_SUPPORTED) {
			retval = 0;
			continue;
		}

		if (retval >= 0) {
			p_ch_info = p_band_info->channel_info;

			while (p_ch_info != NULL) {
				struct regulatory_channel *channel;
				int is_available;

				channel = &p_ch_info->regulatory_channel;
				is_available = (local_regulatory_is_channel_avaliable(
							power_table,
							channel->channel,
							bandwidth) == 1);


				if (isset(&channel->bw, bit_of_ch_available) && is_available) {
					setbit(chanlist_vals, channel->channel - 1);
				}

				if ((channel->properties & CHAN_DFS_REQUIRED) && (dfs_ch_cnt < ARRAY_SIZE(dfs_channel))) {
					dfs_channel[dfs_ch_cnt++] = channel->channel;
				}

				if ((channel->properties & CHAN_WEATHER_RADAR) && (weather_radar_chs_cnt < ARRAY_SIZE(weather_radar_chs))) {
					weather_radar_chs[weather_radar_chs_cnt++] = channel->channel;
				}

				p_ch_info = p_ch_info->next;
			}

			retval2 = local_regulatory_get_regulatory_non_primary_band_info(p_band_info->regulatory,
					&p_non_primary_band_info, p_band_info->band_index);
			if (retval2 >= 0) {
				if (p_non_primary_band_info != NULL &&
					p_non_primary_band_info->channel_info != NULL) {
					struct regulatory_non_primary_channel_info *p = p_non_primary_band_info->channel_info;

					while (p) {
						if (isset(&p->non_primary_channel.bw, bit_of_ch_available)) {
							setbit(non_primary_chanlist_vals, p->non_primary_channel.channel - 1);
						}
						p = p->next;
					}
				}
			local_regulatory_free_regulatory_non_primary_band_info(&p_non_primary_band_info);
			}
			local_regulatory_free_regulatory_info(&p_band_info);
		}
	}

	if (retval >=0) {

		for (iter = 0; iter < chanlist_array_size; iter++) {
			sprintf( &chanlist_strs[iter][0], "%d", chanlist_vals[iter] );
			chanlist_argv[ iter ] = &chanlist_strs[iter][0];
		}

		retval = call_private_ioctl(
			  skfd,
			  chanlist_argv, argc,
			  ifname,
			  "setchanlist",
			  NULL,
			  0
		);
	}

	if (retval >= 0 && dfs_ch_cnt > 0) {
		retval = local_wifi_sub_ioctl_submit(ifname,
				SIOCDEV_SUBIO_SET_MARK_DFS_CHAN,
				dfs_channel,
				dfs_ch_cnt);
	}

	if (retval >= 0 && weather_radar_chs > 0) {
		retval = local_wifi_sub_ioctl_submit(ifname,
				SIOCDEV_SUBIO_SET_WEATHER_CHAN,
				weather_radar_chs,
				weather_radar_chs_cnt);
	}

	for (i = 0; i < COUNT_802_11_CHANNELS; i++) {
		if (isset(chanlist_vals, i)) {
			int inactive = !!isset(non_primary_chanlist_vals, i);

			local_wifi_set_chan_pri_inactive(skfd, ifname, i + 1, inactive,
					CHAN_PRI_INACTIVE_CFG_DATABASE);
			if (inactive) {
				local_generic_syslog(__func__, LOG_INFO,
					"Set channel %d as inactive primary channel\n", i + 1);
			}
		}
	}

	if (retval == QCSAPI_REGION_NOT_SUPPORTED) {
		printf("Region setting is not supported\n");
	}

	return retval;
}

static int
local_regulatory_get_regulatory_tx_power(
		qcsapi_wifi_mode wifi_mode,
		const qcsapi_unsigned_int the_channel,
		const struct tx_power_table *power_table,
		const qcsapi_bw bandwidth,
		int8_t *p_tx_power
)
{
	struct regulatory_domain_band_info *regulatory_domain_band_info = NULL;
	int8_t local_tx_power = QCSAPI_TX_POWER_NOT_CONFIGURED;
	int band_index = 0;
	int retval = 0;
	int rf_chipid = 0;
	int sta_dfs_en = 0;

	band_index = local_get_band_index(the_channel);

	int max_bands = 0;

	retval = local_regulatory_get_L1_domain_int(&max_bands, 0, TYPE_REGULATORY_DOMAIN_MAX_BAND);

	if (retval < 0)
		retval = -EOPNOTSUPP;

	if (retval >= 0) {
	    retval = local_wifi_get_rf_chipid(&rf_chipid);
		if ((retval >= 0) && rf_chipid == CHIPID_5_GHZ) {
			max_bands = MAX_5_GHZ_RF_BAND_INDEX;
		}
	}

	if (band_index >= 1 && band_index <= max_bands) {

		retval = local_regulatory_get_regulatory_info(
					power_table,
					&regulatory_domain_band_info,
					band_index,
					NULL);

		if (retval == QCSAPI_BAND_NOT_SUPPORTED) {
			retval = -EINVAL;
		}

		if (retval >= 0) {
			struct regulatory_channel_info *p_ch_info= NULL;
			p_ch_info = regulatory_domain_band_info->channel_info;
			int channel_fund = 0;
			int bit_of_ch_available = local_get_bit_of_chan_available(bandwidth);

			while (p_ch_info != NULL) {
				if (the_channel == p_ch_info->regulatory_channel.channel) {
					if (isclr(&p_ch_info->regulatory_channel.bw, bit_of_ch_available))
						channel_fund = 0;
					else
						channel_fund = 1;
					break;
				}
				p_ch_info =  p_ch_info->next;
			}
			if (channel_fund == 1) {
				retval = local_get_regulatory_conductive_tx_power(
							wifi_mode,
							regulatory_domain_band_info,
							sta_dfs_en,
							&local_tx_power);

				if (retval >= 0) {
					*p_tx_power = local_tx_power;
				}
			} else {
				retval = -EINVAL;
			}
		}

		if (retval == QCSAPI_REGION_NOT_SUPPORTED) {
			printf("Region setting is not supported\n");
			retval = -EINVAL;
		}

		local_regulatory_free_regulatory_info(&regulatory_domain_band_info);

	} else {
		retval = -EINVAL;
	}

	return retval;
}

static int
local_regulatory_get_list_bands(
	const char *region_by_name,
	string_128 list_of_band
)
{
	int retval = 0;
	int rf_chipid = 0;

	if (region_by_name == NULL || list_of_band == NULL)
		retval = -EFAULT;

	if (retval >= 0) {

		int i = 1; /* Band index always starts from 1 */
		char band_str[ 12 ];
		int started_list = 0;
		int band_usable = 1;
		struct	regulatory_domain_band_info *regulatory_domain_band_info = NULL;
		struct tx_power_table power_table;

		*list_of_band = '\0';

		int max_bands = 0;

		retval = local_regulatory_get_L1_domain_int(&max_bands, 0, TYPE_REGULATORY_DOMAIN_MAX_BAND);

		if (retval < 0)
			retval = -EOPNOTSUPP;

		if (retval >= 0) {
			retval = local_wifi_get_rf_chipid(&rf_chipid);
			if ((retval >= 0) && rf_chipid == CHIPID_2_4_GHZ) {
				/* On 2.4GHz only board RF bands - 5. Start the index from 5 */
				i = MAX_2_4_GHZ_RF_BAND_INDEX;
			} else if ((retval >= 0) && rf_chipid == CHIPID_5_GHZ) {
				/* On 5GHz only board RF bands range <1-4> */
				max_bands = MAX_5_GHZ_RF_BAND_INDEX;
			}
		}

		local_init_tx_power_table(region_by_name, &power_table);

		for (; i <= max_bands; i ++) {

			retval = local_regulatory_get_regulatory_info(
						&power_table,
						&regulatory_domain_band_info,
						i,
						NULL);

			if (retval == QCSAPI_BAND_NOT_SUPPORTED) {
				retval = 0;
				band_usable = 0;
			}

			if (retval >= 0) {
				if (band_usable) {

					sprintf( &band_str[0], "%d", i);
					if (started_list == 0)
					  started_list = 1;
					else
					  strcat(list_of_band, ",");
					strcat( list_of_band, &band_str[0]);
				}
			}

			if (retval == QCSAPI_REGION_NOT_SUPPORTED) {
				printf("Region setting is not supported\n");
			}

			/* band_usable should be set to 1 for next bands */
			band_usable = 1;
			local_regulatory_free_regulatory_info(&regulatory_domain_band_info);
		}

		local_cleanup_tx_power_table(&power_table);
	}

	return( retval );

}

/*
 * Restriction:
 *     0: no additional restrictions beyond regulatory region and band width.
 *     1: DFS is NOT required for the channel.
 *     2: DFS IS required for the channel.
 */

static int
local_regulatory_get_restricted_list_channels(
	const char *region_by_name,
	const qcsapi_unsigned_int bw,
	const int restriction,
	string_1024 list_of_channels
)
{
	int retval = 0;
	int bit_of_ch_available;

	if (bw != qcsapi_bw_40MHz && bw != qcsapi_bw_20MHz && bw != qcsapi_bw_80MHz)
		return -EINVAL;

	bit_of_ch_available = local_get_bit_of_chan_available(bw);
	if (region_by_name == NULL || list_of_channels == NULL || bit_of_ch_available > 2)
		retval = -EFAULT;

	if (retval >= 0) {
		int i = 1; /* Band index always starts from 1 */
		char channel_str[ 12 ];
		int started_list = 0;
		struct regulatory_domain_band_info *regulatory_domain_band_info = NULL;
		struct regulatory_channel_info *p_ch_info = NULL;
		struct tx_power_table power_table;
		int rf_chipid = 0;

		*list_of_channels = '\0';

		int max_bands = 0;

		retval = local_regulatory_get_L1_domain_int(&max_bands, 0, TYPE_REGULATORY_DOMAIN_MAX_BAND);

		if (retval < 0)
			retval = -EOPNOTSUPP;

		if (retval >= 0) {
			retval = local_wifi_get_rf_chipid(&rf_chipid);
			if ((retval >= 0) && rf_chipid == CHIPID_2_4_GHZ) {
				/* On 2.4GHz only board RF bands - 5. Start the index from 5 */
				i = MAX_2_4_GHZ_RF_BAND_INDEX;
			} else if ((retval >= 0) && rf_chipid == CHIPID_5_GHZ) {
				/* On 5GHz only board RF bands range <1-4> */
				max_bands = MAX_5_GHZ_RF_BAND_INDEX;
			}
		}

		local_init_tx_power_table(region_by_name, &power_table);

		for (; i <= max_bands; i ++) {

			retval = local_regulatory_get_regulatory_info(
						&power_table,
						&regulatory_domain_band_info,
						i,
						NULL);

			if (retval == QCSAPI_BAND_NOT_SUPPORTED) {
				retval = 0;
				continue;
			}

			if (retval == QCSAPI_REGION_NOT_SUPPORTED) {
				printf("region setting is not supported\n");
				retval = -EINVAL;
				break;
			}

			if (retval >= 0) {
				p_ch_info = regulatory_domain_band_info->channel_info;
			}

			while (p_ch_info != NULL) {
				int	channel_usable = 1;
				if ((isclr(&p_ch_info->regulatory_channel.bw, bit_of_ch_available)) ||
						local_regulatory_is_channel_avaliable(&power_table, p_ch_info->regulatory_channel.channel, bw) == 0) {
					channel_usable = 0;
				}

				if (channel_usable) {

					if (restriction == 1 &&
							(p_ch_info->regulatory_channel.properties & CHAN_DFS_REQUIRED)) {
						channel_usable = 0;
					}
					else if (restriction == 2 &&
					       !(p_ch_info->regulatory_channel.properties & CHAN_DFS_REQUIRED)) {
						channel_usable = 0;
					}

				}

				if (channel_usable) {

					sprintf( &channel_str[0], "%d", p_ch_info->regulatory_channel.channel);
					if (started_list == 0)
					  started_list = 1;
					else
					  strcat(list_of_channels, ",");
					strcat( list_of_channels, &channel_str[0]);
				}

				p_ch_info = p_ch_info->next;
			}

			local_regulatory_free_regulatory_info(&regulatory_domain_band_info);
		}

		local_cleanup_tx_power_table(&power_table);
	}

	return( retval );
}

static int
local_regulatory_get_configured_tx_power(
	const qcsapi_unsigned_int the_channel,
	const struct tx_power_table *power_table,
	const uint8_t power_index,
	const qcsapi_bw bandwidth,
	const qcsapi_wifi_mode wifi_mode,
	int *p_configured_power
)
{
	int8_t regulatory_tx_power = 0;
	int default_tx_power = local_bootcfg_get_default_tx_power();
	int configured_tx_power = default_tx_power;
	int retval = 0;
	int retval2 = 0;
	int8_t database_tx_power = 0;

	retval = local_regulatory_get_regulatory_tx_power(
				wifi_mode, the_channel,
				power_table,
				bandwidth,
				&regulatory_tx_power);

	if (retval >= 0) {
		if (regulatory_tx_power < configured_tx_power)
			configured_tx_power = regulatory_tx_power;

		retval2 = local_regulatory_get_tx_power_info(
					power_table,
					the_channel,
					power_index,
					bandwidth,
					NULL,
					NULL,
					NULL,
					&database_tx_power);

		if (retval2 >= 0 || database_tx_power > 0) {
			if (database_tx_power < configured_tx_power)
				configured_tx_power = database_tx_power;
		}
	}

	if (retval >= 0)
		*p_configured_power = configured_tx_power;

	return retval;
}

static int
local_regulatory_get_current_channel_bw_region(
	int skfd,
	const char *ifname,
	qcsapi_unsigned_int *p_channel,
	qcsapi_bw *p_bw,
	char *p_current_region)
{
	int retval = 0;
	qcsapi_unsigned_int local_channel;
	char local_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION];
	qcsapi_bw local_bw = qcsapi_nosuch_bw;

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

	*p_channel = local_channel;
	*p_bw = local_bw;
	strcpy(p_current_region, &local_region[0]);

	return retval;
}

int
local_use_new_tx_power(void)
{
	int retval = -qcsapi_region_database_not_found;
	FILE *fp = NULL;
	struct stat file_stat;

	fp = fopen(QTN_REGULATORY_DB_BIN, "r");
	if (fp != NULL) {
		retval = 1;
		fclose(fp);
	} else if (stat(QTN_REGULATORY_DB_PATH, &file_stat) == 0) {
		char database_path[256]={0};

		if ((long long)file_stat.st_size < sizeof(database_path)) {
			fp = fopen(QTN_REGULATORY_DB_PATH, "r");
		}

		if (fp != NULL) {
			fscanf(fp, "%s", database_path);
			fclose(fp);
			fp = NULL;

			if (stat(database_path, &file_stat) == 0) {
				retval = 1;
			}
		}
	}

	return retval;
}

/*
 * Get regulatory tx power from database.
 * EIRP has higher priority than conducted tx power limit.
 * Station mode has higher priority than AP mode.
 * Return 0 if anything wrong.
 */
static int
local_get_regulatory_tx_power(
	qcsapi_wifi_mode wifi_mode,
	struct regulatory_domain_band_info *regulatory_domain_band_info,
	int sta_dfs_en
)
{
	int8_t c_tx_power = 0, e_tx_power = 0;

	if (regulatory_domain_band_info != NULL) {
		if (regulatory_domain_band_info->regulatory_tx_power.ap_pc > 0) {
			c_tx_power = regulatory_domain_band_info->regulatory_tx_power.ap_pc;
		}

		if (regulatory_domain_band_info->regulatory_tx_power.ap_pe > 0) {
			e_tx_power = regulatory_domain_band_info->regulatory_tx_power.ap_pe;
		}

		/*
		 * Replace EIRP or Conducted tx power limit if regulatory define station mode power.
		 * And it will be configured to driver and sent out by Country IE to STA for
		 * multiple regulatory domain support.
		 */
		if (wifi_mode == qcsapi_station && sta_dfs_en == 0) {
			if (regulatory_domain_band_info->regulatory_tx_power.sta_pc > 0) {
				c_tx_power = regulatory_domain_band_info->regulatory_tx_power.sta_pc;
			}
			if (regulatory_domain_band_info->regulatory_tx_power.sta_pe > 0) {
				e_tx_power = regulatory_domain_band_info->regulatory_tx_power.sta_pe;
			}
		}

		if (e_tx_power > 0) {
			return e_tx_power;
		} else {
			return c_tx_power;
		}
	} else {
		return 0;
	}
}

int local_regulatory_set_bw_power(const char *ifname,
			const qcsapi_unsigned_int the_channel,
			const qcsapi_unsigned_int bf_on,
			const qcsapi_unsigned_int number_ss,
			const int power_20M,
			const int power_40M,
			const int power_80M)
{
	int retval = 0;
	int min_tx_power = local_bootcfg_get_min_tx_power();
	int max_tx_power = local_bootcfg_get_default_tx_power();
	int8_t configured_tx_power_20M;
	int8_t configured_tx_power_40M;
	int8_t configured_tx_power_80M;
	int8_t regulatory_tx_power;
	int skfd = -1;
	qcsapi_bw bandwidth = qcsapi_bw_40MHz;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char curr_region_name[QCSAPI_MIN_LENGTH_REGULATORY_REGION];

	retval = local_use_new_tx_power();
	if (retval < 0) {
		local_generic_syslog(__func__, LOG_ERR,
			"File %s doesn't exist\n",QTN_REGULATORY_DB_BIN);
		return retval;
	}

	if (the_channel > QCSAPI_MAX_CHANNEL || the_channel < QCSAPI_MIN_CHANNEL)
		retval = -EINVAL;

	if (number_ss <= 0 || number_ss > QCSAPI_QDRV_NUM_RF_STREAMS)
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
	}

	if (retval >= 0 && strcasecmp(curr_region_name, "none")) {
		struct tx_power_table power_table;

		local_init_tx_power_table(curr_region_name, &power_table);

		if (local_regulatory_get_regulatory_tx_power(
					wifi_mode,
					the_channel,
					&power_table,
					bandwidth,
					&regulatory_tx_power) < 0) {
			regulatory_tx_power = max_tx_power;
		}

		if (local_regulatory_get_tx_power_info(
				&power_table,
				the_channel,
				(bf_on ? QCSAPI_POWER_INDEX_BFON_1SS :
						QCSAPI_POWER_INDEX_BFOFF_1SS) + number_ss - 1,
				bandwidth,
				&configured_tx_power_80M,
				&configured_tx_power_40M,
				&configured_tx_power_20M,
				NULL) < 0) {
			configured_tx_power_20M = max_tx_power;
			configured_tx_power_40M = max_tx_power;
			configured_tx_power_80M = max_tx_power;
		}

		local_cleanup_tx_power_table(&power_table);
	} else if (retval >= 0) {
		regulatory_tx_power = max_tx_power;
		configured_tx_power_20M = max_tx_power;
		configured_tx_power_40M = max_tx_power;
		configured_tx_power_80M = max_tx_power;
	} else {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		regulatory_tx_power = MIN(regulatory_tx_power, max_tx_power);
		if (power_20M && configured_tx_power_20M != -1) {
			if (power_20M < min_tx_power ||
					power_20M > regulatory_tx_power ||
					power_20M > configured_tx_power_20M) {
				local_generic_syslog(__func__, LOG_ERR,
					"Invalid 20MHz power! should be less than %d and larger than %d\n",
					MIN(regulatory_tx_power, configured_tx_power_20M), min_tx_power);
				retval = -EINVAL;
			}
		}
		if (power_40M && configured_tx_power_40M != -1) {
			if (power_40M < min_tx_power ||
					power_40M > regulatory_tx_power ||
					power_40M > configured_tx_power_40M) {
				local_generic_syslog(__func__, LOG_ERR,
					"Invalid 40MHz power! should be less than %d and larger than %d\n",
					MIN(regulatory_tx_power, configured_tx_power_40M), min_tx_power);
				retval = -EINVAL;
			}
		}
		if (power_80M && configured_tx_power_80M != -1) {
			if (power_80M < min_tx_power ||
					power_80M > regulatory_tx_power ||
					power_80M > configured_tx_power_80M) {
				local_generic_syslog(__func__, LOG_ERR,
					"Invalid 80MHz power! should be less than %d and larger than %d\n",
					MIN(regulatory_tx_power, configured_tx_power_80M), min_tx_power);
				retval = -EINVAL;
			}
		}
		if (retval >= 0) {
			if (power_20M && configured_tx_power_20M != -1) {
				retval = local_wifi_configure_bw_tx_power(
						skfd,
						ifname,
						the_channel,
						bf_on,
						number_ss,
						QTN_BW_20M,
						power_20M);
			}
		}
		if (retval >= 0) {
			if (power_40M && configured_tx_power_40M != -1) {
				retval = local_wifi_configure_bw_tx_power(
						skfd,
						ifname,
						the_channel,
						bf_on,
						number_ss,
						QTN_BW_40M,
						power_40M);
			}
		}
		if (retval >= 0) {
			if (power_80M && configured_tx_power_80M != -1) {
				retval = local_wifi_configure_bw_tx_power(
						skfd,
						ifname,
						the_channel,
						bf_on,
						number_ss,
						QTN_BW_80M,
						power_80M);
			}
		}
	}

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	return retval;
}

static int
local_regulatory_set_regulatory_tx_power_by_ch(
	int skfd,
	const char *ifname,
	const struct tx_power_table *power_table,
	qcsapi_wifi_mode wifi_mode,
	struct regulatory_domain_band_info *p_band_info,
	int channel,
	qcsapi_bw bandwidth,
	int sta_dfs_en
)
{
	int8_t power_config_80M;
	int8_t power_config_40M;
	int8_t power_config_20M;
	int8_t power_config;
	int pwr_idx;
	int index;
	int bf_on;
	int num_ss;
	int idx_bf;
	int idx_ss;
	int default_tx_power = local_bootcfg_get_default_tx_power();
	int min_tx_power = local_bootcfg_get_min_tx_power();
	int8_t regulatory_max_power = 0;
	int regulatory_tx_power = 0;
	int retval;
	struct chan_tx_power_data tx_power_data;
	struct ieee80211_chan_power_table chan_power_table;

	retval = local_get_regulatory_conductive_tx_power(
			wifi_mode,
			p_band_info,
			sta_dfs_en,
			&regulatory_max_power);
	if (retval < 0) {
		return retval;
	}

	regulatory_tx_power = local_get_regulatory_tx_power(wifi_mode, p_band_info, sta_dfs_en);

	memset(&chan_power_table, 0, sizeof(chan_power_table));
	chan_power_table.chan_ieee = channel;

	memset(&tx_power_data, 0, sizeof(tx_power_data));
	local_get_chan_tx_power_data_from_power_table(power_table, channel, &tx_power_data);

	for (pwr_idx = QCSAPI_POWER_INDEX_BFOFF_1SS; pwr_idx < QCSAPI_POWER_TOTAL; pwr_idx++)
	{
		bf_on = pwr_idx >= QCSAPI_POWER_INDEX_BFON_1SS;
		num_ss = pwr_idx + 1 -
				(bf_on ? QCSAPI_POWER_INDEX_BFON_1SS : QCSAPI_POWER_INDEX_BFOFF_1SS);
		idx_bf = PWR_IDX_BF_OFF + bf_on;
		idx_ss = PWR_IDX_1SS + num_ss - 1;

		if (tx_power_data.valid_index_count == 0) {
			power_config_80M = default_tx_power;
			power_config_40M = default_tx_power;
			power_config_20M = default_tx_power;
			power_config = default_tx_power;
		} else {
			index = power_table_mapping[tx_power_data.valid_index_count - 1][pwr_idx];
			power_config_80M = (index == -1) ? -1 : tx_power_data.power_80M[index];
			power_config_40M = (index == -1) ? -1 : tx_power_data.power_40M[index];
			power_config_20M = (index == -1) ? -1 : tx_power_data.power_20M[index];
			switch (bandwidth) {
			case qcsapi_bw_80MHz:
				power_config = power_config_80M;
				break;
			case qcsapi_bw_40MHz:
				power_config = power_config_40M;
				break;
			default:
				power_config = power_config_20M;
				break;
			}
		}

		if (retval >= 0) {
			if (pwr_idx == QCSAPI_POWER_INDEX_BFOFF_1SS) {
				if (power_config != -1) {
					if (power_config < min_tx_power) {
						power_config = min_tx_power;
					}
					power_config = (power_config >= regulatory_max_power) ?
							MIN(regulatory_max_power, default_tx_power):
							MIN(power_config, default_tx_power);
				}
			}
			if (bandwidth >= qcsapi_bw_80MHz && power_config_80M > 0) {
				if (power_config_80M < min_tx_power) {
					power_config_80M = min_tx_power;
				}
				power_config_80M = (power_config_80M >= regulatory_max_power) ?
						MIN(regulatory_max_power, default_tx_power):
						MIN(power_config_80M, default_tx_power);
			}
			if (bandwidth >= qcsapi_bw_40MHz && power_config_40M > 0) {
				if (power_config_40M < min_tx_power) {
					power_config_40M = min_tx_power;
				}
				power_config_40M = (power_config_40M >= regulatory_max_power) ?
						MIN(regulatory_max_power, default_tx_power):
						MIN(power_config_40M, default_tx_power);
			}
			if (power_config_20M > 0) {
				if (power_config_20M < min_tx_power) {
					power_config_20M = min_tx_power;
				}
				power_config_20M = (power_config_20M >= regulatory_max_power) ?
						MIN(regulatory_max_power, default_tx_power):
						MIN(power_config_20M, default_tx_power);
			}
		}

		chan_power_table.maxpower_table[idx_bf][idx_ss][PWR_IDX_20M] = power_config_20M;
		chan_power_table.maxpower_table[idx_bf][idx_ss][PWR_IDX_40M] = power_config_40M;
		chan_power_table.maxpower_table[idx_bf][idx_ss][PWR_IDX_80M] = power_config_80M;

		if (pwr_idx == QCSAPI_POWER_INDEX_BFOFF_1SS) {
			retval = local_wifi_configure_band_tx_power(
					skfd,
					ifname,
					channel,
					channel,
					power_config,
					min_tx_power
			);
			local_wifi_configure_regulatory_tx_power(
					skfd,
					ifname,
					channel,
					channel,
					regulatory_tx_power
					);
		}

		if (pwr_idx == (QCSAPI_POWER_INDEX_BFOFF_1SS + QCSAPI_POWER_TOTAL - 1) && retval >= 0) {
			retval = local_wifi_set_chan_power_table(ifname, &chan_power_table);
		}
	}

	return 0;
}

static int
local_regulatory_set_regulatory_tx_power_by_region(
	int skfd,
	const char *ifname,
	const struct tx_power_table *power_table,
	qcsapi_wifi_mode wifi_mode,
	qcsapi_bw bandwidth
)
{
	struct regulatory_domain_band_info *p_band_info = NULL;
	struct regulatory_channel_info *p_ch_info = NULL;
	int i = 0;
	int max_bands = 0;
	int sta_dfs_en = 0;
	int retval = 0;

	retval = local_regulatory_get_L1_domain_int(&max_bands, 0,  TYPE_REGULATORY_DOMAIN_MAX_BAND);

	if (retval < 0)
		return -EOPNOTSUPP;

	if (retval >= 0) {
		retval = local_wifi_option_getparam(skfd, ifname, IEEE80211_PARAM_MARKDFS, &sta_dfs_en);
	}

	i = 1;
	if (retval >= 0) {
		int rf_chipid = 0;
		retval = local_wifi_get_rf_chipid(&rf_chipid);
		if ((retval >= 0) && rf_chipid == CHIPID_2_4_GHZ) {
			/* On 2.4GHz only board RF bands - 5. Start the index from 5 */
			i = MAX_2_4_GHZ_RF_BAND_INDEX;
		} else if ((retval >= 0) && rf_chipid == CHIPID_5_GHZ) {
			/* On 5GHz only board RF bands range <1-4> */
			max_bands = MAX_5_GHZ_RF_BAND_INDEX;
		}
	}
	for (; i <= max_bands; i++) {
		retval = local_regulatory_get_regulatory_info(power_table, &p_band_info, i, NULL);

		if (retval >= 0) {
			p_ch_info = p_band_info->channel_info;
			while (p_ch_info != NULL) {
				if (local_regulatory_set_regulatory_tx_power_by_ch(
						skfd,
						ifname,
						power_table,
						wifi_mode,
						p_band_info,
						p_ch_info->regulatory_channel.channel,
						bandwidth,
						sta_dfs_en) < 0) {
					local_regulatory_free_regulatory_info(&p_band_info);
					return -EOPNOTSUPP;
				}
				p_ch_info = p_ch_info->next;
			}
		} else if (retval == QCSAPI_BAND_NOT_SUPPORTED) {
			retval = 0;
			continue;
		}
		local_regulatory_free_regulatory_info(&p_band_info);
	}

	return 0;
}

static int
__local_regulatory_set_chan_power_table(
		const char *ifname,
		qcsapi_wifi_mode wifi_mode,
		qcsapi_bw bandwidth,
		struct tx_power_table *power_table,
		qcsapi_channel_power_table *power_from_user
)
{
	int8_t power_config[PWR_IDX_BW_MAX];
	int8_t power_per_index_from_table[PWR_IDX_BW_MAX];
	int8_t regulatory_tx_power;
	int index;
	int pwr_idx;
	int bf_on;
	int num_ss;
	int idx_bf;
	int idx_ss;
	int idx_bw;
	int retval;
	int max_tx_power = local_bootcfg_get_default_tx_power();
	int min_tx_power = local_bootcfg_get_min_tx_power();
	struct chan_tx_power_data power_from_table;
	struct ieee80211_chan_power_table power_from_qdrv;
	struct ieee80211_chan_power_table power_to_qdrv;

	power_from_qdrv.chan_ieee = power_from_user->channel;
	retval = local_wifi_get_chan_power_table(ifname, &power_from_qdrv);
	if (retval < 0 || power_from_qdrv.chan_ieee == 0) {
		return -1;
	}

	power_per_index_from_table[PWR_IDX_20M] = max_tx_power;
	power_per_index_from_table[PWR_IDX_40M] = max_tx_power;
	power_per_index_from_table[PWR_IDX_80M] = max_tx_power;
	if (power_table) {
		memset(&power_from_table, 0, sizeof(power_from_table));
		local_get_chan_tx_power_data_from_power_table(
				power_table,
				power_from_user->channel,
				&power_from_table);
		if (power_from_table.valid_index_count == 0) {
			return -1;
		}

		if (local_regulatory_get_regulatory_tx_power(
				wifi_mode,
				power_from_user->channel,
				power_table,
				bandwidth,
				&regulatory_tx_power) < 0) {
			regulatory_tx_power = max_tx_power;
		} else {
			regulatory_tx_power = MIN(regulatory_tx_power, max_tx_power);
		}
	} else {
		regulatory_tx_power = max_tx_power;
	}

	memset(&power_to_qdrv, 0, sizeof(power_to_qdrv));
	power_to_qdrv.chan_ieee = power_from_user->channel;

	for (pwr_idx = QCSAPI_POWER_INDEX_BFOFF_1SS; pwr_idx < QCSAPI_POWER_TOTAL; pwr_idx++)
	{
		bf_on = pwr_idx >= QCSAPI_POWER_INDEX_BFON_1SS;
		num_ss = pwr_idx + 1 -
				(bf_on ? QCSAPI_POWER_INDEX_BFON_1SS : QCSAPI_POWER_INDEX_BFOFF_1SS);
		idx_bf = PWR_IDX_BF_OFF + bf_on;
		idx_ss = PWR_IDX_1SS + num_ss - 1;

		power_config[PWR_IDX_80M] = power_from_user->power_80M[pwr_idx];
		power_config[PWR_IDX_40M] = power_from_user->power_40M[pwr_idx];
		power_config[PWR_IDX_20M] = power_from_user->power_20M[pwr_idx];

		if (power_table) {
			index = power_table_mapping[power_from_table.valid_index_count - 1][pwr_idx];
			power_per_index_from_table[PWR_IDX_80M] =
					(index == -1) ? -1 : power_from_table.power_80M[index];
			power_per_index_from_table[PWR_IDX_40M] =
					(index == -1) ? -1 : power_from_table.power_40M[index];
			power_per_index_from_table[PWR_IDX_20M] =
					(index == -1) ? -1 : power_from_table.power_20M[index];
		}

		for (idx_bw = PWR_IDX_20M; idx_bw < PWR_IDX_BW_MAX; idx_bw++) {
			if (power_per_index_from_table[idx_bw] == -1 ||
					power_config[idx_bw] < min_tx_power) {
				power_config[idx_bw] =
						power_from_qdrv.maxpower_table[idx_bf][idx_ss][idx_bw];
			} else if (power_config[idx_bw] > regulatory_tx_power ||
					power_config[idx_bw] > power_per_index_from_table[idx_bw]) {
				power_config[idx_bw] =
						MIN(regulatory_tx_power, power_per_index_from_table[idx_bw]);
			}
			power_to_qdrv.maxpower_table[idx_bf][idx_ss][idx_bw] = power_config[idx_bw];
		}
	}

	retval = local_wifi_set_chan_power_table(ifname, &power_to_qdrv);

	return retval;
}

int local_regulatory_set_chan_power_table(const char *ifname,
		qcsapi_channel_power_table *chan_power_table)
{
	int retval = 0;
	int skfd = -1;
	char current_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION] = {'\0'};
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	qcsapi_bw bandwidth = 0;
	struct tx_power_table power_table;
	struct tx_power_table *power_table_p = NULL;

	retval = local_use_new_tx_power();

	if (retval < 0) {
		return retval;
	}

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}

	if (retval >= 0) {
		retval = local_wifi_get_bandwidth( skfd, ifname, &bandwidth );
	}

	if (retval >= 0) {
		retval = local_get_internal_regulatory_region(skfd, ifname, &current_region[0]);
	}

	if (retval >= 0) {
		if (strcasecmp(&current_region[0], "none")) {
			power_table_p = &power_table;
			local_init_tx_power_table(current_region, power_table_p);
		}

		retval = __local_regulatory_set_chan_power_table(
				ifname,
				wifi_mode,
				bandwidth,
				power_table_p,
				chan_power_table);

		if (power_table_p) {
			local_cleanup_tx_power_table(power_table_p);
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	return retval;
}

int
local_regulatory_set_regulatory_region(
	const char *ifname,
	const char *region_by_name
)
{
	int retval = 0;
	int retval2 = -1;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char regulatory_by_name[4] = {'\0'};
	qcsapi_bw bandwidth = 0;
	retval = local_use_new_tx_power();
	struct tx_power_table power_table;

	if (retval < 0) {
		return retval;
	}

	if (ifname == NULL || region_by_name == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_wifi_get_bandwidth( skfd, ifname, &bandwidth );
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		char	current_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION];

		retval = local_get_internal_regulatory_region(skfd, ifname, &current_region[0]);
		if (strcasecmp(&current_region[0], "none") != 0 &&
				strcasecmp(&current_region[0], region_by_name) != 0) {
			retval = -EOPNOTSUPP;
		}
	}

	if (region_by_name != NULL)
		local_init_tx_power_table(region_by_name, &power_table);

	if (retval >= 0) {
		if (wifi_mode == qcsapi_station) {
			retval = local_set_active_channel_lists(skfd, ifname, &power_table);
			if (retval < 0) {
				printf("STA mode active channels by bw could not be set\n");
			}
		}

		retval = local_regulatory_set_chan_list(skfd, ifname, &power_table, bandwidth);
	}

	if (retval == QCSAPI_REGION_NOT_SUPPORTED) {
		printf("region setting is not supported\n");
		retval = -EINVAL;
	}

	if (retval >= 0) {
		int dfs_band_index = 3;
		int rf_chipid = 0;

		retval2 = local_wifi_get_rf_chipid(&rf_chipid);
		if ((retval2 >= 0) && rf_chipid == CHIPID_5_GHZ) {
			do {
				memset( &regulatory_by_name[ 0 ], 0, sizeof( regulatory_by_name ) );
				retval2 = local_regulatory_get_regulatory_info(&power_table, NULL, dfs_band_index, regulatory_by_name);
			}while (retval2 < 0 && dfs_band_index-- > 2);
		}
	}

	if (retval2 >= 0) {
		local_regulatory_setup_radar(skfd, ifname, regulatory_by_name);
		local_set_internal_regulatory_region(skfd, ifname, region_by_name, 1);

		/* For AP mode, always enable radar detection
		 * For STA mode, enable/disable radar detection according to user config
		 * Note: here no check on retval is on purpose for supporting dynamical mode reloading
		 */
		local_wifi_check_radar_mode(ifname, regulatory_by_name, skfd);
	}

	if (retval >= 0) {
		retval = local_regulatory_set_regulatory_tx_power_by_region(skfd, ifname, &power_table,
					wifi_mode, bandwidth);
	}

	if (region_by_name != NULL)
		local_cleanup_tx_power_table(&power_table);

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	return retval;
}

int
qcsapi_regulatory_set_regulatory_region(
	const char *ifname,
	const char *region_by_name
)
{
	int retval;

	enter_qcsapi();
	retval = local_regulatory_set_regulatory_region(ifname, region_by_name);
	leave_qcsapi();

	return retval;
}

int
qcsapi_regulatory_restore_regulatory_tx_power(const char *ifname)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char current_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION] = {'\0'};
	qcsapi_bw bandwidth = 0;

	enter_qcsapi();

	retval = local_use_new_tx_power();

	if (retval < 0) {
		return retval;
	}

	if (ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_wifi_get_bandwidth( skfd, ifname, &bandwidth );
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}

	if (retval >= 0) {
		retval = local_get_internal_regulatory_region(skfd, ifname, &current_region[0]);
		if (strcasecmp(&current_region[0], "none") == 0) {
			retval = -EOPNOTSUPP;
		}
	}

	if (retval >= 0) {
		struct tx_power_table power_table;

		local_init_tx_power_table(current_region, &power_table);
		retval = local_regulatory_set_regulatory_tx_power_by_region(skfd, ifname, &power_table,
					wifi_mode, bandwidth);
		local_cleanup_tx_power_table(&power_table);
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_regulatory_get_regulatory_tx_power(
	const char *ifname,
	const qcsapi_unsigned_int the_channel,
	const char *region_by_name,
	int *p_tx_power
)
{
	int retval = 0;
	int8_t local_tx_power = QCSAPI_TX_POWER_NOT_CONFIGURED;
	int skfd = -1;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;

	enter_qcsapi();

	retval = local_use_new_tx_power();

	if (retval < 0) {
		leave_qcsapi();
		return retval;
	}

	if (p_tx_power == NULL || region_by_name == NULL || ifname == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error( &skfd );
	}

	if (retval >= 0) {
		retval = local_wifi_get_mode( skfd, ifname, &wifi_mode );
	}
  /*
   * Provide access to the regulatory TX power if calstate = 1.
   */
	if (retval >= 0) {
		char calstate_value[ 4 ] = { '\0' };
		int ival = local_bootcfg_get_parameter("calstate", &calstate_value[0], sizeof(calstate_value));

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
	if (retval >= 0) {
		struct tx_power_table power_table;

		local_init_tx_power_table(region_by_name, &power_table);
		retval = local_regulatory_get_regulatory_tx_power(
					wifi_mode,
					the_channel,
					&power_table,
					qcsapi_bw_20MHz,
					&local_tx_power);
		local_cleanup_tx_power_table(&power_table);
	}

	if (retval >= 0) {
		*p_tx_power = local_tx_power;
	}

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return retval;
}

int
qcsapi_regulatory_get_list_regulatory_regions(
		string_256 list_regulatory_regions
)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_use_new_tx_power();

	if (retval < 0) {
		leave_qcsapi();
		return retval;
	}

	if (list_regulatory_regions == NULL) {
		retval = -EFAULT;
	} else {
		local_regulatory_get_list_regulatory_regions(list_regulatory_regions);
	}

	leave_qcsapi();

	return( retval );
}

int
qcsapi_regulatory_get_list_regulatory_channels(
	const char *region_by_name,
	const qcsapi_unsigned_int bw,
	string_1024 list_of_channels
)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_use_new_tx_power();

	if (retval < 0) {
		leave_qcsapi();
		return retval;
	}

	retval = local_regulatory_get_restricted_list_channels( region_by_name, bw, 0, list_of_channels );

	leave_qcsapi();

	return( retval );
}

int
qcsapi_regulatory_get_list_regulatory_bands(
	const char *region_by_name,
	string_128 list_of_bands
)
{
	int retval = 0;

	enter_qcsapi();

	retval = local_use_new_tx_power();

	if (retval < 0) {
		leave_qcsapi();
		return retval;
	}

	retval = local_regulatory_get_list_bands(region_by_name, list_of_bands);

	leave_qcsapi();

	return( retval );
}

int
qcsapi_regulatory_get_list_DFS_channels(
	const char *region_by_name,
	const int DFS_flag,
	const qcsapi_unsigned_int bw,
	string_1024 list_of_channels
)
{
	int retval = 0;
	int local_restriction = 0;

	enter_qcsapi();

	retval = local_use_new_tx_power();

	if (retval < 0) {
		leave_qcsapi();
		return retval;
	}

	if (DFS_flag == 0) {
		local_restriction = 1;
	} else if (DFS_flag == 1) {
		local_restriction = 2;
	} else {
		retval = -EINVAL;
	}

	if (retval >= 0) {
		retval = local_regulatory_get_restricted_list_channels(
					region_by_name,
					bw,
					local_restriction,
					list_of_channels );
	}

	leave_qcsapi();

	return( retval );
}

/*
 * Channel is either subject to DFS restrictions or it is not.  Bandwidth does not matter.
 */
static int local_regulatory_is_channel_DFS(
		const struct tx_power_table *power_table,
		const qcsapi_unsigned_int the_channel,
		int *p_channel_is_DFS
)
{
	int retval = 0;
	struct regulatory_domain_band_info *p_band_info= NULL;
	struct regulatory_channel_info *p_ch_info= NULL;
	uint8_t band_index = 0;
	qcsapi_bw bw = qcsapi_bw_20MHz;
	int skfd = -1;
	int rf_chipid = 0;

	retval = local_open_iw_socket_with_error(&skfd);

	if (p_channel_is_DFS == NULL)
	  retval = -EFAULT;

	if (retval >= 0) {

		int bit_of_ch_available = 0;
		int found_entry = 0;

		band_index = local_get_band_index(the_channel);

		retval = local_wifi_get_rf_chipid(&rf_chipid);
		if ((retval >= 0) && rf_chipid == CHIPID_2_4_GHZ) {
			/* On 2.4GHz only board RF bands - 5. Start the index from 5 */
			if (band_index < MAX_2_4_GHZ_RF_BAND_INDEX) {
				retval = -EINVAL;
			}
		} else if ((retval >= 0) && rf_chipid == CHIPID_5_GHZ) {
			/* On 5GHz only board RF bands range <1-4> */
			if(band_index > MAX_5_GHZ_RF_BAND_INDEX) {
				retval = -EINVAL;
			}
		}

		if (retval >= 0)
			retval = local_regulatory_get_regulatory_info(
					power_table,
					&p_band_info,
					band_index,
					NULL);

		if (retval >= 0) {
			retval = local_wifi_get_bandwidth(skfd, "wifi0", &bw);
		}

		if (retval >= 0) {
			p_ch_info = p_band_info->channel_info;
		}

		bit_of_ch_available = local_get_bit_of_chan_available(bw);

		while (p_ch_info != NULL) {

			if (p_ch_info->regulatory_channel.channel == the_channel &&
					isset(&p_ch_info->regulatory_channel.bw, bit_of_ch_available) &&
					local_regulatory_is_channel_avaliable(power_table,
							p_ch_info->regulatory_channel.channel, bw) == 1) {
				found_entry = 1;

				if (p_ch_info->regulatory_channel.properties & CHAN_DFS_REQUIRED)
					*p_channel_is_DFS = 1;
				else
					*p_channel_is_DFS = 0;
			}

			p_ch_info = p_ch_info->next;
		}

		local_regulatory_free_regulatory_info(&p_band_info);

		if (found_entry == 0)
			retval = -EINVAL;

		if (retval == QCSAPI_REGION_NOT_SUPPORTED) {
			printf("region setting is not supported\n");
			retval = -EINVAL;
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	return retval;
}

int
qcsapi_regulatory_is_channel_DFS(
		const char *region_by_name,
		const qcsapi_unsigned_int the_channel,
		int *p_channel_is_DFS
)
{
	int retval = 0;
	struct tx_power_table power_table;

	enter_qcsapi();

	retval = local_use_new_tx_power();

	if (retval < 0) {
		leave_qcsapi();
		return retval;
	}

	if (region_by_name == NULL) {
		leave_qcsapi();
		return -EFAULT;
	}

	local_init_tx_power_table(region_by_name, &power_table);

	retval = local_regulatory_is_channel_DFS(&power_table,
				the_channel,
				p_channel_is_DFS);

	local_cleanup_tx_power_table(&power_table);

	leave_qcsapi();

	return retval;
}

int qcsapi_regulatory_get_configured_tx_power_ext(
		const char *ifname,
		const qcsapi_unsigned_int the_channel,
		const char *region_by_name,
		const qcsapi_bw the_bw,
		const qcsapi_unsigned_int bf_on,
		const qcsapi_unsigned_int number_ss,
		int *p_tx_power)
{
	int retval = 0;
	int skfd = -1;
	char calstate[4];
	qcsapi_wifi_mode wifi_mode = qcsapi_access_point;
	int tx_power_max = 0;
	uint8_t power_index;

	enter_qcsapi();

	if (!ifname || !region_by_name || !p_tx_power
			|| (the_channel > QCSAPI_MAX_CHANNEL)
			|| (the_channel < QCSAPI_MIN_CHANNEL)
			|| (number_ss < 1)
			|| (number_ss > QCSAPI_QDRV_NUM_RF_STREAMS))
		retval = -EFAULT;

	if (retval >= 0) {
		if ((the_bw != qcsapi_bw_20MHz)
				&& (the_bw != qcsapi_bw_40MHz)
				&& (the_bw != qcsapi_bw_80MHz))
			retval = -EFAULT;
	}

	if (retval >= 0)
		retval = local_use_new_tx_power();

	if (retval >= 0)
		retval = local_open_iw_socket_with_error(&skfd);

	if (retval >= 0) {
		if ((local_bootcfg_get_parameter("calstate", calstate, sizeof(calstate)) >= 0)
				&& (strcmp(calstate, "1") == 0)) {
			/* If calstate = 1, default to AP as the WiFi mode */
			wifi_mode = qcsapi_access_point;
		} else {
			retval = local_wifi_get_mode(skfd, ifname, &wifi_mode);

			if (retval >= 0)
				retval = local_verify_interface_is_primary(ifname);
		}
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
		skfd = -1;
	}

	if (retval >= 0) {
		struct tx_power_table power_table;

		power_index = (bf_on ? QCSAPI_POWER_INDEX_BFON_1SS :
				QCSAPI_POWER_INDEX_BFOFF_1SS) + number_ss - 1;

		local_init_tx_power_table(region_by_name, &power_table);
		retval = local_regulatory_get_configured_tx_power(
					the_channel,
					&power_table,
					power_index,
					the_bw,
					wifi_mode,
					&tx_power_max);
		local_cleanup_tx_power_table(&power_table);
	}

	if (retval >= 0)
		*p_tx_power = tx_power_max;

	leave_qcsapi();

	return retval;
}

int
qcsapi_regulatory_get_configured_tx_power(
		const char *ifname,
		const qcsapi_unsigned_int the_channel,
		const char *region_by_name,
		const qcsapi_unsigned_int the_bw,
		int *p_tx_power)
{
	/* beamforming off, one spatial stream */
	return qcsapi_regulatory_get_configured_tx_power_ext(
			ifname,
			the_channel,
			region_by_name,
			the_bw,
			0,
			1,
			p_tx_power);
}

int
qcsapi_regulatory_set_regulatory_channel(
	const char *ifname,
	const qcsapi_unsigned_int the_channel,
	const char *region_by_name,
	const qcsapi_unsigned_int tx_power_offset
)
{
	int retval = 0;
	int local_tx_power = 0;
	int min_tx_power = local_bootcfg_get_min_tx_power();
	int max_tx_power = local_bootcfg_get_default_tx_power();
	int configured_tx_power;
	int skfd = -1;
	int8_t regulatory_tx_power_limit;
	qcsapi_bw bandwidth = qcsapi_bw_40MHz;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char current_region_by_name[QCSAPI_MIN_LENGTH_REGULATORY_REGION] = {'\0'};
	struct tx_power_table power_table;

	if (region_by_name == NULL)
		return -EINVAL;

	enter_qcsapi();

	retval = local_use_new_tx_power();

	if (retval < 0) {
		leave_qcsapi();
		return retval;
	}

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

	/*
	 * Get the current regulatory region and power limits of this region
	 */
	if (retval >= 0) {
		retval = local_get_internal_regulatory_region( skfd, ifname, &current_region_by_name[0]);
	}

	if (retval >= 0) {
		if (strcasecmp(current_region_by_name, region_by_name) != 0) {
			retval = -EINVAL;
		}
	}

	local_init_tx_power_table(current_region_by_name, &power_table);

	if (retval >= 0) {
		retval = local_regulatory_get_regulatory_tx_power(
					wifi_mode,
					the_channel,
					&power_table,
					bandwidth,
					&regulatory_tx_power_limit);
	}

	if (retval >= 0 && regulatory_tx_power_limit < 1) {
		retval = -qcsapi_configuration_error;
	}

	/*
	 * Get configured transmit power of the given regulatory region
	 */

	if (retval >= 0) {
		retval = local_regulatory_get_configured_tx_power(
					the_channel,
					&power_table,
					QCSAPI_POWER_INDEX_BFOFF_1SS,
					bandwidth,
					wifi_mode,
					&configured_tx_power);
	}

	if (retval >= 0) {
		local_tx_power = configured_tx_power - tx_power_offset;

		if (local_tx_power < min_tx_power ||
				local_tx_power > max_tx_power ||
				local_tx_power > regulatory_tx_power_limit ||
				local_tx_power > configured_tx_power) {
			retval = -EINVAL;
		}
		/*
		 * First configure TX power for the channel - then set the channel
		 */
		if (retval >= 0) {
			retval = local_wifi_set_tx_power( skfd, ifname, the_channel, local_tx_power );
		}

		if (retval >= 0) {
			retval = local_wifi_set_channel(skfd, ifname, the_channel);
		}
	}

	local_cleanup_tx_power_table(&power_table);

	if (skfd >= 0) {
		local_close_iw_sockets( skfd );
	}

	leave_qcsapi();

	return( retval );
}

int
local_regulatory_set_tx_power(const char *ifname,
			const qcsapi_unsigned_int the_channel,
			const int tx_power)
{
	int retval = 0;
	int min_tx_power = local_bootcfg_get_min_tx_power();
	int max_tx_power = local_bootcfg_get_default_tx_power();
	int8_t regulatory_tx_power_limit;
	uint8_t pwr_idx;
	int tmp_tx_power = 0;
	int configured_tx_power = max_tx_power;
	int skfd = -1;
	qcsapi_bw bandwidth = qcsapi_bw_40MHz;
	qcsapi_wifi_mode wifi_mode = qcsapi_nosuch_mode;
	char curr_region_name[QCSAPI_MIN_LENGTH_REGULATORY_REGION] = { '\0' };
	struct tx_power_table power_table;

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
	}

	local_init_tx_power_table(curr_region_name, &power_table);

	if (retval >= 0 && strcasecmp(curr_region_name, "none")) {
		retval = local_regulatory_get_regulatory_tx_power(
					wifi_mode,
					the_channel,
					&power_table,
					bandwidth,
					&regulatory_tx_power_limit);

		if (retval >= 0 && regulatory_tx_power_limit < 1)
			retval = -qcsapi_configuration_error;
	} else if (retval >= 0) {
		regulatory_tx_power_limit = max_tx_power;
		configured_tx_power = max_tx_power;
	}

	if (retval >= 0) {
		if (tx_power < min_tx_power || tx_power > max_tx_power ||
				tx_power > regulatory_tx_power_limit ||
				tx_power > configured_tx_power)
			retval = -EINVAL;
	}

	if (retval >= 0) {
		int qtn_bw;
		int num_ss;
		int bf_on;
		int retval2;

		switch (bandwidth) {
		case qcsapi_bw_80MHz:
			qtn_bw = QTN_BW_80M;
			break;
		case qcsapi_bw_40MHz:
			qtn_bw = QTN_BW_40M;
			break;
		default:
			qtn_bw = QTN_BW_20M;
			break;
		}

		for (pwr_idx = QCSAPI_POWER_INDEX_BFOFF_1SS;
				pwr_idx < QCSAPI_POWER_TOTAL; pwr_idx++)
		{
			bf_on = pwr_idx >= QCSAPI_POWER_INDEX_BFON_1SS;
			num_ss = pwr_idx + 1 - (bf_on ? QCSAPI_POWER_INDEX_BFON_1SS :
					QCSAPI_POWER_INDEX_BFOFF_1SS);

			if (strcasecmp(curr_region_name, "none") == 0 ||
					local_regulatory_get_configured_tx_power(
							the_channel,
							&power_table,
							pwr_idx,
							bandwidth,
							wifi_mode,
							&tmp_tx_power) < 0) {
				tmp_tx_power = 0;
			}
			if (tmp_tx_power != -1) {
				if (tmp_tx_power > 0 && tx_power > tmp_tx_power) {
					retval = -EINVAL;
				} else {
					retval2 = local_wifi_configure_bw_tx_power(
							skfd,
							ifname,
							the_channel,
							bf_on,
							num_ss,
							qtn_bw,
							tx_power);
					if (retval2 < 0 && retval >= 0) {
						retval = retval2;
					}
				}
			}
		}
	}

	local_cleanup_tx_power_table(&power_table);

	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	return retval;
}

int
local_regulatory_get_supported_tx_power_levels(
	const char *ifname,
	string_128 available_percentages)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_wifi_mode current_wifi_mode = qcsapi_mode_not_defined;
	qcsapi_unsigned_int current_channel = 0;
	qcsapi_bw current_bw = qcsapi_nosuch_bw;
	int8_t regulatory_tx_power_limit = 0;
	int configured_tx_power = 0;
	int min_tx_power = 0;
	int tx_power_iter = 0;
	char current_region_by_name[QCSAPI_MIN_LENGTH_REGULATORY_REGION] = {'\0'};
	struct tx_power_table power_table;

	if (ifname == NULL || available_percentages == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval < 0)
		goto ready_to_return;

	retval = local_regulatory_get_current_channel_bw_region(
				skfd,
				ifname,
				&current_channel,
				&current_bw,
				current_region_by_name);

	if (retval < 0)
		goto ready_to_return;

	local_init_tx_power_table(current_region_by_name, &power_table);

	retval = local_regulatory_get_regulatory_tx_power(
				current_wifi_mode,
				current_channel,
				&power_table,
				current_bw,
				&regulatory_tx_power_limit);

	if (retval >= 0 && regulatory_tx_power_limit < 1)
		retval = -qcsapi_configuration_error;

	if (retval < 0) {
		local_cleanup_tx_power_table(&power_table);
		goto ready_to_return;
	}

	retval = local_regulatory_get_configured_tx_power(
				current_channel,
				&power_table,
				QCSAPI_POWER_INDEX_BFOFF_1SS,
				current_bw,
				current_wifi_mode,
				&configured_tx_power);

	local_cleanup_tx_power_table(&power_table);

	if (retval < 0)
		goto ready_to_return;

	min_tx_power = local_bootcfg_get_min_tx_power();

	available_percentages[0] = '\0';

	for (tx_power_iter = min_tx_power;
			tx_power_iter <= configured_tx_power;
			tx_power_iter++) {

		unsigned int tx_power_percentage = POWER_PERCENTAGE(tx_power_iter, configured_tx_power);
		char	percentage_str[6];

		snprintf(&percentage_str[0], sizeof(percentage_str), "%u", tx_power_percentage);
		if (tx_power_iter > min_tx_power) {
			strcat(available_percentages, ",");
		}
		strcat(available_percentages, &percentage_str[0]);
	}

  ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	return retval;
}

int
local_regulatory_get_current_tx_power_level(
	const char *ifname,
	uint32_t *p_current_percentage)
{
	int retval = 0;
	int skfd = -1;
	qcsapi_unsigned_int current_channel;
	qcsapi_bw current_bw;
	qcsapi_wifi_mode current_wifi_mode = -qcsapi_nosuch_mode;
	int local_tx_power = 0;
	int configured_tx_power = 0;
	char current_region_by_name[QCSAPI_MIN_LENGTH_REGULATORY_REGION] = {'\0'};
	struct tx_power_table power_table;

	if (ifname == NULL || p_current_percentage == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_regulatory_get_current_channel_bw_region(
				skfd,
				ifname,
				&current_channel,
				&current_bw,
				current_region_by_name);

	if (retval < 0) {
		goto ready_to_return;
	}

	retval = local_get_tx_power(skfd, ifname, current_channel, &local_tx_power);

	if (retval < 0) {
		goto ready_to_return;
	}

	local_init_tx_power_table(current_region_by_name, &power_table);

	retval = local_regulatory_get_configured_tx_power(
				current_channel,
				&power_table,
				QCSAPI_POWER_INDEX_BFOFF_1SS,
				current_bw,
				current_wifi_mode,
				&configured_tx_power);

	local_cleanup_tx_power_table(&power_table);

	if (retval < 0) {
		goto ready_to_return;
	}

	if (local_tx_power < 1) {
		local_tx_power = 1;
	}

	*p_current_percentage = POWER_PERCENTAGE(local_tx_power, configured_tx_power);

  ready_to_return:
	if (skfd >= 0)
		local_close_iw_sockets(skfd);

	return retval;
}

int qcsapi_regulatory_get_regulatory_domain(
		const int band_index,
		const char *region_by_name,
		char *p_regulatory_name

)
{
	int retval = 0;
	enter_qcsapi();
	retval = local_get_regulatory_domain(region_by_name, band_index, p_regulatory_name);
	leave_qcsapi();

	return retval;
}

int qcsapi_regulatory_overwrite_country_code(
	const char *ifname,
	const char *curr_country_name,
	const char *new_country_name)
{
	int retval = 0;
	int skfd = -1;
	char current_region[6] = {0};
	const char *eu_region = NULL;
	int is_eu_region = 0;

	enter_qcsapi();

	if (ifname == NULL || new_country_name == NULL) {
		retval = -EFAULT;
	} else {
		retval = local_open_iw_socket_with_error(&skfd);
	}

	if (retval >= 0) {
		retval = local_verify_interface_is_primary(ifname);
	}

	if (retval >= 0) {
		retval = local_get_internal_regulatory_region(skfd, ifname, current_region);
	}

	if (retval >= 0) {
		if (strncasecmp(current_region, curr_country_name, 2) != 0) {
			retval = -qcsapi_region_not_supported;
		}
	}

	if (retval >= 0) {
		eu_region = get_default_region_name(QCSAPI_REGION_EUROPE);
		if (strncasecmp(eu_region, current_region, 2) == 0)
			is_eu_region = 1;
		if ((is_eu_region == 0) && (local_use_new_tx_power() == 1))
			retval = -qcsapi_configuration_error;
	}

	if (retval >= 0) {
		retval = local_wifi_set_country_code(skfd, ifname, new_country_name);
	}

	if (retval >= 0) {
		retval = local_wifi_enable_country_ie(skfd, ifname, 1);
	}

	if (skfd >= 0) {
		local_close_iw_sockets(skfd);
	}

	leave_qcsapi();

	return retval;
}

int local_qcsapi_regulatory_disable_dfs_channels(const char *ifname, const int scheme, const int inp_chan)
{
	int			retval = 0,
				skfd = -1;
	qcsapi_bw		band_width = qcsapi_nosuch_bw;
	int			is_channel_DFS = 0;
	char			local_region[QCSAPI_MIN_LENGTH_REGULATORY_REGION] = { '\0' };
	struct tx_power_table	power_table;

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

	local_init_tx_power_table(local_region, &power_table);

	if (retval >= 0) {
		if (scheme > 0 && inp_chan > 0) {
			retval = local_regulatory_is_channel_DFS(&power_table,
						inp_chan,
						&is_channel_DFS);

			if (retval >= 0 && is_channel_DFS > 0)
				retval = -EINVAL;
		}
	}

	if (retval >= 0)
		retval = local_wifi_get_bandwidth(skfd, ifname, &band_width);

	if (retval >= 0) {
		retval = local_wifi_pre_deactive_DFS_channels(skfd, ifname, scheme);
	}

	if (retval >= 0) {
		retval = local_regulatory_set_chan_list(skfd,
					ifname, &power_table, band_width);
	}

	/* Forces a channel switch to avoid keep in a DFS channel */
	/* if non DFS option has been selected */
	if (retval >= 0 && skfd >= 0 && inp_chan > 0) {
		retval = local_wifi_set_channel(skfd, ifname, inp_chan);
	}

	local_cleanup_tx_power_table(&power_table);

	if (skfd >= 0)
		local_close_iw_sockets( skfd );

	if(retval >= 0)
		retval = 0;

	return retval;
}

int qcsapi_regulatory_get_db_version(int *p_version, const int index)
{
	int retval = 0;

	enter_qcsapi();
	*p_version = 0;
	retval = local_regulatory_get_L1_domain_int(p_version, index, TYPE_REGULATORY_DOMAIN_VERSION);
	leave_qcsapi();

	return retval;
}

int qcsapi_regulatory_apply_tx_power_cap(int capped)
{
	int retval = 0;

	enter_qcsapi();
	retval = local_regulatory_apply_tx_power_cap(capped);
	leave_qcsapi();

	return retval;
}

