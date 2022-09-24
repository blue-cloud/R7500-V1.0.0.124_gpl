/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2014 Quantenna Communications Inc                   **
**                            All Rights Reserved                            **
**                                                                           **
**                                                                           **
*******************************************************************************
EH0*/
#include <linux/types.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/io.h>
#include <linux/igmp.h>
#include <linux/hardirq.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ctype.h>
#include <linux/if_ether.h>
#include <linux/net/bridge/br_public.h>
#include <linux/moduleloader.h>

#include <net80211/if_ethersubr.h>
#include <net80211/ieee80211.h>

#include <qtn/qtn_debug.h>
#include <qtn/qtn_uc_comm.h>
#include <qtn/qtn_net_packet.h>
#include <qtn/iputil.h>
#include <qtn/topaz_tqe.h>
#include <qtn/topaz_tqe_cpuif.h>
#include <qtn/topaz_fwt_cpuif.h>
#include <qtn/topaz_fwt_if.h>
#include <qtn/topaz_fwt_sw.h>
#include <qtn/topaz_fwt_db.h>
#include <qtn/topaz_fwt.h>
#include <qtn/topaz_tqe.h>
#include <qtn/mproc_sync_base.h>

MODULE_DESCRIPTION("Forwarding Table");
MODULE_AUTHOR("Quantenna Communications, Inc.");
MODULE_LICENSE("Proprietary");
MODULE_VERSION("1.0");

#define PRINT_FWT(a...)		do { if (g_debug) { printk(a); } } while(0)

const char *const g_port_names[] = TOPAZ_TQE_PORT_NAMES;

/* Set success return status */
#define FWT_SW_STATUS_SUCCESS (1)

/* Set to true to see prints of changing stats in FWT*/
static int g_debug = 1;

/* FWT entries counter */
static uint16_t g_fwt_ent_cnt = 0;

/* FWT interface service enable / disable indication */
static int g_is_enable = 1;

/* Enable / Disable the ageing mechanism */
static int g_ageing_enable = 1;

/* User Mode: allow entries to be inserted with no limitation from console */
static int g_auto_mode = 1;

struct _fwt_qdrv_cb {
	fwt_fetch_timestamp fetch_ts;
	fwt_notify_entry_add notify_entry_add;
	void *ctx;
} fwt_qdrv_cbs;

/*
 * The current FWT algorithm hash table ensure that the first level entries are always
 * empty slot before the second level entries in order to speed up the lookup indexer.
 * In scenarios where there is a need to delete first level entry and there is a matching
 * second level entry we extract second level entry and place it over the first level.
 * later on the algorithm declare that the second level entry should be deleted.
 * We register this callback function to the fwt.c delete function to keep up the same
 * delete method and keep both HW and SW tables synchronise.
 * @param src_index: The extracted entry
 * @param dst_index: The overwrite table entry.
 */
static void fwt_sw_overwrite_table_entries(uint16_t dst_index, uint16_t src_index)
{
	fwt_db_entry *src_element = fwt_db_get_table_entry(src_index);

	fwt_db_table_insert(dst_index, src_element);
}

static int fwt_sw_is_exists(int fwt_index)
{
	fwt_db_entry *db;

	if (fwt_index < 0) {
		return 0;
	}

	/* get the current entry by index */
	db = fwt_db_get_table_entry(fwt_index);

	/* if its the same index then the device was already inserted */
	return (db && (db->fwt_index == fwt_index));
}

static bool fwt_sw_is_last_node(const struct topaz_fwt_sw_mcast_entry *e)
{
	if (!topaz_fwt_sw_mcast_is_flood_forward(e) &&
			topaz_fwt_sw_mcast_entry_nodes_clear(e)) {
		return e->port_bitmap == 0;
	}

	return false;
}

/* Rules for valid FWT entry
* @param node_num: The candidate node number from new entry
* @param port_id: port number corresponding to the TQE enumeration
*/
static bool fwt_sw_is_valid_entry(uint8_t node_num, uint8_t port_id)
{
	bool is_valid = true;

	switch (port_id) {
	case TOPAZ_TQE_WMAC_PORT:
		/* node can't be zero for WMAC entry */
		if (node_num == 0) {
			is_valid = false;
		}
		break;
	default:
		return true;
	}
	return is_valid;
}

/*
 * Validate the fwt table entry before placing it to FWT HW.
 * in case where there is a negative index by the FWT HW algorithm
 * the entry cannot be placed.
 * @param element: the fwt element entry info
 *
 */
static int fwt_sw_sync_entry(fwt_db_entry *element)
{
	int index = -1;
	if (fwt_sw_is_valid_entry(element->out_node, element->out_port)) {
		/* TODO: Handle FWT full scenario, delete unused / old entries  */
		index = topaz_fwt_add_entry(element->mac_id,
				element->out_port, &element->out_node,
				1, element->portal);
	}
	return index;
}

static void inline fwt_sw_disable_auto_ageing(bool disable)
{
	uint32_t val;

	val = readl(TOPAZ_FWT_TIME_STAMP_CTRL);
	val = TOPAZ_FWT_SET_BIT_FIELD(val, TOPAZ_FWT_TIME_STAMP_DIS_AUTO_UPDATE_S, 1, disable);
	qtn_mproc_sync_mem_write_wmb(TOPAZ_FWT_TIME_STAMP_CTRL, val);
}

/*
 * Delete a node from a multicast entry.
 * If they become empty, possibly delete the multicast entry, the alias_table, and the fwt entry.
 */
static int fwt_sw_delete_node(struct fwt_db_entry *db_ent,
		uint8_t port_id, uint8_t node_num, uint8_t ip_alias)
{
	struct topaz_fwt_sw_mcast_entry *mcast_entry;
	int mcast_last_node;

	mcast_entry = fwt_db_get_sw_mcast(db_ent, ip_alias);

	if (mcast_entry == NULL) {
		return -ENOENT;
	}

	if (topaz_fwt_sw_mcast_port_has_nodes(port_id)) {
		topaz_fwt_sw_mcast_node_clear(mcast_entry, port_id, node_num);
	} else {
		topaz_fwt_sw_mcast_port_clear(mcast_entry, port_id);
	}
	topaz_fwt_sw_mcast_flush(mcast_entry);

	/* update the node list */
	fwt_db_delete_index_from_node_table(node_num, db_ent->fwt_index, ip_alias, port_id);

	mcast_last_node = fwt_sw_is_last_node(mcast_entry);
	PRINT_FWT("FWT: [%pM] delete node, port:%s node:%u ip_alias:%u%s\n",
			db_ent->mac_id, g_port_names[port_id], node_num,
			ip_alias, mcast_last_node ? " (empty)" : "");
	/* if this is the last multicast entry, delete it */
	if (unlikely(mcast_last_node)) {
		if (unlikely(fwt_db_delete_sw_mcast(db_ent, ip_alias))) {
			fwt_sw_delete_device(db_ent->mac_id);
		}
	}

	return 0;
}

static int fwt_sw_update_params(uint16_t index, uint8_t new_port,
		uint8_t new_node, bool use_4addr)
{
	fwt_db_entry *entry = fwt_db_get_table_entry(index);
	uint8_t old_node;
	uint8_t old_port;
	/* TODO: Update the enable parameter once the service enable / disable node is back*/
	bool enable = true;
	int rc;

	if (!entry->valid) {
		return -1;
	}

	old_port = entry->out_port;
	old_node = entry->out_node;

	fwt_db_update_timestamp(index);

	/* check if update is needed */
	if (new_port == entry->out_port && new_node == old_node) {
		return -EPERM;
	}

	/*
	 * Update the HW entry before the SW one
	 * and change parameters in the HW entry
	 */
	rc = topaz_update_entry(index, new_port, use_4addr, 0, new_node, enable);
	if (FWT_IF_ERROR(rc)) {
		return rc;
	}

	topaz_fwt_sw_entry_set(index, new_port, &new_node, 1, use_4addr);

	rc = fwt_db_update_params(index, new_port, new_node, use_4addr);
	if (FWT_IF_ERROR(rc)) {
		return rc;
	}

	/* update the node table */
	fwt_db_delete_index_from_node_table(old_node, index, FWT_DB_INVALID_IPV4, new_port);
	fwt_db_add_new_node(new_node, index, NULL, new_port);

	PRINT_FWT("FWT: [%pM] updated, port:%s->%s node:%d->%d\n",
			entry->mac_id,
			g_port_names[old_port], g_port_names[new_port],
			old_node, new_node);

	return FWT_SW_STATUS_SUCCESS;
}
static fwt_sw_remapper_t g_fwt_sw_remappers[TOPAZ_TQE_NUM_PORTS];

void fwt_sw_register_port_remapper(uint8_t port, fwt_sw_remapper_t remapper)
{
	if (port < ARRAY_SIZE(g_fwt_sw_remappers)) {
		g_fwt_sw_remappers[port] = remapper;
	}
}
EXPORT_SYMBOL(fwt_sw_register_port_remapper);

static uint8_t fwt_sw_remap_port(uint8_t port_id, const uint8_t *mac_be)
{
	if (port_id < ARRAY_SIZE(g_fwt_sw_remappers) &&
			g_fwt_sw_remappers[port_id]) {
		return g_fwt_sw_remappers[port_id](port_id, mac_be);
	}

	return port_id;
}

RUBY_INLINE int fwt_sw_scale_to_jiffies(int scale)
{
	if (scale >= 0) {
		return scale * TOPAZ_FWT_RESOLUTION_MSEC * HZ / 1000;
	} else {
		return ULONG_MAX;
	}
}

void fwt_sw_update_false_miss(int index, uint8_t false_miss)
{
#ifndef TOPAZ_DISABLE_FWT_WAR
	struct fwt_db_entry *db_ent;

	db_ent = fwt_db_get_table_entry(index);
	if (db_ent && db_ent->fwt_index == index) {
		db_ent->false_miss += false_miss;
	}
#endif
}
EXPORT_SYMBOL(fwt_sw_update_false_miss);

int fwt_sw_get_index_from_mac_be(const uint8_t *mac_be)
{

	int timeout;
	union topaz_fwt_lookup fwt_lu;
	uint8_t false_miss = 0;
	if (mac_be == NULL) {
		return -EINVAL;
	}

	fwt_lu = topaz_fwt_hw_lookup_wait_be(mac_be, &timeout, &false_miss);
	if (!timeout && fwt_lu.data.valid) {
		if (false_miss)
			fwt_sw_update_false_miss(fwt_lu.data.entry_addr, false_miss);
		return fwt_lu.data.entry_addr;
	} else {
		if (timeout) {
			printk(KERN_CRIT "%s: fwt lookup timeout\n", __FUNCTION__);
		}
		return -ENOENT;
	}
}
EXPORT_SYMBOL(fwt_sw_get_index_from_mac_be);

static void fwt_sw_auto_mode(int enable)
{
	if (enable == false) {
		br_register_hooks_cbk_t(NULL, NULL, NULL, NULL);
		br_register_mult_cbk_t(NULL, NULL);
	} else {
		br_register_hooks_cbk_t(fwt_sw_add_device, fwt_sw_delete_device,
				fwt_sw_get_timestamp, fwt_sw_get_entries_cnt);
		br_register_mult_cbk_t(fwt_sw_leave_multicast, fwt_sw_join_multicast);
	}
	g_auto_mode = enable;
}

int fwt_sw_get_ipff(char *buf, int buflen)
{
	return fwt_db_get_ipff(buf, buflen);
}

int fwt_sw_cmd(fwt_if_usr_cmd cmd, struct fwt_if_common* data)
{
	int i;
	int rc;

	if (!data) {
		return -1;
	}
	switch(cmd) {
	case FWT_IF_CMD_CLEAR:
		fwt_sw_reset();
		break;
	case FWT_IF_CMD_ON:
	case FWT_IF_CMD_OFF:
		g_is_enable = data->param;
		break;
	case FWT_IF_CMD_PRINT:
		fwt_sw_print();
		break;
	case FWT_IF_CMD_AGEING:
		g_ageing_enable = data->param;
		break;
	case FWT_IF_CMD_DEBUG:
		g_debug = data->param;
		break;
	case FWT_IF_CMD_AUTO:
	case FWT_IF_CMD_MANUAL:
		fwt_sw_auto_mode(data->param);
		break;
	case FWT_IF_CMD_ADD:
		if (ETHER_IS_MULTICAST(data->id.mac_be)) {
			for (i = 0; i < FWT_IF_USER_NODE_MAX; i++) {
				if ( data->node[i] != FWT_DB_INVALID_NODE) {
					rc = fwt_sw_join_multicast(data->node[i], data->port,
									&data->id.ip);
					PRINT_FWT("FWT: [%pM] add mc port:%s node:%d rc:%d\n",
							data->id.mac_be, g_port_names[data->port],
							data->node[i], rc);
				}
			}
		} else {
			fwt_sw_add_device(data->id.mac_be, data->port, data->node[0], NULL);
		}
		break;
	case FWT_IF_CMD_DELETE:
		fwt_sw_delete_device(data->id.mac_be);
		break;
	case FWT_IF_CMD_4ADDR:
		fwt_sw_set_4_address_support(data->id.mac_be, data->param);
		break;
	default:
		return -1;
		break;
	}
	return 1;
}
EXPORT_SYMBOL(fwt_sw_cmd);

/*
 * Remove entry from both FWT HW and SW.
 * @param mac_id: MAC ID in big endian representation
 * Note: the delete algorithm call swap call back for ensuring the first level entries are always
 * first before the second ones.
 */
int fwt_sw_delete_device(const uint8_t *mac_be)
{
	int index = -EINVAL;
	fwt_db_entry *delete_element;

	if (mac_be == NULL ) {
		return -EINVAL;
	}

	/* get the index from the FWT HW algorithm */
	index = fwt_sw_get_index_from_mac_be(mac_be);

	/* check for index error */
	if (FWT_IF_SUCCESS(index)) {

		delete_element = fwt_db_get_table_entry(index);

		if (!delete_element) {
			return -EINVAL;
		}

		/* first perform clean up for any node for the specific deleted device */
		if (delete_element->out_node != FWT_DB_INVALID_NODE) {
			/*
			 * In cases where FWT entry is remove we need to maintain the specific index from
			 * the node table since its not relevant anymore.
			 * We conduct the maintenance procedure in order to take advantage of the knowledge
			 * of the specific node index so we can avoid going through the whole database when
			 * one ask to remove node
			 */
			fwt_db_delete_index_from_node_table(
					delete_element->out_node,
					index, FWT_DB_INVALID_IPV4, delete_element->out_port);
		}
		g_fwt_ent_cnt--;
		PRINT_FWT("FWT: [%pM] delete entry, index:%d\n", mac_be, index);


		/* safe to delete FWT HW entry */
		index = topaz_fwt_del_entry(mac_be);

		/* remove from mirror table */
		fwt_db_delete_table_entry(index);
	}

	return index;
}
EXPORT_SYMBOL(fwt_sw_delete_device);

uint16_t fwt_sw_get_entries_cnt(void)
{
	return g_fwt_ent_cnt;
}

int fwt_sw_set_4_address_support(const uint8_t *mac_be, fwt_sw_4addr_status addr)
{
	fwt_db_entry *fwt_db_entry;
	int table_index;

	/* Ignore adding node if service disabled */
	if (!g_is_enable) {
		return -EPERM;
	}

	if (mac_be == NULL ) {
		return -EINVAL;
	}

	/* Validate logical HW compatible portal status */
	if (addr >= FWT_SW_4_ADDR_MAX) {
		return -EPERM;
	}

	/* find fwt entry */
	table_index = fwt_sw_get_index_from_mac_be(mac_be);
	if (table_index < 0) {
		return -ENOENT;
	}

	/* get the device entry from the fwt if database */
	fwt_db_entry = fwt_db_get_table_entry(table_index);

	if (fwt_db_entry) {
		/* Update the SW FWT table */
		fwt_db_entry->portal = addr;
		/* Update the HW FWT table */
		topaz_set_portal(table_index, addr);

		return FWT_SW_STATUS_SUCCESS;
	} else {
		return -ENOENT;
	}
}

uint32_t fwt_sw_get_entry_aging(int index)
{
	uint32_t lhost_diff = ULONG_MAX;
	uint32_t muc_diff = ULONG_MAX;

	lhost_diff = (uint32_t)jiffies - fwt_db_get_timestamp(index);
	if (fwt_qdrv_cbs.ctx && fwt_qdrv_cbs.fetch_ts) {
		uint32_t muc_j;
		muc_j = fwt_qdrv_cbs.fetch_ts(fwt_qdrv_cbs.ctx, index);
		if (muc_j != ULONG_MAX)
			muc_diff = (uint32_t)jiffies - muc_j;
	}

	return lhost_diff < muc_diff ? lhost_diff : muc_diff;
}

uint32_t fwt_sw_get_timestamp(const uint8_t *mac_be)
{
	int age_scaled = -1;
	int fwt_index;
	uint32_t diff = ULONG_MAX;
	uint32_t sw_diff = ULONG_MAX;

	if (!g_is_enable) {
		return -1;
	}

	if (!g_ageing_enable) {
		return -1;
	}

	fwt_sw_disable_auto_ageing(true);

	fwt_index = fwt_sw_get_index_from_mac_be(mac_be);

	age_scaled = fwt_db_calculate_ageing_scale(fwt_index);
	fwt_sw_disable_auto_ageing(false);

	diff = fwt_sw_scale_to_jiffies(age_scaled);
	sw_diff = fwt_sw_get_entry_aging(fwt_index);

	return min(diff, sw_diff);
}

int fwt_sw_remove_node(uint8_t node_num)
{
	fwt_db_node_element *node_element;
	fwt_db_node_iterator *ptr;
	struct fwt_db_entry *db_ent;

	int fwt_index;
	int count = 0;
	uint8_t port;
	uint8_t ip;

	node_num = IEEE80211_NODE_IDX_UNMAP(node_num);

	ptr = fwt_db_iterator_acquire(node_num);

	while (ptr && ptr->element) {

		/* Get the current point iterator element and advance the iterator for next cycle */
		node_element = fwt_db_iterator_next(&ptr);
		ip = node_element->ip_alias;
		port = node_element->port;
		fwt_index = node_element->index;

		/* Get the device entry from the fwt if database */
		db_ent = fwt_db_get_table_entry(fwt_index);
		if (fwt_sw_delete_node(db_ent, port, node_num, ip) >= 0) {
			count++;
		}
	}

	fwt_db_iterator_release();

	return count;
}
EXPORT_SYMBOL(fwt_sw_remove_node);

static fwt_sw_4addr_callback_t fwt_sw_4addr_callback = NULL;
static void *fwt_sw_4addr_callback_token = NULL;

void fwt_sw_4addr_callback_set(fwt_sw_4addr_callback_t callback, void *token)
{
	fwt_sw_4addr_callback = callback;
	fwt_sw_4addr_callback_token = token;
}
EXPORT_SYMBOL(fwt_sw_4addr_callback_set);

void fwt_sw_register_node(uint8_t node_num, uint8_t vap_idx)
{
	struct topaz_fwt_sw_mcast_entry *mcast_entry = fwt_db_get_sw_mcast_ff(vap_idx);

	node_num = IEEE80211_NODE_IDX_UNMAP(node_num);
	if (node_num >= TOPAZ_FWT_SW_NODE_MAX) {
		return;
	}

	topaz_fwt_sw_mcast_node_set(mcast_entry, TOPAZ_TQE_WMAC_PORT, node_num);

	topaz_fwt_sw_mcast_flush(mcast_entry);
}
EXPORT_SYMBOL(fwt_sw_register_node);

void fwt_sw_unregister_node(uint8_t node_num, uint8_t vap_idx)
{
	struct topaz_fwt_sw_mcast_entry *mcast_entry = fwt_db_get_sw_mcast_ff(vap_idx);

	node_num = IEEE80211_NODE_IDX_UNMAP(node_num);
	if (node_num >= TOPAZ_FWT_SW_NODE_MAX) {
		return;
	}

	topaz_fwt_sw_mcast_node_clear(mcast_entry, TOPAZ_TQE_WMAC_PORT, node_num);

	topaz_fwt_sw_mcast_flush(mcast_entry);
}
EXPORT_SYMBOL(fwt_sw_unregister_node);

static int fwt_sw_add_new_node(const uint8_t *mac_be, uint8_t node_num, uint8_t port,
				const struct br_ip *group)
{
	struct fwt_db_entry *db_ent;
	struct topaz_fwt_sw_mcast_entry *mcast_entry;
	int fwt_index;

	/* Ignore adding node if service disabled */
	if (!g_is_enable) {
		return -EPERM;
	}

	if (mac_be == NULL ) {
		return -EINVAL;
	}

	node_num = IEEE80211_NODE_IDX_UNMAP(node_num);

	/* find fwt entry */
	fwt_index = fwt_sw_get_index_from_mac_be(mac_be);
	if (fwt_index < 0) {
		return -ENOENT;
	}

	if (group == NULL) {
		return -EINVAL;
	}

	/* get the device entry from the fwt if database */
	db_ent = fwt_db_get_table_entry(fwt_index);
	mcast_entry = fwt_db_get_or_add_sw_mcast(db_ent, group);
	if (mcast_entry == NULL) {
		return -ENOENT;
	}

	/* prevent duplicate node */
	if (topaz_fwt_sw_mcast_node_is_set(mcast_entry, port, node_num)) {
		return -EPERM;
	}

	topaz_fwt_sw_mcast_port_set(mcast_entry, port);
	if ((port == TOPAZ_TQE_WMAC_PORT) && (node_num == 0)) {
		topaz_fwt_sw_mcast_flood_forward_set(mcast_entry, 1);
	} else {
		topaz_fwt_sw_mcast_node_set(mcast_entry, port, node_num);
	}
	topaz_fwt_sw_mcast_flush(mcast_entry);

	/* set node list */
	if (fwt_db_add_new_node(node_num, fwt_index, group, port) == false) {
		return -EINVAL;
	}

	if (group->proto == htons(ETHERTYPE_IPV6)) {
		PRINT_FWT("FWT: [%pM] add IPv6: %pI6", mac_be, &group->u.ip6);
	} else {
		PRINT_FWT("FWT: [%pM] add IPv4: %pI4", mac_be, &group->u.ip4);
	}
	PRINT_FWT(" port:%s node:%d\n", g_port_names[port], node_num);

	return 1;
}

int fwt_sw_add_device(const uint8_t *mac_be, uint8_t port_id, uint8_t node_num,
		const struct br_ip *group)
{
	int use_4addr = FWT_SW_DEFAULT_4ADDR;
	fwt_db_entry new_device;
	int fwt_index;
	/* Ignore adding new device if service disabled */
	if (!g_is_enable) {
		return -EPERM;
	}

	if (ETHER_IS_MULTICAST(mac_be) && (group == NULL)) {
		return -EINVAL;
	}
	node_num = IEEE80211_NODE_IDX_UNMAP(node_num);
	port_id = fwt_sw_remap_port(port_id, mac_be);
	/*
	 * In an 'portal' mode callback is registered, determine whether this FWT
	 * entry should be registered as 3addr or 4addr
	 */
	if (fwt_sw_4addr_callback && !ETHER_IS_MULTICAST(mac_be)) {
		use_4addr = fwt_sw_4addr_callback(fwt_sw_4addr_callback_token,
				mac_be, port_id, node_num);
		if ((use_4addr < 0) && g_auto_mode) {
			return -EINVAL;
		}
	}
	fwt_index = fwt_sw_get_index_from_mac_be(mac_be);

	/* prevent duplication */
	if (fwt_sw_is_exists(fwt_index)) {
		/* Check for parameters change in the current entry, if so
		 * update an existing entry */
		if (!ETHER_IS_MULTICAST(mac_be)) {
			fwt_sw_update_params(fwt_index, port_id, node_num, use_4addr);
		} else {
			/*
			 * NOTE: Ideally this should never be reached. It indicates a
			 * false FWT lookup miss.
			 */
			PRINT_FWT("WARNING: Invalid FWT update [%pM], port-->%s\n",
				mac_be, g_port_names[port_id]);
		}
		return -EEXIST;
	}

	/* clear new device */
	fwt_db_init_entry(&new_device);

	/* Set MAC ID */
	memcpy(&new_device.mac_id, mac_be, ETH_ALEN);

	new_device.out_port = port_id;
	new_device.portal = use_4addr;
	new_device.out_node = node_num;

	/* Set port according to the new entry */
	/* For multicast entries we direct the traffic to the lhost */
	if (group && ETHER_IS_MULTICAST(mac_be)) {
		new_device.out_port = TOPAZ_TQE_LHOST_PORT;
	} else {
		new_device.out_port = port_id;
	}

	/*
	 * Add the hardware FWT entry
	 * Flood-forwarding entries will not be added to the HW table because node is 0.
	 * This is good because entries added to the HW table are aged out.
	 */
	new_device.fwt_index = fwt_sw_sync_entry(&new_device);
	/* if no error and entry was accepted, insert new entry to fwt database */
	if (FWT_IF_SUCCESS(new_device.fwt_index)) {
		new_device.valid = true;
		new_device.timestamp_jiffies = jiffies;
		fwt_db_table_insert(new_device.fwt_index, &new_device);
		if (fwt_qdrv_cbs.notify_entry_add && fwt_qdrv_cbs.ctx)
			fwt_qdrv_cbs.notify_entry_add(fwt_qdrv_cbs.ctx, new_device.fwt_index);
		g_fwt_ent_cnt++;
		PRINT_FWT("FWT: [%pM] add entry, port:%s node:%d entries:%d\n",
				mac_be, g_port_names[port_id], node_num, g_fwt_ent_cnt);
		/* set node list */
		fwt_db_add_new_node(node_num, new_device.fwt_index, group, port_id);
	}
	return FWT_SW_STATUS_SUCCESS;
}
EXPORT_SYMBOL(fwt_sw_add_device);

static int fwt_sw_multicast_group_invalid(const struct br_ip *group)
{
	if (group->proto == htons(ETH_P_IP)) {
		if (group->u.ip4 == IPUTIL_V4_ADDR_SSDP) {
			return 1;
		}
		return 0;
	} else if (group->proto == htons(ETH_P_IPV6)) {
		return 0;
	} else {
		printk("Unable to join. Invalid multicast address\n");
		/* invalid address family */
		BUG();
		return 1;
	}
}

int fwt_sw_join_multicast(uint8_t node, uint8_t port_id,
		const struct br_ip *group)
{
	uint8_t mac_be[ETH_ALEN];
	int fwt_index;

	/* Ignore if service disabled */
	if (!g_is_enable) {
		return -EPERM;
	}

	if (fwt_sw_multicast_group_invalid(group)) {
		return -EINVAL;
	}

	fwt_mcast_to_mac(mac_be, group);
	port_id = fwt_sw_remap_port(port_id, mac_be);
	fwt_index = fwt_sw_get_index_from_mac_be(mac_be);
	if (!fwt_sw_is_exists(fwt_index)) {
		fwt_sw_add_device(mac_be, port_id, node, group);
	}

	fwt_sw_add_new_node(mac_be, node, port_id, group);

	return FWT_SW_STATUS_SUCCESS;
}

int fwt_sw_leave_multicast(uint8_t node, uint8_t port_id,
		const struct br_ip *group)
{
	uint8_t mac_be[ETH_ALEN];
	int fwt_index;
	struct fwt_db_entry *db_ent;
	int8_t ip_alias;

	/* Ignore if service disabled */
	if (!g_is_enable) {
		return -EPERM;
	}

	node = IEEE80211_NODE_IDX_UNMAP(node);

	fwt_mcast_to_mac(mac_be, group);
	port_id = fwt_sw_remap_port(port_id, mac_be);

	ip_alias = fwt_mcast_to_ip_alias(group);
	if (FWT_IF_ERROR(ip_alias)) {
		return -ENOENT;
	}

	/* Get the FWT SW entry and check if its the last node to leave */
	fwt_index = fwt_sw_get_index_from_mac_be(mac_be);
	if (FWT_IF_ERROR(fwt_index)) {
		return -ENOENT;
	}
	/* Get the device entry from the fwt if database */
	db_ent = fwt_db_get_table_entry(fwt_index);
	if (!db_ent) {
		return -ENOENT;
	}
	/* delete the node, and possibly the multicast entry */
	fwt_sw_delete_node(db_ent, port_id, node, ip_alias);
	return FWT_SW_STATUS_SUCCESS;
}

void fwt_sw_reset(void)
{
	int i;
	uint8_t mac_be[ETH_ALEN];
	for (i = 0; i < TOPAZ_FWT_HW_TOTAL_ENTRIES; i++) {
		if (topaz_get_mac_be_from_index(i, mac_be)) {
			topaz_fwt_del_entry(mac_be);
			fwt_db_delete_table_entry(i);
		}
	}

	/* Clear the node list */
	for (i = 0; i < QTN_NCIDX_MAX; i++) {
		fwt_db_clear_node(i);
	}

	g_fwt_ent_cnt = 0;
}
EXPORT_SYMBOL(fwt_sw_reset);

int fwt_sw_print(void)
{
	return fwt_db_print(false) + fwt_db_print(true);
}
EXPORT_SYMBOL(fwt_sw_print);

const struct topaz_fwt_sw_mcast_entry * __sram_text
fwt_sw_get_mcast_entry(uint16_t fwt_index, const void *addr, uint16_t ether_type, uint8_t vap_idx)
{
	struct fwt_db_entry *db;
	int8_t ip_alias;
	const struct topaz_fwt_sw_mcast_entry *mcast_entry;

	db = fwt_db_get_table_entry(fwt_index);
	if (unlikely(!db)) {
		return NULL;
	}

	ip_alias = topaz_fwt_mcast_to_ip_alias(addr, ether_type);
	if (FWT_IF_ERROR(ip_alias)) {
		return NULL;
	}

	mcast_entry = fwt_db_get_sw_mcast(db, ip_alias);
	if (unlikely(!mcast_entry)) {
		return NULL;
	}

	/* if the flood-forwarding flag is set, use the ff entry instead of the dynamic entry */
	if (topaz_fwt_sw_mcast_is_flood_forward(mcast_entry)) {
		mcast_entry = fwt_db_get_sw_mcast_ff(vap_idx);
	}

	return mcast_entry;
}
EXPORT_SYMBOL(fwt_sw_get_mcast_entry);

const struct fwt_db_entry * __sram_text
fwt_sw_get_ucast_entry(const unsigned char *src_mac_be, const unsigned char *dst_mac_be)
{
	int index = 0;
	fwt_db_entry *fwt_ent;
	fwt_db_entry *fwt_ent_out;

	index = fwt_sw_get_index_from_mac_be(dst_mac_be);
	if (index < 0) {
		return NULL;
	}

	fwt_ent_out = fwt_db_get_table_entry(index);
	if (!fwt_ent_out || !fwt_ent_out->valid) {
		return NULL;
	}

	index = fwt_sw_get_index_from_mac_be(src_mac_be);
	if (index < 0) {
		return NULL;
	}

	fwt_ent = fwt_db_get_table_entry(index);
	if (!fwt_ent || !fwt_ent->valid) {
		return NULL;
	}

	fwt_db_update_timestamp(index);

	return fwt_ent_out;
}
EXPORT_SYMBOL(fwt_sw_get_ucast_entry);

bool fwt_sw_is_mult_ports(uint8_t port)
{
	if (port == TOPAZ_TQE_WMAC_PORT) {
		return true;
	}
	return false;
}

static struct topaz_ipmac_uc_entry *ipmac_uc_free_head;
static struct topaz_ipmac_uc_entry *ipmac_uc_free_tail;
static spinlock_t ipmac_lock;
static uint32_t ipmac_sram = 1;

static struct topaz_ipmac_uc_table *ipmac_table_lhost;
static struct topaz_ipmac_uc_entry **ipmac_hash_lhost;
static struct topaz_ipmac_uc_entry *ipmac_base_lhost;
static void *ipmac_unaligned;
dma_addr_t ipmac_hash_bus;
EXPORT_SYMBOL(ipmac_hash_bus);

static inline void *fwt_sw_bus_to_virt(unsigned long bus_addr)
{
	if (!bus_addr)
		return NULL;

	return (void *)((unsigned long)ipmac_hash_lhost +
		(bus_addr - (unsigned long)ipmac_hash_bus));
}

static inline unsigned long fwt_sw_virt_to_bus(void *virt_addr)
{
	if (!virt_addr)
		return 0;

	return ipmac_hash_bus +
		((unsigned long)virt_addr - (unsigned long)ipmac_hash_lhost);
}

void fwt_sw_register_qdrv_cb(void *ctx, fwt_fetch_timestamp fetch, fwt_notify_entry_add notify)
{
	fwt_qdrv_cbs.ctx = ctx;
	fwt_qdrv_cbs.fetch_ts = fetch;
	fwt_qdrv_cbs.notify_entry_add = notify;
}
EXPORT_SYMBOL(fwt_sw_register_qdrv_cb);

static inline uint16_t fwt_sw_ip_hash(const uint8_t *ip, uint16_t type)
{
	if (type == __constant_htons(ETH_P_IP))
		return topaz_ipmac_uc_hash(get_unaligned((uint32_t *)ip));
	else
		return topaz_ipmac_ipv6uc_hash(ip);
}

static inline int fwt_sw_ipmac_match(const struct topaz_ipmac_uc_entry *entry,
		const uint8_t *ip, uint16_t type)
{
	if (type != entry->type)
		return 0;

	if (type == __constant_htons(ETH_P_IP))
		return !memcmp(ip, entry->u.ipv4_addr, sizeof(entry->u.ipv4_addr));
	else
		return !memcmp(ip, entry->u.ipv6_addr, sizeof(entry->u.ipv6_addr));
}

static struct topaz_ipmac_uc_entry *fwt_sw_alloc_ipmac_uc_entry(void)
{
	struct topaz_ipmac_uc_entry *ipmac_ent = NULL;
	unsigned long flags;

	spin_lock_irqsave(&ipmac_lock, flags);

	if (ipmac_uc_free_head) {
		ipmac_ent = ipmac_uc_free_head;
		ipmac_uc_free_head = ipmac_uc_free_head->lhost_next;

		if (ipmac_uc_free_tail == ipmac_ent)
			ipmac_uc_free_tail = ipmac_uc_free_head;
	}

	spin_unlock_irqrestore(&ipmac_lock, flags);

	return ipmac_ent;
}

/*
 * Freed entries are added to the end of the queue to minimise any chance of reusing an entry that
 * is currently in use without the overhead of locking.  The impact of reuse is low, as it will
 * only result in assigning the wrong address to at maximum one packet going to a defunct target.
 */
static void fwt_sw_free_ipmac_uc_entry(struct topaz_ipmac_uc_entry *ipmac_ent)
{
	unsigned long flags;

	ipmac_ent->lhost_next = NULL;

	spin_lock_irqsave(&ipmac_lock, flags);

	if (!ipmac_uc_free_tail) {
		ipmac_uc_free_head = ipmac_ent;
	} else {
		ipmac_uc_free_tail->lhost_next = ipmac_ent;
	}
	ipmac_uc_free_tail = ipmac_ent;

	spin_unlock_irqrestore(&ipmac_lock, flags);
}

static void fwt_sw_ipmac_uc_entry_link(const uint8_t *ip, uint16_t type,
		struct topaz_ipmac_uc_entry *new_entry)
{
	struct topaz_ipmac_uc_entry *entry;
	struct topaz_ipmac_uc_entry **prev;
	uint16_t hash = fwt_sw_ip_hash(ip, type);
	unsigned long flags;

	spin_lock_irqsave(&ipmac_lock, flags);

	prev = ipmac_hash_lhost + hash;
	entry = fwt_sw_bus_to_virt(arc_read_uncached_32(ipmac_hash_lhost + hash));
	while (entry) {
		prev = &entry->next;
		entry = fwt_sw_bus_to_virt(arc_read_uncached_32(&entry->next));
	}

	arc_write_uncached_32(prev, (uint32_t)fwt_sw_virt_to_bus(new_entry));

	arc_write_uncached_32(&ipmac_table_lhost->update_cnt_lhost,
		arc_read_uncached_32(&ipmac_table_lhost->update_cnt_lhost) + 1);

	spin_unlock_irqrestore(&ipmac_lock, flags);
}

static void fwt_sw_ipmac_uc_entry_unlink(const uint8_t *ip, uint16_t type)
{
	struct topaz_ipmac_uc_entry *entry;
	struct topaz_ipmac_uc_entry **prev;
	uint16_t hash = fwt_sw_ip_hash(ip, type);
	unsigned long flags;

	spin_lock_irqsave(&ipmac_lock, flags);

	prev = ipmac_hash_lhost + hash;
	entry = fwt_sw_bus_to_virt(arc_read_uncached_32(ipmac_hash_lhost + hash));
	while (entry) {
		if (fwt_sw_ipmac_match(entry, ip, type)) {
			arc_write_uncached_32(prev,
				arc_read_uncached_32(&entry->next));
			arc_write_uncached_32(&entry->next, 0);
			memset(&entry->u, 0, sizeof(entry->u));	/* IPADDR_ANY */

			arc_write_uncached_32(&ipmac_table_lhost->update_cnt_lhost,
				arc_read_uncached_32(&ipmac_table_lhost->update_cnt_lhost) + 1);
			break;
		}

		prev = &entry->next;
		entry = fwt_sw_bus_to_virt(arc_read_uncached_32(&entry->next));
	}

	spin_unlock_irqrestore(&ipmac_lock, flags);
}

static struct topaz_ipmac_uc_entry *fwt_sw_ipmac_uc_entry_find(const uint8_t *ip, uint16_t type)
{
	struct topaz_ipmac_uc_entry *entry;
	uint16_t hash = fwt_sw_ip_hash(ip, type);
	unsigned long flags;

	spin_lock_irqsave(&ipmac_lock, flags);

	entry = fwt_sw_bus_to_virt((unsigned long)(*(ipmac_hash_lhost + hash)));
	while (entry) {
		if (fwt_sw_ipmac_match(entry, ip, type))
			break;

		entry = fwt_sw_bus_to_virt((unsigned long)(entry->next));
	}

	spin_unlock_irqrestore(&ipmac_lock, flags);

	return entry;
}

static inline struct topaz_ipmac_uc_entry *fwt_sw_ipmac_uc_entry_get_idx(uint16_t idx)
{
	return &ipmac_base_lhost[idx];
}

int fwt_sw_update_uc_ipmac(const uint8_t *mac_be, const uint8_t *ip, uint16_t type)
{
	struct topaz_ipmac_uc_entry *ipmac_ent;

	if (type != __constant_htons(ETH_P_IP)
			&& type != __constant_htons(ETH_P_IPV6))
		return -EINVAL;

	ipmac_ent = fwt_sw_ipmac_uc_entry_find(ip, type);
	if (ipmac_ent) {
		if (likely(memcmp(mac_be, ipmac_ent->mac_addr, ETH_ALEN) == 0)) {
			return 0;
		}
		/* recycle this entry & allocate a new one */
		fwt_sw_ipmac_uc_entry_unlink(ip, type);
		fwt_sw_free_ipmac_uc_entry(ipmac_ent);
	}

	ipmac_ent = fwt_sw_alloc_ipmac_uc_entry();
	if (!ipmac_ent)
		return -ENOMEM;

	ipmac_ent->lhost_next = NULL;
	ipmac_ent->next = NULL;
	ipmac_ent->type = type;
	memcpy(&ipmac_ent->u, ip,
		(type == __constant_htons(ETH_P_IP) ? sizeof(__be32) : sizeof(struct in6_addr)));
	memcpy(ipmac_ent->mac_addr, mac_be, ETH_ALEN);

	flush_dcache_sizerange_safe(ipmac_ent, sizeof(struct topaz_ipmac_uc_entry));

	fwt_sw_ipmac_uc_entry_link(ip, type, ipmac_ent);

	if (type == __constant_htons(ETH_P_IP))
		PRINT_FWT("mapping %pI4 to %pM\n", ip, mac_be);
	else
		PRINT_FWT("mapping %pI6 to %pM\n", ip, mac_be);

	return 0;
}
EXPORT_SYMBOL(fwt_sw_update_uc_ipmac);

void fwt_sw_remove_uc_ipmac(const uint8_t *ip, uint16_t type)
{
	struct topaz_ipmac_uc_entry *ipmac_ent;

	if (type == __constant_htons(ETH_P_IP))
		PRINT_FWT("delete mapping IP %pI4\n", ip);
	else if (type == __constant_htons(ETH_P_IPV6))
		PRINT_FWT("delete mapping IP %pI6\n", ip);
	else
		return;

	ipmac_ent = fwt_sw_ipmac_uc_entry_find(ip, type);
	if (ipmac_ent) {
		fwt_sw_ipmac_uc_entry_unlink(ip, type);
		fwt_sw_free_ipmac_uc_entry(ipmac_ent);
	}
}
EXPORT_SYMBOL(fwt_sw_remove_uc_ipmac);

static void __exit fwt_ipmac_uc_exit(void)
{
	if (ipmac_sram)
		heap_sram_free(ipmac_unaligned);
	else
		kfree(ipmac_unaligned);
}

static void __exit fwt_sw_exit(void)
{
	g_is_enable = false;
	fwt_sw_auto_mode(false);
	topaz_fwt_register_overwrite(NULL);
	fwt_if_register_cbk_t(NULL);
	tqe_register_fwt_cbk(NULL, NULL, NULL);
	tqe_register_ucastfwt_cbk(NULL);
	fwt_sw_reset();
	fwt_ipmac_uc_exit();
}

static int __init fwt_ipmac_uc_init(void)
{
	unsigned int i;
	struct topaz_ipmac_uc_entry *curr;
	void *mem;
	struct topaz_ipmac_uc_table *tbl;

	mem = heap_sram_alloc(TOPAZ_IPMAC_UC_TBL_SIZE + ARC_DCACHE_LINE_LEN);
	if (!mem) {
		printk("Failed to allocate SRAM IP-MAC lookup table, size 0x%lx\n",
				TOPAZ_IPMAC_UC_TBL_SIZE + ARC_DCACHE_LINE_LEN);
		mem = kmalloc(TOPAZ_IPMAC_UC_TBL_SIZE + ARC_DCACHE_LINE_LEN, GFP_KERNEL);
		ipmac_sram = 0;
		if (!mem) {
			printk(KERN_ERR"Failed to allocate IP-MAC hash table with Kmalloc\n");
			return -ENOMEM;
		}
	}

	tbl = (struct topaz_ipmac_uc_table *)ALIGN((unsigned long)mem, ARC_DCACHE_LINE_LEN);

	memset(tbl, 0, TOPAZ_IPMAC_UC_TBL_SIZE);

	ipmac_hash_bus = virt_to_bus(tbl);
	ipmac_hash_lhost = tbl->slots;
	ipmac_base_lhost = tbl->entries;
	ipmac_table_lhost = tbl;
	ipmac_unaligned = mem;

	ipmac_uc_free_head = fwt_sw_ipmac_uc_entry_get_idx(0);
	curr = ipmac_uc_free_head;
	for (i = 1; i < TOPAZ_IPMAC_UC_ENTRY_COUNT; i++) {
		curr->next = NULL;
		curr->lhost_next = fwt_sw_ipmac_uc_entry_get_idx(i);
		curr = curr->lhost_next;
	}

	curr->lhost_next = NULL;
	ipmac_uc_free_tail = curr;

	spin_lock_init(&ipmac_lock);

	return 0;
}

static int __init fwt_sw_init(void)
{
	uint32_t val;

	if (fwt_ipmac_uc_init() != 0)
		panic("Failed to initialize IP-MAC mapping\n");

	topaz_fwt_init();
	fwt_db_init();

	/* Set up a bridge hook so we can extract data from the bridge learning phase */
	fwt_sw_auto_mode(true);

	/*
	 * initialize ageing timer
	 * clear timer, read back to flush pipeline, then configure & enable
	 */
	qtn_mproc_sync_mem_write_wmb(TOPAZ_FWT_TIME_STAMP_CTRL, TOPAZ_FWT_TIME_STAMP_CTRL_CLEAR);
	val = SM(TOPAZ_FWT_TIMESTAMP_UNIT, TOPAZ_FWT_TIME_STAMP_CTRL_UNIT) |
			SM(TOPAZ_FWT_TIMESTAMP_SCALE, TOPAZ_FWT_TIME_STAMP_CTRL_SCALE);
	qtn_mproc_sync_mem_write_wmb(TOPAZ_FWT_TIME_STAMP_CTRL, val);

	/* Register overwrite of table entries in case of second level delete scenario */
	topaz_fwt_register_overwrite(fwt_sw_overwrite_table_entries);
	fwt_if_register_cbk_t(fwt_sw_cmd);
	tqe_register_fwt_cbk(fwt_sw_get_mcast_entry, fwt_db_get_sw_mcast_ff, fwt_sw_update_false_miss);
	tqe_register_ucastfwt_cbk(fwt_sw_get_ucast_entry);
	return 0;
}
module_init(fwt_sw_init);
module_exit(fwt_sw_exit);

