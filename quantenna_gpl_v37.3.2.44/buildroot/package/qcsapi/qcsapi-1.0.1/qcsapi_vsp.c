/*
*******************************************************************************
**                                                                           **
**         Copyright (c) 2012 Quantenna Communications, Inc.                 **
**                            All Rights Reserved                            **
**                                                                           **
**  Author      : Quantenna Communications Inc                               **
**  File        : qcsapi_vsp.c                                               **
**  Description : Video Stream Protection                                    **
**                                                                           **
*******************************************************************************
*/

#include "qcsapi.h"
#include "qcsapi_private.h"
#include <qtn/qvsp_ioctl.h>

static int vsp_ioctl_fd = -1;
static const char *vsp_ioctl_path = "/proc/qvsp_ctrl";

int local_qtm_invalid_params[] = {
	QVSP_CFG_DISABLE_DEMOTE,
	QVSP_CFG_DISABLE_DEMOTE_FIX_FAT,
	QVSP_CFG_STRM_RMT_DIS_TCP,
	QVSP_CFG_STRM_RMT_DIS_UDP,
	QVSP_CFG_3RDPT_CTL,
	QVSP_CFG_3RDPT_LOCAL_THROT,
	QVSP_CFG_3RDPT_QTN,
	QVSP_CFG_BA_THROT_INTV,
	QVSP_CFG_BA_THROT_DUR_MIN,
	QVSP_CFG_BA_THROT_DUR_STEP,
	QVSP_CFG_BA_THROT_WINSIZE_MIN,
	QVSP_CFG_BA_THROT_WINSIZE_MAX,
	QVSP_CFG_WME_THROT_AC,
	QVSP_CFG_WME_THROT_AIFSN,
	QVSP_CFG_WME_THROT_ECWMIN,
	QVSP_CFG_WME_THROT_ECWMAX,
	QVSP_CFG_WME_THROT_TXOPLIMIT,
	QVSP_CFG_WME_THROT_THRSH_DISABLED,
	QVSP_CFG_WME_THROT_THRSH_VICTIM,
	QVSP_CFG_STRM_TPUT_MAX_TCP,
	QVSP_CFG_STRM_TPUT_MAX_FIRST,
	QVSP_CFG_STRM_TPUT_MAX_TCP_AC0,
	QVSP_CFG_STRM_TPUT_MAX_TCP_AC1,
	QVSP_CFG_STRM_TPUT_MAX_TCP_AC2,
	QVSP_CFG_STRM_TPUT_MAX_TCP_AC3,
	QVSP_CFG_STRM_TPUT_MAX_UDP,
	QVSP_CFG_STRM_TPUT_MAX_UDP_AC0,
	QVSP_CFG_STRM_TPUT_MAX_UDP_AC1,
	QVSP_CFG_STRM_TPUT_MAX_UDP_AC2,
	QVSP_CFG_STRM_TPUT_MAX_UDP_AC3,
	QVSP_CFG_STRM_TPUT_MAX_LAST,
};

static int local_qtm_invalid_cfg_check(unsigned int param)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(local_qtm_invalid_params); i++) {
		if (local_qtm_invalid_params[i] == param)
			return 1;
	}

	return 0;
}

static int local_vsp_get_ioctl_fd(void)
{
	if (vsp_ioctl_fd < 0) {
		vsp_ioctl_fd = open(vsp_ioctl_path, O_RDWR);
	}

	return vsp_ioctl_fd;
}

static int local_vsp_getter_ioctl(unsigned int ioctl_num,
		unsigned int index, void *p, unsigned int p_count)
{
	struct qvsp_ioctl_get io;
	int fd;
	int rc;

	rc = local_swfeat_check_supported(SWFEAT_ID_QTM);
	if (rc < 0)
		return rc;

	fd = local_vsp_get_ioctl_fd();
	if (fd < 0) {
		if (fd == -EPERM) {
			return -qcsapi_not_supported;
		} else {
			return -EBADF;
		}
	}

	if (!ioctl_num || ioctl_num >= QVSP_IOCTL_MAX || !p_count) {
		return -EINVAL;
	}

	if (!p) {
		return -EFAULT;
	}

	io.index = index;
	io.param = p;
	io.count = p_count;

	return ioctl(fd, ioctl_num, &io);
}

static int local_vsp_setter_ioctl(unsigned int ioctl_num, union qvsp_ioctl_set *set)
{
	int fd;
	int rc;

	rc = local_swfeat_check_supported(SWFEAT_ID_QTM);
	if (rc < 0)
		return rc;

	fd = local_vsp_get_ioctl_fd();
	if (fd < 0) {
		if (fd == -EPERM) {
			return -qcsapi_not_supported;
		} else {
			return -EBADF;
		}
	}

	if (!ioctl_num || ioctl_num >= QVSP_IOCTL_MAX) {
		return -EINVAL;
	}

	if (!set) {
		return -EFAULT;
	}

	rc = ioctl(fd, ioctl_num, set);

	return rc;
}

int qcsapi_qtm_get_state(const char *ifname, unsigned int param, unsigned int *value)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_getter_ioctl(QVSP_IOCTL_STATE_GET, param, value, 1);

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_get_state_all(const char *ifname, struct qcsapi_data_128bytes *value, unsigned int max)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_getter_ioctl(QVSP_IOCTL_STATE_GET, 0, value->data, max);

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_set_state(const char *ifname, unsigned int param, unsigned int value)
{
	int rc;
	union qvsp_ioctl_set s;

	s.cfg.index = param;
	s.cfg.value = value;

	enter_qcsapi();

	rc = local_vsp_setter_ioctl(QVSP_IOCTL_STATE_SET, &s);

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_get_config(const char *ifname, unsigned int param, unsigned int *value)
{
	int rc;

	enter_qcsapi();

	if (!local_qtm_invalid_cfg_check(param))
		rc = local_vsp_getter_ioctl(QVSP_IOCTL_CFG_GET, param, value, 1);
	else
		rc = -qcsapi_not_supported;

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_get_config_all(const char *ifname, struct qcsapi_data_1Kbytes *value, unsigned int max)
{
	int rc;
	int i;
	unsigned int *p_value;

	enter_qcsapi();

	rc = local_vsp_getter_ioctl(QVSP_IOCTL_CFG_GET, 0, value->data, max);

	/* hide unsupported parameter in QTM */
	if (!rc) {
		p_value = (unsigned int *)value->data;
		for (i = 0; i < ARRAY_SIZE(local_qtm_invalid_params); i++)
			p_value[local_qtm_invalid_params[i]] = QCSAPI_QTM_CFG_INVALID;
	}

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_set_config(const char *ifname, unsigned int param, unsigned int value)
{
	int rc;
	union qvsp_ioctl_set s;

	s.cfg.index = param;
	s.cfg.value = value;

	enter_qcsapi();

	if (!local_qtm_invalid_cfg_check(param))
		rc = local_vsp_setter_ioctl(QVSP_IOCTL_CFG_SET, &s);
	else
		rc = -qcsapi_not_supported;

	leave_qcsapi();

	return rc;
}

#ifndef TOPAZ_QTM
int qcsapi_vsp_add_wl(const char *ifname, const struct qvsp_wl_flds *entry)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_setter_ioctl(QVSP_IOCTL_WL_ADD, (void*)entry);

	leave_qcsapi();

	return rc;
}

int qcsapi_vsp_del_wl(const char *ifname, const struct qvsp_wl_flds *entry)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_setter_ioctl(QVSP_IOCTL_WL_DEL, (void*)entry);

	leave_qcsapi();

	return rc;
}

int qcsapi_vsp_del_wl_index(const char *ifname, unsigned int index)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_setter_ioctl(QVSP_IOCTL_WL_DEL_INDEX, (void*)&index);

	leave_qcsapi();

	return rc;
}

int qcsapi_vsp_get_wl(const char *ifname, struct qvsp_wl_flds *entries, unsigned int max_entries)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_getter_ioctl(QVSP_IOCTL_WL_GETLIST, 0, entries, max_entries);

	leave_qcsapi();

	return rc;
}
#else
int qcsapi_vsp_add_wl(const char *ifname, const struct qvsp_wl_flds *entry)
{
	return -qcsapi_not_supported;
}

int qcsapi_vsp_del_wl(const char *ifname, const struct qvsp_wl_flds *entry)
{
	return -qcsapi_not_supported;
}

int qcsapi_vsp_del_wl_index(const char *ifname, unsigned int index)
{
	return -qcsapi_not_supported;
}

int qcsapi_vsp_get_wl(const char *ifname, struct qvsp_wl_flds *entries, unsigned int max_entries)
{
	return -qcsapi_not_supported;
}
#endif

int qcsapi_qtm_add_rule(const char *ifname, const struct qcsapi_data_128bytes *entry)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_setter_ioctl(QVSP_IOCTL_RULE_ADD, (void*)entry->data);

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_del_rule(const char *ifname, const struct qcsapi_data_128bytes *entry)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_setter_ioctl(QVSP_IOCTL_RULE_DEL, (void*)entry->data);

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_del_rule_index(const char *ifname, unsigned int index)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_setter_ioctl(QVSP_IOCTL_RULE_DEL_INDEX, (void*)&index);

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_get_rule(const char *ifname, struct qcsapi_data_3Kbytes *entries, unsigned int max_entries)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_getter_ioctl(QVSP_IOCTL_RULE_GETLIST, 0, entries->data, max_entries);

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_get_strm(const char *ifname, struct qcsapi_data_4Kbytes *entries,
		unsigned int max_entries, int show_all)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_getter_ioctl(
		show_all ? QVSP_IOCTL_STRM_GETLIST_ALL : QVSP_IOCTL_STRM_GETLIST,
		0, entries->data, max_entries);

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_get_stats(const char *ifname, struct qcsapi_data_512bytes *stats)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_getter_ioctl(QVSP_IOCTL_STATS_GET, 0, stats->data, 1);

	leave_qcsapi();

	return rc;
}

int qcsapi_qtm_get_inactive_flags(const char *ifname, unsigned long *p_flags)
{
	int rc;

	enter_qcsapi();

	rc = local_vsp_getter_ioctl(QVSP_IOCTL_INACTIVE_FLAGS_GET, 0, p_flags, 1);

	leave_qcsapi();

	return rc;
}

