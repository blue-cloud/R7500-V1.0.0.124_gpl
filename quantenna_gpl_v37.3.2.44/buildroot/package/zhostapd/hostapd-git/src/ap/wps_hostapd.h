/*
 * hostapd / WPS integration
 * Copyright (c) 2008-2010, Jouni Malinen <j@w1.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef WPS_HOSTAPD_H
#define WPS_HOSTAPD_H

#ifdef CONFIG_WPS

int hostapd_init_wps(struct hostapd_data *hapd,
		     struct hostapd_bss_config *conf);
int hostapd_init_wps_complete(struct hostapd_data *hapd);
void hostapd_deinit_wps(struct hostapd_data *hapd);
void hostapd_update_wps(struct hostapd_data *hapd);
int hostapd_wps_add_pin(struct hostapd_data *hapd, int selected, const u8 *addr,
			const char *uuid, const char *pin, int timeout);
int hostapd_wps_button_pushed(struct hostapd_data *hapd,
			      const u8 *p2p_dev_addr);
int hostapd_wps_button_pushed_interface(struct hostapd_data *hapd,
				const char *interface);
int hostapd_wps_start_oob(struct hostapd_data *hapd, char *device_type,
			  char *path, char *method, char *name);
int hostapd_wps_get_mib_sta(struct hostapd_data *hapd, const u8 *addr,
			    char *buf, size_t buflen);
void hostapd_wps_ap_pin_enable(struct hostapd_data *hapd, int timeout);
void hostapd_wps_ap_pin_disable(struct hostapd_data *hapd);
const char * hostapd_wps_ap_pin_random(struct hostapd_data *hapd, int timeout);
const char * hostapd_wps_ap_pin_get(struct hostapd_data *hapd);
int hostapd_wps_ap_pin_set(struct hostapd_data *hapd, const char *pin,
			   int timeout);
int hostapd_wps_set_ap_pin_fail_method(struct hostapd_data *hapd,
					char *name);
char *hostapd_wps_get_ap_pin_fail_method(struct hostapd_data *hapd);
void hostapd_wps_update_ie(struct hostapd_data *hapd);
int hostapd_wps_config_ap(struct hostapd_data *hapd, const char *ssid,
			  const char *auth, const char *encr, const char *key);
int hostapd_ctrl_iface_wps_get_status(struct hostapd_data *hapd,
				      char *status_str,
				      const size_t status_len);
int hostapd_wps_upnp_init(struct hostapd_data *hapd,
				 struct wps_context *wps);
void hostapd_wps_upnp_deinit(struct hostapd_data *hapd);
void hostapd_sta_require_leave(struct hostapd_data *hapd, u8 *addr);
int hostapd_wps_probing_db_process(struct hostapd_data *hapd, const u8 *addr, int remove);

#else /* CONFIG_WPS */

static inline int hostapd_init_wps(struct hostapd_data *hapd,
				   struct hostapd_bss_config *conf)
{
	return 0;
}

static inline void hostapd_deinit_wps(struct hostapd_data *hapd)
{
}

static inline int hostapd_init_wps_complete(struct hostapd_data *hapd)
{
    return 0;
}

static inline void hostapd_update_wps(struct hostapd_data *hapd)
{
}

static inline int hostapd_wps_get_mib_sta(struct hostapd_data *hapd,
					  const u8 *addr,
					  char *buf, size_t buflen)
{
	return 0;
}

static inline int hostapd_wps_button_pushed(struct hostapd_data *hapd,
					    const u8 *p2p_dev_addr)
{
	return 0;
}

static inline int hostapd_wps_upnp_init(struct hostapd_data *hapd,
				 struct wps_context *wps)
{
	return 0;
}

static void hostapd_wps_upnp_deinit(struct hostapd_data *hapd)
{
	return 0;
}

static void hostapd_sta_require_leave(struct hostapd_data *hapd, u8 *addr)
{

}

static int hostapd_wps_probing_db_process(struct hostapd_data *hapd, const u8 *addr, int remove)
{
	return 0;
}

#endif /* CONFIG_WPS */

#endif /* WPS_HOSTAPD_H */
