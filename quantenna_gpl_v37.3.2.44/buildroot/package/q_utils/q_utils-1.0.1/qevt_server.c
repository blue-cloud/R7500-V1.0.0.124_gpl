/**
 * Copyright (c) 2014 Quantenna Communications, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <wpa_ctrl.h>
#include <dirent.h>

#include <qtn_logging.h>
#include <pthread.h>
#include "iwlib.h"

#define QEVT_DEFAULT_PORT 3490
#define QEVT_TX_BUF_SIZE 1024
#define QEVT_RX_BUF_SIZE 4096
#define QEVT_TXT_PREFIX	"QEVT: "
#define QEVT_CONFIG_VERSION "v1.00"
#define QEVT_VERSION "QEVT_VERSION"
#define QEVT_CONFIG  "QEVT_CONFIG"
#define QEVT_CONFIG_RESET QEVT_CONFIG"_RESET"
#define QEVT_CONFIG_RX_BUF 256
#define QEVT_MAX_MSG_CONFIGS 32
#define QEVT_MAX_PREFIX_LEN 15
#define QEVT_WPA_PREFIX "WPACTRL"
#define QEVT_HOSTAPD "/var/run/hostapd/"
#define QEVT_WPA     "/var/run/wpa_supplicant/"
#define QEVT_WIFI_INTERFACE_NAME "wifi"

/*
 * Static information about wireless interface.
 * We cache this info for performance reasons.
 */
struct qevt_wifi_iface {
	struct qevt_wifi_iface	*next;			/* Linked list */
	int			ifindex;		/* Interface index */
	char			ifname[IFNAMSIZ + 1];	/* Interface name */
	struct			iw_range range;		/* Wireless static data */
	int			has_range;
};

struct qevt_wpa_iface {
	struct qevt_wpa_iface	*next;
	struct wpa_ctrl		*wpa_event;
	struct wpa_ctrl		*wpa_control;
	int			fd;
	uint32_t		event_check	:1;
	uint32_t		dead		:1;
	char			ifname[IFNAMSIZ + 1];	/* Interface name */
};

struct qevt_server_config {
	struct qevt_wifi_iface	*if_cache;		/* Cache of wireless interfaces */
	struct qevt_wpa_iface	*if_wpa;
	pthread_t		wpa_thread;
	pthread_mutex_t		wpa_mutex;
	volatile int		running;
	struct sockaddr_nl	netlink_dst;
	int			netlink_socket;
	int			client_socket;
	int			server_socket;
	uint16_t		port;
};

struct qevt_config_flags
{
	uint32_t dynamic	: 1;
	uint32_t seen		: 1;
	uint32_t disabled	: 1;
	uint32_t prfx		: 1;
	uint32_t interface	: 1;
	uint32_t timestamp	: 1;
	uint32_t message	: 1;
	uint32_t newline	: 1;
};

struct qevt_message_config {
	struct qevt_message_config	*next;
	char				*prefix;
	struct qevt_config_flags	flags;
};

static struct qevt_server_config qevt_server_cfg = {.if_cache = NULL, .if_wpa = NULL,
	.wpa_mutex = PTHREAD_MUTEX_INITIALIZER, .running = 0};

/* these are initialised in qevt_server_init */
static struct qevt_message_config qevt_nondef;
static struct qevt_message_config qevt_default;

/* this tracks the number of dynamic configs created */
static uint32_t qevt_cfg_count = 0;

/* these are built-in initial settings - used to initialise qevt_nondef & qevt_default */
static const struct qevt_message_config qevt_nondef_init = {
					.next = NULL,
					.prefix = "nondefined",
					.flags.dynamic = 0,
					.flags.seen = 0,
					.flags.disabled = 1,
					.flags.prfx = 1,
					.flags.interface = 0,
					.flags.timestamp = 0,
					.flags.message = 0,
					.flags.newline = 0
				};
static const struct qevt_message_config qevt_default_init = {
					.next = &qevt_nondef,
					.prefix = "default",
					.flags.dynamic = 0,
					.flags.seen = 0,
					.flags.disabled = 0,
					.flags.prfx = 1,
					.flags.interface = 1,
					.flags.timestamp = 0,
					.flags.message = 1,
					.flags.newline = 1
				};

static struct qevt_message_config *qevt_messages = &qevt_default;


static void qevt_iwevent_action(struct iw_event *event, char *ifname);

/*
 * qevt_prefix function takes a input line and searches for a "prefix" within that. A prefix
 * is a consecutive sequence of (non-space) characters, immediately followed by a colon (":")
 * For example ThisIsAPrefix:
 * A special exclusion is that a MAC address is specifically tested, to avoid being mistaken as
 * a prefix.
 * Also, the text immediately from the prefix is returned (if pointer is provided for that).
 */
static char * qevt_prefix(char *msg, char **text)
{
	char *colon;
	char *space;

	/* search out prefix: */
	while ((colon = strstr(msg, ":")) && (space = strstr(msg, " ")) && (space < colon)) {
		msg = space + 1;
	}

	/* is this a free-form MAC address mistaken as a prefix ? */
	if (colon && (colon >= msg + 2)) {
		unsigned int mac_dummy;

		/* check if we identify all 6 MAC address elements - if so, reject */
		if (sscanf(colon - 2, "%02x:%02x:%02x:%02x:%02x:%02x", &mac_dummy, &mac_dummy,
				&mac_dummy, &mac_dummy, &mac_dummy, &mac_dummy) == 6) {
			return NULL;
		}
	}

	/* prefix cannot be longer than QEVT_MAX_PREFIX_LEN and must be alphanumeric */
	if (colon && (msg < colon) && ((msg + QEVT_MAX_PREFIX_LEN)  >= colon)) {
		char *check = msg;
		int  alphacount = 0;
		int  numbercount = 0;

		/* check all prefix characters are only alphanumeric (or underscore) */
		while (check < colon) {
			char test = *check;

			if (isalpha(test) || test == '_') {
				alphacount++;
			} else if (isdigit(test)) {
				numbercount++;
			} else {
				return NULL;
			}
			check++;
		}

		/* there has to be at least 1 non-numeric character and no more than 2 numeric */
		if (alphacount == 0 || numbercount > 2) {
			return NULL;
		}

		/* check only a single colon */
		if (colon[1] == ':') {
			return NULL;
		}

		if (text) {
			*text = colon;
		}
		return msg;
	}
	return NULL;
}

static struct qevt_message_config * qevt_find(struct qevt_message_config **phead, char *prefix)
{
	struct qevt_message_config *msg_cfg = phead ? *phead : NULL;

	while (msg_cfg) {
		if (!strcmp(msg_cfg->prefix, prefix)) {
			return msg_cfg;
		}
		msg_cfg = msg_cfg->next;
	}
	return NULL;
}

static struct qevt_message_config * qevt_add(struct qevt_message_config **phead, char *prefix)
{
	struct qevt_message_config *msg_cfg;
	static int max_count_reached = 0;
	char *data;

	msg_cfg = qevt_find(phead, prefix);

	if (msg_cfg) {
		return msg_cfg;
	}

	/* avoid generating excessive error messages (just do it once) */
	if (qevt_cfg_count > QEVT_MAX_MSG_CONFIGS) {
		if (!max_count_reached) {
			fprintf(stderr, QEVT_TXT_PREFIX"maximum number (%d) of message prefix "
				"types reached\n", QEVT_MAX_MSG_CONFIGS);
			max_count_reached = 1;
		}
		return NULL;
	} else {
		max_count_reached = 0;
	}

	qevt_cfg_count++;

	msg_cfg = malloc(sizeof(*msg_cfg));
	data = msg_cfg ? malloc(strlen(prefix) + 1) : NULL;

	if (!msg_cfg || !data) {
		fprintf(stderr, QEVT_TXT_PREFIX"malloc failed\n");

		if (msg_cfg) {
			free(msg_cfg);
		}
		return NULL;
	}
	memset(msg_cfg, 0, sizeof(*msg_cfg));

	msg_cfg->prefix = data;
	msg_cfg->flags = qevt_default.flags;
	msg_cfg->flags.dynamic = 1;

	strcpy(msg_cfg->prefix, prefix);

	if (*phead) {
		struct qevt_message_config *head = *phead;

		while (head && head->next) {
			head = head->next;
		}
		head->next = msg_cfg;
	} else {
		*phead = msg_cfg;
	}
	return msg_cfg;
}

static void qevt_cleanup(struct qevt_message_config **phead)
{
	struct qevt_message_config *head = phead ? *phead : NULL;

	/* delete all the dynamically allocated list entries */
	while (head) {
		struct qevt_message_config *next = head->next;

		if (head->flags.dynamic) {
			if (head->prefix) {
				free(head->prefix);
			}
			free(head);
		}
		head = next;
	}
	qevt_cfg_count = 0;
}

static char *qevt_report(struct qevt_message_config **phead, char *buffer, uint32_t len,
			char *prefix)
{
	struct qevt_message_config *head;
	int output;
	char *report = NULL;

	head = phead ? *phead : NULL;

	if (prefix) {
		output = snprintf(buffer, len - 1, "%s", prefix);

		if (output < len) {
			len -= output;
			buffer += output;
		} else {
			len = 0;
		}
	}

	while (head && len) {
		struct qevt_config_flags flags = head->flags;

		output = snprintf(buffer, len - 1, " %s:%s%s%s%s%s%s", head->prefix,
						   flags.disabled ? "-" : "+",
						   flags.prfx ? "P" : "",
						   flags.interface ? "I" : "",
						   flags.timestamp ? "T" : "",
						   flags.message ? "M" : "",
						   flags.newline ? "N" : ""
						 );

		if (output < len) {
			len -= output;
			buffer += output;
		} else {
			len = 0;
		}
		head = head->next;
	}
	return report;
}


/*
 * Get name of interface based on interface index
 */
static int qevt_index2name(const int skfd, const int ifindex,
				char *const name, const int name_len)
{
	struct ifreq if_req;

	memset(name, 0, name_len);

	/*
	 * Get interface name.
	 * For some reasons, ifi_index in the RTNETLINK message has bit 17 set.
	 */
	if_req.ifr_ifindex = ifindex & 0xFF;

	if (ioctl(skfd, SIOCGIFNAME, &if_req) < 0)
		return -1;

	strncpy(name, if_req.ifr_name, MIN(IFNAMSIZ, name_len));

	return 0;
}

static void qevt_cache_free(void)
{
	struct qevt_wifi_iface *curr = qevt_server_cfg.if_cache;
	struct qevt_wifi_iface *prev;

	while (curr) {
		prev = curr;
		curr = curr->next;
		if (prev)
			free(prev);
	}
}

/*
 * Get interface data from cache.  Create the cache entry if it doesn't already exist.
 */
static struct qevt_wifi_iface *qevt_get_interface_data(const int ifindex)
{
	struct qevt_wifi_iface *curr = qevt_server_cfg.if_cache;
	int skfd;

	/* Search for it in the cache first */
	while (curr) {
		if (curr->ifindex == ifindex) {
			return curr;
		}
		curr = curr->next;
	}

	skfd = iw_sockets_open();
	if (skfd < 0) {
		perror(QEVT_TXT_PREFIX"iw_sockets_open");
		return NULL;
	}

	/* Create new entry */
	curr = calloc(1, sizeof(struct qevt_wifi_iface));
	if (!curr) {
		fprintf(stderr, QEVT_TXT_PREFIX"malloc failed\n");
		iw_sockets_close(skfd);
		return NULL;
	}

	curr->ifindex = ifindex;

	/* Extract static data */
	if (qevt_index2name(skfd, ifindex, curr->ifname, sizeof(curr->ifname)) < 0) {
		perror(QEVT_TXT_PREFIX"qevt_index2name");
		iw_sockets_close(skfd);
		free(curr);
		return NULL;
	}

	curr->has_range = (iw_get_range_info(skfd, curr->ifname, &curr->range) >= 0);

	iw_sockets_close(skfd);

	/* Link it */
	curr->next = qevt_server_cfg.if_cache;
	qevt_server_cfg.if_cache = curr;

	return curr;
}

#define QEVT_TIMESTAMP_BUFFER 64
char *qevt_timestamp()
{
	static char buffer[QEVT_TIMESTAMP_BUFFER];
	struct timeval time_now;

	uint32_t days;
	uint32_t hours;
	uint32_t minutes;
	uint32_t seconds;
	uint32_t milliseconds;

	gettimeofday(&time_now, NULL);

	seconds = time_now.tv_sec;
	minutes = seconds / 60;
	seconds -= minutes * 60;
	hours = minutes / 60;
	minutes -= hours * 60;
	days = hours / 24;
	hours -= days * 24;
	milliseconds = time_now.tv_usec / 1000;

	snprintf(buffer, QEVT_TIMESTAMP_BUFFER, "(%u/%02u:%02u:%02u.%03u) ",
		 days, hours, minutes, seconds, milliseconds);

	return buffer;
}

void qevt_timedwait(uint32_t microsecond_delay)
{
	struct timespec delay_end;
	struct timeval time_now;
	uint32_t delay_secs;
	uint32_t delay_usecs;

	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

	gettimeofday(&time_now, NULL);

	delay_usecs = time_now.tv_usec + microsecond_delay;
	delay_secs = delay_usecs / 1000000;
	delay_usecs -= delay_secs * 1000000;
	delay_secs += time_now.tv_sec;

	delay_end.tv_sec = delay_secs;
	delay_end.tv_nsec = delay_usecs * 1000;

	pthread_mutex_lock(&mutex);
	pthread_cond_timedwait(&cond, &mutex, &delay_end);
	pthread_mutex_unlock(&mutex);
}

static void qevt_wpa_open(struct qevt_wpa_iface *if_wpa)
{
	int size;
	char *file;

	size = strlen(if_wpa->ifname) + MAX(sizeof(QEVT_HOSTAPD), sizeof(QEVT_WPA));

	file = malloc(size);

	if (file == NULL) {
		fprintf(stderr, QEVT_TXT_PREFIX"malloc failed\n");
		return;
	}

	/* we don't know which between hostapd or wpa_supplicant are present - try both */
	if (if_wpa->wpa_event == NULL) {
		strcpy(file, QEVT_HOSTAPD);
		strcat(file, if_wpa->ifname);
		if_wpa->wpa_event = wpa_ctrl_open(file);
	}
	if (if_wpa->wpa_event != NULL  && if_wpa->wpa_control == NULL) {
		if_wpa->wpa_control = wpa_ctrl_open(file);
	}

	if (if_wpa->wpa_event == NULL) {
		strcpy(file, QEVT_WPA);
		strcat(file, if_wpa->ifname);
		if_wpa->wpa_event = wpa_ctrl_open(file);
	}

	if (if_wpa->wpa_event != NULL && if_wpa->wpa_control == NULL) {
		if_wpa->wpa_control = wpa_ctrl_open(file);
	}

	free(file);

	if (if_wpa->wpa_event) {
		if_wpa->fd = wpa_ctrl_get_fd(if_wpa->wpa_event);
		wpa_ctrl_attach(if_wpa->wpa_event);
	}
	else {
		if_wpa->fd  = 0;
	}
}

static void qevt_wpa_close(struct qevt_wpa_iface *if_wpa)
{
	if (if_wpa->wpa_control) {
		wpa_ctrl_close(if_wpa->wpa_control);
	}
	if (if_wpa->wpa_event) {
		wpa_ctrl_detach(if_wpa->wpa_event);
		wpa_ctrl_close(if_wpa->wpa_event);
	}
	if_wpa->wpa_event = NULL;
	if_wpa->wpa_control = NULL;
	if_wpa->fd = 0;
	if_wpa->event_check = 0;
}

static void qevt_wpa_cleanup()
{
	struct qevt_wpa_iface *head = qevt_server_cfg.if_wpa;

	qevt_server_cfg.running = 0;
	pthread_join(qevt_server_cfg.wpa_thread, NULL);

	while (head) {
		struct qevt_wpa_iface *next = head->next;

		qevt_wpa_close(head);
		free(head);
		head = next;
	}
	qevt_server_cfg.if_wpa = NULL;
}

static void qevt_wpa_add_iface(struct qevt_wpa_iface **if_wpa_head, char *iface)
{
	struct qevt_wpa_iface *if_wpa = malloc(sizeof(*if_wpa));

	if (if_wpa == NULL) {
		fprintf(stderr, QEVT_TXT_PREFIX"malloc failed\n");
		return;
	}

	memset(if_wpa, 0, sizeof(*if_wpa));
	strncpy(if_wpa->ifname, iface, IFNAMSIZ);

	if_wpa->ifname[IFNAMSIZ] = 0;

	qevt_wpa_open(if_wpa);

	if_wpa->next = *if_wpa_head;
	*if_wpa_head = if_wpa;

}



#define WPA_CTRL_REQ_BUFFER 32
static int qevt_wpa_ping(struct qevt_wpa_iface *if_wpa)
{
	if (if_wpa->wpa_event && if_wpa->wpa_control) {
		char buffer[WPA_CTRL_REQ_BUFFER];
		size_t buffer_len = WPA_CTRL_REQ_BUFFER - 1;

		buffer[0] = 0;

		if (wpa_ctrl_request(if_wpa->wpa_control, "PING", sizeof("PING") - 1, buffer,
				     &buffer_len, NULL) == 0) {

			buffer[MIN(buffer_len, WPA_CTRL_REQ_BUFFER - 1)] = 0;

			if (!strcmp(buffer, "PONG\n")) {
				/* wpa/hostapd connection alive! */
				return 1;
			} else {
				fprintf(stderr, QEVT_TXT_PREFIX"unexpected wpa reply on '%s': %s\n",
					if_wpa->ifname, buffer);
			}
		}
	}
	return 0;
}

static int qevt_wpa_scan(struct qevt_server_config *config)
{
	DIR *d;
	struct dirent *dir;
	struct qevt_wpa_iface *if_wpa_head;

	/* this gives us a list of all network interfaces */
	d = opendir("/sys/class/net");
	if (!d) {
		fprintf(stderr, QEVT_TXT_PREFIX"unable to open /sys/class/net\n");
		return -1;
	}

	/* we may be changing the wpa connection data, so lock it */
	pthread_mutex_lock(&config->wpa_mutex);

	if_wpa_head = config->if_wpa;

	/* start by assuming all are dead, and then confirm alive */
	while (if_wpa_head) {
		if_wpa_head->dead = 1;
		if_wpa_head = if_wpa_head->next;
	}

	/* check for all wifi interfaces */
	while ((dir = readdir(d)) != NULL)
	{
		char *wifi;

		wifi = strstr(dir->d_name, QEVT_WIFI_INTERFACE_NAME);
		if (wifi) {
			int found = 0;

			if_wpa_head = config->if_wpa;
			while (if_wpa_head) {
				if (!strcmp(wifi, if_wpa_head->ifname)) {
					found = 1;
					if_wpa_head->dead = 0;
					break;
				}
				if_wpa_head = if_wpa_head->next;
			}

			if (found) {
				/* in case wpa not connected yet */
				if (!if_wpa_head->wpa_event || !if_wpa_head->wpa_control) {
					qevt_wpa_open(if_wpa_head);
				}

				/* check the wpa socket is alive and well */
				if (!qevt_wpa_ping(if_wpa_head)) {
					qevt_wpa_close(if_wpa_head);
				}
			} else {
				qevt_wpa_add_iface(&config->if_wpa, wifi);
			}
		}
	}
	closedir(d);

	if_wpa_head = config->if_wpa;

	/* look for dead wifi interfaces (no longer listed in /sys/class/net) */
	while (if_wpa_head) {
		if (if_wpa_head->dead) {
			qevt_wpa_close(if_wpa_head);
		}
		if_wpa_head = if_wpa_head->next;
	}
	pthread_mutex_unlock(&config->wpa_mutex);

	return 0;
}

static void *qevt_wpa_monitor_thread(void *arg)
{
	struct qevt_server_config *config = (struct qevt_server_config*) arg;

	while (config->running) {
		int status = qevt_wpa_scan(config);

		if (status < 0) {
			pthread_exit(NULL);
			return (void*)status;
		}
		/* wait 1 second before checking wpa connectivity again */
		qevt_timedwait(1000000);
	}
	pthread_exit(NULL);
	return NULL;
}

static int qevt_server_wpa_init(void)
{
	qevt_server_cfg.running = 1;
	if (pthread_create(&qevt_server_cfg.wpa_thread, NULL, qevt_wpa_monitor_thread,
		&qevt_server_cfg)) {
		return -1;
	}
	return 0;
}

static void qevt_wpa_event(struct qevt_wpa_iface *wpa)
{
	static char buffer[IW_CUSTOM_MAX + 1];
	size_t reply_len;
	struct iw_event event;
	int wpa_prefix_len;
	char *wpa_event_msg;

	snprintf(buffer, IW_CUSTOM_MAX, QEVT_WPA_PREFIX":");
	wpa_prefix_len = strlen(buffer);

	reply_len = IW_CUSTOM_MAX - wpa_prefix_len;
	wpa_event_msg = buffer + wpa_prefix_len;
	wpa_ctrl_recv(wpa->wpa_event, wpa_event_msg, &reply_len);

	wpa_event_msg[MIN(IW_CUSTOM_MAX - wpa_prefix_len, reply_len)] = 0;

	/*
	 * look for wpa message level eg <3> and reformat message to give individual prefix types
	 * per message level eg WPACTRL3: etc
	 */
	if ((reply_len > 3) && (wpa_event_msg[0] == '<') && (wpa_event_msg[2] == '>')) {
		snprintf(buffer, IW_CUSTOM_MAX, QEVT_WPA_PREFIX"%c:", wpa_event_msg[1]);
		wpa_prefix_len = strlen(buffer);
		memmove(buffer + wpa_prefix_len, wpa_event_msg + 3, strlen(wpa_event_msg + 3) + 1);
	}
	event.cmd = IWEVCUSTOM;
	event.u.data.pointer = buffer;
	event.u.data.length = strlen(buffer);

	qevt_iwevent_action(&event, wpa->ifname);
}

static int qevt_server_init(void)
{
	struct sockaddr_in srv_addr;
	int optval = 1;

	qevt_server_cfg.server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (qevt_server_cfg.server_socket < 0) {
		perror(QEVT_TXT_PREFIX"failed to create server socket");
		return -1;
	}

	if (setsockopt(qevt_server_cfg.server_socket, SOL_SOCKET, SO_REUSEADDR,
			&optval, sizeof(optval)) < 0) {
		perror(QEVT_TXT_PREFIX"setsockopt");
		close(qevt_server_cfg.server_socket);
		return -1;
	}

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	srv_addr.sin_port = htons(qevt_server_cfg.port);
	if (bind(qevt_server_cfg.server_socket, (struct sockaddr *)&srv_addr,
			sizeof(srv_addr)) < 0) {
		perror(QEVT_TXT_PREFIX"cannot bind server socket");
		close(qevt_server_cfg.server_socket);
		return -1;
	}

	if (listen(qevt_server_cfg.server_socket, 1) < 0) {
		perror(QEVT_TXT_PREFIX"listen");
		close(qevt_server_cfg.server_socket);
		return -1;
	}

	/* reset the built-in configurations */
	qevt_default = qevt_default_init;
	qevt_nondef = qevt_nondef_init;

	if (qevt_server_wpa_init() < 0) {
		return -1;
	}

	return 0;
}

static int qevt_accept_client_connection(void)
{
	do {
		qevt_server_cfg.client_socket = accept(qevt_server_cfg.server_socket, NULL, NULL);
	} while (qevt_server_cfg.client_socket < 0 && errno == EINTR);

	if (qevt_server_cfg.client_socket < 0) {
		perror(QEVT_TXT_PREFIX"accept");
		return -1;
	}

	return 0;
}

static void qevt_send_to_client(const char *fmt, ...)
{
	va_list ap;
	char loc_buf[QEVT_TX_BUF_SIZE] = {0};
	int sent_bytes = 0;
	int ret;

	va_start(ap, fmt);
	vsnprintf(loc_buf, sizeof(loc_buf), fmt, ap);
	va_end(ap);

	do {
		ret = send(qevt_server_cfg.client_socket, loc_buf + sent_bytes,
				strlen(loc_buf) - sent_bytes, 0);
		if (ret >= 0)
			sent_bytes += ret;
		else if (errno == EINTR)
			continue;
		else
			break;
	} while (sent_bytes < strlen(loc_buf));

	if (ret < 0)
		fprintf(stderr, QEVT_TXT_PREFIX"failure sending a message to client\n");
}

/*
 * QEVT_CONFIG is an input command from the client, to configure the host event
 * message filtering and output format.
 * Host event messages have a prefix following by colon eg 'MessagePrefix:'
 *
 * example config: QEVT_CONFIG MessagePrefix:[+/-][P][I][M][N][T]
 *
 * the + or - immediately after the prefix select whether to enable or disable
 * if not specified, the state is unchanged
 *
 * the P, I, M, N, T are single character options. They can be specified in
 * any order. If present, the option is on; if not present, the option is off.
 *
 * P = prefix; the event message will indicate the prefix
 * I = interface; the event message will indicate the interface name
 * M = message; the event message will indicate the message (!)
 * N = newline; the event message will be terminated by newline
 * T = timestamp; the event message will have timestamp NOT YET SUPPORTED
 *
 * A naked QEVT_CONFIG (with no parameters) will just return back the current
 * settings.
 */
static void qevt_client_config(char *config)
{
	char *prefix = NULL;
	char *params = NULL;
	char *item;
	struct qevt_message_config *msg_cfg;

	if (config[sizeof(QEVT_CONFIG) - 1] == ' ') {
		prefix = qevt_prefix(config + sizeof(QEVT_CONFIG), &params);
	}

	while (prefix) {
		if (!params) {
			/* some problem */
			return;
		}
		/* params points to colon at the end of prefix */
		*params++ = 0;

		msg_cfg = qevt_add(&qevt_messages, prefix);

		if (!msg_cfg) {
			/* some problem */
			return;
		}

		item = strstr(params, " ");
		if (item) {
			*item = 0;
		}

		if (params[0] == '+') {
			msg_cfg->flags.disabled = 0;
		} else if (params[0] == '-') {
			msg_cfg->flags.disabled = 1;
		}

		msg_cfg->flags.prfx = strstr(params, "P") ? 1 : 0;
		msg_cfg->flags.interface = strstr(params, "I") ? 1 : 0;
		msg_cfg->flags.message = strstr(params, "M") ?  1 : 0;
		msg_cfg->flags.newline = strstr(params, "N") ? 1: 0;
		msg_cfg->flags.timestamp = strstr(params, "T") ? 1: 0;

		if (item) {
			prefix = qevt_prefix(item + 1, &params);
		} else {
			prefix = NULL;
		}
	}
}

static void qevt_client_input(char *input, int len)
{
	char *command;

	/* QEVT_VERSION is a input request from the client, to request the server version */
	command = strstr(input, QEVT_VERSION);
	if (command && command[sizeof(QEVT_VERSION) - 1] <= ' ') {
		qevt_send_to_client("%s\n", QEVT_VERSION" "QEVT_CONFIG_VERSION);
		return;
	}

	/* QEVT_CONFIG is an input command from the client, to configure the server */
	command = strstr(input, QEVT_CONFIG);
	if (command && command[sizeof(QEVT_CONFIG) - 1] <= ' ') {
		qevt_client_config(command);

		/* report back the total configuration as confirmation (reuse input buffer) */
		qevt_report(&qevt_messages, input, len, QEVT_CONFIG);
		qevt_send_to_client("%s\n", input);
		return;
	}

	/* QEVT_CONFIG_RESET reverts back to default configuration (loses learned entries) */
	command = strstr(input, QEVT_CONFIG_RESET);
	if (command && command[sizeof(QEVT_CONFIG_RESET) - 1] <= ' ') {
		qevt_cleanup(&qevt_messages);

		/* reset the built-in configurations */
		qevt_default = qevt_default_init;
		qevt_nondef = qevt_nondef_init;

		/* report back the total configuration as confirmation (reuse input buffer) */
		qevt_report(&qevt_messages, input, len, QEVT_CONFIG);
		qevt_send_to_client("%s\n", input);
		return;
	}
	/* all other input is ignored */
}

static int qevt_client_connected(void)
{
	static char buffer[QEVT_CONFIG_RX_BUF];
	int count = recv(qevt_server_cfg.client_socket, buffer, sizeof(buffer), MSG_DONTWAIT);

	if (count > 0) {
		buffer[MIN(sizeof(buffer) - 1, count)] = 0;
		qevt_client_input(buffer, sizeof(buffer));
	}
	return count;
}

static int qevt_netlink_open(void)
{
	qevt_server_cfg.netlink_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (qevt_server_cfg.netlink_socket < 0) {
		perror(QEVT_TXT_PREFIX"cannot open netlink socket");
		return -1;
	}

	memset(&qevt_server_cfg.netlink_dst, 0, sizeof(qevt_server_cfg.netlink_dst));
	qevt_server_cfg.netlink_dst.nl_family = AF_NETLINK;
	qevt_server_cfg.netlink_dst.nl_groups = RTMGRP_LINK;
	if (bind(qevt_server_cfg.netlink_socket, (struct sockaddr *)&qevt_server_cfg.netlink_dst,
			sizeof(qevt_server_cfg.netlink_dst)) < 0) {
		close(qevt_server_cfg.netlink_socket);
		perror(QEVT_TXT_PREFIX"cannot bind netlink socket");
		return -1;
	}

	return 0;
}

static void qevt_send_event_to_client(struct qevt_message_config *msg_cfg, char *message,
				      char *ifname)
{
	struct qevt_config_flags flags = msg_cfg->flags;

	msg_cfg->flags.seen = 1;

	if (!flags.disabled) {
		char *newline = strstr(message, "\n");
		char *timestamp = flags.timestamp ? qevt_timestamp() : "";

		do {
			if (newline) {
				*newline = 0;
			}
			qevt_send_to_client("%s%s%s%s%s%s%s%c",
					    flags.prfx ? msg_cfg->prefix : "",
					    flags.prfx ? ": " : "",
					    flags.interface ? "[" : "",
					    flags.interface ? ifname : "",
					    flags.interface ? "] " : "",
					    timestamp,
					    flags.message ? message : "",
					    flags.newline ? '\n' : 0);

			if (newline) {
				message = newline + 1;
				newline = strstr(message, "\n");
			}
		} while (newline);
	}
}

static void qevt_iwevent_action(struct iw_event *event, char *ifname)
{
	static char custom[IW_CUSTOM_MAX + 1];
	struct qevt_message_config *msg_cfg = NULL;
	char *prefix = NULL;
	char *message = NULL;
	char *data = NULL;
	int chars_to_copy = 0;

	switch (event->cmd) {
	case IWEVCUSTOM:
		if (event->u.data.pointer && event->u.data.length) {
			chars_to_copy = event->u.data.length;
			data = event->u.data.pointer;
		}
		break;
	case SIOCGIWSCAN:
		data = QEVT_COMMON_PREFIX"notify scan done";
		chars_to_copy = strlen(data);
		break;
	default:
		return;
	}

	if (data == NULL || chars_to_copy == 0) {
		return;
	}
	chars_to_copy = MIN(chars_to_copy, IW_CUSTOM_MAX);
	memcpy(custom, data, chars_to_copy);
	custom[chars_to_copy] = '\0';

	prefix = qevt_prefix(custom, &message);

	/* only recognise prefix at the start of line */
	if (prefix && (prefix == custom)) {
		/* message points to the colon at the end of prefix */
		*message++ = 0;
		msg_cfg = qevt_add(&qevt_messages, prefix);
	} else {
		message = custom;
		msg_cfg = &qevt_nondef;
		prefix = qevt_nondef.prefix;
	}

	if (prefix && msg_cfg) {
		qevt_send_event_to_client(msg_cfg, message, ifname);
	}
}

static void qevt_iwevent_stream_parse(const int ifindex, char *data, const int len)
{
	struct stream_descr stream;
	struct iw_event event;
	struct qevt_wifi_iface *wireless_data;

	/* Get data from cache */
	wireless_data = qevt_get_interface_data(ifindex);

	if (!wireless_data)
		return;

	iw_init_event_stream(&stream, data, len);

	while (iw_extract_event_stream(&stream, &event,
					wireless_data->range.we_version_compiled) > 0) {
		qevt_iwevent_action(&event, wireless_data->ifname);
	}
}

/* Respond to a single RTM_NEWLINK event from the rtnetlink socket. */
static void qevt_rtnetlink_parse(struct nlmsghdr *nlh)
{
	struct ifinfomsg *ifim = (struct ifinfomsg *)NLMSG_DATA(nlh);
	struct rtattr *rta = IFLA_RTA(ifim);
	size_t rtasize = IFLA_PAYLOAD(nlh);

	/* Only keep add/change events */
	if (nlh->nlmsg_type != RTM_NEWLINK)
		return;

	while (RTA_OK(rta, rtasize)) {
		if (rta->rta_type == IFLA_WIRELESS) {
			qevt_iwevent_stream_parse(ifim->ifi_index,
							RTA_DATA(rta), RTA_PAYLOAD(rta));
		}

		rta = RTA_NEXT(rta, rtasize);
	}
}

static int qevt_netlink_read(void)
{
	int len;
	char buf[QEVT_RX_BUF_SIZE];
	struct iovec iov = {buf, sizeof(buf)};
	struct msghdr msg;
	struct nlmsghdr *nlh;

	msg = (struct msghdr){NULL, 0, &iov, 1, NULL, 0, 0};

	do {
		len = recvmsg(qevt_server_cfg.netlink_socket, &msg, 0);
	} while (len < 0 && errno == EINTR);

	if (len <= 0) {
		perror(QEVT_TXT_PREFIX"error reading netlink");
		return -1;
	}

	for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len);
			nlh = NLMSG_NEXT(nlh, len)) {
		/* The end of multipart message. */
		if (nlh->nlmsg_type == NLMSG_DONE)
			break;

		if (nlh->nlmsg_type == RTM_NEWLINK)
			qevt_rtnetlink_parse(nlh);
		}

	return 0;
}

static void qevt_wait_for_event(void)
{
	fd_set rfds;
	int last_fd;
	int ret;

	for (;;) {
		struct qevt_wpa_iface *wpa;
		struct timeval tv;
		int wpa_event_check = 1;

		/* Re-generate rfds each time */
		FD_ZERO(&rfds);
		FD_SET(qevt_server_cfg.netlink_socket, &rfds);
		FD_SET(qevt_server_cfg.client_socket, &rfds);

		last_fd = MAX(qevt_server_cfg.netlink_socket, qevt_server_cfg.client_socket);

		if (pthread_mutex_trylock(&qevt_server_cfg.wpa_mutex) != 0) {
			/*
			 * The wpa_monitor thread is updating the internal wpa state
			 * (a wpa socket might be going down or coming up), so wait 100ms.
			 */
			qevt_timedwait(100000);

			if (pthread_mutex_trylock(&qevt_server_cfg.wpa_mutex) != 0) {
				/* wpa_monitor is momentarily stuck, so skip it */
				wpa_event_check = 0;
			}
		}
		wpa = qevt_server_cfg.if_wpa;
		while (wpa) {
			if (wpa->wpa_event && wpa->fd && wpa_event_check) {
				FD_SET(wpa->fd, &rfds);
				last_fd = MAX(last_fd, wpa->fd);
				/*
				 * in case wpa state changes (ie a new connection comes up later),
				 * it would not be registered here but the wpa->event_check would
				 * be 0 for that
				 */
				wpa->event_check = 1;
			} else {
				wpa->event_check = 0;
			}
			wpa = wpa->next;
		}
		if (wpa_event_check) {
			pthread_mutex_unlock(&qevt_server_cfg.wpa_mutex);
		}

		/* timeout after 1 second in case wpa monitor finds something new */
		tv.tv_sec = 0;
		tv.tv_usec = 1000000;

		/* Wait until something happens or timeout */
		ret = select(last_fd + 1, &rfds, NULL, NULL, &tv);

		/* Check if there was an error */
		if (ret < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			fprintf(stderr, QEVT_TXT_PREFIX"unhandled signal - exiting\n");
			break;
		}

		/* Check if there was a timeout */
		if (ret == 0) {
			continue;
		}

		if (FD_ISSET(qevt_server_cfg.client_socket, &rfds)) {
			if (!qevt_client_connected()) {
				close(qevt_server_cfg.client_socket);
				close(qevt_server_cfg.netlink_socket);
				if (qevt_accept_client_connection() < 0)
					break;
				if (qevt_netlink_open() < 0)
					break;
				continue;
			}
		}

		/* Check for interface discovery events. */
		if (FD_ISSET(qevt_server_cfg.netlink_socket, &rfds)) {
			qevt_netlink_read();
		}

		wpa = qevt_server_cfg.if_wpa;
		while (wpa) {
			if (wpa->event_check && wpa->fd && FD_ISSET(wpa->fd, &rfds)) {
				qevt_wpa_event(wpa);
			}
			wpa = wpa->next;
		}
	}
}

int main(int argc, char *argv[])
{
	if (argc != 1 && argc != 2) {
		fprintf(stderr, "Usage: %s {server IP port}\n", argv[0]);
		return EXIT_FAILURE;
	}

	if (argc == 2)
		qevt_server_cfg.port = atoi(argv[1]);
	else
		qevt_server_cfg.port = QEVT_DEFAULT_PORT;

	if (qevt_server_init() < 0)
		return EXIT_FAILURE;

	if (qevt_accept_client_connection() < 0)
		return EXIT_FAILURE;

	if (qevt_netlink_open() < 0)
		return EXIT_FAILURE;

	qevt_wait_for_event();
	qevt_cache_free();
	qevt_cleanup(&qevt_messages);
	qevt_wpa_cleanup();

	return EXIT_SUCCESS;
}

