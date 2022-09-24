#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <../../../../common/ruby_pm.h>

#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))
#endif

static const char *qtn_pm_param_names[QTN_PM_IOCTL_MAX] = QTN_PM_PARAM_NAMES;
static const int32_t default_state[QTN_PM_IOCTL_MAX] = QTN_PM_PARAM_DEFAULTS;

static void __qpm_show_help(FILE *f)
{
	int i;

	fprintf(f, "Usage:\n");
	fprintf(f, "  qpm show [conf]\n");
	fprintf(f, "  cat <conf_file> | qpm setup\n");
	fprintf(f, "  qpm <param> [set value]\n");
	fprintf(f, "    Where <param> is one of:\n");
	for (i = 0; i < ARRAY_SIZE(qtn_pm_param_names); i++) {
		fprintf(f, "\t%s\n", qtn_pm_param_names[i]);
	}
}

static void qpm_show_help(void)
{
	__qpm_show_help(stdout);
}

static int qpm_read_state(const char *ifname, int32_t *state)
{
	const char *ioctlname = "get_pm";

	int rc = 0;
	FILE *fp = NULL;
	int i;

	char proc[128];
	char ifname_read[32] = {0};
	char ioctlname_read[32] = {0};

	/* spawn iwpriv subprocess to read from */
	snprintf(proc, sizeof(proc), "iwpriv %s %s", ifname, ioctlname);
	fp = popen(proc, "r");
	if (fp == NULL) {
		rc = -errno;
		fprintf(stderr, "Error starting '%s'\n", proc);
		goto out;
	}

	/* Output should be: '<ifname>   <ioctlname>:<numbers>' */
	if ((fscanf(fp, "%s %[^:]:", ifname_read, ioctlname_read) != 2) ||
			strncmp(ifname, ifname_read, sizeof(ifname_read)) ||
			strncmp(ioctlname, ioctlname_read, sizeof(ioctlname_read))) {
		rc = -EINVAL;
		fprintf(stderr, "Unknown output from iwpriv\n");
		goto out;
	}

	/*
	 * remaining output is a memory dump of the state array,
	 * bytewise with '%d's
	 */
	for (i = 0; i < QTN_PM_IOCTL_MAX * sizeof(state[0]); i++) {
		int d;
		uint8_t *data = (uint8_t *)state;

		if (fscanf(fp, "%d", &d) != 1) {
			rc = -EINVAL;
			fprintf(stderr, "Error parsing number from iwpriv\n");
			goto out;
		}
		data[i] = d;
	}

out:
	if (fp) {
		pclose(fp);
	}

	return rc;
}

static int qpm_set_one(const char *ifname, enum qtn_pm_param param, int32_t val)
{
	char buf[128];

	if (param == QTN_PM_CURRENT_LEVEL) {
		snprintf(buf, sizeof(buf), "echo update %s %d > /proc/soc_pm", BOARD_PM_GOVERNOR_QCSAPI, val);
	} else {
		snprintf(buf, sizeof(buf), "iwpriv %s pm %d\n", ifname, QTN_PM_PACK_PARAM_VALUE(param, val));
	}
	return system(buf);
}

static int qpm_set_one_parse(const char *ifname, enum qtn_pm_param param, const char *arg)
{
	int val;

	if (strcmp(arg, "off") == 0) {
		val = BOARD_PM_LEVEL_FORCE_NO;
	} else if (strcmp(arg, "on") == 0 || strcmp(arg, "auto") == 0) {
		val = -1;
	} else if (strcmp(arg, "suspend") == 0) {
		val = BOARD_PM_LEVEL_SUSPEND;
	} else if (sscanf(arg, "%d", &val) == 1) {
		/* correctly parsed */
	} else {
		fprintf(stderr, "%s: could not parse '%s'\n", __FUNCTION__, arg);
		return -EINVAL;
	}

	return qpm_set_one(ifname, param, val);
}

static enum qtn_pm_param qpm_parse_param_name(const char *name)
{
	int i;
	enum qtn_pm_param param = QTN_PM_IOCTL_MAX;

	for (i = 0; i < ARRAY_SIZE(qtn_pm_param_names); i++) {
		if (strcmp(name, qtn_pm_param_names[i]) == 0) {
			param = i;
		}
	}

	if (param >= QTN_PM_IOCTL_MAX || param >= ARRAY_SIZE(qtn_pm_param_names)) {
		fprintf(stderr, "%s: unrecognized parameter '%s'\n", __FUNCTION__, name);
	}

	return param;
}

static int qpm(int argc, char **argv)
{
	const char *ifname = "wifi0";
	int i;
	int val;
	int rc = -EINVAL;
	enum qtn_pm_param param;
	int32_t state[QTN_PM_IOCTL_MAX] = QTN_PM_PARAM_DEFAULTS;

	if (argc < 1) {
		qpm_show_help();
		return 0;
	} else if (strcmp(argv[0], "show") == 0) {
		int show_conf = 0;

		if (argc == 2 && strcmp(argv[1], "conf") == 0) {
			show_conf = 1;
		}

		rc = qpm_read_state(ifname, state);
		if (rc) {
			goto out;
		}

		for (i = 0; i < QTN_PM_IOCTL_MAX; i++) {
			if (!show_conf ||
					(i != QTN_PM_CURRENT_LEVEL &&
					 state[i] != default_state[i])) {
				fprintf(stdout, "%s %d\n", qtn_pm_param_names[i], state[i]);
			}
		}
	} else if (strcmp(argv[0], "setup") == 0) {
		char buf[128];
		char paramstr[32];

		while (fgets(buf, sizeof(buf), stdin) != NULL) {
			if (sscanf(buf, "%s %d", paramstr, &val) == 2) {
				param = qpm_parse_param_name(paramstr);
				if (param < QTN_PM_IOCTL_MAX) {
					state[param] = val;
				}
			}
		}

		for (i = 0; i < QTN_PM_IOCTL_MAX; i++) {
			if (i == QTN_PM_CURRENT_LEVEL) {
				continue;
			}

			rc = qpm_set_one(ifname, i, state[i]);
			if (rc) {
				goto out;
			}
		}
	} else {
		param = qpm_parse_param_name(argv[0]);
		if (param >= QTN_PM_IOCTL_MAX) {
			qpm_show_help();
			return -EINVAL;
		}

		if (argc == 1) {
			rc = qpm_read_state(ifname, state);
			if (rc) {
				goto out;
			}
			fprintf(stdout, "%u\n", state[param]);
		} else if (argc == 2) {
			rc = qpm_set_one_parse(ifname, param, argv[1]);
		} else {
			qpm_show_help();
		}
	}

out:
	if (rc < 0) {
		fprintf(stderr, "returned error %d: %s\n", rc, strerror(rc));
	}

	return rc;
}

int main(int argc, char **argv) {
	return qpm(argc - 1, argv + 1);
}

