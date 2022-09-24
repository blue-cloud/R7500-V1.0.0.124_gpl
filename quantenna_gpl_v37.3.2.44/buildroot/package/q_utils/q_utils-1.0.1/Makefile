.PHONY: qevent

PROGS= show_rfcal_version restore_bootcfg_env writerfmem

INSTALL_DIR= $(PREFIX)/sbin/

install: $(PROGS)
	install -m 755 -d $(INSTALL_DIR)
	install -m 755 $(PROGS) $(INSTALL_DIR)

qevt_server.o: qevt_server.c
	$(CC) $(CFLAGS) -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX \
	 -I../../zhostapd/hostapd-git/src/utils  -I../../zhostapd/hostapd-git/src/common \
	 -c qevt_server.c

wpa_ctrl.o: ../../zhostapd/hostapd-git/src/common/wpa_ctrl.c
	$(CC) $(CFLAGS) -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX \
	 -I../../zhostapd/hostapd-git/src/utils -I../../zhostapd/hostapd-git/src/common \
	 -c ../../zhostapd/hostapd-git/src/common/wpa_ctrl.c

os_unix.o: ../../zhostapd/hostapd-git/src/utils/os_unix.c
	$(CC) $(CFLAGS) -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX \
	 -I../../zhostapd/hostapd-git/src/utils -I../../zhostapd/hostapd-git/src/common \
	 -c ../../zhostapd/hostapd-git/src/utils/os_unix.c

qevent: qevt_server.o wpa_ctrl.o os_unix.o
	$(CC) $(CFLAGS) $(LDFLAGS) -liw -pthread -o qevt_server qevt_server.o wpa_ctrl.o os_unix.o

install_qevent: qevent
	install -m 755 -d $(INSTALL_DIR)
	install -m 755 qevt_server $(INSTALL_DIR)

clean:
	rm -f $(PROGS) qevt_server wpa_ctrl.o qevt_server.o os_unix.o
