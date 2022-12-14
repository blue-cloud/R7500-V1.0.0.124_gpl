#############################################################
#
# iptables
#
#############################################################
IPTABLES_VER:=1.3.7
IPTABLES_SOURCE_URL:=ftp.netfilter.org/pub/iptables
IPTABLES_SOURCE:=iptables-$(IPTABLES_VER).tar.bz2
IPTABLES_CAT:=$(BZCAT)
IPTABLES_BUILD_DIR:=$(BUILD_DIR)/iptables-$(IPTABLES_VER)

$(DL_DIR)/$(IPTABLES_SOURCE):
	 $(WGET) -P $(DL_DIR) $(IPTABLES_SOURCE_URL)/$(IPTABLES_SOURCE) 

$(IPTABLES_BUILD_DIR)/.unpacked: $(DL_DIR)/$(IPTABLES_SOURCE)
	$(IPTABLES_CAT) $(DL_DIR)/$(IPTABLES_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	touch $(IPTABLES_BUILD_DIR)/.unpacked

$(IPTABLES_BUILD_DIR)/.configured: $(IPTABLES_BUILD_DIR)/.unpacked
	# Allow patches.  Needed for openwrt for instance.
	toolchain/patch-kernel.sh $(IPTABLES_BUILD_DIR) package/iptables/ iptables\*.patch
	#
	$(SED) "s;\[ -f /usr/include/netinet/ip6.h \];grep -q '__UCLIBC_HAS_IPV6__ 1' \
		$(STAGING_DIR)/include/bits/uClibc_config.h;" $(IPTABLES_BUILD_DIR)/Makefile
	touch $(IPTABLES_BUILD_DIR)/.configured

$(IPTABLES_BUILD_DIR)/iptables: $(IPTABLES_BUILD_DIR)/.configured
	$(TARGET_CONFIGURE_OPTS) \
	$(MAKE1) -C $(IPTABLES_BUILD_DIR) \
		KERNEL_DIR=$(LINUX_HEADERS_DIR) PREFIX=/usr \
		CC=$(TARGET_CC) COPT_FLAGS="$(TARGET_CFLAGS)"

$(TARGET_DIR)/usr/sbin/iptables: $(IPTABLES_BUILD_DIR)/iptables
	$(TARGET_CONFIGURE_OPTS) \
	$(MAKE1) -C $(IPTABLES_BUILD_DIR) \
		KERNEL_DIR=$(LINUX_HEADERS_DIR) PREFIX=/usr \
		CC=$(TARGET_CC) COPT_FLAGS="$(TARGET_CFLAGS)" \
		DESTDIR=$(TARGET_DIR) install
	$(STRIP) $(TARGET_DIR)/usr/sbin/iptables*
	$(STRIP) $(TARGET_DIR)/usr/lib/iptables/*.so
	rm -rf $(TARGET_DIR)/usr/man

iptables: $(TARGET_DIR)/usr/sbin/iptables

iptables-source: $(DL_DIR)/$(IPTABLES_SOURCE)

iptables-clean:
	-$(MAKE1) -C $(IPTABLES_BUILD_DIR) clean
	rm -rf $(TARGET_DIR)/usr/sbin/iptables* $(TARGET_DIR)/usr/lib/iptables

iptables-dirclean:
	rm -rf $(IPTABLES_BUILD_DIR)
#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_IPTABLES)),y)
TARGETS+=iptables
endif
