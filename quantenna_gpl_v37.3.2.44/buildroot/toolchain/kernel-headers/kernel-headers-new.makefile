#############################################################
#
# full kernel tarballs >= 2.6.19.1
#
#############################################################

ifeq ("$(DEFAULT_KERNEL_HEADERS)","2.6.20")
VERSION:=2
PATCHLEVEL:=6
SUBLEVEL:=20
EXTRAVERSION:=
LOCALVERSION:=
LINUX_HEADERS_VERSION:=$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)
LINUX_HEADERS_SITE:=http://www.kernel.org/pub/linux/kernel/v2.6/
LINUX_HEADERS_SOURCE:=linux-$(LINUX_HEADERS_VERSION).tar.bz2
LINUX_HEADERS_CAT:=$(BZCAT)
LINUX_HEADERS_UNPACK_DIR:=$(BUILD_DIR)/linux-$(LINUX_HEADERS_VERSION)
LINUX_HEADERS_DIR:=$(TOOL_BUILD_DIR)/linux
LINUX_HEADERS_IS_KERNEL=y

ifeq ($(LINUX_HEADERS_IS_KERNEL),y)

$(LINUX_HEADERS_UNPACK_DIR)/.unpacked: $(DL_DIR)/$(LINUX_HEADERS_SOURCE)
	rm -rf $(LINUX_HEADERS_DIR)
	[ -d $(BUILD_DIR) ] || $(INSTALL) -d $(BUILD_DIR)
	$(LINUX_HEADERS_CAT) $(DL_DIR)/$(LINUX_HEADERS_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	touch $@

$(LINUX_HEADERS_UNPACK_DIR)/.patched: $(LINUX_HEADERS_UNPACK_DIR)/.unpacked
	toolchain/patch-kernel.sh $(LINUX_HEADERS_UNPACK_DIR) toolchain/kernel-headers \
		linux-$(LINUX_HEADERS_VERSION)-\*.patch{,.gz,.bz2}
	touch $@

$(LINUX_HEADERS_DIR)/.configured: $(LINUX_HEADERS_UNPACK_DIR)/.patched
	(cd $(LINUX_HEADERS_UNPACK_DIR) ; \
	 $(MAKE) ARCH=$(KERNEL_ARCH) CC="$(HOSTCC)" \
		INSTALL_HDR_PATH=$(LINUX_HEADERS_DIR) headers_install ; \
	)
	touch $@

endif


$(DL_DIR)/$(LINUX_HEADERS_SOURCE):
	$(WGET) -P $(DL_DIR) $(LINUX_HEADERS_SITE)/$(LINUX_HEADERS_SOURCE)

kernel-headers: $(LINUX_HEADERS_DIR)/.configured

kernel-headers-source: $(DL_DIR)/$(LINUX_HEADERS_SOURCE)

endif
LINUX_HEADERS_DIR:=$(TOOL_BUILD_DIR)/linux
kernel-headers: $(LINUX_HEADERS_DIR)/.configured
