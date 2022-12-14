#############################################################
#
# lzma
#
#############################################################
LZMA_VER:=4.32.0beta3
LZMA_SOURCE:=lzma-$(LZMA_VER).tar.gz
LZMA_CAT:=$(ZCAT)
LZMA_SITE:=http://tukaani.org/lzma/
LZMA_HOST_DIR:=$(TOOL_BUILD_DIR)/lzma-$(LZMA_VER)
LZMA_TARGET_DIR:=$(BUILD_DIR)/lzma-$(LZMA_VER)
LZMA_CFLAGS:=$(TARGET_CFLAGS)
ifeq ($(BR2_LARGEFILE),y)
LZMA_CFLAGS+=-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
endif
LZMA_TARGET_BINARY:=bin/lzma

$(DL_DIR)/$(LZMA_SOURCE):
	$(WGET) -P $(DL_DIR) $(LZMA_SITE)/$(LZMA_SOURCE)

######################################################################
#
# lzma host
#
######################################################################

$(LZMA_HOST_DIR)/.source: $(DL_DIR)/$(LZMA_SOURCE)
	$(LZMA_CAT) $(DL_DIR)/$(LZMA_SOURCE) | tar -C $(TOOL_BUILD_DIR) $(TAR_OPTIONS) -
	toolchain/patch-kernel.sh $(LZMA_HOST_DIR) package/lzma/ lzma\*.patch
	touch $(LZMA_HOST_DIR)/.source

$(LZMA_HOST_DIR)/.configured: $(LZMA_HOST_DIR)/.source
	(cd $(LZMA_HOST_DIR); rm -f config.cache ;\
		CC="$(HOSTCC)" \
		CXX="$(HOSTCXX)" \
		./configure \
		--prefix=/ \
	);
	touch $(LZMA_HOST_DIR)/.configured;

$(LZMA_HOST_DIR)/src/lzma/lzma: $(LZMA_HOST_DIR)/.configured
	$(MAKE) -C $(LZMA_HOST_DIR) all
	touch -c $@

$(STAGING_DIR)/bin/lzma: $(LZMA_HOST_DIR)/src/lzma/lzma
	$(MAKE) DESTDIR=$(STAGING_DIR) -C $(LZMA_HOST_DIR) install

lzma-host: uclibc $(STAGING_DIR)/bin/lzma

######################################################################
#
# lzma target
#
######################################################################

$(LZMA_TARGET_DIR)/.source: $(DL_DIR)/$(LZMA_SOURCE)
	$(LZMA_CAT) $(DL_DIR)/$(LZMA_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	toolchain/patch-kernel.sh $(LZMA_TARGET_DIR) package/lzma/ lzma\*.patch
	touch $(LZMA_TARGET_DIR)/.source

$(LZMA_TARGET_DIR)/.configured: $(LZMA_TARGET_DIR)/.source
	(cd $(LZMA_TARGET_DIR); rm -f config.cache ;\
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) $(LZMA_CFLAGS)" \
		ac_cv_func_malloc_0_nonnull=yes \
		./configure \
		--target=$(GNU_TARGET_NAME) \
		--host=$(GNU_TARGET_NAME) \
		--build=$(GNU_HOST_NAME) \
		--prefix=/usr \
		--exec-prefix=$(TARGET_DIR)/usr/bin \
		--libdir=$(TARGET_DIR)/lib \
		--includedir=$(TARGET_DIR)/include \
		--disable-debug \
		$(DISABLE_NLS) \
		$(DISABLE_LARGEFILE) \
	);
	touch $(LZMA_TARGET_DIR)/.configured;

$(LZMA_TARGET_DIR)/src/lzma/lzma: $(LZMA_TARGET_DIR)/.configured
	$(MAKE) -C $(LZMA_TARGET_DIR) all
	touch -c $@

$(TARGET_DIR)/$(LZMA_TARGET_BINARY): $(LZMA_TARGET_DIR)/src/lzma/lzma
	cp -dpf $(LZMA_TARGET_DIR)/src/lzma/lzma $@
	-$(STRIP) --strip-unneeded $@
	touch -c $@

#lzma-headers: $(TARGET_DIR)/$(LZMA_TARGET_BINARY)

lzma-target: uclibc $(TARGET_DIR)/$(LZMA_TARGET_BINARY)

lzma-source: $(DL_DIR)/$(LZMA_SOURCE)

lzma-clean:
	rm -f $(TARGET_DIR)/usr/bin/lzma
	-$(MAKE) -C $(LZMA_TARGET_DIR) clean

lzma-dirclean:
	rm -rf $(LZMA_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_LZMA_HOST)),y)
TARGETS+=lzma-host
endif

ifeq ($(strip $(BR2_PACKAGE_LZMA_TARGET)),y)
TARGETS+=lzma-target
endif

#ifeq ($(strip $(BR2_PACKAGE_LZMA_TARGET_HEADERS)),y)
#TARGETS+=lzma-headers
#endif
