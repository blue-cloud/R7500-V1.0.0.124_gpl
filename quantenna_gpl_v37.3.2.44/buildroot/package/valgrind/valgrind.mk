#############################################################
#
# valgrind
#
#############################################################

VALGRIND_VERSION=3.2.1
VALGRIND_SITE:=http://valgrind.org/downloads/
VALGRIND_DIR:=$(BUILD_DIR)/valgrind-$(VALGRIND_VERSION)
VALGRIND_SOURCE:=valgrind-$(VALGRIND_VERSION).tar.bz2
VALGRIND_CAT:=$(BZCAT)

$(DL_DIR)/$(VALGRIND_SOURCE):
	$(WGET) -P $(DL_DIR) $(VALGRIND_SITE)/$(VALGRIND_SOURCE)

$(VALGRIND_DIR)/.unpacked: $(DL_DIR)/$(VALGRIND_SOURCE)
	$(VALGRIND_CAT) $(DL_DIR)/$(VALGRIND_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	touch $(VALGRIND_DIR)/.unpacked

$(VALGRIND_DIR)/.patched: $(VALGRIND_DIR)/.unpacked
	toolchain/patch-kernel.sh $(VALGRIND_DIR) package/valgrind/ valgrind\*.patch
	touch $(VALGRIND_DIR)/.patched

$(VALGRIND_DIR)/.configured: $(VALGRIND_DIR)/.patched
	(cd $(VALGRIND_DIR); rm -rf config.cache; \
		$(TARGET_CONFIGURE_OPTS) \
		./configure \
		--target=$(GNU_TARGET_NAME) \
		--host=$(GNU_TARGET_NAME) \
		--build=$(GNU_HOST_NAME) \
		--prefix=/usr \
		--exec-prefix=/usr \
		--bindir=/usr/bin \
		--sbindir=/usr/sbin \
		--libdir=/lib \
		--libexecdir=/usr/lib \
		--sysconfdir=/etc \
		--datadir=/usr/share \
		--localstatedir=/var \
		--mandir=/usr/man \
		--infodir=/usr/info \
		$(DISABLE_NLS) \
		--without-uiout --disable-valgrindmi \
		--disable-tui --disable-valgrindtk \
		--without-x --without-included-gettext \
		--disable-tls \
	);
	touch $(VALGRIND_DIR)/.configured

$(VALGRIND_DIR)/none/vgskin_none.so: $(VALGRIND_DIR)/.configured
	$(MAKE) -C $(VALGRIND_DIR)
	-$(STRIP) --strip-unneeded $(VALGRIND_DIR)/*.so*
	touch -c $(VALGRIND_DIR)/none/vgskin_none.so

$(TARGET_DIR)/usr/bin/valgrind: $(VALGRIND_DIR)/none/vgskin_none.so
	$(MAKE) \
	    prefix=$(TARGET_DIR)/usr \
	    exec_prefix=$(TARGET_DIR)/usr \
	    bindir=$(TARGET_DIR)/usr/bin \
	    sbindir=$(TARGET_DIR)/usr/sbin \
	    libexecdir=$(TARGET_DIR)/usr/lib \
	    datadir=$(TARGET_DIR)/usr/share \
	    sysconfdir=$(TARGET_DIR)/etc \
	    sharedstatedir=$(TARGET_DIR)/usr/com \
	    localstatedir=$(TARGET_DIR)/var \
	    libdir=$(TARGET_DIR)/usr/lib \
	    infodir=$(TARGET_DIR)/usr/info \
	    mandir=$(TARGET_DIR)/usr/man \
	    includedir=$(TARGET_DIR)/usr/include \
	    -C $(VALGRIND_DIR) install;
	mv $(TARGET_DIR)/usr/bin/valgrind $(TARGET_DIR)/usr/bin/valgrind.bin
	cp package/valgrind/uclibc.supp $(TARGET_DIR)/usr/lib/valgrind/
	cp package/valgrind/valgrind.sh $(TARGET_DIR)/usr/bin/valgrind
	chmod a+x $(TARGET_DIR)/usr/bin/valgrind
	rm -rf $(TARGET_DIR)/usr/share/doc/valgrind
	#mkdir -p $(TARGET_DIR)/etc/default
	#cp $(VALGRIND_DIR)/valgrind.default $(TARGET_DIR)/etc/default/valgrind
	#mkdir -p $(TARGET_DIR)/usr/lib/valgrind
	#cp $(VALGRIND_DIR)/woody.supp $(TARGET_DIR)/usr/lib/valgrind/
	touch -c $(TARGET_DIR)/usr/bin/valgrind

valgrind: $(TARGET_DIR)/usr/bin/valgrind

valgrind-source: $(DL_DIR)/$(VALGRIND_SOURCE)

valgrind-clean:
	$(MAKE) -C $(VALGRIND_DIR) clean

valgrind-dirclean:
	rm -rf $(VALGRIND_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_VALGRIND)),y)
TARGETS+=valgrind
endif
