#############################################################
#
# asterisk
#
##############################################################
ASTERISK_VERSION := 1.2.0-beta1
ASTERISK_SOURCE := asterisk-$(ASTERISK_VERSION).tar.gz
ASTERISK_SITE := ftp://ftp.digium.com/pub/asterisk/old-releases
ASTERISK_DIR := $(BUILD_DIR)/asterisk-$(ASTERISK_VERSION)
ASTERISK_BINARY := asterisk
ASTERISK_TARGET_BINARY := usr/sbin/asterisk

$(DL_DIR)/$(ASTERISK_SOURCE):
	$(WGET) -P $(DL_DIR) $(ASTERISK_SITE)/$(ASTERISK_SOURCE)

$(ASTERISK_DIR)/.source: $(DL_DIR)/$(ASTERISK_SOURCE)
	$(ZCAT) $(DL_DIR)/$(ASTERISK_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	toolchain/patch-kernel.sh $(ASTERISK_DIR) package/asterisk/ asterisk\*.patch
	touch $(ASTERISK_DIR)/.source

$(ASTERISK_DIR)/.configured: $(ASTERISK_DIR)/.source
	touch $(ASTERISK_DIR)/.configured

$(ASTERISK_DIR)/$(ASTERISK_BINARY): $(ASTERISK_DIR)/.configured
	$(MAKE1) -C $(ASTERISK_DIR) CROSS_ARCH=Linux CROSS_COMPILE=$(TARGET_CROSS) CROSS_COMPILE_BIN=$(STAGING_DIR)/bin/ CROSS_COMPILE_TARGET=$(STAGING_DIR) CROSS_PROC=$(OPTIMIZE_FOR_CPU) OPTIMIZE="$(TARGET_OPTIMIZATION)" OPTIONS=-DLOW_MEMORY DEBUG= $(TARGET_CONFIGURE_OPTS)

$(TARGET_DIR)/$(ASTERISK_TARGET_BINARY): $(ASTERISK_DIR)/$(ASTERISK_BINARY)
	$(MAKE) -C $(ASTERISK_DIR) CROSS_ARCH=Linux CROSS_COMPILE=$(TARGET_CROSS) CROSS_COMPILE_BIN=$(TARGET_CC) CROSS_COMPILE_TARGET=$(STAGING_DIR) CROSS_PROC=$(OPTIMIZE_FOR_CPU) OPTIMIZE="$(TARGET_OPTIMIZATION)" OPTIONS=-DLOW_MEMORY DEBUG= $(TARGET_CONFIGURE_OPTS) DESTDIR=$(TARGET_DIR) install
	$(STRIP) $(TARGET_DIR)/usr/sbin/asterisk
	$(STRIP) $(TARGET_DIR)/usr/sbin/stereorize
	$(STRIP) $(TARGET_DIR)/usr/sbin/streamplayer
	$(STRIP) --strip-unneeded $(TARGET_DIR)/usr/lib/asterisk/modules/*.so
	$(INSTALL) -m 755 $(ASTERISK_DIR)/contrib/init.d/rc.debian.asterisk $(TARGET_DIR)/etc/init.d/S60asterisk
	mv $(TARGET_DIR)/usr/include/asterisk $(STAGING_DIR)/include/
	rm -Rf $(TARGET_DIR)/usr/share/man
	rm -f $(TARGET_DIR)/usr/sbin/safe_asterisk
	rm -f $(TARGET_DIR)/usr/sbin/autosupport
	rm -f $(TARGET_DIR)/usr/sbin/astgenkey
	touch -c $(TARGET_DIR)/$(ASTERISK_TARGET_BINARY)

asterisk: uclibc ncurses zlib openssl mpg123 $(TARGET_DIR)/$(ASTERISK_TARGET_BINARY)

asterisk-source: $(DL_DIR)/$(ASTERISK_SOURCE)

asterisk-clean:
	rm -Rf $(STAGING_DIR)/include/asterisk
	rm -Rf $(TARGET_DIR)/etc/asterisk
	rm -Rf $(TARGET_DIR)/usr/lib/asterisk
	rm -Rf $(TARGET_DIR)/var/lib/asterisk
	rm -Rf $(TARGET_DIR)/var/spool/asterisk
	rm -f $(TARGET_DIR)/etc/init.d/S60asterisk
	rm -f $(TARGET_DIR)/usr/sbin/stereorize
	rm -f $(TARGET_DIR)/usr/sbin/streamplayer
	-$(MAKE) -C $(ASTERISK_DIR) clean

asterisk-dirclean:
	rm -rf $(ASTERISK_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_ASTERISK)),y)
TARGETS+=asterisk
endif
