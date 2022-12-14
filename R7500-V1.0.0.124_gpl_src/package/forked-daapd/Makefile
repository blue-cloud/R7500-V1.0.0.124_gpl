# $Id$

include $(TOPDIR)/rules.mk

PKG_NAME:=forked-daapd
PKG_VERSION:=20.0
PKG_RELEASE:=20140216
PKG_REV:=bdfb726c659c14c188e087d48465ef423dd4301c

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/ejurgensen/forked-daapd.git
PKG_SOURCE_VERSION:=$(PKG_REV)

PKG_FIXUP:=libtool
PKG_INSTALL:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/forked-daapd
SECTION:=sound
CATEGORY:=Sound
TITLE:=Improved iTunes (DAAP) server. Support for Apple Remote and AirPlay.
MAINTAINER:=Espen Jürgensen <espenjurgensen+openwrt@gmail.com>
URL:=https://github.com/jasonmc/forked-daapd
DEPENDS:=+libgpg-error +libgcrypt +libgdbm +zlib +libexpat +libunistring \
	+libevent +libdaemon +libantlr3c +confuse +glib2 +alsa-lib +libffmpeg-full \
	+mxml +libavl +avahi-daemon +libavahi-client +sqlite3-cli +libplist
endef

define Package/forked-daapd/conffiles
/etc/forked-daapd.conf
endef

# Fix for libevent
TARGET_CPPFLAGS += -I$(STAGING_DIR)/usr/include/libevent
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib/libevent

TARGET_CFLAGS += $(FPIC)
TARGET_LDFLAGS += -Wl,-rpath-link,$(STAGING_DIR)/usr/lib

define Build/Configure
	$(call Build/Configure/Default, \
		--enable-shared \
		--enable-static \
		--enable-itunes)
endef

define Package/forked-daapd/install
	$(INSTALL_DIR) $(1)/etc
	ln -sf /tmp/etc/forked-daapd.conf $(1)/etc/forked-daapd.conf
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DIR) $(1)/usr/lib/forked-daapd
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/forked-daapd/* $(1)//usr/lib/forked-daapd/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/itunes_allow_control $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/forked-daapd $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/forked-daapd.init $(1)/etc/init.d/forked-daapd
endef

$(eval $(call BuildPackage,forked-daapd))
