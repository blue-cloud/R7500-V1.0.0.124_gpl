include $(TOPDIR)/rules.mk

PKG_NAME=qsdk-wifi-script
PKG_VERSION=1
PKG_RELEASE=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/qsdk-wifi-script
  SECTION:=net
  TITLE:=qca-wifi scripts
  MAINTAINER:=Matthew McClintock <mmcclint@qca.qualcomm.com>
endef

define Build/Prepare
	$(CP) $(GIT_HOME)/qsdk-wifi-script.git/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/lib/wifi/
	cp -af $(PKG_BUILD_DIR)/lib/wifi/* $(1)/lib/wifi
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/wifi/wps-hostapd-update-uci \
					$(1)/lib/wifi/wps-hostapd-update-uci

endef

$(eval $(call BuildPackage,qsdk-wifi-script))
