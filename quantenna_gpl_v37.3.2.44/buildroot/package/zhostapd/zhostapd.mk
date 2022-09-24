#############################################################
#
# hostap
#
#############################################################
ZHOSTAPD_VERSION=hostapd-2.1
ZHOSTAPD_BASE_DIR=$(TOPDIR)/package/zhostapd
ZHOSTAPD_DIR=$(ZHOSTAPD_BASE_DIR)/$(ZHOSTAPD_VERSION)/hostapd

.PHONY: FORCE

$(ZHOSTAPD_DIR)/hostapd: FORCE
	cp -f $(ZHOSTAPD_BASE_DIR)/zhostapd.config $(ZHOSTAPD_DIR)/.config
	$(MAKE) -C $(ZHOSTAPD_DIR) hostapd CC=$(TARGET_CC)

$(TARGET_DIR)/usr/sbin/hostapd: $(ZHOSTAPD_DIR)/hostapd
	# Copy hostapd
	cp -af $< $@

zhostapd: $(TARGET_DIR)/usr/sbin/hostapd

zhostapd-clean:
	-$(MAKE) -C $(ZHOSTAPD_DIR) clean

zhostapd-dirclean: zhostapd-clean
	rm -f $(ZHOSTAPD_DIR)/.config
	rm -f $(TARGET_DIR)/usr/sbin/hostapd

#############################################################
#
# hostapd_cli
#
#############################################################

$(ZHOSTAPD_DIR)/hostapd_cli: FORCE
	$(MAKE) -C $(ZHOSTAPD_DIR) hostapd_cli CC=$(TARGET_CC)

$(TARGET_DIR)/usr/sbin/hostapd_cli: $(ZHOSTAPD_DIR)/hostapd_cli
	# Copy hostapd_cli
	cp -af $(ZHOSTAPD_DIR)/hostapd_cli $(TARGET_DIR)/usr/sbin/

hostapd_cli: $(TARGET_DIR)/usr/sbin/hostapd_cli

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_ZHOSTAPD)),y)
TARGETS+=zhostapd
# Targets used for debugging
TARGETS+=hostapd_cli
endif
