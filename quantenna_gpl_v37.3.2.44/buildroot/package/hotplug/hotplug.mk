#############################################################
#
# hotplug support
#
#############################################################
HOTPLUG_SOURCE=package/hotplug/diethotplug-0.5.tar
HOTPLUG_SITE=http://www.kernel.org/pub/linux/utils/kernel/hotplug/
HOTPLUG_DIR=$(BUILD_DIR)/diethotplug-0.5
HOTPLUG_CAT=cat

$(HOTPLUG_DIR): $(HOTPLUG_SOURCE)
	$(HOTPLUG_CAT) $(HOTPLUG_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	toolchain/patch-kernel.sh $(HOTPLUG_DIR) package/hotplug/ hotplug\*.patch

$(HOTPLUG_DIR)/hotplug: $(HOTPLUG_DIR)
	$(MAKE) CROSS=$(TARGET_CROSS) DEBUG=false KLIBC=false \
	    KERNEL_INCLUDE_DIR=$(STAGING_DIR)/include \
	    TARGET_DIR=$(TARGET_DIR) -C $(HOTPLUG_DIR);
	$(STRIP) $(HOTPLUG_DIR)/hotplug;
	touch -c $(HOTPLUG_DIR)/hotplug

$(TARGET_DIR)/sbin/hotplug: $(HOTPLUG_DIR)/hotplug
	cp $(HOTPLUG_DIR)/hotplug $(TARGET_DIR)/sbin/hotplug;
	touch -c $(TARGET_DIR)/sbin/hotplug

hotplug: uclibc $(TARGET_DIR)/sbin/hotplug

hotplug-source: $(DL_DIR)/$(HOTPLUG_SOURCE)

hotplug-clean:
	rm -f $(TARGET_DIR)/sbin/hotplug
	-$(MAKE) -C $(HOTPLUG_DIR) clean

hotplug-dirclean:
	rm -rf $(HOTPLUG_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_HOTPLUG)),y)
TARGETS+=hotplug
endif
