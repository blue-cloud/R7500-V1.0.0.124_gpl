#############################################################
#
# wipe
#
# http://abaababa.ouvaton.org/wipe/wipe-0.20.tar.gz
#############################################################
WIPE_SOURCE:=wipe-0.20.tar.gz
#WIPE_PATCH:=wipe_0.2-19.diff.gz
WIPE_SITE:=http://abaababa.ouvaton.org/wipe
WIPE_CAT:=$(ZCAT)
WIPE_DIR:=$(BUILD_DIR)/wipe-0.20
WIPE_BINARY:=wipe
WIPE_TARGET_BINARY:=bin/wipe

$(DL_DIR)/$(WIPE_SOURCE):
	 $(WGET) -P $(DL_DIR) $(WIPE_SITE)/$(WIPE_SOURCE)

ifneq ($(WIPE_PATCH),)
$(DL_DIR)/$(WIPE_PATCH):
	 $(WGET) -P $(DL_DIR) $(WIPE_SITE)/$(WIPE_PATCH)
endif

wipe-source: $(DL_DIR)/$(WIPE_SOURCE) $(DL_DIR)/$(WIPE_PATCH)

$(WIPE_DIR)/.unpacked: $(DL_DIR)/$(WIPE_SOURCE) $(DL_DIR)/$(WIPE_PATCH)
	$(WIPE_CAT) $(DL_DIR)/$(WIPE_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	#toolchain/patch-kernel.sh $(WIPE_DIR) $(DL_DIR) $(WIPE_PATCH)
	touch $(WIPE_DIR)/.unpacked

$(WIPE_DIR)/.configured: $(WIPE_DIR)/.unpacked
	touch  $(WIPE_DIR)/.configured

$(WIPE_DIR)/$(WIPE_BINARY): $(WIPE_DIR)/.configured
	$(MAKE) CC=$(TARGET_CC) -C $(WIPE_DIR)  generic

$(TARGET_DIR)/$(WIPE_TARGET_BINARY): $(WIPE_DIR)/$(WIPE_BINARY)
	cp -a $(WIPE_DIR)/$(WIPE_BINARY) $(TARGET_DIR)/$(WIPE_TARGET_BINARY)

wipe: uclibc $(TARGET_DIR)/$(WIPE_TARGET_BINARY)

wipe-clean:
	#$(MAKE) DESTDIR=$(TARGET_DIR) CC=$(TARGET_CC) -C $(WIPE_DIR) uninstall
	-$(MAKE) -C $(WIPE_DIR) clean

wipe-dirclean:
	rm -rf $(WIPE_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_WIPE)),y)
TARGETS+=wipe
endif
