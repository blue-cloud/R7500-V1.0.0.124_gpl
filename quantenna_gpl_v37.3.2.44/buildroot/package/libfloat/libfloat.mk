#############################################################
#
# libfloat
#
#############################################################
LIBFLOAT_SOURCE:=libfloat_990616.orig.tar.gz
LIBFLOAT_PATCH:=libfloat_990616-3.diff.gz
LIBFLOAT_SITE:=http://ftp.debian.org/debian/pool/main/libf/libfloat
LIBFLOAT_CAT:=$(ZCAT)
LIBFLOAT_DIR:=$(BUILD_DIR)/libfloat

LIBFLOAT_TARGET=
ifeq ($(strip $(SOFT_FLOAT)),true)
ifeq ("$(strip $(ARCH))","arm")
ifeq ($(findstring 3.3.,$(GCC_VERSION)),3.3.)
LIBFLOAT_TARGET+=$(STAGING_DIR)/lib/libfloat.so
endif
endif
endif

$(DL_DIR)/$(LIBFLOAT_SOURCE):
	 $(WGET) -P $(DL_DIR) $(LIBFLOAT_SITE)/$(LIBFLOAT_SOURCE)

$(DL_DIR)/$(LIBFLOAT_PATCH):
	 $(WGET) -P $(DL_DIR) $(LIBFLOAT_SITE)/$(LIBFLOAT_PATCH)

libfloat-source: $(DL_DIR)/$(LIBFLOAT_SOURCE) $(DL_DIR)/$(LIBFLOAT_PATCH)

$(LIBFLOAT_DIR)/.unpacked: $(DL_DIR)/$(LIBFLOAT_SOURCE) $(DL_DIR)/$(LIBFLOAT_PATCH)
	$(LIBFLOAT_CAT) $(DL_DIR)/$(LIBFLOAT_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	# Remove the binary files distributed with the the package.
	$(MAKE) -C $(LIBFLOAT_DIR) clean
	toolchain/patch-kernel.sh $(LIBFLOAT_DIR) $(DL_DIR) $(LIBFLOAT_PATCH)
	toolchain/patch-kernel.sh $(LIBFLOAT_DIR) package/libfloat/ libfloat\*.patch
	touch $(LIBFLOAT_DIR)/.unpacked

$(LIBFLOAT_DIR)/libfloat.so.1: $(LIBFLOAT_DIR)/.unpacked $(TARGET_CC)
	$(MAKE) CC=$(TARGET_CC) LD=$(TARGET_CROSS)ld -C $(LIBFLOAT_DIR)

$(STAGING_DIR)/lib/libfloat.so: $(LIBFLOAT_DIR)/libfloat.so.1
	cp -dpf $(LIBFLOAT_DIR)/libfloat.a $(STAGING_DIR)/lib/libfloat.a
	cp -dpf $(LIBFLOAT_DIR)/libfloat.so.1 $(STAGING_DIR)/lib/libfloat.so.1
	(cd $(STAGING_DIR)/lib ; ln -snf libfloat.so.1 libfloat.so)
	cp -dpf $(LIBFLOAT_DIR)/libfloat.a $(TARGET_DIR)/usr/lib/libfloat.a
	cp -dpf $(LIBFLOAT_DIR)/libfloat.so.1 $(TARGET_DIR)/lib/libfloat.so.1
	$(STRIP) $(TARGET_DIR)/lib/libfloat.so.1 > /dev/null 2>&1
	(cd $(TARGET_DIR)/lib ; ln -snf libfloat.so.1 libfloat.so)
	(cd $(TARGET_DIR)/usr/lib ; ln -snf /lib/libfloat.so libfloat.so)

libfloat: $(STAGING_DIR)/lib/libfloat.so

libfloat-clean:
	-$(MAKE) -C $(LIBFLOAT_DIR) clean

libfloat-dirclean:
	rm -rf $(LIBFLOAT_DIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
#ifeq ($(strip $(BR2_PACKAGE_LIBFLOAT)),y)
#TARGETS+=libfloat
#endif
