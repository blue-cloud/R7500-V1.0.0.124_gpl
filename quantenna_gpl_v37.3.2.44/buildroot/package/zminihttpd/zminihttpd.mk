
.PHONY: minihttpd

MINIHTTPDDIR=$(TOPDIR)/package/zminihttpd

MINIHTTPD_VER:=1.19

MINIHTTPD_BUILD_DIR=$(MINIHTTPDDIR)/mini_httpd-$(MINIHTTPD_VER)
EXTRA_WARNINGS= -Wall -Wshadow -Werror

minihttpd:
	$(MAKE) -C $(MINIHTTPD_BUILD_DIR) PREFIX="$(TARGET_DIR)" \
		BUILD_DIR="$(BUILD_DIR)" TOOLCHAIN_DIR="$(TOOLCHAIN_EXTERNAL_PATH)/$(TOOLCHAIN_EXTERNAL_PREFIX)"\
		install

minihttpd-clean:
	-$(MAKE) -C $(MINIHTTPD_BUILD_DIR) clean

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_MINIHTTPD)),y)
TARGETS+=minihttpd
endif
