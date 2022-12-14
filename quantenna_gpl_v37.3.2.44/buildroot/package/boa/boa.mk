#############################################################
#
# boa
#
#############################################################

BOA_VERSION=0.94.14rc21

# Don't alter below this line unless you (think) you know
# what you are doing! Danger, Danger!

BOA_SOURCE=boa-$(BOA_VERSION).tar.gz
BOA_CAT:=$(ZCAT)
BOA_SITE=http://www.boa.org/
BOA_DIR=$(BUILD_DIR)/${shell basename $(BOA_SOURCE) .tar.gz}
BOA_WORKDIR=$(BUILD_DIR)/boa_workdir

ifeq ($(BR2_INET_IPV6),y)
	BOA_IPV6_OPT="-DINET6"
endif

$(DL_DIR)/$(BOA_SOURCE):
	$(WGET) -P $(DL_DIR) $(BOA_SITE)/$(BOA_SOURCE)

$(BOA_DIR)/.unpacked:	$(DL_DIR)/$(BOA_SOURCE)
	$(BOA_CAT) $(DL_DIR)/$(BOA_SOURCE) | tar -C $(BUILD_DIR) $(TAR_OPTIONS) -
	touch $(BOA_DIR)/.unpacked
	sed -i '55 i\	const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;' $(BOA_DIR)/src/ip.c

$(BOA_WORKDIR)/Makefile: $(BOA_DIR)/.unpacked
	rm -f $(BOA_WORKDIR)/Makefile
	mkdir -p $(BOA_WORKDIR)
	#CONFIG_SITE=package/boa/boa-config.site-$(ARCH)
	(cd $(BOA_WORKDIR); rm -rf config.cache; \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(SED_CFLAGS) $(BOA_IPV6_OPT)" \
		$(BOA_DIR)/configure \
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
	);
	touch $(BOA_WORKDIR)/Makefile

$(BOA_WORKDIR)/src/boa $(BOA_WORKDIR)/src/boa_indexer:	$(BOA_WORKDIR)/Makefile
	rm -f $@
	$(MAKE) -C $(BOA_WORKDIR)

$(BOA_WORKDIR)/.installed: $(BOA_WORKDIR)/src/boa $(BOA_WORKDIR)/src/boa_indexer
	mkdir -p $(TARGET_DIR)/usr/sbin
	cp -f $(BOA_WORKDIR)/src/boa $(TARGET_DIR)/usr/sbin/boa
	mkdir -p $(TARGET_DIR)/usr/lib/boa
	cp -f $(BOA_WORKDIR)/src/boa_indexer $(TARGET_DIR)/usr/lib/boa/boa_indexer
	mkdir -p $(TARGET_DIR)/var/log/boa
	mkdir -p $(TARGET_DIR)/usr/lib/cgi-bin
	mkdir -p $(TARGET_DIR)/var/www
	mkdir -p $(TARGET_DIR)/etc/boa
	cp -f package/boa/boa.conf $(TARGET_DIR)/etc/boa
	cp -f package/boa/mime.types $(TARGET_DIR)/etc/mime.types
	cp -f package/boa/S42boa $(TARGET_DIR)/etc/init.d
	cp -f package/boa/admin.conf $(TARGET_DIR)/etc/init.d
	$(STRIP) --strip-all $(TARGET_DIR)/usr/sbin/boa $(TARGET_DIR)/usr/lib/boa/boa_indexer
	touch $(BOA_WORKDIR)/.installed

.PHONY: $(BOA_WORKDIR)/.installed

boa:	uclibc $(BOA_WORKDIR)/.installed

boa-source: $(DL_DIR)/$(BOA_SOURCE)

boa-clean:
	@if [ -f $(BOA_WORKDIR)/Makefile ] ; then \
		$(MAKE) -C $(BOA_WORKDIR) clean ; \
	fi;

boa-dirclean:
	rm -rf $(BOA_DIR) $(BOA_WORKDIR)

#############################################################
#
# Toplevel Makefile options
#
#############################################################
ifeq ($(strip $(BR2_PACKAGE_BOA)),y)
TARGETS+=boa
endif
