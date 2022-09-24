#
# Copyright (c) 2012-2014 Quantenna Communications, Inc. All rights reserved.
#

LINK_QCSAPI:=-lqcsapi

ifeq ($(QCSAPI),no)
CFLAGS+= -DNOQCSAPI
CFLAGS+= -Wno-error=unused-variable -Wno-error=unused-but-set-variable
CFLAGS+= -Wno-error=uninitialized -Wno-error=maybe-uninitialized
CFLAGS+= -Wno-error=unused-label
LINK_QCSAPI:=
endif

ifeq ($(QCSAPI),remote)
CHECK_QCSAPI_CLIENT=check-qcsapi-client
CFLAGS+= -DREMOTE_QCSAPI
LDFLAGS+= -L$(QCSAPI_CLIENT_DIR) -Wl,-rpath=$(shell readlink -f $(QCSAPI_CLIENT_DIR))
LINK_QCSAPI:=-lqcsapi_client
endif

ifeq ($(strip $(LIBCURL_STATIC)),y)
LINK_CURL=-l:libcurl.a
else
LINK_CURL=-lcurl
endif

ifeq ($(strip $(LIBJSON_STATIC)),y)
LINK_JSON=-l:libjson.a
else
LINK_JSON=-ljson
endif

VERSION=1.24
CFLAGS += -I$(SDK_DIR)/buildroot/package/qcsapi/qcsapi-1.0.1/
CFLAGS += -I$(SDK_DIR)
CFLAGS += -I$(SDK_DIR)/include
CFLAGS += -I$(SDK_DIR)/drivers/include/shared

CFLAGS+= -Werror -Wall
CFLAGS+= -DVERSION="$(VERSION)"
CFLAGS+= -std=gnu99

QHARVESTD_SRCS = $(wildcard *.c)
QHARVESTD_OBJS = $(QHARVESTD_SRCS:.c=.o)
ifneq ($(strip $(QHARVESTD_SRCS)),)
ALL=all
endif
QHARVESTD = qharvestd
QHARVESTD_CONF = qharvestd.conf

define FILES_TO_INSTALL
$(QHARVESTD)		755	$(PREFIX)/sbin/$(QHARVESTD)
$(QHARVESTD_CONF)	644	$(PREFIX)/etc/$(QHARVESTD_CONF)
endef
export FILES_TO_INSTALL

all: $(QHARVESTD)

check-sdk:
	@test $(SDK_DIR) || (echo "'SDK_DIR' is not defined" && exit 1)
	@test -d $(SDK_DIR) || (echo "SDK_DIR='$(SDK_DIR)' not found" && exit 1)

check-qcsapi-client:
	@test $(QCSAPI_CLIENT_DIR) || (echo "'QCSAPI_CLIENT_DIR' is not defined" && exit 1)
	@test -d $(QCSAPI_CLIENT_DIR) || \
		(echo "QCSAPI_CLIENT_DIR='$(QCSAPI_CLIENT_DIR)' not found" && exit 1)

$(QHARVESTD): check-sdk $(CHECK_QCSAPI_CLIENT) $(QHARVESTD_OBJS)
	$(CC) $(LDFLAGS) -Os -Wall -o $@ $(QHARVESTD_OBJS) \
		-lm $(LINK_CURL) -lssl $(LINK_JSON) -lpthread $(LINK_QCSAPI)

files_to_install:
	echo "$$FILES_TO_INSTALL" | while read file mode path; do \
		echo $$file; \
	done

install: $(ALL)
	echo "$$FILES_TO_INSTALL" | while read file mode path; do \
		install -D -m $$mode $$file $$path; \
	done

.c.o:
	$(CC) $(CFLAGS) -pipe -Wall -fPIC -c $<
clean:
	rm -rf $(QHARVESTD) *.o *.so *.so.*

distclean: clean
	-rm -rf $(QHARVESTD)

