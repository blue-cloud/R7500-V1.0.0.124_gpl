
include helper.mk

CFLAGS =
CC = $(CROSS_COMPILE)gcc
CPP = $(CROSS_COMPILE)gcc -E
LD = $(CROSS_COMPILE)ld
OBJCOPY = $(CROSS_COMPILE)objcopy

U_BOOT_CHILD_OFFSET = 0x14000

TOPAZ_EP_MINI_UBOOT = 0
ifeq ($(board_config),topaz_pcie_config)
TOPAZ_EP_MINI_UBOOT = 1
endif
ifeq ($(board_config),topaz_pcie_realign_config)
TOPAZ_EP_MINI_UBOOT = 1
endif

default: $(TARGET)-piggy $(TARGET)-piggy.bin

ifeq ($(TARGET),u-boot-mini)
TEXT_BASE_OFFSET_PARENT = 0x0
TEXT_BASE_OFFSET_CHILD = $(U_BOOT_CHILD_OFFSET)
CFLAGS += -DU_BOOT_MINI
endif
ifeq ($(TARGET),u-boot)
TEXT_BASE_OFFSET_PARENT = 0x0
TEXT_BASE_OFFSET_CHILD = $(U_BOOT_CHILD_OFFSET)
.PHONY: u-boot.bin
endif

BUILD_DIR=./$(TARGET).build

-include $(shell find $(BUILD_DIR) -name \*.d)

gccincdir = $(shell $(CC) -print-file-name=include)

CFLAGS +=	-Wall -Werror -Wno-unused-parameter \
		-Os \
		-D__KERNEL__ -D__ARC__ -DRUBY_MINI \
		-mA7 \
		-fno-builtin -ffreestanding -fomit-frame-pointer \
		-nostdinc \
		-mno-sdata -mvolatile-cache -mno-millicode \
		-pipe \
		-Iinclude/ -Iboard/ruby/ -I../common/ -I../include/qtn/ \
		-isystem $(gccincdir) \
		-DTEXT_BASE_OFFSET=$(TEXT_BASE_OFFSET_PARENT) \
		-DTEXT_BASE_OFFSET_CHILD=$(TEXT_BASE_OFFSET_CHILD) \
		-DPIGGY_BUILD

AFLAGS = -D__ASSEMBLY__ $(CFLAGS)

.PHONY: FORCE
.PRECIOUS: $(BUILD_DIR)/%.o $(BUILD_DIR)/%.bin.lzma.c $(BUILD_DIR)/u-boot.bin.lzma.o

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $< -c -o $@ -MP -MD -MF $@.d

$(BUILD_DIR)/%.o: %.S
	@mkdir -p $(@D)
	$(CC) $(AFLAGS) $< -c -o $@ -MP -MD -MF $@.d

$(BUILD_DIR)/%.s: %.S
	@mkdir -p $(@D)
	$(CPP) $(AFLAGS) $< -o $@ -MP -MD -MF $@.d

ifeq ($(PIGGY_DEBUG),1)
CFLAGS += -DPIGGY_DEBUG
DEBUG_OBJS =	\
	board/ruby_mini/ruby_mini_common.o	\
	board/ruby/serial.o			\
	board/ruby/timer.o			\
	board/ruby/gpio.o			\
	board/ruby/reset.o			\
	lib_generic/ctype.o			\
	lib_generic/vsprintf.o			\
	lib_generic/string.o

LDFLAGS = -L /home/ARC/toolchain_gcc/gcc_2.3.ipv6/bin/../lib/gcc/arc-linux-uclibc/4.2.1 -lgcc
endif

ifeq ($(TOPAZ_EP_MINI_UBOOT),1)
LZMA_LIB:=lib_generic/lzma/LzmaDecode.o
else
LZMA_LIB:=lib_generic/lzma/LzmaDecodeSize.o
endif

OBJS =	board/ruby/start.o		\
	board/ruby/flip.o		\
	cpu/arc/cache.o			\
	${DEBUG_OBJS}			\
	board/ruby_mini/ruby_piggy.o	\
	lib_generic/lzma/LzmaTools.o	\
	$(LZMA_LIB)

LZMA = ../host/utilities/lzma
LDMAP = $(BUILD_DIR)/u-boot-piggy.lds

%.lzma: %
	$(LZMA) --keep --best $< -c > $@

$(BUILD_DIR)/%.bin.lzma.c: %.bin.lzma
	@mkdir -p $(@D)
	cat $< > $(@D)/payload
	cd $(@D) && xxd -i payload > $(@F)

%-piggy: %.bin $(OBJS:%=$(BUILD_DIR)/%) $(BUILD_DIR)/%.bin.lzma.o $(LDMAP)
	$(LD) -Bstatic -T $(LDMAP) $(filter %.o,$^) -Map $@.map -o $@ $(LDFLAGS)

%.bin: %
	$(OBJCOPY) -O binary $< $@

$(LDMAP): $(RUBY_MINI_LDMAP_SRC)
	$(call build-mini-ldmap,$(CFLAGS))
