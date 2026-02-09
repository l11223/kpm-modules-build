CROSS_COMPILE ?= aarch64-linux-gnu-
CC      := $(CROSS_COMPILE)gcc
LD      := $(CROSS_COMPILE)ld

KPM_SDK_DIR ?= ../../kpm_sdk

MODULE_NAME := skroot-selinux
MODULE_SRC  := main.c

CFLAGS := -ffreestanding -nostdlib -fno-plt -fno-pic \
          -fno-stack-protector -fno-common \
          -fno-asynchronous-unwind-tables \
          -I$(KPM_SDK_DIR)/include \
          -O2 -Wall -Wextra -Werror

LDFLAGS := -r -T $(KPM_SDK_DIR)/kpm.lds

MODULE_OBJ := $(MODULE_SRC:.c=.o)
MODULE_KPM := $(MODULE_NAME).kpm

.PHONY: all clean

all: $(MODULE_KPM)

$(MODULE_KPM): $(MODULE_OBJ)
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(MODULE_OBJ) $(MODULE_KPM)
