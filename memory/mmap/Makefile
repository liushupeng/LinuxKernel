
# To build modules outside of the kernel tree, we run "make"
# in the kernel source tree; the Makefile these then includes this
# Makefile once again.
# This conditional selects whether we are being included from the
# kernel Makefile or not.
ifeq ($(KERNELRELEASE),)

    # Assume the source tree is where the running kernel was built
    # You should set KERNELDIR in the environment if it's elsewhere
    KERNELDIR ?= /lib/modules/$(shell uname -r)/build
    # The current directory is passed to sub-makes as argument
    PWD := $(shell pwd)

all: modules test build

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

test:
	gcc -static test_mapping.c -o test_mapping

build: modules test
	@mkdir -p $(PWD)/build
	@mv *.o *.ko *.mod.c *.mod .*.cmd modules.order Module.symvers $(PWD)/build
	@mv test_mapping $(PWD)/build

clean:
	rm -rf $(PWD)/build

.PHONY: modules modules_install clean build test

else
	ccflags-y += -I$(shell dirname $(shell dirname $(PWD)))/include
    # called from kernel build system: just declare what our modules are
    obj-m := mapping.o
endif

