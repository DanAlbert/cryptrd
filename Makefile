obj-m := cryptrd.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm modules.order
	rm Module.symvers
	rm *.ko
	rm *.ko.*
	rm *.mod.*
	rm *.o

.PHONY: clean
