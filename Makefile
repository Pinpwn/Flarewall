obj-m += flarewall.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

clean :
       	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
default:
        $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
