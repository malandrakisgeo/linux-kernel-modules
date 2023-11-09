obj-m+=netfilter.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	find . -type f -name "*.mod.c" -o -name "*.o" -o -name "*.cmd"  -o -name "*.ko" -o -name "*.mod"
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
