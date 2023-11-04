obj-m+=connect_syscall_hook.o

all:
	make -C /lib/modules/5.10.0-20-amd64/build M=$(PWD) modules

clean:
	find . -type f -name "*.mod.c" -o -name "*.o" -o -name "*.cmd"  -o -name "*.ko" -o -name "*.mod"
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
