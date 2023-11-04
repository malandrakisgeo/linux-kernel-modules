obj-m+=connect_syscall_hook.o

all:
	make -C /lib/modules/5.10.0-20-amd64/build M=$(PWD) modules

clean:
	find  . -name \*.mod.c -type f -delete
	find  . -name \*.mod.o -type f -delete
	find  . -name \*.o -type f -delete
	find  . -name \*.cmd -type f -delete
	find  . -name \*.ko -type f -delete
	find  . -name \*.mod -type f -delete
	find  . -name \*.order -type f -delete
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
