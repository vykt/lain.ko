obj-m += lainko.o
EXTRA_CFLAGS=-O1

all:
	#make -C /home/vykt/linux-source-6.10/ M=$(PWD) modules
	make -C /usr/src/$(uname -r) modules

clean:
	#make -C /home/vykt/linux-source-6.10/ M=$(PWD) clean
	rm Module.symvers compile.err lainko.ko lainko.mod lainko.mod.c lainko.mod.o lainko.o modules.order
