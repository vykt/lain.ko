#make -C /home/vykt/projects/kernel/linux-source-6.10/ M=$PWD modules 2> compile.err
make -C /usr/src/linux-$(uname -r) M=$PWD modules
