#!/bin/bash
<<<<<<< HEAD
fio --debug=io -filename=/mnt/ramdisk/new_test.txt  -ioengine=libaio -direct=1 -rw=randwrite -iodepth=8 -size=4k -bs=4K   -runtime=120 -time_based=1 -name=libaio-nova
=======
fio -filename=/mnt/ramdisk/new_test.txt  -ioengine=libaio -direct=1 -rw=randwrite -iodepth=8 -size=4k -bs=4K   -runtime=120 -time_based=1 -name=libaio-nova
>>>>>>> e49fb84464b98f504dd82a33480738920afa6c4b
