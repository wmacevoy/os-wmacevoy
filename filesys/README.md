#filesys

Binary Viewer Extension: Binary Viewer v1.1.1 Qiao Jie


random bytes
```
dd if=/dev/random of=rand.dat bs=$((1024*1024)) count=1
```

zeros
```
dd if=/dev/zero of=rand.dat bs=$((1024*1024)) count=1
```

vfat filesystem
```
dd if=/dev/zero of=vfatfs.raw bs=$((1024*1024)) count=100
mkfs.vfat vfatfs.raw
mkdir /vfatfs
mount -t vfat -o loop vfatfs.raw /vfatfs
```

