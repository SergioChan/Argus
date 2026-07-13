#!/bin/sh
set -u

export PATH=/usr/sbin:/usr/bin:/sbin:/bin

argus_fail() {
  printf 'ARGUS_FIRECRACKER_INIT_ERROR=%s\n' "$1"
  printf 'ARGUS_FIRECRACKER_EXIT_CODE=125\n'
  sync
  reboot -f >/dev/null 2>&1 || poweroff -f >/dev/null 2>&1
  exit 125
}

mount -t proc proc /proc || argus_fail mount-proc
mount -t sysfs sysfs /sys || argus_fail mount-sysfs
mount -t devtmpfs devtmpfs /dev || argus_fail mount-devtmpfs

mkdir -p /mnt/argus-input /mnt/scratch
mount -t ext4 -o ro,nosuid,nodev,noexec /dev/vdb /mnt/argus-input || argus_fail mount-input
mount -t ext4 -o rw,nosuid,nodev /dev/vdc /mnt/scratch || argus_fail mount-scratch
chown 65532:65532 /mnt/scratch || argus_fail chown-scratch

setpriv --reuid=65532 --regid=65532 --clear-groups /bin/sh /mnt/argus-input/entrypoint.sh
argus_status=$?
printf 'ARGUS_FIRECRACKER_EXIT_CODE=%s\n' "$argus_status"
sync
reboot -f >/dev/null 2>&1 || poweroff -f >/dev/null 2>&1
exit "$argus_status"
