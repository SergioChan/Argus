#!/bin/sh
set -u

export LC_ALL=C

trust_path=/opt/argus/trust/verifier/tc29-write-attempt
trust_error=/mnt/scratch/trust-write.stderr
egress_error=/mnt/scratch/egress.stderr

printf 'tamper\n' 2>"$trust_error" >"$trust_path"
trust_write_rc=$?

timeout 2 /bin/bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' > /dev/null 2>"$egress_error"
egress_rc=$?

interfaces="$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | paste -sd, -)"
default_route_count="$(awk 'NR > 1 && $2 == "00000000" { count += 1 } END { print count + 0 }' /proc/net/route)"
trust_mount_count="$(awk '$2 ~ /^\/opt\/argus\/trust(\/|$)/ { count += 1 } END { print count + 0 }' /proc/mounts)"
root_options="$(awk '$2 == "/" { print $4 }' /proc/mounts)"
input_options="$(awk '$2 == "/mnt/argus-input" { print $4 }' /proc/mounts)"
scratch_options="$(awk '$2 == "/mnt/scratch" { print $4 }' /proc/mounts)"
scratch_bytes="$(df -B1 --output=size /mnt/scratch | awk 'NR == 2 { print $1 }')"

printf 'scratch-write-ok\n' >/mnt/scratch/write-probe
scratch_write_rc=$?

printf 'ARGUS_TC29_TRUST_WRITE_RC=%s\n' "$trust_write_rc"
printf 'ARGUS_TC29_TRUST_WRITE_ERROR=%s\n' "$(tr '\n' ' ' <"$trust_error")"
printf 'ARGUS_TC29_EGRESS_RC=%s\n' "$egress_rc"
printf 'ARGUS_TC29_EGRESS_ERROR=%s\n' "$(tr '\n' ' ' <"$egress_error")"
printf 'ARGUS_TC29_INTERFACES=%s\n' "$interfaces"
printf 'ARGUS_TC29_DEFAULT_ROUTE_COUNT=%s\n' "$default_route_count"
printf 'ARGUS_TC29_TRUST_MOUNT_COUNT=%s\n' "$trust_mount_count"
printf 'ARGUS_TC29_ROOT_OPTIONS=%s\n' "$root_options"
printf 'ARGUS_TC29_INPUT_OPTIONS=%s\n' "$input_options"
printf 'ARGUS_TC29_SCRATCH_OPTIONS=%s\n' "$scratch_options"
printf 'ARGUS_TC29_SCRATCH_BYTES=%s\n' "$scratch_bytes"
printf 'ARGUS_TC29_GUEST_UID=%s\n' "$(id -u)"

case ",$root_options," in
  *,ro,*) root_is_read_only=1 ;;
  *) root_is_read_only=0 ;;
esac
case ",$input_options," in
  *,ro,*) input_is_read_only=1 ;;
  *) input_is_read_only=0 ;;
esac
case ",$scratch_options," in
  *,rw,*) scratch_is_writable=1 ;;
  *) scratch_is_writable=0 ;;
esac

if [ "$trust_write_rc" -eq 0 ] || [ "$egress_rc" -eq 0 ] || [ "$interfaces" != "lo" ] || \
   [ "$default_route_count" -ne 0 ] || [ "$trust_mount_count" -ne 0 ] || \
   [ "$root_is_read_only" -ne 1 ] || [ "$input_is_read_only" -ne 1 ] || \
   [ "$scratch_is_writable" -ne 1 ] || [ "$scratch_write_rc" -ne 0 ] || \
   [ "$(id -u)" -eq 0 ]; then
  printf 'ARGUS_TC29_STATUS=FAIL\n'
  exit 1
fi

printf 'ARGUS_TC29_STATUS=PASS\n'
