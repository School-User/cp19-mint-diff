#!/usr/bin/env bash
# Run this with sudo once to mount the practice VM
# Usage: sudo bash ~/Projects/cp19-mint-diff/mount_vm.sh [mount|unmount]

VMDK="/mnt/1tb/cp19_pr_e_mint21/Mint 21 64-bit-cl4.vmdk"
MNT="/mnt/vm_mint"

case "${1:-mount}" in
  mount)
    modprobe nbd max_part=8
    qemu-nbd -c /dev/nbd0 "$VMDK"
    udevadm settle
    partprobe /dev/nbd0
    udevadm settle
    echo "Partition table:"
    fdisk -l /dev/nbd0
    mkdir -p "$MNT"
    # Mint 21 default: p1=EFI or swap, p2=ext4 root  (adjust if fdisk shows otherwise)
    # Try p2 first, then p1
    if mount /dev/nbd0p2 "$MNT" 2>/dev/null; then
        echo "Mounted /dev/nbd0p2 at $MNT"
    elif mount /dev/nbd0p1 "$MNT" 2>/dev/null; then
        echo "Mounted /dev/nbd0p1 at $MNT"
    else
        echo "Auto-mount failed — check 'fdisk -l /dev/nbd0' and mount manually"
        exit 1
    fi
    echo "Done. Now run: bash ~/Projects/cp19-mint-diff/mint_diff.sh $MNT"
    ;;
  unmount|umount)
    umount "$MNT" 2>/dev/null || true
    qemu-nbd -d /dev/nbd0
    echo "Unmounted and disconnected nbd0"
    ;;
esac
