#!/usr/bin/env bash
#
# nixstallman - NixOS 25.11 UEFI installer with LUKS encryption
# Run from NixOS live ISO
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
die()       { log_error "$1"; exit 1; }

# Hash password
hash_password() {
    local password="$1"
    if command -v mkpasswd &>/dev/null; then
        echo -n "$password" | mkpasswd -m sha-512 -s
    else
        local salt
        salt=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16)
        openssl passwd -6 -salt "$salt" "$password"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

echo ""
echo -e "${GREEN}nixstallman${NC} - NixOS 25.11 LUKS Installer"
echo "============================================"
echo ""

# Check root
[[ $EUID -eq 0 ]] || die "Run as root"
[[ -f /etc/NIXOS ]] || die "Run from NixOS live ISO"

# -----------------------------------------------------------------------------
# 1. Select target disk
# -----------------------------------------------------------------------------
echo -e "${CYAN}Available disks:${NC}"
echo ""
lsblk -d -o NAME,SIZE,MODEL | grep -E "^(NAME|sd|nvme|vd)"
echo ""
read -r -p "Target disk (e.g. sda, nvme0n1): " DISK_INPUT
[[ -z "$DISK_INPUT" ]] && die "No disk specified"

# Add /dev/ prefix if needed
if [[ "$DISK_INPUT" =~ ^/dev/ ]]; then
    TARGET_DISK="$DISK_INPUT"
else
    TARGET_DISK="/dev/$DISK_INPUT"
fi

[[ -b "$TARGET_DISK" ]] || die "Not a block device: $TARGET_DISK"
log_info "Target: $TARGET_DISK"

# -----------------------------------------------------------------------------
# 2. Username and password
# -----------------------------------------------------------------------------
echo ""
read -r -p "Username: " USERNAME
[[ -z "$USERNAME" ]] && die "Username required"

read -r -s -p "Password: " USER_PASS
echo ""
read -r -s -p "Confirm password: " USER_PASS2
echo ""
[[ "$USER_PASS" == "$USER_PASS2" ]] || die "Passwords don't match"
[[ -z "$USER_PASS" ]] && die "Password required"

# -----------------------------------------------------------------------------
# 3. System settings
# -----------------------------------------------------------------------------
echo ""
read -r -p "Hostname [nixos]: " HOSTNAME
HOSTNAME="${HOSTNAME:-nixos}"

read -r -p "Timezone [UTC]: " TIMEZONE
TIMEZONE="${TIMEZONE:-UTC}"

read -r -p "Locale [en_US.UTF-8]: " LOCALE
LOCALE="${LOCALE:-en_US.UTF-8}"

read -r -p "Keyboard [us]: " KEYBOARD
KEYBOARD="${KEYBOARD:-us}"

# -----------------------------------------------------------------------------
# 4. Swap size
# -----------------------------------------------------------------------------
echo ""
read -r -p "Swap size in GB (0 for no swap) [0]: " SWAP_GB
SWAP_GB="${SWAP_GB:-0}"

# -----------------------------------------------------------------------------
# 5. Filesystem
# -----------------------------------------------------------------------------
echo ""
echo "Filesystem: 1) ext4  2) btrfs  3) xfs"
read -r -p "Choice [1]: " FS_CHOICE
case "$FS_CHOICE" in
    2) ROOT_FS="btrfs" ;;
    3) ROOT_FS="xfs" ;;
    *) ROOT_FS="ext4" ;;
esac

# -----------------------------------------------------------------------------
# 6. LUKS passphrase
# -----------------------------------------------------------------------------
echo ""
log_warn "Set disk encryption passphrase (needed at every boot)"
read -r -s -p "LUKS passphrase: " LUKS_PASS
echo ""
read -r -s -p "Confirm passphrase: " LUKS_PASS2
echo ""
[[ "$LUKS_PASS" == "$LUKS_PASS2" ]] || die "Passphrases don't match"
[[ -z "$LUKS_PASS" ]] && die "Passphrase required"

# -----------------------------------------------------------------------------
# 7. Confirm
# -----------------------------------------------------------------------------
echo ""
echo "============================================"
echo -e "${CYAN}Summary${NC}"
echo "============================================"
echo "  Disk:       $TARGET_DISK"
echo "  Username:   $USERNAME"
echo "  Hostname:   $HOSTNAME"
echo "  Timezone:   $TIMEZONE"
echo "  Locale:     $LOCALE"
echo "  Keyboard:   $KEYBOARD"
echo "  Swap:       ${SWAP_GB}GB"
echo "  Filesystem: $ROOT_FS"
echo ""
echo -e "${RED}WARNING: ALL DATA ON $TARGET_DISK WILL BE DESTROYED${NC}"
read -r -p "Type 'yes' to continue: " CONFIRM
[[ "$CONFIRM" == "yes" ]] || die "Aborted"

# -----------------------------------------------------------------------------
# 8. Partition disk
# -----------------------------------------------------------------------------
log_info "Partitioning $TARGET_DISK..."

# Partition suffix (nvme uses p1, sda uses 1)
if [[ "$TARGET_DISK" =~ nvme|mmcblk|loop ]]; then
    P="p"
else
    P=""
fi

wipefs -af "$TARGET_DISK"

if [[ "$SWAP_GB" -gt 0 ]]; then
    SWAP_END=$((512 + SWAP_GB * 1024))
    parted -s "$TARGET_DISK" -- \
        mklabel gpt \
        mkpart ESP fat32 1MiB 513MiB \
        set 1 esp on \
        mkpart swap 513MiB "${SWAP_END}MiB" \
        mkpart root "${SWAP_END}MiB" 100%

    EFI_PART="${TARGET_DISK}${P}1"
    SWAP_PART="${TARGET_DISK}${P}2"
    LUKS_PART="${TARGET_DISK}${P}3"
else
    parted -s "$TARGET_DISK" -- \
        mklabel gpt \
        mkpart ESP fat32 1MiB 513MiB \
        set 1 esp on \
        mkpart root 513MiB 100%

    EFI_PART="${TARGET_DISK}${P}1"
    LUKS_PART="${TARGET_DISK}${P}2"
fi

sleep 2
partprobe "$TARGET_DISK"

# -----------------------------------------------------------------------------
# 9. Setup LUKS
# -----------------------------------------------------------------------------
log_info "Setting up LUKS encryption..."
echo -n "$LUKS_PASS" | cryptsetup luksFormat --type luks2 --batch-mode "$LUKS_PART" -
echo -n "$LUKS_PASS" | cryptsetup open "$LUKS_PART" cryptroot -
LUKS_PASS=""

# -----------------------------------------------------------------------------
# 10. Format filesystems
# -----------------------------------------------------------------------------
log_info "Formatting filesystems..."
mkfs.fat -F 32 -n NIXBOOT "$EFI_PART"

case "$ROOT_FS" in
    btrfs) mkfs.btrfs -f -L NIXROOT /dev/mapper/cryptroot ;;
    xfs)   mkfs.xfs -f -L NIXROOT /dev/mapper/cryptroot ;;
    *)     mkfs.ext4 -F -L NIXROOT /dev/mapper/cryptroot ;;
esac

if [[ "$SWAP_GB" -gt 0 ]]; then
    mkswap -L NIXSWAP "$SWAP_PART"
    swapon "$SWAP_PART"
fi

# -----------------------------------------------------------------------------
# 11. Mount
# -----------------------------------------------------------------------------
log_info "Mounting filesystems..."

if [[ "$ROOT_FS" == "btrfs" ]]; then
    mount /dev/mapper/cryptroot /mnt
    btrfs subvolume create /mnt/@
    btrfs subvolume create /mnt/@home
    btrfs subvolume create /mnt/@nix
    umount /mnt

    mount -o subvol=@,compress=zstd,noatime /dev/mapper/cryptroot /mnt
    mkdir -p /mnt/{home,nix,boot}
    mount -o subvol=@home,compress=zstd,noatime /dev/mapper/cryptroot /mnt/home
    mount -o subvol=@nix,compress=zstd,noatime /dev/mapper/cryptroot /mnt/nix
else
    mount /dev/mapper/cryptroot /mnt
    mkdir -p /mnt/boot
fi

mount "$EFI_PART" /mnt/boot

# -----------------------------------------------------------------------------
# 12. Generate config
# -----------------------------------------------------------------------------
log_info "Generating NixOS configuration..."

nixos-generate-config --root /mnt

# Get LUKS UUID
LUKS_UUID=$(blkid -s UUID -o value "$LUKS_PART")

# Add LUKS to hardware-configuration.nix (only if not already present)
HW_CONF="/mnt/etc/nixos/hardware-configuration.nix"
if ! grep -q "boot.initrd.luks.devices" "$HW_CONF"; then
    sed -i '/^}$/d' "$HW_CONF"
    cat >> "$HW_CONF" << EOF

  # LUKS
  boot.initrd.luks.devices."cryptroot" = {
    device = "/dev/disk/by-uuid/${LUKS_UUID}";
    allowDiscards = true;
  };
}
EOF
else
    log_info "LUKS config already present in hardware-configuration.nix"
fi

# Hash password
PW_HASH=$(hash_password "$USER_PASS")
USER_PASS=""

# Write configuration.nix
cat > /mnt/etc/nixos/configuration.nix << EOF
{ config, pkgs, ... }:

{
  imports = [ ./hardware-configuration.nix ];

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  networking.hostName = "${HOSTNAME}";
  networking.networkmanager.enable = true;

  time.timeZone = "${TIMEZONE}";
  i18n.defaultLocale = "${LOCALE}";
  console.keyMap = "${KEYBOARD}";

  users.users.${USERNAME} = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" "video" "audio" ];
    initialHashedPassword = "${PW_HASH}";
  };

  environment.systemPackages = with pkgs; [ vim git wget curl ];

  services.openssh.enable = true;
  networking.firewall.enable = true;

  system.stateVersion = "25.11";
}
EOF

# -----------------------------------------------------------------------------
# 13. Install
# -----------------------------------------------------------------------------
log_info "Installing NixOS..."
nixos-install --no-root-passwd

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
echo ""
echo "============================================"
echo -e "${GREEN}Installation complete!${NC}"
echo "============================================"
echo ""
echo "User: $USERNAME"
echo "Host: $HOSTNAME"
echo ""
echo "Reboot and enter your LUKS passphrase at boot."
echo ""
