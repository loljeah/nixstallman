#!/usr/bin/env bash
#
# nixstallman - NixOS 25.11 UEFI installer with LUKS encryption
# Run from NixOS live ISO (pure bash)
#
# Usage: ./install.sh [config-url] [target-disk]
#
# Examples:
#   ./install.sh                                    # Interactive vanilla install
#   ./install.sh "" /dev/nvme0n1                    # Vanilla install to specific disk
#   ./install.sh https://github.com/user/nixos-config/archive/main.tar.gz /dev/nvme0n1
#

set -euo pipefail

# NixOS version to install
NIXOS_VERSION="25.11"
NIXOS_CHANNEL="https://channels.nixos.org/nixos-${NIXOS_VERSION}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Layout configuration (set during interactive prompts)
SWAP_SIZE=""
ROOT_FS="ext4"
USE_SWAP="no"

# User configuration
USERNAME=""
USER_PASSWORD=""
HOSTNAME=""
TIMEZONE=""
LOCALE=""
KEYBOARD=""

# Encryption
LUKS_PASSPHRASE=""

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_prompt() { echo -e "${CYAN}[?]${NC} $1"; }
die()       { log_error "$1"; exit 1; }

# Hash password using available tools
hash_password() {
    local password="$1"
    # Try mkpasswd first (from whois package), fall back to openssl
    if command -v mkpasswd &>/dev/null; then
        echo -n "$password" | mkpasswd -m sha-512 -s
    else
        # Use openssl with random salt
        local salt
        salt=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16)
        openssl passwd -6 -salt "$salt" "$password"
    fi
}

# -----------------------------------------------------------------------------
# Validation functions
# -----------------------------------------------------------------------------

validate_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https:// ]]; then
        die "Config URL must use HTTPS: $url"
    fi
    if ! curl --head --silent --fail --max-time 10 "$url" > /dev/null 2>&1; then
        die "Cannot reach config URL: $url"
    fi
}

validate_disk() {
    local disk="$1"
    if [[ ! -b "$disk" ]]; then
        die "Not a valid block device: $disk"
    fi
    if findmnt -n -o SOURCE / 2>/dev/null | grep -q "^${disk}"; then
        die "Refusing to install to disk containing running system: $disk"
    fi
}

confirm_action() {
    local prompt="$1"
    local response
    echo -e "${YELLOW}${prompt}${NC}"
    read -r -p "Type 'yes' to confirm: " response
    if [[ "$response" != "yes" ]]; then
        die "Aborted by user"
    fi
}

# -----------------------------------------------------------------------------
# Disk selection
# -----------------------------------------------------------------------------

select_disk() {
    log_info "Available disks:"
    echo ""
    lsblk -d -o NAME,SIZE,MODEL,TRAN | grep -E "^(NAME|sd|nvme|vd)"
    echo ""

    local disk
    read -r -p "Enter target disk (e.g., /dev/sda or /dev/nvme0n1): " disk

    if [[ ! "$disk" =~ ^/dev/ ]]; then
        disk="/dev/${disk}"
    fi

    echo "$disk"
}

# -----------------------------------------------------------------------------
# Layout configuration (interactive)
# -----------------------------------------------------------------------------

configure_layout() {
    local disk="$1"
    local disk_size

    disk_size=$(lsblk -b -d -n -o SIZE "$disk" | head -1)
    local disk_size_gb=$((disk_size / 1024 / 1024 / 1024))

    echo ""
    echo "============================================================"
    echo -e "${CYAN}Disk Layout Configuration${NC}"
    echo "============================================================"
    echo ""
    echo "Disk: $disk (${disk_size_gb}GB)"
    echo ""
    echo "The EFI partition (512MB) will be created automatically."
    echo ""

    # Ask about swap
    log_prompt "Do you want a swap partition? (y/n)"
    read -r -p "> " swap_choice
    if [[ "$swap_choice" =~ ^[Yy] ]]; then
        USE_SWAP="yes"
        echo ""
        log_prompt "Enter swap size (e.g., 8G, 16G, or 'ram' for RAM size):"
        read -r -p "> " SWAP_SIZE
        if [[ "$SWAP_SIZE" == "ram" ]]; then
            local ram_kb
            ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
            SWAP_SIZE="$((ram_kb / 1024 / 1024 + 1))G"
            log_info "Using RAM size for swap: ${SWAP_SIZE}"
        fi
    fi

    # Ask about filesystem
    echo ""
    log_prompt "Select root filesystem:"
    echo "  1) ext4 (recommended, stable)"
    echo "  2) btrfs (snapshots, compression)"
    echo "  3) xfs (performance)"
    read -r -p "> " fs_choice
    case "$fs_choice" in
        2) ROOT_FS="btrfs" ;;
        3) ROOT_FS="xfs" ;;
        *) ROOT_FS="ext4" ;;
    esac

    # Show summary
    echo ""
    echo "============================================================"
    echo -e "${CYAN}Layout Summary${NC}"
    echo "============================================================"
    echo "  EFI:  512MB (FAT32)"
    if [[ "$USE_SWAP" == "yes" ]]; then
        echo "  Swap: ${SWAP_SIZE} (inside LUKS)"
    fi
    echo "  Root: remaining space (${ROOT_FS}, LUKS encrypted)"
    echo ""
}

# -----------------------------------------------------------------------------
# System configuration collection
# -----------------------------------------------------------------------------

collect_system_config() {
    echo ""
    echo "============================================================"
    echo -e "${CYAN}System Configuration${NC}"
    echo "============================================================"
    echo ""

    # Hostname
    log_prompt "Enter hostname:"
    read -r -p "> " HOSTNAME
    if [[ -z "$HOSTNAME" ]]; then
        HOSTNAME="nixos"
    fi

    # Timezone
    echo ""
    log_prompt "Enter timezone (e.g., America/New_York, Europe/London, Asia/Tokyo):"
    echo "  Tip: Run 'timedatectl list-timezones' to see all options"
    read -r -p "> " TIMEZONE
    if [[ -z "$TIMEZONE" ]]; then
        TIMEZONE="UTC"
    fi

    # Locale
    echo ""
    log_prompt "Enter locale (e.g., en_US.UTF-8, de_DE.UTF-8, ja_JP.UTF-8):"
    read -r -p "> " LOCALE
    if [[ -z "$LOCALE" ]]; then
        LOCALE="en_US.UTF-8"
    fi

    # Keyboard layout
    echo ""
    log_prompt "Enter keyboard layout (e.g., us, de, uk, fr, jp):"
    read -r -p "> " KEYBOARD
    if [[ -z "$KEYBOARD" ]]; then
        KEYBOARD="us"
    fi
}

# -----------------------------------------------------------------------------
# User configuration collection
# -----------------------------------------------------------------------------

collect_user_config() {
    echo ""
    echo "============================================================"
    echo -e "${CYAN}User Setup${NC}"
    echo "============================================================"
    echo ""

    # Username
    while true; do
        log_prompt "Enter username (lowercase, no spaces):"
        read -r -p "> " USERNAME

        if [[ -z "$USERNAME" ]]; then
            log_error "Username cannot be empty"
            continue
        fi

        if [[ ! "$USERNAME" =~ ^[a-z][a-z0-9_-]*$ ]]; then
            log_error "Username must start with lowercase letter and contain only a-z, 0-9, _ or -"
            continue
        fi

        break
    done

    # User password
    echo ""
    log_warn "Set password for user '${USERNAME}'"

    local pass1 pass2
    while true; do
        read -r -s -p "Enter user password: " pass1
        echo ""
        read -r -s -p "Confirm password: " pass2
        echo ""

        if [[ -z "$pass1" ]]; then
            log_error "Password cannot be empty"
            continue
        fi

        if [[ "$pass1" != "$pass2" ]]; then
            log_error "Passwords do not match"
            continue
        fi

        break
    done

    USER_PASSWORD="$pass1"
}

# -----------------------------------------------------------------------------
# Encryption password collection
# -----------------------------------------------------------------------------

collect_encryption_password() {
    echo ""
    echo "============================================================"
    echo -e "${CYAN}LUKS Disk Encryption${NC}"
    echo "============================================================"
    echo ""
    log_warn "Choose a strong passphrase. You'll need it every boot."
    echo ""

    local pass1 pass2

    while true; do
        read -r -s -p "Enter encryption passphrase: " pass1
        echo ""
        read -r -s -p "Confirm passphrase: " pass2
        echo ""

        if [[ -z "$pass1" ]]; then
            log_error "Passphrase cannot be empty"
            continue
        fi

        if [[ "$pass1" != "$pass2" ]]; then
            log_error "Passphrases do not match"
            continue
        fi

        if [[ ${#pass1} -lt 8 ]]; then
            log_warn "Passphrase is short. Use at least 8 characters for security."
            read -r -p "Continue anyway? (y/n): " cont
            if [[ ! "$cont" =~ ^[Yy] ]]; then
                continue
            fi
        fi

        break
    done

    LUKS_PASSPHRASE="$pass1"
}

# -----------------------------------------------------------------------------
# Partitioning (UEFI + LUKS)
# -----------------------------------------------------------------------------

partition_disk() {
    local disk="$1"

    log_info "Partitioning ${disk}..."

    local part_suffix=""
    if [[ "$disk" =~ nvme|mmcblk|loop ]]; then
        part_suffix="p"
    fi

    # Wipe existing partition table
    wipefs -af "$disk"

    # Build partition commands based on layout
    if [[ "$USE_SWAP" == "yes" ]]; then
        # EFI + Swap + Root
        parted -s "$disk" -- \
            mklabel gpt \
            mkpart ESP fat32 1MiB 513MiB \
            set 1 esp on \
            mkpart swap 513MiB "$((512 + $(echo "$SWAP_SIZE" | sed 's/G//' | sed 's/g//') * 1024))MiB" \
            mkpart root "$((512 + $(echo "$SWAP_SIZE" | sed 's/G//' | sed 's/g//') * 1024))MiB" 100%
    else
        # EFI + Root only
        parted -s "$disk" -- \
            mklabel gpt \
            mkpart ESP fat32 1MiB 513MiB \
            set 1 esp on \
            mkpart root 513MiB 100%
    fi

    partprobe "$disk"
    sleep 2

    local efi_part="${disk}${part_suffix}1"
    local luks_part

    if [[ "$USE_SWAP" == "yes" ]]; then
        local swap_part="${disk}${part_suffix}2"
        luks_part="${disk}${part_suffix}3"
    else
        luks_part="${disk}${part_suffix}2"
    fi

    # Format EFI partition
    log_info "Formatting EFI partition..."
    mkfs.fat -F 32 -n NIXBOOT "$efi_part"

    # Setup LUKS on root partition
    log_info "Setting up LUKS encryption..."
    echo -n "$LUKS_PASSPHRASE" | cryptsetup luksFormat \
        --type luks2 \
        --cipher aes-xts-plain64 \
        --key-size 512 \
        --hash sha512 \
        --pbkdf argon2id \
        --iter-time 3000 \
        --batch-mode \
        "$luks_part" -

    # Open LUKS volume
    log_info "Opening LUKS volume..."
    echo -n "$LUKS_PASSPHRASE" | cryptsetup open "$luks_part" cryptroot -

    # Clear passphrase from memory
    LUKS_PASSPHRASE=""

    # Format root filesystem
    log_info "Formatting root filesystem (${ROOT_FS})..."
    case "$ROOT_FS" in
        btrfs)
            mkfs.btrfs -L NIXROOT /dev/mapper/cryptroot
            ;;
        xfs)
            mkfs.xfs -L NIXROOT /dev/mapper/cryptroot
            ;;
        *)
            mkfs.ext4 -L NIXROOT /dev/mapper/cryptroot
            ;;
    esac

    # Setup swap if enabled
    if [[ "$USE_SWAP" == "yes" ]]; then
        log_info "Formatting swap partition..."
        mkswap -L NIXSWAP "$swap_part"
        swapon "$swap_part"
    fi

    # Return partition info
    echo "${efi_part}:${luks_part}"
}

# -----------------------------------------------------------------------------
# Mount filesystems
# -----------------------------------------------------------------------------

mount_filesystems() {
    local efi_part="$1"

    log_info "Mounting filesystems..."

    if [[ "$ROOT_FS" == "btrfs" ]]; then
        # Create btrfs subvolumes
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

    mount "$efi_part" /mnt/boot
}

# -----------------------------------------------------------------------------
# Fetch configuration
# -----------------------------------------------------------------------------

fetch_config() {
    local config_url="$1"
    local config_dir="/mnt/etc/nixos"

    log_info "Fetching NixOS configuration..."

    mkdir -p "$config_dir"

    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' RETURN

    local archive="${tmpdir}/config.tar.gz"
    curl -fsSL --max-time 120 -o "$archive" "$config_url"

    tar -xf "$archive" -C "$tmpdir"

    local extracted_dir
    extracted_dir=$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d | head -1)

    if [[ -d "$extracted_dir" ]]; then
        cp -r "$extracted_dir"/* "$config_dir"/
    else
        cp -r "$tmpdir"/* "$config_dir"/
    fi

    log_info "Configuration fetched to ${config_dir}"
}

# -----------------------------------------------------------------------------
# Generate hardware configuration
# -----------------------------------------------------------------------------

generate_hardware_config() {
    local luks_part="$1"

    log_info "Generating hardware configuration..."

    nixos-generate-config --root /mnt

    local luks_uuid
    luks_uuid=$(blkid -s UUID -o value "$luks_part")

    local hw_config="/mnt/etc/nixos/hardware-configuration.nix"

    # Insert LUKS config before the closing brace
    # Remove the final closing brace, add LUKS config, then add it back
    sed -i '/^}$/d' "$hw_config"

    cat >> "$hw_config" << EOF

  # LUKS encrypted root
  boot.initrd.luks.devices."cryptroot" = {
    device = "/dev/disk/by-uuid/${luks_uuid}";
    preLVM = true;
    allowDiscards = true;
  };
}
EOF

    log_info "Hardware configuration generated with LUKS UUID: ${luks_uuid}"
}

# -----------------------------------------------------------------------------
# Generate base configuration (if remote config doesn't have one)
# -----------------------------------------------------------------------------

generate_base_config() {
    local config_file="/mnt/etc/nixos/configuration.nix"

    # Only generate if no configuration.nix exists
    if [[ -f "$config_file" ]]; then
        log_info "Using fetched configuration.nix"

        # Patch existing config with our settings if needed
        # Check if it imports hardware-configuration.nix
        if ! grep -q "hardware-configuration.nix" "$config_file"; then
            log_warn "Adding hardware-configuration.nix import to existing config"
            sed -i '1a\  imports = [ ./hardware-configuration.nix ];' "$config_file"
        fi
        return
    fi

    log_info "Generating base configuration.nix..."

    # Hash password before writing config
    local pw_hash
    pw_hash=$(hash_password "$USER_PASSWORD")

    cat > "$config_file" << EOF
{ config, pkgs, ... }:

{
  imports = [
    ./hardware-configuration.nix
  ];

  # Bootloader
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # Hostname
  networking.hostName = "${HOSTNAME}";

  # Network
  networking.networkmanager.enable = true;

  # Timezone
  time.timeZone = "${TIMEZONE}";

  # Locale
  i18n.defaultLocale = "${LOCALE}";
  i18n.extraLocaleSettings = {
    LC_ALL = "${LOCALE}";
  };

  # Console keyboard
  console.keyMap = "${KEYBOARD}";

  # X11 keyboard (if using graphical)
  services.xserver.xkb.layout = "${KEYBOARD}";

  # User account
  users.users.${USERNAME} = {
    isNormalUser = true;
    description = "${USERNAME}";
    extraGroups = [ "wheel" "networkmanager" "video" "audio" ];
    initialHashedPassword = "${pw_hash}";
  };

  # Allow unfree packages
  nixpkgs.config.allowUnfree = true;

  # Basic packages
  environment.systemPackages = with pkgs; [
    vim
    git
    wget
    curl
  ];

  # Enable OpenSSH
  services.openssh.enable = true;

  # Firewall
  networking.firewall.enable = true;

  # NixOS version
  system.stateVersion = "${NIXOS_VERSION}";
}
EOF

    log_info "Base configuration generated"
}

# -----------------------------------------------------------------------------
# Apply user password to fetched config
# -----------------------------------------------------------------------------

apply_user_to_config() {
    local config_file="/mnt/etc/nixos/configuration.nix"

    if [[ ! -f "$config_file" ]]; then
        return
    fi

    # Check if user is already defined
    if grep -q "users.users.${USERNAME}" "$config_file"; then
        log_info "User ${USERNAME} already in config, updating password hash..."

        # Generate password hash
        local pw_hash
        pw_hash=$(hash_password "$USER_PASSWORD")

        # Try to update initialHashedPassword if it exists
        if grep -q "initialHashedPassword" "$config_file"; then
            sed -i "s|initialHashedPassword = \"[^\"]*\"|initialHashedPassword = \"${pw_hash}\"|" "$config_file"
        fi
    else
        log_info "Adding user ${USERNAME} to configuration..."

        local pw_hash
        pw_hash=$(hash_password "$USER_PASSWORD")

        # Insert user block before the closing brace
        sed -i "/^}$/i\\
  # User added by nixstallman\\
  users.users.${USERNAME} = {\\
    isNormalUser = true;\\
    extraGroups = [ \"wheel\" \"networkmanager\" ];\\
    initialHashedPassword = \"${pw_hash}\";\\
  };" "$config_file"
    fi

    # Clear password from memory
    USER_PASSWORD=""
}

# -----------------------------------------------------------------------------
# Configure channel
# -----------------------------------------------------------------------------

configure_channel() {
    log_info "Configuring NixOS ${NIXOS_VERSION} channel..."

    nix-channel --add "$NIXOS_CHANNEL" nixos
    nix-channel --update

    log_info "Channel configured: ${NIXOS_CHANNEL}"
}

# -----------------------------------------------------------------------------
# Install NixOS
# -----------------------------------------------------------------------------

install_nixos() {
    log_info "Installing NixOS ${NIXOS_VERSION}..."

    if [[ ! -f /mnt/etc/nixos/configuration.nix ]]; then
        log_warn "No configuration.nix found. Generating default..."
        nixos-generate-config --root /mnt
    fi

    nixos-install --no-root-passwd --channel "$NIXOS_CHANNEL"

    log_info "Installation complete!"
}

# -----------------------------------------------------------------------------
# Post-install
# -----------------------------------------------------------------------------

show_post_install() {
    echo ""
    echo "============================================================"
    echo -e "${GREEN}NixOS ${NIXOS_VERSION} installation complete!${NC}"
    echo "============================================================"
    echo ""
    echo "System: ${HOSTNAME}"
    echo "User:   ${USERNAME}"
    echo ""
    echo "Next steps:"
    echo "  1. (Optional) Set root password: nixos-enter --root /mnt -c 'passwd'"
    echo "  2. Reboot: reboot"
    echo "  3. Log in as '${USERNAME}' with the password you set"
    echo ""
    echo "Your LUKS-encrypted root is at: /dev/mapper/cryptroot"
    echo "Remember your disk encryption passphrase!"
    echo ""
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    echo ""
    echo "============================================================"
    echo -e "${GREEN}nixstallman${NC} - NixOS ${NIXOS_VERSION} Installer"
    echo "============================================================"
    echo ""

    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root"
    fi

    if [[ ! -f /etc/NIXOS ]]; then
        die "This script must be run from a NixOS live environment"
    fi

    local config_url="${1:-}"
    local target_disk="${2:-}"

    # Get config URL (optional - skip for vanilla install)
    if [[ -z "$config_url" ]]; then
        echo "Enter the URL to your NixOS configuration tarball."
        echo "Example: https://github.com/user/repo/archive/main.tar.gz"
        echo ""
        echo -e "${CYAN}Press Enter to skip and use vanilla NixOS config.${NC}"
        echo ""
        read -r -p "Config URL (or blank for vanilla): " config_url
    fi

    if [[ -n "$config_url" ]]; then
        validate_url "$config_url"
    else
        log_info "No config URL provided - will generate vanilla NixOS configuration"
    fi

    # Get target disk
    if [[ -z "$target_disk" ]]; then
        target_disk=$(select_disk)
    fi
    validate_disk "$target_disk"

    # Collect all configuration interactively
    collect_system_config
    collect_user_config
    configure_layout "$target_disk"
    collect_encryption_password

    # Show summary
    echo ""
    echo "============================================================"
    echo -e "${CYAN}Installation Summary${NC}"
    echo "============================================================"
    echo ""
    echo "  Target disk:    ${target_disk}"
    echo "  Hostname:       ${HOSTNAME}"
    echo "  Username:       ${USERNAME}"
    echo "  Timezone:       ${TIMEZONE}"
    echo "  Locale:         ${LOCALE}"
    echo "  Keyboard:       ${KEYBOARD}"
    echo "  Filesystem:     ${ROOT_FS}"
    if [[ "$USE_SWAP" == "yes" ]]; then
        echo "  Swap:           ${SWAP_SIZE}"
    else
        echo "  Swap:           none"
    fi
    if [[ -n "$config_url" ]]; then
        echo "  Config URL:     ${config_url}"
    else
        echo "  Config:         vanilla (generated)"
    fi
    echo ""

    log_warn "This will DESTROY ALL DATA on ${target_disk}"
    confirm_action "Are you sure you want to continue?"

    # Execute installation
    configure_channel

    local part_info
    part_info=$(partition_disk "$target_disk")
    local efi_part="${part_info%%:*}"
    local luks_part="${part_info##*:}"

    mount_filesystems "$efi_part"

    if [[ -n "$config_url" ]]; then
        fetch_config "$config_url"
    fi

    generate_hardware_config "$luks_part"
    generate_base_config
    apply_user_to_config
    install_nixos
    show_post_install
}

main "$@"
