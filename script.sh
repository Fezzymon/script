#!/bin/bash
# Ubuntu 22.04 Blue Team Hardening Script

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root." 
   exit 1
fi

SCRIPT_PATH="$(realpath "$0")"
TARGET_PASS='plink$1234'
ALLOWED_USERS=("jmoney" "plinktern")

echo "[*] Backing up critical auth files to /root/.backup_auth..."
mkdir -p /root/.backup_auth
cp /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config /root/.backup_auth/
chmod 600 /root/.backup_auth/*

# 1. User Management & Password Enforcement
echo "[*] Ensuring allowed users exist and setting passwords..."
for user in "${ALLOWED_USERS[@]}"; do
    if ! id "$user" &>/dev/null; then
        useradd -m -s /bin/bash "$user"
    fi
    # Single quotes around TARGET_PASS prevent $1234 variable expansion
    echo "${user}:${TARGET_PASS}" | chpasswd
    passwd -u "$user" 2>/dev/null
done

# Ensure root has the known password so it isn't passwordless
echo "root:${TARGET_PASS}" | chpasswd

echo "[*] Removing unauthorized human users (UID >= 1000)..."
# Only target standard users (UID >= 1000) to avoid breaking system/Apache daemons (www-data, sshd, etc.)
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | while read -r user; do
    if [[ "$user" != "jmoney" && "$user" != "plinktern" ]]; then
        echo "[-] Deleting unauthorized user: $user"
        pkill -KILL -u "$user" 2>/dev/null
        userdel -r -f "$user" 2>/dev/null
    fi
done

echo "[*] Locking passwordless accounts and enforcing password requirement..."
# Lock any system account that has an empty password field in /etc/shadow
awk -F: '($2 == "" ) {print $1}' /etc/shadow | while read -r empty_user; do
    if [[ "$empty_user" != "jmoney" && "$empty_user" != "plinktern" && "$empty_user" != "root" ]]; then
        passwd -l "$empty_user" 2>/dev/null
    fi
done

# Remove nullok from PAM so blank passwords cannot authenticate anywhere
sed -i 's/\bnullok\b//g' /etc/pam.d/common-auth
sed -i 's/\bnullok_secure\b//g' /etc/pam.d/common-auth

# 2. Firewall Configuration (UFW) & Apache2
echo "[*] Configuring UFW for SSH (22) and Apache2 (80, 443)..."
apt-get update -y && apt-get install -y ufw apache2

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "[*] Ensuring Apache2 service is active..."
systemctl enable apache2
systemctl restart apache2

# 3. SSH Hardening
echo "[*] Hardening SSH configuration..."
SSHD_CONF="/etc/ssh/sshd_config"

# Remove conflicting directives in drop-in directory (Ubuntu 22.04 often overrides PasswordAuthentication here)
rm -f /etc/ssh/sshd_config.d/*.conf

sed -i -E 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONF"
sed -i -E 's/^#?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONF"
sed -i -E 's/^#?PubkeyAuthentication.*/PubkeyAuthentication no/' "$SSHD_CONF"
sed -i -E 's/^#?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' "$SSHD_CONF"
sed -i -E 's/^#?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD_CONF"
sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONF"
sed -i -E 's/^#?UsePAM.*/UsePAM yes/' "$SSHD_CONF"

# Explicitly append directives if they weren't present in the file
grep -q "^PasswordAuthentication" "$SSHD_CONF" || echo "PasswordAuthentication yes" >> "$SSHD_CONF"
grep -q "^PermitEmptyPasswords" "$SSHD_CONF" || echo "PermitEmptyPasswords no" >> "$SSHD_CONF"
grep -q "^PubkeyAuthentication" "$SSHD_CONF" || echo "PubkeyAuthentication no" >> "$SSHD_CONF"

# Restrict SSH login strictly to the two required accounts
sed -i '/^AllowUsers/d' "$SSHD_CONF"
echo "AllowUsers jmoney plinktern" >> "$SSHD_CONF"

# Wipe authorized_keys to prevent key-based backdoors
rm -rf /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null

# Validate sshd syntax before restarting
if sshd -t; then
    systemctl restart ssh
else
    echo "[!] SSH config syntax error detected! Restoring backup..."
    cp /root/.backup_auth/sshd_config /etc/ssh/sshd_config
    systemctl restart ssh
fi

# 4. Prevent Creation of New Users
echo "[*] Locking user database files and account creation binaries..."
# Restrict chmod on useradd/adduser
chmod 000 /usr/sbin/useradd /usr/sbin/adduser /usr/sbin/groupadd /usr/sbin/newusers 2>/dev/null

# Make user/group databases immutable (even root cannot add users without removing +i first)
chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers
chattr -R +i /etc/sudoers.d 2>/dev/null

# 5. Self-Deletion & Anti-Forensics (History Wipe)
echo "[*] Shredding script and wiping command histories..."
shred -u -z -n 3 "$SCRIPT_PATH" 2>/dev/null || rm -f "$SCRIPT_PATH"

# Wipe bash, zsh, and python/mysql/less histories across root and all user profiles
history_files=(
    "/root/.*_history"
    "/home/*/.*_history"
    "/root/.lesshst"
    "/home/*/.lesshst"
    "/root/.viminfo"
    "/home/*/.viminfo"
)

for pattern in "${history_files[@]}"; do
    for file in $pattern; do
        if [[ -f "$file" ]]; then
            shred -u -z -n 1 "$file" 2>/dev/null || rm -f "$file"
        fi
    done
done

# Truncate current session history and disable history logging for active shells
export HISTSIZE=0
export HISTFILESIZE=0
unset HISTFILE
history -c
history -w

echo "[+] Hardening complete."
