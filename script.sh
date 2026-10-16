#!/usr/bin/env bash
set -euo pipefail

# Ensure script deletes itself on exit to avoid leaving credentials on disk
trap 'rm -f -- "$0"' EXIT

if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
#!/usr/bin/env bash
set -euo pipefail

# Ensure script deletes itself on exit to avoid leaving credentials on disk
trap 'rm -f -- "$0"' EXIT

if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# 1. TEMPORARY FIREWALL (RESTRICTED TO SSH & ESSENTIALS FOR SCRIPT COMPLETION)
apt-get update -y
apt-get install -y ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow in 22/tcp comment 'Allow SSH'
ufw allow out 53/udp comment 'DNS'
ufw allow out 53/tcp comment 'DNS'
ufw allow out 80/tcp comment 'HTTP repos'
ufw allow out 443/tcp comment 'HTTPS repos'
ufw allow out 1514/tcp comment 'Wazuh Agent log forwarding'
ufw allow out 1515/tcp comment 'Wazuh Agent enrollment'
ufw --force enable

# 2. PASSWORDS & AUTHENTICATION POLICY (SET ALL TO $neverhacked, EXCLUDE jmoney)

NEW_PASS='$neverhacked'
USERS_TO_UPDATE=("root")

while IFS=: read -r username _ uid _ _ _ shell; do
  if { [ "$uid" -ge 1000 ] || [ "$uid" -eq 0 ]; } && [[ "$shell" =~ (bash|sh|zsh|dash)$ ]] && [ "$username" != "jmoney" ]; then
    USERS_TO_UPDATE+=("$username")
  fi
done < /etc/passwd

for user in "${USERS_TO_UPDATE[@]}"; do
  if id "$user" &>/dev/null; then
    echo "${user}:${NEW_PASS}" | chpasswd
  fi
done

passwd -l root 2>/dev/null || true
if [ -f /etc/ssh/sshd_config ]; then
  sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config
  sed -i '/^Protocol/d' /etc/ssh/sshd_config
  echo "Protocol 2" >> /etc/ssh/sshd_config
  sed -i '/^AllowUsers/d' /etc/ssh/sshd_config
  echo "AllowUsers jmoney plinktern" >> /etc/ssh/sshd_config
  systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
fi

echo "Removing nopasswdlogin group"
sed -i -e '/nopasswdlogin/d' /etc/group 2>/dev/null || true
chmod 644 /etc/passwd

CURRENT_USER=$(whoami)
echo "🧹 Removing unauthorized users (preserving plinktern, jmoney, nobody, and $CURRENT_USER)..."
for user in $(cut -d: -f1 /etc/passwd); do
  uid=$(id -u "$user" 2>/dev/null)
  if [[ "$uid" -ge 1000 && "$user" != "nobody" && "$user" != "jmoney" && "$user" != "plinktern" && "$user" != "$CURRENT_USER" ]]; then
    echo "❌ Deleting user: $user"
    pkill -u "$user" 2>/dev/null || true
    userdel -r "$user" &>/dev/null || true
  fi
done
echo "✅ User cleanup complete."

# Privilege Management (Only plinktern allowed sudo if it exists)
echo "🔧 Configuring sudo access (plinktern only)..."
if id "plinktern" &>/dev/null; then
  usermod -aG sudo plinktern
fi
for user in $(cut -d: -f1 /etc/passwd); do
  if [[ "$user" != "plinktern" && "$user" != "root" ]]; then
    gpasswd -d "$user" sudo &>/dev/null || true
  fi
done
if id "jmoney" &>/dev/null; then
  usermod -G "" jmoney 2>/dev/null || true
fi
if id "fez" &>/dev/null; then
  usermod -G "" fez 2>/dev/null || true
fi
rm -f /etc/sudoers.d/jmoney /etc/sudoers.d/fez
sed -i '/^jmoney/d' /etc/sudoers
sed -i '/^fez/d' /etc/sudoers
echo "✅ Sudo access restricted exclusively to plinktern."

# 3. SYSTEM UPDATES & UPGRADES

apt-get update -y
apt-get upgrade -y linux-generic
dpkg-reconfigure -f noninteractive unattended-upgrades || true

# 4. REST OF SCRIPT (DEPENDENCIES, EDR, TOOLS, WEB & DB HARDENING)

apt-get install -y \
  clamav clamav-daemon ranger tmux whowatch e2fsprogs \
  curl apparmor-utils gnupg dkms linux-headers-$(uname -r) debsums \
  unattended-upgrades apache2

# Purge attack surface
apt-get purge -y --auto-remove \
  cups cups-browsed avahi-daemon rpcbind snapd \
  apport whoopsie modemmanager gcc g++ make netcat-traditional \
  netcat-openbsd socat cockpit cockpit-bridge cockpit-ws 2>/dev/null || true

systemctl stop avahi-daemon.socket cups.socket cups-browsed.service rpcbind.socket cockpit.socket 2>/dev/null || true
systemctl mask avahi-daemon.socket cups.socket cups-browsed.service rpcbind.socket cockpit.socket 2>/dev/null || true

# Backups & EDR Repositories (fez.tar.gz sent to .5)
tar -czvf /root/fez.tar.gz /etc /var /home /usr/bin/apt /etc/ssh /etc/apache2 /lib/systemd/system/apache2.service /var/www/html /etc/ufw /var/log/debsums_audit.log || true
scp /root/fez.tar.gz plinktern@172.16.t.05:/home/plinktern/ || true

curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | tee /etc/apt/sources.list.d/falcosecurity.list

curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

apt-get update -y

echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
apt-get install -y tshark wireshark-common
groupadd -f wireshark

apt-get install -y falco
WAZUH_MANAGER="127.0.0.1" apt-get install -y wazuh-agent

# Lock user creation & core files
chmod 700 /usr/sbin/useradd /usr/sbin/adduser /usr/sbin/newusers 2>/dev/null || true
chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null || true

# EDR Service Resiliency
FALCO_UNIT=$(systemctl show -p Id falco 2>/dev/null | cut -d= -f2 || true)
if [ -z "$FALCO_UNIT" ]; then
  FALCO_UNIT="falco.service"
fi

mkdir -p /etc/systemd/system/${FALCO_UNIT}.d
cat << EOF > /etc/systemd/system/${FALCO_UNIT}.d/override.conf
[Service]
Restart=always
RestartSec=5
EOF

mkdir -p /etc/systemd/system/wazuh-agent.service.d
cat << 'EOF' > /etc/systemd/system/wazuh-agent.service.d/override.conf
[Service]
Restart=always
RestartSec=5
EOF

systemctl daemon-reload
systemctl enable --now "${FALCO_UNIT}" 2>/dev/null || true
systemctl enable --now wazuh-agent 2>/dev/null || true

# Web directory permissions lockdown
if [ -d /var/www/html ]; then
  chown -R root:root /var/www/html
  find /var/www/html -type d -exec chmod 755 {} \;
  find /var/www/html -type f -exec chmod 644 {} \;
fi

# Permission hardening & AppArmor
chmod 700 /usr/bin/wget 2>/dev/null || true
chmod 700 /usr/bin/curl 2>/dev/null || true
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# Kernel security hardening (sysctl)
cat << 'EOF' > /etc/sysctl.d/99-security-hardening.conf
kernel.kptr_restrict=2
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF
sysctl --system || true

# Tools download
curl -L -o pspy64 https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 || true
chmod +x pspy64 2>/dev/null || true
mv pspy64 /usr/local/bin/ 2>/dev/null || true

# System integrity audit
echo "Running system integrity audit..."
debsums_init 2>/dev/null || true
debsums -ca 2>/dev/null > /var/log/debsums_audit.log || true
chmod 600 /var/log/debsums_audit.log 2>/dev/null || true

# 5. NORMAL FIREWALL CONFIGURATION (FINAL PRODUCTION STATE FOR .10)

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow in 22/tcp comment 'Allow SSH'
ufw allow from 172.16.4.10 to any port 80 proto tcp comment 'Allow HTTP communication with 172.16.4.10'
ufw allow out to 172.16.0.0/16 proto tcp to port 3306 comment 'Allow outbound DB access to Manifest'
ufw deny 443/tcp comment 'Block HTTPS if not used'
ufw deny 4444/tcp comment 'Block Metasploit'
ufw --force enable

# 6. SYSTEM IMMUTABILITY & CLEANUP

chattr +i /lib/systemd/system/${FALCO_UNIT} 2>/dev/null || true
chattr +i /usr/lib/systemd/system/${FALCO_UNIT} 2>/dev/null || true
chattr +i /etc/systemd/system/${FALCO_UNIT}.d/override.conf 2>/dev/null || true

chattr +i /lib/systemd/system/wazuh-agent.service 2>/dev/null || true
chattr +i /usr/lib/systemd/system/wazuh-agent.service 2>/dev/null || true
chattr +i /etc/systemd/system/wazuh-agent.service.d/override.conf 2>/dev/null || true

chattr +i /var/ossec/etc/ossec.conf 2>/dev/null || true
chattr +i /etc/falco/falco.yaml 2>/dev/null || true

chattr -R +i /etc/apt/trusted.gpg.d/ 2>/dev/null || true
chattr -R +i /usr/share/keyrings/ 2>/dev/null || true
chattr +i /etc/apt/sources.list 2>/dev/null || true
chattr -R +i /etc/apt/sources.list.d/ 2>/dev/null || true
chattr +i /etc/ssh/sshd_config 2>/dev/null || true

export HISTFILE=/dev/null
set +o history 2>/dev/null || true
> ~/.bash_history 2>/dev/null || true

echo "Hardening sequence complete for guidance-t (.10). jmoney untouched, openssh-server skipped."
