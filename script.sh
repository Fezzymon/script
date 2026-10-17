#!/bin/bash
# Comprehensive Hardening Script for Fedora 38 (ignition-t)
# Horse Plinko Cyber Challenge

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root."
  exit 1
fi

echo "[+] Starting comprehensive system hardening on Fedora 38 (ignition-t)..."

# 1. Update packages to fix OS vulnerabilities
echo "[+] Step 1: Updating system packages..."
dnf upgrade --refresh -y

# 2. User Account Cleanup and Required Password Setting
echo "[+] Step 2: Cleaning up user accounts and setting required credentials..."
for user in $(awk -F: '$3 >= 1000 && $1 != "jmoney" && $1 != "plinktern" {print $1}' /etc/passwd); do
    echo "[*] Removing unauthorized user: $user"
    userdel -r "$user" 2>/dev/null || userdel "$user"
done

# Set required passwords for plinktern and jmoney
echo "plinktern:plink\$1234" | chpasswd
echo "jmoney:plink\$1234" | chpasswd

# Enforce system-wide password policies in login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs

# 3. Firewall Configuration (firewalld)
echo "[+] Step 3: Configuring firewalld..."
systemctl enable --now firewalld
firewall-cmd --set-default-zone=public

# Allow required services and ports
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-port=8080/tcp

# Allow the internal competition subnet
firewall-cmd --permanent --add-source=172.16.0.0/16

firewall-cmd --reload
echo "[+] Firewall rules applied successfully."

# 4. Ensure SSH remains active and running
echo "[+] Step 4: Verifying SSH service..."
systemctl enable --now sshd
systemctl restart sshd

# 5. Restrict User Creation Binaries
echo "[+] Step 5: Restricting user creation binaries..."
chmod 700 /usr/sbin/useradd /usr/sbin/adduser /usr/sbin/usermod

# 6. Apply Immutability to Core Shell and System Commands
echo "[+] Step 6: Applying immutable flags to core commands..."
chattr +i /bin/bash /bin/sh /usr/bin/sudo /usr/bin/passwd /usr/bin/su

echo "[+] Hardening complete on ignition-t."

# 7. Clear history and self-destruct
history -c
history -w
unset HISTFILE
rm -- "$0"
