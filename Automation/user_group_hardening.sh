#!/bin/bash

# ========================
# CCDC User Hardening Script for CentOS (can modify for Ubuntu/Debian)
# Add all known/given admin/user accounts to lists below
# All other accounts will be disabled 
# All accounts in the list will be moved to the correct user groups
# ========================

# Valid admin users
ADMINS=(
  # Add admin users as needed
)

# Valid non-admin users
USERS=(
  # Add non-admin users as needed
)

# Combine into one big list
VALID_USERS=("${ADMINS[@]}" "${USERS[@]}")

echo "[+] Hardening users..."
echo "[+] Valid users: ${#VALID_USERS[@]}"

# ------------------------------------------
# STEP 1: Disable any user NOT in valid list
# ------------------------------------------
for u in $(awk -F: '{print $1}' /etc/passwd); do
    if [[ ! " ${VALID_USERS[@]} " =~ " ${u} " ]]; then
        if [[ "$u" != "root" ]]; then
            echo "[!] Disabling unknown user: $u"
            usermod -L "$u"
            usermod -s /sbin/nologin "$u"
        fi
    fi
done

# ------------------------------------------
# STEP 2: Ensure admin users are in wheel
# ------------------------------------------
for admin in "${ADMINS[@]}"; do
    if id "$admin" &>/dev/null; then
        echo "[+] Ensuring $admin is in wheel group"
        usermod -aG wheel "$admin"
    fi
done

# ------------------------------------------
# STEP 3: Ensure non-admins are NOT in wheel
# ------------------------------------------
for nonadmin in "${USERS[@]}"; do
    if id "$nonadmin" &>/dev/null; then
        gpasswd -d "$nonadmin" wheel 2>/dev/null
    fi
done

echo "[+] User hardening complete."
