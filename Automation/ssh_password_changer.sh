#!/bin/bash
#
# This script is to be used on the device used to connect to the remote network
# Make sure to change variables to the host IP and user with admin access
# 
HOST="remote.host.ip"
ADMINUSER="admin-user"
OUTPUT="passwords_list.txt"

echo "Generating passwords and updating users on $HOST..."
> "$OUTPUT"

# Pulls list of normal (non-system) users
USERS=$(ssh $ADMINUSER@$HOST "awk -F: '\$3 >= 1000 && \$1 != \"nobody\" {print \$1}' /etc/passwd")

for user in $USERS; do
    # Generates a secure 15-character password (can change length)
    newpass=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*()_+=-{}[]<>?' < /dev/urandom | head -c 15)

    echo "Updating password for $user..."

    # Changes the passwords on the remote host without storing them on the device (could protect against red team getting new passwords)
    ssh $ADMINUSER@$HOST "echo \"$user:$newpass\" | sudo chpasswd"

    # Save to local file only
    echo "$user:$newpass" >> "$OUTPUT"
done

echo "All done. Passwords saved to $OUTPUT."
