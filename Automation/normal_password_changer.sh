#!/bin/bash
#
# This script is to be run ON the remote host
# The password file is stored in RAM, so it is harder for the red team to find it since it isn't stored in the  home directory
#
# Temporary in-RAM file (never stored on disk)
OUTPUT="/dev/shm/passwords_list.txt"

echo "Generating passwords in file: $OUTPUT"
> "$OUTPUT"

# Pulls list of normal (non-system) users
USERS=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)

for user in $USERS; do
    # Generates a secure 15-character password (can change length)
    newpass=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#$%^&*()_+=-{}[]<>?' < /dev/urandom | head -c 15)

    echo "Setting password for $user..."
    echo "$user:$newpass" | sudo chpasswd

    # Store in RAM file
    echo "$user:$newpass" >> "$OUTPUT"
done

echo "Done!"
echo "Password file is in: $OUTPUT"
echo "Download it from your local machine, then delete it."

# Run the following command to download: scp admin-user@remote.host.ip:/dev/shm/passwords_list.txt ./passwords_list.txt
# Then remove file from remote host: rm /dev/shm/passwords_list.txt
