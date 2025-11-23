#!/bin/bash
#
# This script is used to automate the deletion of existing ssh keys that the red team could have saved
# Make sure you run on the remote host
#
echo "Removing SSH keys for all regular users..."

# All users with UID >= 1000 (non-system users)
USERS=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)

for user in $USERS; do
    userhome=$(eval echo "~$user")
    sshdir="$userhome/.ssh"

    echo "Processing user: $user"

    if [ -d "$sshdir" ]; then
        # Remove authorized keys files if they exist
        rm -f "$sshdir/authorized_keys" "$sshdir/authorized_keys2"

        # Optional: removes the entire .ssh folder (comment this out if not needed)
        rm -rf "$sshdir"

        # Recreates empty .ssh with proper permissions
        mkdir -p "$sshdir"
        chmod 700 "$sshdir"
        chown -R "$user:$user" "$sshdir"

        echo "SSH keys removed for $user."
    else
        echo "No SSH directory for $user — skipping."
    fi
done

echo "All done."
