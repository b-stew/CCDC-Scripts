#!/bin/bash
##############################################
# Debian Threat Hunting & Triage Reference
##############################################
# DO NOT RUN AS A SCRIPT
# Reference-only gameplan for CCDC-style Linux triage
# Debian / Ubuntu focused
##############################################

##############################################
# 1. NETWORK CONNECTION ENUMERATION
##############################################

# ss = socket statistics (replacement for netstat)
# -t = TCP sockets
# -u = UDP sockets
# -p = show owning process (PID/program name)
# -a = show all sockets (listening + established)
# -n = do not resolve hostnames or service names
# Use this to identify C2 beacons, backdoors, or unexpected listeners
ss -tupan

# lsof = list open files (network sockets count as files)
# -i = show only network-related files
# -n = disable DNS resolution
# -P = show numeric ports instead of service names
# Useful for mapping processes to outbound connections
sudo lsof -i -n -P

##############################################
# 2. PROCESS ENUMERATION
##############################################

# ps = process status
# a = processes from all users
# u = user-oriented output (owner, CPU, MEM)
# x = include processes without a TTY
# --sort=-%cpu = sort by CPU usage descending
# Look for resource-hogging or suspicious processes
ps aux --sort=-%cpu

# Same as above, but sorted by memory usage
ps aux --sort=-%mem

# -e = show all processes
# -H = hierarchical output (process tree)
# Helps identify parent/child relationships and suspicious spawns
ps -eH

# find = search filesystem
# /tmp /dev/shm /var/tmp = attacker-favored writable locations
# -type f = regular files
# -executable = files with execute permission
# -print = output matches
# Malware often runs from these directories
sudo find /tmp /dev/shm /var/tmp -type f -executable -print

# kill = send signal to process
# -9 = SIGKILL (force termination, cannot be ignored)
# Use only after identifying persistence
sudo kill -9 <PID>

# systemctl = control systemd services
# stop = immediately stop the service
# disable = prevent service from starting at boot
# Used to neutralize malicious persistence
sudo systemctl stop <service>
sudo systemctl disable <service>

##############################################
# 3. USER LOGIN & AUTHENTICATION ENUMERATION
##############################################

# last = show successful logins from /var/log/wtmp
# Useful for spotting unauthorized access
last

# lastb = show failed login attempts from /var/log/btmp
# Indicates brute force or credential stuffing
sudo lastb

# tail = view end of file
# -f = follow log output in real time
# auth.log = authentication and sudo activity on Debian
sudo tail -f /var/log/auth.log

# passwd = manage user passwords
# -l = lock account (disables password login)
# Use to contain compromised accounts
sudo passwd -l <username>

# Reset password for compromised user
sudo passwd <username>

##############################################
# 4. PERSISTENCE ENUMERATION
##############################################

# list-units = show loaded systemd units
# --type=service = only service units
# Identifies currently running services
systemctl list-units --type=service

# list-unit-files = services installed on disk
# grep enabled = services configured to start at boot
# Persistence often lives here
systemctl list-unit-files --type=service | grep enabled

# Cron directories containing per-user crontabs
sudo ls -la /var/spool/cron/crontabs

# Show current user's cron jobs
sudo crontab -l

# System-wide cron configuration
sudo cat /etc/crontab

# Locations attackers commonly drop custom services
sudo ls -la /etc/systemd/system/
sudo ls -la /etc/init.d/

# Remove malicious systemd service
# Always stop + disable before deleting
sudo systemctl stop <service>
sudo systemctl disable <service>
sudo rm /etc/systemd/system/<service>.service

# Manually edit cron jobs if persistence is found
sudo crontab -e

##############################################
# 5. ROOTKIT & MALWARE SCANNING
##############################################

# apt update = refresh package lists
sudo apt update

# Install common rootkit and integrity scanners
# chkrootkit = known rootkit signatures
# rkhunter   = heuristic + signature-based checks
# debsums    = package file integrity verification
sudo apt install chkrootkit rkhunter debsums -y

# Run debsums
# -c = shows only failed checksum files
sudo debsums -c 
# checks all files and only failed/modified ones
sudo debsums -a | grep -v OK

# Run chkrootkit scan
sudo chkrootkit

# Update rkhunter signatures
sudo rkhunter --update

# --check = perform scan
# --sk = skip interactive prompts
sudo rkhunter --check --sk

##############################################
# 6. LISTENING PORT & SERVICE ENUMERATION
##############################################

# -l = listening sockets only
# -n = numeric output
# -p = show owning process
# Identify exposed services and backdoors
ss -tulnp

# Filter output for a specific port
sudo ss -tulnp | grep :<port>

# Stop service bound to suspicious port
sudo systemctl stop <service>

# ufw = uncomplicated firewall (default on Debian/Ubuntu)
# deny = block traffic
# <port>/tcp = TCP port to block
sudo ufw deny <port>/tcp

# Reload firewall rules
sudo ufw reload

##############################################
# 7. FILESYSTEM THREAT HUNTING
##############################################

# -mtime -2 = modified within last 2 days
# 2>/dev/null = suppress permission errors
sudo find / -mtime -2 2>/dev/null

# -perm /6000 = files with SUID or SGID bits
# Often abused for privilege escalation
sudo find / -perm /6000 -type f -print 2>/dev/null

# -perm -0002 = world-writable files
# Dangerous if executable or system-owned
sudo find / -type f -perm -0002 -print 2>/dev/null

# Hidden files (dotfiles)
# Malware often hides here
sudo find / -type f -name ".*" -print 2>/dev/null

# chmod = change permissions
# o-w = remove write permission for others
sudo chmod o-w <file>

# rm = remove file
# -f = force removal without prompt
sudo rm -f <file>

##############################################
# 8. PACKAGE INTEGRITY VERIFICATION
##############################################

# debsums -s
# -s = show only modified or missing files
# Detects tampering of installed packages
sudo debsums -s

# Reinstall known-good version of package
sudo apt install --reinstall <package> -y

##############################################
# 9. FIREWALL ENUMERATION
##############################################

# Show firewall status and rules verbosely
sudo ufw status verbose

# Deny inbound traffic on specific port
sudo ufw deny <port>/tcp

# Apply firewall changes
sudo ufw reload

##############################################
# 10. LOG ANALYSIS
##############################################

# dmesg = kernel ring buffer
# tail -n 50 = show most recent messages
dmesg | tail -n 50

# journalctl = systemd journal viewer
# -x = include explanations
# -e = jump to end (most recent)
sudo journalctl -xe

# View logs for a specific service
sudo journalctl -u <service>

