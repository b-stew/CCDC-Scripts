##############################################
# 0. INTRODUCTION
##############################################
# Do not actually run this script
# It is for reference use only for various threat hunting tasks
# Most is tailored to CentOS, but can be adapted for other systems

##############################################
# 1. NETWORK CONNECTION ENUMERATION
##############################################

# ss -tupan
# ss      = socket statistics tool
# -t      = show TCP sockets
# -u      = show UDP sockets
# -p      = show the process using each socket (PID/program)
# -a      = show ALL sockets (listening + established)
# -n      = do NOT resolve DNS; show raw IP addresses
ss -tupan

# lsof -i -n -P
# lsof    = list open files (network connections count as "files")
# -i      = show only network files/sockets
# -n      = no DNS lookup (faster & avoids misleading hostnames)
# -P      = no service name lookup (shows port numbers instead of names)
sudo lsof -i -n -P

##############################################
# 2. PROCESS ENUMERATION
##############################################

# ps aux --sort=-%cpu
# ps        = process status
# a         = show processes for ALL users
# u         = show user-oriented format (owner, CPU, MEM)
# x         = show processes not tied to a terminal
# --sort    = sort output
# -%cpu     = sort descending by CPU usage
ps aux --sort=-%cpu

# Same as above but sorted by memory use
ps aux --sort=-%mem

# ps -eH
# -e        = show every running process
# -H        = hierarchical "tree" view to see parent/child relationships
ps -eH

# find <dirs> -type f -executable -print
# find       = search for files
# <dirs>     = /tmp /dev/shm /var/tmp (common attacker locations)
# -type f    = only files
# -executable= file has execute permission
# -print     = output matches to the screen
sudo find /tmp /dev/shm /var/tmp -type f -executable -print

# kill -9 <PID>
# kill     = send signal to a process
# -9       = SIGKILL (force-kill, cannot be ignored)
sudo kill -9 <PID>

# systemctl stop/disable <service>
# stop     = stops service immediately
# disable  = prevents service from starting on boot
sudo systemctl stop <service>
sudo systemctl disable <service>

##############################################
# 3. USER LOGIN & AUTHENTICATION ENUMERATION
##############################################

# last
# last = shows successful login history based on /var/log/wtmp
last

# lastb
# lastb = shows FAILED login attempts based on /var/log/btmp
sudo lastb

# tail -f /var/log/secure
# tail     = view end of file
# -f       = follow live output as it updates
sudo tail -f /var/log/secure

# passwd -l <user>
# passwd   = manage passwords
# -l       = lock account (disables login)
sudo passwd -l <username>

# passwd <user>
# Resets password for compromised account
sudo passwd <username>

##############################################
# 4. PERSISTENCE ENUMERATION
##############################################

# systemctl list-units --type=service
# list-units     = list loaded systemd units
# --type=service = only show services
systemctl list-units --type=service

# systemctl list-unit-files --type=service | grep enabled
# list-unit-files = show services installed on disk
# grep enabled    = show services configured to run at boot
systemctl list-unit-files --type=service | grep enabled

# Check cron jobs
# ls -la = long listing with hidden files
sudo ls -la /var/spool/cron
sudo crontab -l
sudo cat /etc/crontab

# List systemd service files
# Shows custom malicious services attackers often drop
sudo ls -la /etc/systemd/system/
sudo ls -la /etc/init.d/

# Remove malicious service
sudo systemctl stop <service>
sudo systemctl disable <service>
sudo rm /etc/systemd/system/<service>.service

# Remove cron entry (manual edit)
sudo crontab -e

##############################################
# 5. ROOTKIT & MALWARE SCANNING
##############################################

# chkrootkit installation
sudo dnf install chkrootkit -y
# dnf      = package manager
# install  = install a package
# -y       = automatically answer yes to prompts

# Run chkrootkit scan
sudo chkrootkit

# Install rkhunter
sudo dnf install epel-release -y  # needed for rkhunter
sudo dnf install rkhunter -y

# rkhunter --update
# --update = update malware definitions
sudo rkhunter --update

# rkhunter --check --sk
# --check  = perform rootkit scan
# --sk     = skip interactive "press enter" prompts
sudo rkhunter --check --sk

##############################################
# 6. LISTENING PORT & SERVICE ENUMERATION
##############################################

# ss -tulnp
# -t = TCP
# -u = UDP
# -l = show only listening sockets
# -n = no DNS lookup
# -p = show owning process
ss -tulnp

# Filter for a specific port
sudo ss -tulnp | grep :<port>

# Close service binding to the port
sudo systemctl stop <service>

# Block port in firewall
# --permanent = survives reboot
# add-rich-rule = advanced rule syntax
# reject        = actively reject connections
sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' port port='<port>' protocol='tcp' reject"
sudo firewall-cmd --reload

##############################################
# 7. FILESYSTEM THREAT HUNTING
##############################################

# find / -mtime -2
# /         = search entire filesystem
# -mtime -2 = files modified in the last 2 days
sudo find / -mtime -2

# find SUID/SGID binaries
# -perm /6000 = has SUID (4000) or SGID (2000) bits set
sudo find / -perm /6000 -type f -print

# world-writable files
# -perm -0002 = "other" has write permission
sudo find / -type f -perm -0002 -print

# hidden files
# -name ".*" = filenames starting with dot
sudo find / -type f -name ".*" -print

# Remove world-writable bit
# o-w = remove write for "other"
sudo chmod o-w <file>

# Remove malicious file
sudo rm -f <file>

##############################################
# 8. PACKAGE INTEGRITY VERIFICATION
##############################################

# rpm -Va
# rpm  = package manager
# -V   = verify installed packages
# -a   = verify ALL packages
sudo rpm -Va

# rpm -qa --qf ...
# -q    = query package
# -a    = list all installed packages
# --qf  = custom output format
# %{SIGPGP} = show signature field
sudo rpm -qa --qf "%{NAME} %{SIGPGP:pgpsig}\n" | grep "(none)"

# dnf reinstall
sudo dnf reinstall <package> -y

##############################################
# 9. FIREWALL ENUMERATION
##############################################

# firewall-cmd --list-all
# --list-all = show active firewall zone, sources, ports, services
sudo firewall-cmd --list-all

# firewall-cmd --list-ports
# Lists ONLY manually-opened ports
sudo firewall-cmd --list-ports

# Close a port
sudo firewall-cmd --permanent --remove-port=<port>/tcp
sudo firewall-cmd --reload

##############################################
# 10. LOG ANALYSIS
##############################################

# dmesg | tail -n 50
# dmesg       = kernel ring buffer messages
# tail -n 50  = show last 50 lines
dmesg | tail -n 50

# journalctl -xe
# journalctl = view system logs
# -x         = show explanations for messages
# -e         = jump to end of log (most recent)
sudo journalctl -xe

# journalctl -u <service>
# -u <service> = filter logs for one service
sudo journalctl -u <service>
