# SSH honeypot
This project aims to develop a high-interaction SSH-focused honeypot system suitable for small to medium-scale deployment on a single host while being less complex and easier to deploy than those general-purpose high-interaction honeypot systems.

## Properties
* SSH focused
* High interaction
* Simple and easy to set up
* Real operating system
* No modification of software or installation of loggers on the OS of honeypot required
* Can run on a single host

## Building the honeypot
To build the honeypot, a 64-bit installation of Ubuntu is required.
The honeypot is tested on Ubuntu 16.04 and 17.10.
The following steps can be used to build the honeypot on Ubuntu 16.04:
```
apt-get update
apt-get install build-essential git libssl-dev libcurl4-openssl-dev \
libjansson-dev libpq-dev libcurl3 libjansson4 libpq5 \
libssl-dev libcurl4-openssl-dev
cd code
make my_hpot_main
```
The steps above should produce an executable named “my_hpot_main” in the same directory

## Running the honeypot
The following steps can be used to run the honeypot on Ubuntu 16.04:

Install required packages:
```
apt-get update
apt-get install libssl-dev libcurl4-openssl-dev libjansson-dev \
libpq-dev postgresql postgresql-contrib lxd \
libcurl3 libjansson4 libpq5 libssl-dev libcurl4-openssl-dev
```
Change the listening port of SSH server to 2200 by changing the line "Port 22" to "Port 2200" in “/etc/ssh/sshd_config”.
Restart the SSH server:
```
systemctl restart ssh
```
Create a new database user named "hpot": (a potential "Permission denied" warning can be ignored)
```
sudo -u postgres createuser hpot
```
Create a new database named "hpot":
```
sudo -u postgres createdb hpot
```
Open a PostgreSQL interactive terminal:
```
sudo -u postgres psql
```
In psql, set user password to "mypasswd":
```
alter user hpot with encrypted password ’mypasswd’;
```
In psql, grant database privileges:
```
grant all privileges on database hpot to hpot;
```
Quit psql and create the tables:
```
psql -h 127.0.0.1 -U hpot -d hpot -a -f my_pqsql_table.sql
```
Initialise LXD and answer all questions with default options:
```
lxd init
```
Create a temporary Ubuntu 16.04 VM named "tempvm":
```
lxc launch ubuntu:16.04 tempvm
```
Enter the shell of the VM:
```
lxc exec tempvm bash
```
In the VM, set root password to "123456":
```
echo -e "123456\n123456" | passwd
```
In the VM, change line “PermitRootLogin prohibit-password” to “PermitRootLogin yes” and “PasswordAuthentication no” to “PasswordAuthentication yes” in “/etc/ssh/sshd_conf” to enable password login for root over SSH.

Quit the VM shell and stop the VM:
```
lxc stop tempvm
```
Turn the VM into an image named "my_image":
```
lxc publish tempvm --alias my_image
```
Generate SSH server keys:
```
ssh-keygen -t rsa -f ssh_host_rsa_key
ssh-keygen -t ecdsa -f ssh_host_ecdsa_key
ssh-keygen -t ed25519 -f ssh_host_ed25519_key
```
Launch the honeypot:
```
./my_hpot_main my_example_config.json
```
Note that the honeypot will create the VMs and initial snapshots the first time it is run, which can take a few minutes.
If the honeypot is no longer needed, the VMs can be deleted by "lxc delete <VM name>". A list of VMs can be obtained by "lxc list".

It is possible to run the honeypot as a non-root user.
Add the user to group "lxd":
```
adduser <user> lxd
```
Allow the honeypot executable to bind to privileged ports:
```
setcap capnetbindservice=+ep my_hpot_main
```
Disable SNAT feature by setting "iptables_snat_enabled" to false in the configuration file.
