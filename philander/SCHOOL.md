Philander Smith College

# CCDC Blueteam Manual

## Pre-Competition Methodology

The events that you will encounter in CCDC will be correlated to real paths attackers will take, but the competition is a bit gamified in order to present a challenge to both the blue team and red team. Many of the things you learn to defend systems in this competition will directly translate to real-world applicable cybersecurity skills.

When initially given the blue team manual before the qualifier round, the number one thing to do is enumerate the attack surfaces of your new machines. Here are some good questions that you should have answered as a team long before the competition begins.

1. What operating systems are running? 
2. What services are running on these boxes? 
3. Are there any CVEs for these services? 
4. How do you change the default credentials for these services? 
5. What ports are required to stay open?

### If you can't build the environment, there is no way you can defend it!

Once you are told what the environment that you need to defend is going to look like, it is vital to replicate this environment as fast and as accurately as possible. The team should get practice with the services at hand and know how they operate, how they are configured, and how to make changes to them on the fly.

### Stop Chasing Ghosts!

Many people will get caught up with the idea that a red team could be in their systems and will panic at everything they see that they do not recognize. Often the unknown files, processes, or user accounts are standard Linux or Windows features. Chasing these leads that turn out to be nothing malicious will only eat up time and will allow the red team to gain an advantage. **It is vital to understand the machine you are defending!** If you do not know what the baseline normal is for a machine, you cannot possibly identify an anomaly. This is a major reason for replicating the target environment before the competition. It would be wise to get a list of the common files, processes, and user accounts for the operating systems that you will be defending to minimize your time chasing ghosts.

## Initial Cleaning

---

As soon as you gain access to your new machines during the competition, every single person needs to have a solid plan of action. Often teams will have a plan for the first 15 minutes, then it falls apart when people get stuck or notice suspected red team activity. This is the responsibility of the team leader to ensure everyone is working together and as a single unit. **Your team will either succeed together or fail together.** Here are some common things to address immediately after gaining access to your systems.

### Linux

**Commands listed are not all-encompassing and are for a baseline only!**

1. Change **all** user passwords. *Yes, especially the credentials given to you!*

    `# passwd username`

2. Audit /etc/shadow for users with passwords set, or no password at all.

    `cat /etc/shadow`

3. Remove all SSH keys present on the box.

    `# find / -name authorized_keys 2> /dev/null`

    `# find / -name id_rsa 2> /dev/null`
4. Audit sudo access given to users.

    `# cat /etc/sudoers`

    `# cat /etc/sudoers.d/*`

    `# getent group sudo | cut -d: -f4` (The *sudo* group is Debian, *wheel* is for RHEL)
5. Audit /etc/passwd to check for account shells and UIDs.

    `$ cat /etc/passwd | grep :0:`

    `$ cat /etc/passwd | grep -v /bin/false | grep -v /sbin/nologin`
6. Verify that there are not any non-standard cron jobs on the system.

    `# cat /etc/cron.d/*`

    `# for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l; done`
7. Remove packages that could be used for malicious purposes if not needed.

    `# apt remove socat nc ncat nmap netcat` (*apt* is for Debian, *yum* is for RHEL). Other packages must be manually inspected in order to prevent taking down critical services.
8. Stop services that are not critical to the system or competition needs.

    `# systemctl --type=service --state=active`

    `# systemctl stop servicename`
8. Identify SUID and SGID files. Cross-reference with https://gtfobins.github.io/ to narrow down malicous instances of SUID and SGID files.

    `# find / -perm -4000 -print 2>/dev/null` for SUID

    `# find / -perm -2000 -print 2>/dev/null` for SGID

10. Identify world-writable files and directories.

    `# find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \;` for directories

    `# find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null` for files

11. Check who is currently logged into the machine.

    `$ who`

#### Additional Resources

- [Linux Privilege Escalation Guide](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [Linux Persistence Guide](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md)

#### Useful Tools

- [LinEnum](https://github.com/rebootuser/LinEnum)
- [pspy](https://github.com/DominicBreuker/pspy)

### Windows

1. Change **all** user passwords. *Yes, especially the credentials given to you!*

    `> net user <username> <password>` NOTE: If domain user, append `/domain`

2. Audit important groups.

    `> net localgroup Administrators`

    `> net localgroup "Remote Desktop Users"`

    `> net localgroup "Remote Management Users"`

3. Disable WinRM if not needed.

    `PS> Disable-PSRemoting -Force`

4. Check Windows Defender registry keys

    `> regedit.exe`  HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender

5. Check for tasks set to run through the registry.

    - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
    - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices
    - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce

6. Check system and user startup folder.

    - User: C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
    - System: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\

7. Audit scheduled tasks.

    `> schtasks`

8. Check PowerShell Execution policy.

    `PS> Get-ExecutionPolicy`

    `PS> Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine`

9. Check Windows Defender status.

    `PS> Get-MPComputerStatus`

10. Audit SMB shares.

    `> net view \\127.0.0.1`

11. Disable Guest account.

    `> net user guest /active no`

#### Additional Resources

- [Windows Privilege Escalation Guide](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [Windows Persistence Guide](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)

#### Useful Tools

- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)

## Monitoring Activity

---

### Linux

1. Audit listening ports and established connections

    `# lsof -i -P -n`

2. Audit running processes

    `# ps aux`

3. Monitor logs in `/var/log/`

### Windows

1.  Audit listening ports

    `> netstat –na`

2. List the SMB sessions this machine has opened with
other systems

    `> net use`

3. List the open SMB sessions with this machine

   `> net session`

4. Audit running processes

    `> tasklist

## Windows Endpoint Checklist
Priority|Task|Method|Procedure
--|--|--|--|
High|Enable host-based firewalls|GUI|wf.msc > RClick Windows Advanced... > Properties > ON
High|Reset default passwords for AD user accounts|CLI/Script|`Set-ADAccountPassword`/[Script Reset password for all specified users](https://gallery.technet.microsoft.com/scriptcenter/Reset-password-for-all-412fbc72)
High|Reset local admin passwords|CLI|`net user <user> <pass>`
High|Install important patches|GUI|Windows Update
High|Deploy vendor endpoint protection|GUI|Windows Defender, AppLocker, etc.
Medium|Disable SMBv1|GUI|[Detect Enable and Disable SMB versions in windows](https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and)
Medium|Begin regular monitoring with TCPView, Process Explorer, Regmon, or scheduled tasks|GUI|Sysinternals
Medium|Disable Unnecessary Services|CLI/GUI|start with `netstat -anob`/resmon.exe
Medium|Manage host-based firewalls via policy|GUI|[Managing Windows Firewall with GPOs](https://itconnect.uw.edu/wares/msinf/ous/guide/firewallgpo/)
Low|Deploy sysmon|GUI|[Sysinternals Sysmon suspicious activity guide – Windows Security](https://blogs.technet.microsoft.com/motiba/2017/12/07/sysinternals-sysmon-suspicious-activity-guide/)
Low|Deploy centralized Windows logging|GUI|WEFFLES
Low|Custom audit configurations|GPO|Google it
Low|Configure LAPS for local admin passwords|GUI|[Microsoft LAPS](https://technet.microsoft.com/en-us/mt227395.aspx)

## Considerations
- Service/software inventory: which ports are used? is software up to date? is it securely configured?
- Network and local user inventory: are network accounts being used across multiple assets? 
- System inventory: are new systems appearing? are current systems reachable?

## Powershell/Windows Shell

### List Firewall Rules
#### Get all rules beginning with a string
`Get-NetFirewallRule -DisplayGroup Remote*` 

#### Get all inbound rules beginning with a string
`Get-NetFirewallRule -Action Allow -Enabled False -Direction Inbound -DisplayGroup Network* | select DisplayName, DisplayGroup`

### User Account Administration
#### Change AD user account password:
`Set-ADAccountPassword -Identity <sAMAccountName> -Reset -NewPassword <password>`

#### Change local user account password:
`net user <username> <newpass>`

### Active Directory
#### Create GPO report:

```powershell
Import-Module ActiveDirectory
Import-Module GroupPolicy

# identify the DC
$dc = Get-ADDomainController -Discover -Service PrimaryDC

# use this to generate HTML report for single GPO
Get-GPOReport -Name "A Group Policy Object" -Domain awesome.lab -Server $dc -ReportType HTML -Path C:\Users\Person\Desktop\GPOreport.html

# use this to generate HTML report for all GPOs in the domain
Get-GPOReport -All -Domain awesome.lab -Server $dc -ReportType HTML -Path C:\Users\Person\Desktop\AllGPOreport.html
```

### Event Logs
### Display local event logs 
`eventquery.vbs | more`
`eventquery.vbs /L Security | more`

### Search for a specific event ID
`wevtutil qe security /q:”*[System[(EventID=1102)]]” /c:5 /f:text /rd:true`

>/q: Specifies the query. The only thing you really need to change in here is the EventID, just replace it for the one you want. You can use truth operators in here as well as query specific alert levels.
>/c: specifies the number of events to display. (If you place nothing here, it will find all matching events)
>/f: Specifies the output type, by default it uses XML which can be difficult to read.
>/rd: This takes True or False. Set this to true in order to see the newest logs first.

### Services, Processes, and Ports
#### List running processes and output to file
tasklist > c:\processes.txt

#### wmic query examples from stack overflow
```bash
# Name and account for all services:
wmic service get name,startname

# started services only:
wmic service where started=true get  name, startname

# services with specific pattern in name:
wmic service where 'name like "%sql%"' get  name, startname

# nicely formatted as html table (and then opened in your browser):
(wmic service where 'name like "%sql%"' get  name, startname /format:htable >out.html) && out.html

# Full syntax here: https://msdn.microsoft.com/en-us/library/aa394531%28v=vs.85%29.aspx
```


#### List listening ports/connections, PIDs, files responsible
`netstat -anob`

#### Resource monitor
**resmon.exe** - the above plus process names and firewall rule status for the service/application

### File Integrity
Computes the cryptographic hash of a given file. Algorithms are: MD2 MD4 MD5 SHA1 SHA256 SHA384 SHA512.
`certutil -hashfile C:\path\to\file SHA256`

## Nix Handy Stuff
`netstat -tunapl` - listening ports and processes
`ps auxf` - process tree view
`cat /etc/passwd` - list users
