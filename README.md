# ODIN - A DFIR ENDGAME

![ODIN](https://github.com/Worldsleaks/DFIR-Powershell/assets/99112106/4b630b92-febd-4cfa-ba6f-19ffb160e6db)

## Extracted Artefacts
Odin collects information from multiple sources and structures the output in the current directory in a folder named 'DFIR-_hostname_-_year_-_month_-_date_'. This folder is zipped at the end, so that folder can be remotely collected. This script can also be used within Defender For Endpoint in a Live Response session. The DFIR script collects the following information when running as normal user:
- Computer information
- Local IP Info
- Active network connections
- Firewall rules
- DNS cache
- Running Processes
- Running services
- Process Command line
- Network shares
- Active SMB Shares
- DNS Cache
- Recently installed software
- Installed Software
- Running Services
- Scheduled Tasks
- Local users
- Administrator users
- RDP Sessions

For the best experience run the script as admin, then the following items will also be collected:
- Windows Security Events
- Powershell History of all users
