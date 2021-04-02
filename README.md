# AutomationAnywhere
AutomationAnywhere Powershell Module and Scripts

## What is it
This module allows you to interact with AutomationAnywhere APIs to simplify a few
operational tasks and monitoring. It was mainly tested against the Enterprise edition
but for most part it also works with the free community version.

## How to use it
I suggest you start by storing your credential as a Secret in some kind of Vault like
Azure Keyvault, Windows Credential Manager or CyberArk.
A great solution is provided by Microsoft in the SecretManagement module:
https://devblogs.microsoft.com/powershell/secretmanagement-preview-3/


``` powershell
$Credential=Get-Credential # Or use the credential manager suggested above
$ControlRoom='https://mycontrolroom.mydomain.xxx' # also works for the https://community2.cloud-2.automationanywhere.digital/ 
$Token=Get-AAToken -CR $ControlRoom -Credential $Credential
# List Audit Messages
Get-AAAuditMessages -CR $ControlRoom -Header $Token -Shortcut SinceYesterday 
# List Licenses Details
Get-AALicenseDetails -CR $ControlRoom -Header $Token
# Start the execution of an Automation
Start-AAAutomation -CR $ControlRoom -Header $Token -botID 123 -RunnerID 456
```

All functions work in the same way, following the approach described above should give you enough to get started.
