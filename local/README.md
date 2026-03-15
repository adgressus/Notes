# Note Client Code

## Structure

Platform specific front ends in their own directories call shared libraries in the 'shared' directory.

Currently, all client code frontend and backend is in rust, but that may change in the future as more modern

## Logging

`Log` crate style logs are used in all code. Each platform has a speific logging backend that directs logs into the central platform logging utility. 

MacOS: Apple Unified Logging
Windows: Windows Event Log

### Viewing MacOS logs

```bash
log stream --predicate 'subsystem == "com.weatjar.notes"' --level debug
```

### Viewning Windows logs

```powershell
# One time log registration for application
winlog register --name "Notes"

# Recent logs
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Notes'} -MaxEvents 50

# Follow/tail style (poll every 2 seconds)
while ($true) { Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Notes'} -MaxEvents 5 | Format-Table TimeCreated, Message -AutoSize; Start-Sleep 2 }
```

## Building

### MacOS Code signing

```bash
codesign --force --sign <identity> \
    --entitlements notes.entitlements \
    --options runtime \
    Notes.app
```