<#
.SYNOPSIS
An Red|Purple|Blue team lab orchestration tool.

.DESCRIPTION
Tripwire is designed to suppliment local detection labs built in VMware Workstation to provide the user with additional methods to control the lab
and provides an additional interface to monitor alerts.
    
.NOTES
File Name: tripwire.ps1
#>

# *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*

# GLOBAL VARIABLES
$json_file = "<path to .json file>"
$range_path = "<path to virtual machine directory"
$alerts_index = "<elk alerts index>"
$alerts_uri = "<kibana>:<port>/$($alerts_index)/_search"
$elk_api_key = "ApiKey <api key>"
$line = ("*-" * ((($Host.UI.RawUI.WindowSize.Width)/2)-1)) + "*"

# If a vm doesn't have VMware tools available 
#$noVMTools = ("pfSense")

# REQUIREMENTS CHECKS

# VMware Workstation installation.
if (-Not (Test-Path -Path "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")) {
        Write-Host "`nVMware Workstation required!`n" -ForegroundColor Cyan
    }

# environment.json file.
if (-Not (Test-Path -Path $json_file)) {
        Write-Host "`ntripwire_environment.json required`n" -ForegroundColor Cyan
}

if ($PSVersionTable.PSVersion.Major -eq 7) {
    $psversion = 7
}

# *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*

# ---VMWare Functions---

function vmcommand {
    
    Param
    (
        [Parameter(Position=0)]
        $command,
        [Parameter(Position=1)]
        $arguments
    )

    $psinfo = New-Object System.Diagnostics.ProcessStartInfo
    $psinfo.FileName = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
    $psinfo.Arguments = "-T ws $($command) $($arguments)"
    $psinfo.RedirectStandardError = $true
    $psinfo.RedirectStandardOutput = $true
    $psinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    $output = $p.StandardOutput.ReadToEnd()
    $output += $p.StandardError.ReadToEnd()
    return $output
}

function Lab
{
    Param
    (
        [Parameter(Position=0)]
            [string] $action,
        [Parameter(Position=1)]
            [string] $scenario
    )

    title

    # Start|Stop lab

    if (($action -like "*start*") -or ($action -like "*stop*")) {
        $range = Get-Content $json_file | ConvertFrom-Json
        foreach ($item in $range.lab) {
    
            foreach ($vm in $item.VirtualMachines.vmx){
            
                if ($action -like "*start*"){
                    Write-Host "[*] " -ForegroundColor Yellow -NoNewline; Write-Host "Starting $vm"
                    $output = vmcommand("start", $vm)
                    if ($vm -like "*attacker*") {
                        enableSharedFolders
                    }
                }
                if ($action -like "*stop*"){
                    Write-Host "[*] " -ForegroundColor Yellow -NoNewline; Write-Host "Stopping $vm"
                    $output = vmcommand("stop", $vm)
                }
            }

        Start-Sleep 10
        Write-Host ""
        Write-Host "[+] " -ForegroundColor Cyan -NoNewline; Write-Host "Done`n"
        }
    }

    # Resets the lab
    if ($action -like "*reset*"){
        $range = Get-Content $json_file | ConvertFrom-Json
        $reset = $range.scenarios | Where-Object -Property name -eq "reset"
        foreach ($snapshot in $reset.snapshots) { 
            $s = "$($snapshot.vmx) $($snapshot.snapshot)"
            $output = vmcommand("revertToSnapshot", $s)
            Write-Host "Loaded: " -NoNewline; Write-Host $snapshot.snapshot -ForegroundColor Cyan
        }
        Write-Host "`n[+] " -ForegroundColor Cyan -NoNewline; Write-Host "Reset Complete`n"
    }

    # Loads a specific scenario from Range.json.
    if ($action -like "*load*") {
        $range = Get-Content $json_file | ConvertFrom-Json
        $load = $range.scenarios | Where-Object -Property name -eq $scenario
        foreach ($snapshot in $load.snapshots) { 
            $s = "$($snapshot.vmx) $($snapshot.snapshot)"
            $output = vmcommand("revertToSnapshot", $s)
            Write-Host "Loaded: " -NoNewline; Write-Host $snapshot.snapshot -ForegroundColor Cyan
        }
        Write-Host "`n[+] " -ForegroundColor Cyan -NoNewLine; Write-Host $scenario -NoNewLine; Write-Host " loaded`n"
    }

    # Launch lab - Red Ranger will start monitoring
    if ($action -like "*launch*"){
        if ($psversion) {
            Write-Host `u{1F978} -NoNewline; Write-Host " Red Ranger is watching...`n"
        }else {Write-Host "<O.O>" -ForegroundColor Red -NoNewline; Write-Host " Red Ranger is watching...`n"}
        #

        do {$tripped = Launch} until ([System.Console]::KeyAvailable)
        
        Write-Host "[+] Total alerts fired: $($tripped)`n"
    }
}

function List-Running($title) {
    $output = vmcommand("list")
    if (-Not ($title)){
        $output
    }
    if ($output -like "*Total running VMs: 0*") {
        $stopped = Write-Host "[*]" -ForegroundColor Red -NoNewLine
        return "$stopped Lab offline`n"
    } else {
        $started = Write-Host "[*]" -ForegroundColor Green -NoNewLine
        return "$started Lab online`n"
    }
}

function ListSnapshots() {
    Param(
        [string]$vmx
    )

    if(-not($vmx)) { 
        Write-Host "`nTry: " -ForegroundColor Cyan -NoNewline; Write-Host "ListSnapshots <file>.vmx`n"
        $list = Get-ChildItem -path $range_path -filter *.vmx -file -ErrorAction silentlycontinue -recurse | Select-Object -Property Name 
        foreach ($l in $list.name) {
            Write-Host $l}
        Write-Host ""
        break
    }
    $vm_folder = [io.path]::GetFileNameWithoutExtension($vmx)
    $vmx = $vm_folder + "\" + $vmx

    $output = vmcommand("listSnapshots", "$($range_path)\$($vmx)")
    return $output
}

function network() {
    title
    $command = "getGuestIPAddress"
    $range = Get-Content $json_file | ConvertFrom-Json
    foreach ($item in $range.lab) { 
        foreach ($i in $item.VirtualMachines) {
            if (-not ($i.name -in $noVMTools)) {
                $output = vmcommand($command, $i.vmx)
                Write-Host "[+] $($i.name): $($output)"
            }
        }
    }
    $line
}

# Quick fix to enable Shared Folders. 
#function enableSharedFolders() {
#    $command = "enableSharedFolders"
#    $output = vmcommand($command, "<path to virtual machine>")
#}

function Get-VMX() {
    title
    Get-ChildItem -path $range_path -filter *.vmx -file -ErrorAction silentlycontinue -recurse | Select-Object -Property Name
}

# *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*
# ELK API INTEGRATION

if ($psversion) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
} else {
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

$alerts = [System.Collections.ArrayList]::new()

function Launch() {
    $headers = @{
        Authorization=$elk_api_key
    }

    if ($psversion) {
        $hits = Invoke-RestMethod -Method GET -Uri $alerts_uri -Headers $headers -SkipCertificateCheck
    } else { $hits = Invoke-RestMethod -Method GET -Uri $alerts_uri -Headers $headers }

    foreach ($hit in $hits.hits.hits) {
        if ($hit._source.'kibana.alert.workflow_status' -eq 'open') {
            if ($alerts -notcontains $hit._source.'kibana.alert.rule.execution.uuid') {
                [void]$alerts.Add($hit._source.'kibana.alert.rule.execution.uuid')

            # Alert severities
                if ($hit._source.'kibana.alert.severity' -like "*low*"){
                    if ($psversion) {Write-Host `u{1F6A8} -NoNewline;} else {
                    Write-Host "[!] Severity: " -NoNewLine}
                    Write-Host " " -NoNewline; Write-Host $hit._source.'kibana.alert.severity'.ToUpper() -ForegroundColor Green
                }
                if ($hit._source.'kibana.alert.severity' -like "*medium*"){
                    if ($psversion) {Write-Host `u{1F6A8} -NoNewline;} else {
                    Write-Host "[!] Severity: " -NoNewLine}
                    Write-Host " " -NoNewline; Write-Host $hit._source.'kibana.alert.severity'.ToUpper() -ForegroundColor Yellow
                }
                if ($hit._source.'kibana.alert.severity' -like "*high*"){
                    if ($psversion) {Write-Host `u{1F6A8} -NoNewline;} else {
                    Write-Host "[!] Severity: " -NoNewLine}
                    Write-Host " " -NoNewline; Write-Host $hit._source.'kibana.alert.severity'.ToUpper() -ForegroundColor Red
                }
                if ($hit._source.'kibana.alert.severity' -like "*critical*"){
                    if ($psversion) {Write-Host `u{1F6A8} -NoNewline;} else {
                    Write-Host "[!] Severity: " -NoNewLine}
                    Write-Host " " -NoNewline; Write-Host $hit._source.'kibana.alert.severity'.ToUpper() -ForegroundColor DarkRed
                }
                

                $alert_name = ($hit._source.'kibana.alert.rule.name').ToString()
                $l = ("-" * (($alert_name.Length)+6))
                Write-Host $l
                Write-Host "Name: " -NoNewLine; Write-Host $hit._source.'kibana.alert.rule.name'
                Write-Host "   * Timestamp: " -NoNewLine; Write-Host ([DateTime]$hit._source.'@timestamp').ToLocalTime()
                Write-Host "   * Hostname: " -NoNewLine; Write-Host $hit._source.'agent'.hostname
                Write-Host "   * ID: " -NoNewLine; Write-Host $hit._source.'kibana.alert.rule.execution.uuid'
                
            # Example log type specifics  
                # Field names are specific to the ELK; adjust as necessary.
                
                <#
                ### Sysmon Process Name
                if ($hit._source.process.name){
                    Write-Host "   * Process: " -NoNewline; Write-Host $hit._source.process.name -NoNewline; Write-Host $hit._source.command_line
                }

                ### Windows Defender Threat Name
                if ($hit._source.winlog.event_data.'Threat Name'){

                    # Adds the suspect file name
                    if ((($hit._source.winlog.event_data.Path).split(';')[0]).split('file:_')[1]){
                        $defender = $hit._source.winlog.event_data.Path
                        $defender2 = (($defender).split(';')[0]).split('file:_')[1]
                        Write-Host "   * File:"$defender2
                    }

                    Write-Host "   * Threat Name:"$hit._source.winlog.event_data.'Threat Name'
                }
                #>
                
                Write-Host ""
            }
        }
    }
    Start-Sleep 15
    return $alerts.Count
}

# *-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*

# Menu-Fluff
function Tripwire() {
    title
    Write-Host "[+] Tutorial                              -*- For new users"
    Write-Host "[+] Lab (start|stop|reset|launch)         -*- Lab <command> will start, stop, reset, or launch the environment"
    Write-Host "[+] Network                               -*- Lists lab network information`n"
    Write-Host $line
}

function title() {
    Clear-Host
    Write-Host @"

           |*-*-*-*-*-*-*|
  _____    |             |         
 |_   _| _(_)_ ____ __ _(_)_ _ ___ 
   | || '_| | '_ \ V  V / | '_/ -_)
   |_||_| |_| .__/\_/\_/|_|_| \___|
            |_|                    

"@ -ForegroundColor DarkRed
    List-Running('true')
    $line
    Write-Host ""
}

# ---Navigation functions---

function Tutorial() {
    title
    
    Write-Host "Tripwire" -ForegroundColor DarkRed -NoNewLine; Write-Host " is a bring-your-own-virtual-machine orchestration script designed to provide [" -NoNewLine; Write-Host "Red" -ForegroundColor Red -NoNewLine; Write-Host "|"-NoNewLine; Write-Host "Purple" -ForegroundColor DarkMagenta -NoNewLine;
    Write-Host "|" -NoNewLine; Write-Host "Blue" -ForegroundColor blue -NoNewLine; Write-Host "] teamers"; 
    Write-Host "with a lab environment that is being " -NoNewline; Write-Host "monitored" -ForegroundColor Cyan -NoNewline; Write-Host " for malicious activity.`n"

    Write-Host "Command usage:"
    Write-Host "lab start    - Starts virtual machines defined in .json file"
    Write-Host "lab launch   - Red Ranger will start monitoring security alerts and return tripped detections" 
    Write-Host "lab stop     - Shuts down all running virtual machines defined in .json file"
    Write-Host "lab reset    - Reverts virtual machines to the target state defined in the .json file`n"

    Write-Host "Additional commands:"
    Write-Host "network      - Prints associated vm ip addresses"
    Write-Host "list-running - Lists running virtual machines`n"
    
    Write-Host "`nTo every " -NoNewLine; Write-Host "Action" -ForegroundColor Yellow -NoNewline; Write-Host " there is always an equal " -NoNewLine; Write-Host "Reaction" -ForegroundColor Yellow -NoNewLine; Write-Host ". -Sir Isaac Newton"

    Write-Host "`n[?] Wiki: https://github.com/gregohmyeggo/Tripwire/blob/main/wiki.md`n" -ForegroundColor DarkGray
    $line
}
