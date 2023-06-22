#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
 This script extracts information about RC4 Kerberos tickets.

.DESCRIPTION
 Prerequisites: 
 1. The Active Directory PowerShell module should be available.
 2. Audit the creation of Kerberos tickets (TGT/ST). After enabling auditing on your domain controllers, you will start to get the following events:
    * 4768 (for TGT)
    * 4769 (for ST)
 3. Have RPC access or PowerShell remoting access to all your domain controllers.
 
 This script queries all your domain controllers for the usage of RC4 in Kerberos tickets.
 The script outputs the results to a CSV file.

.LINK
 https://github.com/gadla/RC4-Hunter
 

.PARAMETER OutputFile
 This is a required parameter. The script will not run without a provided value.
 The value of -OutputFile must be a string that represents a valid file path.
 You can specify an absolute path or a path relative to the current directory.
 For example, -OutputFile '.\Results.csv' will create an output file named Results.csv in the current directory.
 An absolute path like -OutputFile 'C:\temp\Results.csv' can be used to create an output file in a specific directory.

.PARAMETER NumberOfEvents
 The -NumberOfEvents parameter limits the number of events that the script will retrieve from the security logs on each domain controller.
 By default, the script retrieves all matching events (maximum integer value).
 If you want to retrieve a specific number of events, use this parameter to set that limit.

.PARAMETER EventTime 
 The -EventTime switch includes the event timestamp in the output.
 If this switch is specified, the timestamp is added as the last field in each row of the CSV output file.
 The timestamp is formatted as "dd/MM/yyyy:hh:mm".
 If -EventTime is not specified, the output does not include the event timestamp.

.PARAMETER HoursBack
 The -HoursBack parameter controls how far back in time to search for events.
 The value is specified in hours, and the default value is 24 hours.
 The script searches for events that occurred within the specified number of hours before the script is run.
 The value of -HoursBack must be an integer between 1 and 24, inclusive.

.PARAMETER UseRemoting
 The -UseRemoting switch enables PowerShell remoting to query the domain controllers for events.
 If this switch is specified and the domain controllers are accessible via remoting, the script will use remoting.
 If the switch is not specified or the domain controllers are not accessible via remoting, the script will fall back to RPC calls.

.EXAMPLE  
 .\RC4_Hunter.ps1 -OutputFile '.\Results.csv'
 The output file contains information from the last 24 hours.
 The output does not include the timestamp of each event.

.EXAMPLE
 .\RC4_Hunter.ps1 -OutputFile .\Results.csv -HoursBack 2
 The output file contains information from the last 2 hours.
 The output does not include the timestamp of each event.

.EXAMPLE
 .\RC4_Hunter.ps1 -OutputFile '.\Results.csv' -EventTime
 The output file contains information from the last 24 hours.
 The output also includes a timestamp for each event.

.EXAMPLE
 .\RC4_Hunter.ps1 -OutputFile '.\Results.csv' -UseRemoting
 The output file contains information from the last 24 hours.
 The script uses PowerShell remoting to query the domain controllers for events.
#>

param (
    [Parameter(Mandatory=$true,
               HelpMessage="The full path of the output file. The file must be a .csv file.")]
    [ValidateScript({
        $resolvedPath = Resolve-Path $_
        if(-Not ($resolvedPath.Path.Substring(0,$resolvedPath.Path.LastIndexOf('\')) | Test-Path)) {
            throw "The Path of $($_.Substring(0,$_.LastIndexOf('\'))) does not exist"
        }
        if(-Not $resolvedPath.Path.EndsWith('.csv')) {
            throw "Output file must be a .csv file"
        }
            return $true
        })]
    [string] $OutputFile,

    [Parameter(Mandatory=$false,
               HelpMessage="The maximum number of events to retrieve. If not specified, the default is the maximum integer value.")]
    [int] $NumberOfEvents = [int]::MaxValue,

    [Parameter(Mandatory=$false,
               HelpMessage="If specified, the timestamp of the event will be included in the output.")]
    [switch] $EventTime,

    [Parameter(Mandatory=$false,
               HelpMessage="The number of hours in the past to search for events. If not specified, the default is 24 hours.")]
    [ValidateRange(1,24)]
    [int] $HoursBack = 24,

    [Parameter(Mandatory=$false,
               HelpMessage="Use PowerShell remoting to query the domain controllers for events.")]
    [switch] $UseRemoting
)


# Get all domain controllers
$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
Write-Host -Object "Found $($dcs.Count) Domain Controllers" -BackgroundColor Black -ForegroundColor Yellow

# Prepare for event collection
$events = New-Object System.Collections.ArrayList
$HoursBackms = $HoursBack *3600 *1000 #Converting $HoursBack to Milliseconds
$queryProps = @{
    LogName = 'Security'
    FilterXPath = "Event[System[(EventID=4769 or EventID=4768) and TimeCreated[timediff(@SystemTime) <= $HoursBackms]] and (EventData[Data[@Name='TicketEncryptionType']='0x17'] or EventData[Data[@Name='TicketEncryptionType']='0x18'] or EventData[Data[@Name='TicketEncryptionType']='0x3'] or EventData[Data[@Name='TicketEncryptionType']='0x1'])]"
    MaxEvents = $NumberOfEvents
    ErrorAction = 'SilentlyContinue'
}

if ($UseRemoting) {
    # Check if all of the domain controllers are accessible using PowerShell remoting
    foreach ($dc in $dcs) {
        Write-Verbose "Trying to connect to Domain Controller $dc through PowerShell Remoting"
        Test-WSMan -ComputerName $dc -ErrorAction SilentlyContinue | Out-Null
        if(-not($?)) {
            $reachableDCs = $false
            Write-Host "Domain Controller $dc is not available through PowerShell Remoting" -ForegroundColor Red -BackgroundColor Black
            break
        }
        $reachableDCs = $true
    }

    if ($reachableDCs) {
        Write-Host "Querying all DCs through PS-Remoting"  -ForegroundColor Yellow -BackgroundColor Black
        $session = New-PSSession -ComputerName $dcs -ErrorAction SilentlyContinue
        if ($session) {
            $events = Invoke-Command -Session $session -ScriptBlock {
                Get-WinEvent @using:queryProps
            }
            Remove-PSSession -Session $session
            Write-Host "Total events collected from Domain Controllers: $($events.count)" -BackgroundColor Black -ForegroundColor Yellow
        }
        else {
            Write-Warning "Unable to establish a remote session with one or more domain controllers. Falling back to RPC calls."
            $UseRemoting = $false
        }
    }
    else {
        Write-Warning "One or more domain controllers are not reachable through PS-Remoting. Falling back to RPC calls."
        $UseRemoting = $false
    }
}

if (-not $UseRemoting) {
    # Query each domain controller for events using RPC calls
    $counter = 0
    foreach ($dc in $dcs) {
        Write-Host "Getting events from Domain Controller: $dc" -ForegroundColor Yellow -BackgroundColor Black
        try {
            $events.Add((Get-WinEvent @queryProps -ComputerName $dc)) | Out-Null
            Write-Host -Object "Total RC4 events $($Events[$counter].Count) collected from $dc" -BackgroundColor Black -ForegroundColor Yellow
            $counter++
        }
        catch {
            Write-Host "Failed to get events from Domain Controller: $dc.`n" -ForegroundColor Red -BackgroundColor Black
            Write-Verbose "Error: $($_.Exception.Message)"
        }
    }
}

# Write results to file
Write-Host "Writing results to $OutputFile" -ForegroundColor Yellow -BackgroundColor Black
if($EventTime) {
    $Headers = "UserName,ServiceName,EncryptionType,IP,EventTime"
} else {
    $Headers = "UserName,ServiceName,EncryptionType,IP"
}
New-Item -Path "$OutputFile.workfile.csv" -Force | Out-Null
Add-Content -Path "$OutputFile.workfile.csv" -Value $Headers

foreach ($Entry in $Events) {
    foreach ($Event in $Entry) {
        $Message = $Event.Message
        $Mes = $Message.Split("`r`n")
        $Mes = $Mes.Replace(":", "=")
        $Mes = $Mes | Select-String -Pattern ("Account Name=", "Service Name=", "Ticket Encryption Type=", "Client Address=") 
        $Data = $Mes | ConvertFrom-StringData
        $DataIP = ($Data.'Client Address' | Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches).Matches.Value
        if ($EventTime) {
            $DataString = ($Data.'Account Name', $Data.'Service Name', $Data.'Ticket Encryption Type', $DataIP, $event.TimeCreated.ToString("dd/MM/yyyy:hh:mm")) -join ","
        } else {
            $DataString = ($Data.'Account Name', $Data.'Service Name', $Data.'Ticket Encryption Type', $DataIP) -join ","
        }
        Add-Content -Path "$OutputFile.workfile.csv" -Value $DataString
    }
}

# Remove duplicates
Import-Csv -Path "$OutputFile.workfile.csv" | Select-Object -Property * -Unique | Export-Csv -Path $OutputFile -NoTypeInformation -Force
Remove-Item -Path "$OutputFile.workfile.csv" -Force
