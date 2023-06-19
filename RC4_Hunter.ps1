<#
.SYNOPSIS
 This script will extract information about RC4 kerberos tickets.

.DESCRIPTION
 Prerequisites: 
 1. you shoud audit the creation of kerberos tickets (tgt/st).
    After you have enabled on your domain controllers the auditing you will start to get the following events:
    * 4768 (for TGT)
    * 4769 (for ST)
 2. You should have RPC to all of your domain controllers.
 
 This script will query all of your domain controllers for the usage of RC4 in kerberos tickets.
 After quering your dc's the output of the script will be a csv file. 

.PARAMETER outputfile
 output file in the format of comma seperated value (csv)

.EXAMPLE
 .\RC4_Hunter.ps1 -outputFile '.\Results.csv'
#>
param (
       [string]
       [parameter(Mandatory = $true)]
       [ValidateScript({
        if(-Not ($_.Substring(0,$_.LastIndexOf('\')) | Test-Path)) {
            throw "The Path of $($_.Substring(0,$_.LastIndexOf('\'))) does not exist"
        }
        if(-Not $_.EndsWith('.csv')) {
            throw "Output file must be a .csv file"
        }
            return $true
        })]
       $OutputFile,

       [int]
       $NumberOfEvents = [int]::MaxValue,

       [switch]
       $EventTime
)
# Get all domain controllers
$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty name

# Prepare for event collection
$events = New-Object System.Collections.ArrayList
$queryProps = @{
    LogName = 'Security'
    FilterXPath = "Event[System[(EventID=4769 or EventID=4768)]] and Event[EventData[Data[@Name='TicketEncryptiontYPE']='0x17']] or Event[EventData[Data[@Name='TicketEncryptiontYPE']='0x18']] or Event[EventData[Data[@Name='TicketEncryptiontYPE']='0x3']] or Event[EventData[Data[@Name='TicketEncryptiontYPE']='0x1']]"
    MaxEvents = $NumberOfEvents
    ErrorAction = 'SilentlyContinue'
}

# Query each domain controller for events
$counter = 0
foreach ($dc in $dcs) {
    Write-Host "Getting events from Domain Controller:$dc" -ForegroundColor Yellow -BackgroundColor Black
    try {
        $events.Add( (Get-WinEvent @queryProps -ComputerName $dc) ) | out-null
        Write-Host -Object "Total RC4 events $($Events[$counter].count) collected from $dc"
        $counter++
    } catch {
        Write-Error "Failed to get events from Domain Controller: $dc. Error:$($_.Exception.Message)"
    }
}

# Write results to file
Write-Host "Writing results to $OutputFile" -ForegroundColor Yellow -BackgroundColor Black
$Headers = "UserName,ServiceName,EncryptionType,IP,EventTime"
#New-Item -Path $outputFile -Value $Headers -Force | Out-Null
New-Item -Path "$OutputFile.workfile.csv" -Value $Headers -Force | Out-Null
add-content -Path "$OutputFile.workfile.csv" -Value ""

foreach($Entry in $Events){
    foreach($Event in $Entry) {
        $Message = $Event.message
        $Mes = $Message.Split("`r`n")
        $Mes = $Mes.replace(":","=")
        $Mes = $Mes | Select-String -Pattern ("Account Name=","Service Name=","Ticket Encryption Type=","Client Address=") 
        $Data = $Mes | ConvertFrom-StringData
        $DataIP = ($Data.'Client Address' | Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}" -AllMatches).Matches.value
        if($EventTime) {
            $DataString = ($Data.'Account Name' + "," + $Data.'Service Name' + "," + $Data.'Ticket Encryption Type' + "," + $DataIP + "," + $event.TimeCreated.ToString("dd/MM/yyyy:hh:mm"))
        } else {
            $DataString = ($Data.'Account Name' + "," + $Data.'Service Name' + "," + $Data.'Ticket Encryption Type' + "," + $DataIP)
        }
        Add-Content -Path "$OutputFile.workfile.csv" -Value $DataString
    }
}

# Remove duplicates
Import-Csv -Path "$OutputFile.workfile.csv" | Select-Object -Property * -Unique | Export-Csv -Path $Outputfile -NoTypeInformation -Force
remove-item -Path "$OutputFile.workfile.csv" -Force