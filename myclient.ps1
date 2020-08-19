# This Function logs the input its given to the path its given.
Function Log {
    param(
        [Parameter(Mandatory=$true)][String]$msg,
        [Parameter(Mandatory=$true)][String]$logfname
    )
    $CurrentTime = Get-Date -Format "MM/dd/yyyy HH:mm"
    Add-Content -Path $logfname $CurrentTime' '$msg
}

# This Script Sends a file to a Server for a VirusTotal Scan. 
# The Script uses the file given by the user as an argument, and if none was given finds the most CPU consuming process and sends its executable.
# The Script returns whether the file is dangerous.

# Classifying whether the User entered a file path as an input.
If ($args.Length -eq 0) {
    Write-Host "let's check the process which consumes the most CPU."
    $BiggestProc = Get-Process | Sort-Object CPU -desc | Select-Object -first 1 Path
    $FilePath = $BiggestProc.Path
} Else {
    If ((Test-Path $args[0] -PathType Leaf) -eq $true){
        Write-Host "Let's scan the file you entered."
        $FilePath = $args[0]
    }
    Else {
        Write-Host "You entered an invalid file path. let's check the process which consumes the most CPU."
        $BiggestProc = Get-Process | Sort-Object CPU -desc | Select-Object -first 1 Path
        $FilePath = $BiggestProc.Path
    }
}

# Making a Directory for Client log if it does not already exists
$CurrentPath = Get-Location
$CurrentPath = $CurrentPath.Path
$ClientFolder = $CurrentPath + '\client files'
If ((Test-Path $ClientFolder) -eq $false){
    mkdir $ClientFolder
}

# Logging the file chose to scan
$lhost = HOSTNAME.EXE
$ClientIp = Test-Connection $lhost -count 1 | Select-Object address, IPV4Address
$ClientIp = $ClientIp.IPV4Address.IPAddressToString
$logpath = $ClientFolder + '\' + $ClientIp + ' log.txt'

# Making log file if it does not already exists
If ((Test-Path $ClientFolder) -eq $false){
    New-Item $logpath
}

$logmsg = 'File Chosen to Scan: ' + $FilePath
Log $logmsg $logpath

# Reading the File
$Content = [IO.File]::ReadAllBytes($FilePath)
#$ContentType = 'multipart/form-data'

# Sending a POST request to the server.
$Response = try { (Invoke-WebRequest -Body $Content -Method 'POST' -Uri 'http://10.0.0.27:8080/' -Headers @{'File-Name' = Split-Path -leaf $FilePath})
} Catch [System.Net.WebException] {
    Write-Host "An exception was caught: $($_.Exception.Message)"
    $_.Exception.Response
}
#Logging the Response from the server
$logmsg = 'Response Status Code: ' + $Response.StatusCode + " " + $Response.StatusDescription
Log $logmsg $logpath

$FileSent = Split-Path -Path $FilePath -leaf
# Notifying the User of the results
If ($Response.StatusCode -eq 200) {
    # Saving the Response for analytical purposes
    $Response.Content | Out-File -FilePath .\response.txt

    # Parsing the information from the request
    $json = $Response.Content | ConvertFrom-Json
    $PositiveScans = $json.data.attributes.last_analysis_stats.malicious
    $TotalScans = $json.data.attributes.last_analysis_stats.malicious + $json.data.attributes.last_analysis_stats.undetected
    $MeaningfulName = $json.data.attributes.meaningful_name

    # Notifying the Client of the danger level of the file 
    If ($PositiveScans -gt 0) {
        Write-Host 'Beware Malicious file! The file you sent, also known as:' $MeaningfulName 'was scanned' $TotalScans 'times, was considered malicous' $PositiveScans ' times.'
        $logmsg = 'MALICIOUS FILE: ' + $MeaningfulName
        Log $logmsg $logpath
    } Elseif (($PositiveScans -eq 0) -and ($TotalScans -ne 0) ) {
        Write-Host 'Chill, The file you sent, also known as:' $MeaningfulName 'was scanned' $TotalScans 'times, was not found malicous even once.'
        $logmsg = 'UNDETECTED FILE: ' + $FileSent
        Log $logmsg $logpath
    } Elseif (($PositiveScans -eq 0) -and ($TotalScans -eq 0)) {
        Write-Host 'The file you sent:' $FileSent 'was not scanned. it is probably due to it being an unsuuported format file to scan.'
        $logmsg = 'FAILURE TO SCAN: ' + $FileSent
        Log $logmsg $logpath
    }
# File Was not found on VT
} Elseif ($Response.StatusCode -eq 404) { 
    Write-Host 'The file you sent:' $FileSent 'was not scanned. VT is probably busy, please try again in a few moments'
    $logmsg = 'VIRUSTOTAL BUSY'
        Log $logmsg $logpath
} Elseif ($Response.StatusCode -eq 413){
    Write-Host 'The file you sent:' $FileSent 'was not scanned. The File was too large (has to be smaller than 32MB)'
    $logmsg = 'FILE TOO LARGE'
        Log $logmsg $logpath
}Else {
    Write-Host 'The Server Returned an Error:' $Response.StatusCode
}
