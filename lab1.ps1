<#
Lab1.ps1
Output fornesic information on a local or remote windows machine
#>

Param(
    [string]$ComputerName,
    [switch]$Remote,

    [switch]$CSV,
    [string]$From,
    [string]$To,
    [switch]$Email

)


if ($Remote){
    Invoke-Command -ComputerName $ComputerName -FilePath "C:\System\lab1.ps1" -ArgumentList $CSV
    exit
}

else {

Write-Host "Usage: .\lab1.ps1 [-Remote -ComputerName <Name>] [-CSV]" 
Write-Host "" 
Write-Host "-Remote with a computer name will run the script remotely"
Write-Host " " 
Write-Host "-CSV exports to a csv file called output.csv"
Write-Host "Use -Email, -To, and -From to send the csv output via email"

$delimit = "----------------------------------------------------------"

$csv_obj = New-Object PSObject


Function time_info {
    $date_output = New-Object PSObject

    $date = Get-Date
    $timezone = Get-TimeZone
    $PC_uptime = (get-date) - (gcim Win32_OperatingSystem).LastBootUpTime

    $date_output | Add-Member Current_Date_Time $date 
    $date_output | Add-Member TimeZone $timezone
    $date_output | Add-Member PC_Uptime_hours $PC_uptime

    $csv_obj | Add-Member -MemberType NoteProperty -Name Date -Value $date_output
    Write-Host $delimit
    Write-Host "SYSTEM DATE AND TIME INFORMATION:  "
    Write-Host ($date_output | Format-List | Out-String)
} 



Function os_info {
    $OS_output = New-Object PSObject

    $os_name = gwmi win32_operatingsystem | % caption
    $major_minor_ver = [System.Environment]::OSVersion.Version  #Major, Minor, Build and revision

    $OS_output | Add-Member TypicalName $os_name
    $OS_output | Add-Member Major_Minor_Build_Revision $major_minor_ver

    $csv_obj | Add-Member -MemberType NoteProperty -Name OS -Value $OS_output

    Write-Host $delimit
    Write-Host "OS INFORMATION: " 
    Write-host ($OS_output | Format-list |  Out-String)
}




Function hardware_info {
    $HardwareObj =  New-Object PSObject

    $cpu_name = gwmi win32_processor | % name
    $ram =  gwmi win32_physicalmemoryarray | % maxcapacity
    $ram_gb = $ram/1MB
    $hdd = gwmi win32_diskdrive | % size 
    $hdd_gb = $hdd/1GB

 
    $drives = gdr -PSProvider FileSystem | % Name
    $logical_disk = gwmi win32_logicalDisk | % VolumeName

    $HardwareObj | Add-Member CPU_Brand_Type $cpu_name
    $HardwareObj | Add-Member RAM_AmountGB $ram_gb
    $HardwareObj | Add-Member HDD_AmountGB $hdd_gb
    $HardwareObj | Add-Member Drives $drives
    $Hardwareobj | Add-Member MountPoints $logical_disk

    $csv_obj | Add-Member -MemberType NoteProperty -Name Hardware -Value $HardwareObj

    Write-Host $delimit


    Write-Host "SYSTEM HARDWARE INFORMATION:"
    Write-Host ($HardwareObj | Format-List | Out-String)
}



Function dc_info {
    $domain_controllers = Get-ADDomainController -Filter * | Select Name, ipv4Address, OperatingSystem, site | Sort-Object -Property Name
    Write-Host $delimit
    Write-Host "DC INFO:"
    Write-Host $domain_controllers
    $csv_obj | Add-Member -MemberType NoteProperty -Name DC -Value $domain_controllers
}




Function hostname_info {
    $hostname = gwmi win32_computersystem | Format-Table Name, Domain
    $csv_hostname = gwmi win32_computersystem | select Name, Domain
    $csv_obj | Add-Member -MemberType NoteProperty -Name Hostname -Value $csv_hostname

    Write-Host $delimit
    Write-Host "HOSTNAME AND DOMAIN INFORMATION:"
    Write-Host ($hostname | Out-String)
}




Function user_info {
    $user_info = gwmi win32_useraccount | Format-Table Name, SID 
    $user_info_csv = gwmi win32_useraccount | select Name, SID
    $csv_obj | Add-Member -MemberType NoteProperty -Name SID -Value $user_info_csv

    Write-Host $delimit
    Write-Host "LOCAL USER INFORMATION: " 

    Write-Host ($user_info | format-list | Out-String)
}




Function startup_info {
    $services = get-service | where {$_.starttype -eq 'Automatic'} | Format-Table Name, DisplayName 
    $services_csv = get-service | where {$_.starttype -eq 'Automatic'} | select Name, DisplayName
    $programs = Get-Ciminstance win32_startupcommand | Format-Table Name,command, user, Location
    $programs_csv =  Get-Ciminstance win32_startupcommand | select Name, command, user, Location

    $csv_obj | Add-Member -MemberType NoteProperty -Name services -Value $services_csv
    $csv_obj | Add-Member -MemberType NoteProperty -Name programs -Value $programs_csv

    Write-Host $delimit
    Write-Host "BOOT SERVICES: "
    Write-Host ($services | Format-List | Out-String )
    Write-Host "BOOT PROGRAMS: " 
    Write-Host ($programs | Format-List| Out-String) 
}




Function scheduled_info {
    $Tasks = Get-Scheduledtask | where {$_.State -eq 'Ready'} | Format-Table TaskName

    Write-Host "SCHEDULED TASKS: "
    Write-Host ($Tasks | Format-List | Out-String)
    $csv_tasks = Get-Scheduledtask | where {$_.State -eq 'Ready'} | select TaskName
    $csv_obj | Add-Member -MemberType NoteProperty -Name tasks -Value $csv_tasks
}



Function network_info {
    $arptable = arp -a
    $csv_obj | Add-Member -MemberType NoteProperty -Name arptable -Value $arptable

    $macaddress = getmac 
    $csv_obj | Add-Member -MemberType NoteProperty -Name macaddress -Value $macaddress

    $route = Get-NetRoute
    $csv_obj | Add-Member -MemberType NoteProperty -Name route -Value $route

    $IP = Get-NetIPAddress | Format-Table IPAddress, InterfaceAlias
    $IP_csv = Get-NetIPAddress | select IPAddress, InterfaceAlias
    $csv_obj | Add-Member -MemberType NoteProperty -Name ip -Value $IP_csv

    $dhcp = Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.DHCPEnabled -eq $true -and $_.DHCPServer -ne $null} | select DHCPServer
    $csv_obj | Add-Member -MemberType NoteProperty -Name dhcp -Value $dhcp

    $dns_servers = Get-DnsClientServerAddress | Select-Object -ExpandProperty Serveraddresses
    $dns_servers_csv = Get-DnsClientServerAddress
    $csv_obj | Add-Member -MemberType NoteProperty -Name dnsservers -Value $dns_servers_csv

    $gateway_IPv4 = Get-NetIPConfiguration | % IPv4defaultgateway | Format-List nexthop
    $gateway_IPv4_csv = Get-NetIPConfiguration | % IPv4defaultgateway | select nexthop
    $csv_obj | Add-Member -MemberType NoteProperty -Name gatewayipv4 -Value $gateway_IPv4_csv

    $gateway_IPv6 = Get-NetIPConfiguration | % IPv46defaultgateway | Format-List nexthop
    $csv_obj | Add-Member -MemberType NoteProperty -Name gatewayipv6 -Value $gateway_IPv6

    $tcp_connections = Get-NetTCPConnection -State Listen | Format-Table State, localport, ElemenetName, LocalAddress, RemoteAddress
    $tcp_connections_csv = Get-NetTCPConnection -State Listen | select State, localport, ElemenetName, LocalAddress, RemoteAddress
    $csv_obj | Add-Member -MemberType NoteProperty -Name listeningports -Value $tcp_connections_csv

    $all_tcp_connections = Get-NetTCPConnection | where {$_.State -ne "Listen"} | Format-Table creationtime,LocalPort,LocalAddress,remoteaddress,owningprocess, state
    $csv_obj | Add-Member -MemberType NoteProperty -Name tcpconnections -Value $all_tcp_connections

    $dns_cache = Get-DnsClientCache | Format-Table
    $dns_cache_csv = Get-DnsClientCache
    $csv_obj | Add-Member -MemberType NoteProperty -Name dnscache -Value $dns_cache_csv

    $network_shares = get-smbshare
    $csv_obj | Add-Member -MemberType NoteProperty -Name nwshares -Value $network_shares

    $printers = Get-Printer
    $csv_obj | Add-Member -MemberType NoteProperty -Name printers -Value $printers

    $wifi = netsh.exe wlan show profiles 
    $csv_obj | Add-Member -MemberType NoteProperty -Name wifi -Value $wifi

    Write-Host $delimit
    Write-Host "---Network Info---"
    Write-Host "" 
    Write-Host "ARP table:" 
    Write-Host ($arptable | Format-List | Out-String)

    Write-Host "" 
    Write-Host "MAC Addrs:" 
    Write-host ($macaddress | Format-List | Out-String)

    Write-Host "Routing table:" 
    Write-Host ($route | Out-String)

    Write-Host "IP Addrs:"
    Write-Host ($IP | Format-List | Out-String)

    Write-Host ("DHCP Table:")
    Write-Host ($dhcp | Format-Table | Out-String)  

    Write-Host "DNS Server addresses:"
    Write-Host ($dns_servers | Format-Table | Out-String)

    Write-Host "IPv4 Gateway:"
    Write-Host ($gateway_IPv4 | Format-List | Out-String)

    Write-Host "IPv6 Gateway:"
    Write-Host ($gateway_IPv6 | Format-List | Out-String)

    Write-Host "Listening services:"
    Write-Host ($tcp_connections | Format-List | Out-String)

    Write-Host "Established connections:" 
    Write-Host ($all_tcp_connections | Out-String)

    Write-Host "DNS cache:" 
    Write-Host ($dns_cache | Out-String)

    Write-Host "Network Shares:" 
    Write-Host ($network_shares | Out-String)

    Write-Host "Printers:"
    Write-Host ($printers | Out-String)  

    Write-Host "Wifi Profiles:" 
    Write-Host ($wifi | Format-List | Out-String) 
}


Function program_info {
    $installed_programs = gwmi win32_product | Format-List

    Write-Host $delimit
    Write-Host "Installed Programs:"
    Write-Host ($installed_programs | Format-List | Out-String)

    $csv_obj | Add-Member -MemberType NoteProperty -Name prog -Value $installed_programs
}




Function process_info {
$processes = get-process | Format-Table processname,id,path,owner

$csv_obj | Add-Member -MemberType NoteProperty -Name processes -Value $processes

Write-Host $delimit
Write-Host "Processes:"
Write-Host ($processes | Out-String)

Write-Host "Process Tree :" 
Function Show-ProcessTree  {            
[CmdletBinding()]            
Param()            
    Begin {            
        # Identify top level processes            
        # They have either an identified processID that doesn't exist anymore            
        # Or they don't have a Parentprocess ID at all            
        $allprocess  = Get-WmiObject -Class Win32_process            
        $uniquetop  = ($allprocess).ParentProcessID | Sort-Object -Unique            
        $existingtop =  ($uniquetop | ForEach-Object -Process {$allprocess | Where ProcessId -EQ $_}).ProcessID            
        $nonexistent = (Compare-Object -ReferenceObject $uniquetop -DifferenceObject $existingtop).InPutObject            
        $topprocess = ($allprocess | ForEach-Object -Process {            
            if ($_.ProcessID -eq $_.ParentProcessID){            
                $_.ProcessID            
            }            
            if ($_.ParentProcessID -in $nonexistent) {            
                $_.ProcessID            
            }            
        })            
        # Sub functions            
        # Function that indents to a level i            
        function Indent {            
            Param([Int]$i)            
            $Global:Indent = $null            
            For ($x=1; $x -le $i; $x++)            
            {            
                $Global:Indent += [char]9            
            }            
        }            
        Function Get-ChildProcessesById {            
        Param($ID)            
            # use $allprocess variable instead of Get-WmiObject -Class Win32_process to speed up            
            $allprocess | Where { $_.ParentProcessID -eq $ID} | ForEach-Object {            
                Indent $i            
                '{0}{1} {2}' -f $Indent,$_.ProcessID,($_.Name -split "\.")[0]            
                $i++            
                # Recurse            
                Get-ChildProcessesById -ID $_.ProcessID            
                $i--            
            }            
        } # end of function            
    }            
    Process {            
        $topprocess | ForEach-Object {            
            '{0} {1}' -f $_,(Get-Process -Id $_).ProcessName            
            # Avoid processID 0 because parentProcessId = processID            
            if ($_ -ne 0 )            
            {            
                $i = 1            
                Get-ChildProcessesById -ID $_            
            }            
        }            
    }             
    End {}            
}

Show-ProcessTree
}


Function driver_info {
    $drivers = Get-WmiObject Win32_PnPSignedDriver| Format-Table DeviceName, DriverVersion,InstallDate,Location
    Write-Host $delimit
    Write-Host "Drivers:"
    Write-Host($drivers | Format-Table | Out-String)

    $csv_obj | Add-Member -MemberType NoteProperty -Name driver -Value $drivers
}




Function file_info {
    Write-Host $delimit
    Write-Host "Documents and Downloads:"
    foreach ($user_dir in Get-ChildItem -Path "C:\Users\") {
        $downloads = "C:\Users\" + $user_dir.ToString() + "\Downloads"
        $documents = "C:\Users\" + $user_dir.ToString() + "\Documents"
        $all_documents = Get-ChildItem -Path $documents 2>$null
        $all_downloads = Get-ChildItem -Path $downloads 2>$null
        Write-Host $user_dir
        Write-Host ($all_documents | Format-Table | Out-String)
        Write-Host ($all_downloads | Format-Table | Out-String)
        $csv_obj | Add-Member -MemberType NoteProperty -Name $user_dir -Value $all_documents, $all_downloads
    }
}

time_info
os_info
hardware_info
dc_info
hostname_info
user_info
startup_info
scheduled_info
network_info
program_info
process_info
driver_info
file_info
if ($CSV){
    $csv_obj | Export-Csv output.csv
    if ($Email, $To, $From){
        Send-MailMessage -To $To -From $From -Subject "CSV Results" -Attachments "output.csv"
    }
}
}
