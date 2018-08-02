param($HPOCPassword, $POC, $ESXiHost)

# Create a banner because we want it to be pretty
function Banner {
	write-host "`n---------------------------------" -f yellow
	write-host "Nutani" -f green -nonewline; write-host "x " -f yellow -nonewline; write-host "VCSA Deployment Kit" -f green -nonewline;
	write-host "`n---------------------------------`n" -f yellow
}

function Setup-PrismElement($HPOC, $PEPassword, $HPOCPassword) {
	# Do a bunch of work around crap to work with invalid certs
	if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback +=
                    delegate
                    (
                        Object obj,
                        X509Certificate certificate,
                        X509Chain chain,
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
}
	[ServerCertificateValidationCallback]::Ignore()
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	$HPOCIP = "10.21." + $HPOC + ".29"

	# Set header info to login to PE
	$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('admin'+":"+"$PEPassword"))}

	# CD to Putty Directory
  cd "C:\Program Files (x86)\PuTTY\"

	# Set PE Password
	$HPOCIP = "10.21." + $HPOC + ".29"
  $Result = echo y | ./plink.exe nutanix@$HPOCIP -pw $PEPassword "~/prism/cli/ncli user reset-password user-name=admin password=$HPOCPassword"

  # Accept EULA
	$EULAJson = '{"username": "SE with stage_calmhow.sh","companyName": "Nutanix","jobTitle": "SE"}'
	$EULAAddress = "https://" + $HPOCIP + ":" + "9440/PrismGateway/services/rest/v1/eulas/accept"
	$EULAResponse = Invoke-RestMethod $EULAAddress -Headers $Header -Method POST -Body $EULAJson -ContentType 'application/json'

	# Disable Pulse
	$PULSEJson = '{"emailContactList":null,"enable":false,"verbosityType":null,"enableDefaultNutanixEmail":false,"defaultNutanixEmail":null,"nosVersion":null,"isPulsePromptNeeded":false,"remindLater":null}'
	$PULSEAddress = "https://" + $HPOCIP + ":" + "9440/PrismGateway/services/rest/v1/pulse"
	$PULSEResponse = Invoke-RestMethod $PULSEAddress -Headers $Header -Method PUT -Body $PULSEJson -ContentType 'application/json'

	# TODO: Create storage container
	# if(!(Get-NTNXContainer).Name -eq "VMware") { $CreateContainer = New-NTNXContainer -Name "VMware" }
}

function New-DeployVCSA($HPOCPass, $POC, $ESXiHost) {
	# Draw Banner
	cls
	Banner

	write-host "***** READ THE PROMPTS CAREFULLY *****`n" -f red

	# POC Number
	write-host "Your POC Reservation (" -f yellow -nonewline; write-host "e.g. POC086" -f white -nonewline; write-host "): " -f yellow -nonewline
	$POC = read-host

	# Set VCSA IP Address
	if($POC -like "POC0*" ) {
		$vcsaIP = "10.21." + $POC.Substring($POC.Length - 2) + ".40"
		$Gateway = "10.21." + $POC.Substring($POC.Length - 2) + ".1"
		$ESXiGuess = "10.21." + $POC.Substring($POC.Length - 2) + ".25"
		$HPOC = $POC.Substring($POC.Length - 2)
	} else {
		$vcsaIP = "10.21." + $POC.Substring($POC.Length - 3) + ".40"
		$Gateway = "10.21." + $POC.Substring($POC.Length - 3) + ".1"
		$ESXiGuess = "10.21." + $POC.Substring($POC.Length - 3) + ".25"
		$HPOC = $POC.Substring($POC.Length - 3)
	}

	# ESXi Hosts
	write-host "Is your ESXi Host " -f yellow -nonewline; write-host $ESXiGuess -f white -nonewline; write-host " (Y/n)? " -f yellow -nonewline
	$ESXi = read-host
    switch($ESXi) {
		Y { $ESXi = $ESXiGuess }
		N {
			write-host "Your ESXi Host (" -f yellow -nonewline; write-host "e.g. 10.21.86.25" -f white -nonewline; write-host "): " -f yellow -nonewline
			$ESXi = read-host
		}
		Default { $ESXi = $ESXiGuess }
	}

	# Set HPOC Password if it wasn't already set
	if(!$HPOCPass) {
		write-host "HPOC Password: " -f yellow
		$HPOCPass = read-host
	}

	# Setup PE TODO: Fix hardcoded PW
	Setup-PrismElement $HPOC nutanix/4u $HPOCPass

	# TODO: Check Login before sending deployment package

	# TODO: Ask for verification

	# Create JSON Package
	$JSON = @{
		resID = "DeployVCSA-NCPI-$POC"
		esxHosts = @("$ESXi")
		esxPass = "$HPOCPass"
		vcsaIP = "$vcsaIP"
		datastore = "VMware"
		gateway = "$Gateway"
		subnet = "25"
		dns = "10.21.253.10"
	} | ConvertTo-Json

	# Send the package and report back
	$Response = Invoke-RestMethod 'http://10.21.250.221/deploy' -Method POST -Body $JSON -ContentType 'application/json'

	# Deploy VCSA
	cls
	Banner
	write-host "VCSA is being deployed." -f white;
	write-host "`n***** DO NOT CONTINUE UNTIL A SUCCESS OR FAILURE PROMPT IS GIVEN *****`n" -f red
	#write-host "Visit http://10.21.250.221/status/DeployVCSA-NCPI-$POC to monitor the status via browser`n"
	write-host "Deploying VCSA" -f yellow -nonewline
	do {
		$Completed = $false
		$CheckStatus = Invoke-WebRequest "http://10.21.250.221/status/DeployVCSA-NCPI-$POC" -UseBasicParsing
		if($CheckStatus -like "*Failed*") { $Completed = $true }
		if($CheckStatus -like "*Success*") { $Completed = $true }
		write-host "." -f white -nonewline
		sleep 10;
	} until($Completed)

	if($CheckStatus -like "*Failed*") { write-host " Failed! Please contact your instructor." -f red }
	if($CheckStatus -like "*Success*") { write-host " Success! You may close this window and continue to LAB 12." -f green }
	sleep 600
}

New-DeployVCSA -HPOCPass $HPOCPassword -POC $POC -ESXiHost $ESXiHost
