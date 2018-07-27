param($HPOCPassword)

# Create a banner because we want it to be pretty
function Banner {
	write-host "`n---------------------------------" -f yellow
	write-host "Nutani" -f green -nonewline; write-host "x " -f yellow -nonewline; write-host "VCSA Deployment Kit" -f green -nonewline;
	write-host "`n---------------------------------`n" -f yellow
}

function Setup-PrismElement($HPOC, $PEPassword) {
	<# Set header info to login to PE
	$Header = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('admin'+":"+"nutanix/4u"))}

	# Login to PE and accept EULA
	$EULAJson = @{
		username = "SE with CreateVCSA.ps1"
		companyName = "Nutanix"
		jobTitle = "SE"
	} | ConvertTo-Json
	$EULAResponse = Invoke-RestMethod https://10.21.14.29:9440/PrismGateway/services/rest/v1/eulas/accept -Headers $Header -Method Put -Body $EULAJson -ContentType 'application/json'#>

	# Add NTNX Cmdlets
	Add-PSSnapin NutanixCmdletsPSSnapin

	# Login to PE
	$PEPassword = ConvertTo-SecureString "$PEPassword" -AsPlainText -Force
	$Connect = Connect-NTNXCluster -Server $HPOC -UserName admin -Password $PEPassword -AcceptInvalidSSLCerts

	# Create Containers
	if(!(Get-NTNXContainer).Name -eq "VMware") { $CreateContainer = New-NTNXContainer -Name "VMware" }
}

function New-DeployVCSA($HPOCPass) {
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

	# TODO: Setup PE
	#Setup-PrismElement $ESXiGuess $HPOCPass

	# TODO: Check Login before sending deployment package

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

New-DeployVCSA -HPOCPass $HPOCPassword
