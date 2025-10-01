Add-WindowsFeature RSAT-AD-PowerShell
Import-Module ActiveDirectory

#Creating workstations in the form of Computer Accounts
Write-Host "[i] Adding workstations (computer accounts) to domain"
New-ADComputer -Name "WKST01" -AccountPassword (ConvertTo-SecureString 'wk1Passw0rd!' -AsPlainText -Force)
New-ADComputer -Name "WKST02" -AccountPassword (ConvertTo-SecureString 'wk2Passw0rd!' -AsPlainText -Force)
New-ADComputer -Name "WKST03" -AccountPassword (ConvertTo-SecureString 'wk3Passw0rd!' -AsPlainText -Force)
Write-Host "[+] WKST01, WKST02, and WKST03 computer accounts added to TRAINING.local"

#Creating Organizational Units
Write-Host "[i] Adding Organizational Units to domain"
New-ADOrganizationalUnit -Name "Managers" -Path "DC=TRAINING,DC=local"
New-ADOrganizationalUnit -Name "HR" -Path "DC=TRAINING,DC=local"
New-ADOrganizationalUnit -Name "UserAccounts" -Path "DC=TRAINING,DC=local"
Write-Host "[+] Managers, HR, and UserAccounts Organizational Units added to TRAINING.local"

#Creating Users
Write-Host "[i] Adding regular users to domain"
New-ADUser -Name "Jeniffer Tarantino" -GivenName "Jennifer" -Surname "Tarantino" -SamAccountName "jtarantino" -UserPrincipalName "jtarantino@TRAINING.local" -Path "OU=Managers,DC=TRAINING,DC=local" -AccountPassword (ConvertTo-SecureString "jtPassw0rd!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Donald Dougherty" -GivenName "Donald" -Surname "Dougherty" -SamAccountName "ddougherty" -UserPrincipalName "ddougherty@TRAINING.local" -Path "OU=HR,DC=TRAINING,DC=local" -AccountPassword (ConvertTo-SecureString "ddPassw0rd!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Evelyn Gismond" -GivenName "Evelyn" -Surname "Gismond" -SamAccountName "egismond" -UserPrincipalName "egismond@TRAINING.local" -Path "OU=UserAccounts,DC=TRAINING,DC=local" -AccountPassword (ConvertTo-SecureString "egPassw0rd!" -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Shanon Blue" -GivenName "Shanon" -Surname "Blue" -SamAccountName "sblue" -UserPrincipalName "sblue@TRAINING.local" -Path "OU=UserAccounts,DC=TRAINING,DC=local" -AccountPassword (ConvertTo-SecureString "sbPassw0rd!" -AsPlainText -Force) -Enabled $true

Write-Host "[+] jtarantino, ddougherty, egismond, and sblue user accounts added to TRAINING.local"

#Easing password policy requirements
Set-ADDefaultDomainPasswordPolicy -Identity TRAINING.local -ComplexityEnabled $false -MinPasswordLength 1 -PasswordHistoryCount 1

#Adding new Domain Admin account
Write-Host "[i] Adding TRAININGAdmin Domain Admin account"
New-ADUser -Name "trainingAdmin" -AccountPassword (ConvertTo-SecureString 'Passw0rd!' -AsPlainText -Force) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "trainingAdmin"
net localgroup Administrators trainingAdmin /add
Write-Host "[i] trainingAdmin Domain Admin account added"