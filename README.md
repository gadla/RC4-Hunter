# RC4-Hunter
This script is used to find Kerberos tickets that are signed with RC4 encryption. 
This script will query all of your domain controllers for the usage of RC4 in kerberos tickets. After quering your dc's the output of the script will be a csv file. 

### disclaimer
The PowerShell script provided on this GitHub repository is offered on an as-is basis, without any express or implied warranty or support. While the script is designed to only collect data, it is recommended that you thoroughly test the script in a separate testing environment before deploying it in a production environment. The author shall not be held responsible for any direct or indirect damages resulting from the use of this script. By downloading and using this script, you agree to these terms and conditions.

The csv output file will contain the following information:
 1. The user account that was found
 2. The service name that was ask a ticket for
 3. The encryption type that was used
 4. The ip address of the calling computer


## Prerequisites
1. PowerShell version 4 or higher
2. Active Directory PowerShell module
3. Domain Admin rights
4. Kerberos auditing enabled
5. RPC access to all of the domain controller in the domain

## Usage
```powershell
.\RC4_Hunter.ps1 -outputFile '.\Results.csv'
```

## Kerberos ticket auditing
1. Log on to a domain controller as a domain administrator.
2. Navigate to Group Policy Objects and  create a new Group Policy Object (GPO) named Kerberos Ticket Auditing.
3. Open the Group Policy Management Console and edit the Default Domain Policy. Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Logon. 
4. Enable the Audit Kerberos Authentication Service policy (Success/Failure).
5. Enable the Audit Kerberos Service Ticket Operations policy (Success/Failure).
6. Link the newly created GPO to the Domain Controllers ou.