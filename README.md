# RC4-Hunter
The RC4-Hunter PowerShell script is designed to find Kerberos tickets that are signed with RC4 encryption, which is a weaker encryption standard that can put your network at risk. By querying all of your domain controllers for the usage of RC4 in Kerberos tickets, RC4-Hunter helps you identify potential security vulnerabilities in your network.

Don't wait for a security breach to occur – take proactive measures to protect your network today!

## Usage
To use RC4-Hunter, follow these steps:

Install PowerShell version 4 or higher.
Install the Active Directory PowerShell module.
Ensure that you have domain admin rights.
Enable Kerberos auditing on your domain controllers.
Ensure that you have RPC access to all domain controllers in the domain.
Download the RC4-Hunter script from the GitHub repository.
Open PowerShell and navigate to the directory where you saved the script.
Run the script using the following command: .\RC4_Hunter.ps1 -outputFile '.\Results.csv'
The output of the script will be saved as a CSV file and includes important information such as the user account that was found, the service name that was requested, the encryption type that was used, and the IP address of the calling computer. This information can be used to quickly identify and remediate any potential security threats.

```powershell
.\RC4_Hunter.ps1 -outputFile '.\Results.csv'
```


## Prerequisites
Before using RC4-Hunter, ensure that you have met the following prerequisites:

1. PowerShell version 4 or higher.
2. Active Directory PowerShell module.
3. Domain Admin rights.
4. Kerberos auditing enabled on your domain controllers.
5. RPC access to all of the domain controller in the domain.


## Enabling Kerberos auditing

1. Log on to a domain controller as a domain administrator.
2. Navigate to Group Policy Objects and create a new Group Policy Object (GPO) named Kerberos Ticket Auditing.
3. Open the Group Policy Management Console and edit the Default Domain Policy.
4. Navigate to Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Logon.
5. Enable the Audit Kerberos Authentication Service policy (Success/Failure).
6. Enable the Audit Kerberos Service Ticket Operations policy (Success/Failure).
7. Link the newly created GPO to the Domain Controllers OU.



## disclaimer
The PowerShell script provided on this GitHub repository is offered on an as-is basis, without any express or implied warranty or support. While the script is designed to only collect data, it is recommended that you thoroughly test the script in a separate testing environment before deploying it in a production environment. The author shall not be held responsible for any direct or indirect damages resulting from the use of this script. By downloading and using this script, you agree to these terms and conditions.

Don't wait for a security breach to occur – take proactive measures to protect your network today!