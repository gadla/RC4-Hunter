# RC4-Hunter

## Introduction

RC4-Hunter is a PowerShell script designed to detect Kerberos tickets that are encrypted with the RC4 algorithm. RC4 (Rivest Cipher 4, also known as ARC4 or ARCFOUR, which stands for Alleged RC4) is a stream cipher, symmetric key algorithm. While it was widely used and adopted due to its simplicity and speed, it has several well-known vulnerabilities.

Over the years, multiple vulnerabilities in the RC4 algorithm have been discovered, leading to its depreciation in protocols like TLS (Transport Layer Security) and WPA (Wi-Fi Protected Access).

One of the key weaknesses of RC4 is in its key scheduling algorithm which leads to biases in the byte distribution of the output keystream. This can leak information about the plaintext, making it possible for an attacker to decrypt the ciphertext and gain unauthorized access to sensitive information.

In the context of Kerberos authentication, tickets encrypted with RC4 can potentially be cracked if an attacker has gained access to a weak user's password hash. This is because RC4 encryption in Kerberos does not provide the same level of protection as AES encryption does against certain types of attacks such as offline password guessing attacks.

RC4-Hunter helps identify the usage of RC4 in Kerberos tickets across your network, which can be an important step towards improving your network security. It's recommended to move towards stronger encryption standards for Kerberos, such as AES, to better protect your systems and data.

Don't wait for a security breach to occur – take proactive measures to protect your network today!

<br>

## Usage
To use RC4-Hunter, you will need to run the PowerShell script and provide the desired output file as a parameter:

```powershell
.\RC4_Hunter.ps1 -outputFile '.\Results.csv'
```
Here's what this command does:

* .\RC4_Hunter.ps1: This runs the RC4-Hunter PowerShell script.
* -outputFile: This parameter specifies the output file where the results will be stored.
* '.\Results.csv': This is the name of the output file (in this case, 'Results.csv'). The script will create this file in the same directory where you run the script.
  
<br>
The script will generate a CSV file with information about each instance where RC4 encryption is used in a Kerberos ticket. This includes the user account that requested the ticket, the service name for which the ticket was requested, the encryption type used (which would be RC4), and the IP address of the client machine that made the request.

By analyzing this data, you can identify potential security risks and take steps to mitigate them, such as disabling RC4 encryption where possible and educating users about the risks of weak passwords.

<br>


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

