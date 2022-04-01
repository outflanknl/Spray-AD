# Spray-AD, a Cobalt Strike tool to perform a fast Kerberos password spraying attack against Active Directory.
This tool can help Red and Blue teams to audit Active Directory useraccounts for weak, well known or easy guessable passwords and can help Blue teams to assess whether these events are properly logged and acted upon.

When this tool is executed, it generates event IDs 4771 (Kerberos pre-authentication failed) instead of 4625 (logon failure). This event is not audited by default on domain controllers and therefore this tool might help evading detection while password spraying.

## Usage:

```
Download the Spray-AD folder and load the Spray-AD.cna script within the Cobalt Strike Script Manager.
Syntax within beacon context: Spray-AD [password to test]
To limit the possibility of user lockout use the -Limit flag, By default the limit of BadPwdCount is 4. To ignore the BadPwdCount set the flag to 0: 
Spray-AD [password to test] -Limit <max BadPwdCount>
```

```
This project is written in C/C++
You can use Visual Studio to compile the reflective dll's from source.
```

## Note to Red:
Make sure you always check the Active Directory password and lockout policies before spraying to avoid lockouts.

## Note to Blue:
To detect Active Directory Password Spraying, make sure to setup centralized logging and alarming within your IT environment and enable (at least) the following Advanced Audit policy on your Domain Controllers: 

```
Audit Kerberos Authentication Service (Success & Failure). 
This policy will generate Windows Security Log Event ID 4771 (Kerberos pre-authentication failed).
```

More info can be found in the following post by Sean Metcalf:
https://www.trimarcsecurity.com/post/2018/05/06/trimarc-research-detecting-password-spraying-with-security-event-auditing

## Credits
Author: Cornelis de Plaa (@Cneelis) / Outflank
