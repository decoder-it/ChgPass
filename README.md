# CHGPass Tool

`chgpass.exe` is a Windows standalone executable tool that allows you to change the password of user/computer accounts in Active Directory (AD)  via MS-SAMR protocol. <br>
This tool can be used when you have the necessary permissions on the objects but need a simple way to set passwords using a standalone exe command line.

## Usage

To get the help message and list of arguments, run the following command:

`chgpass.exe -h`


### Command-Line Arguments

`chgpass.exe [-u <user>] [-p <password>] [-d <domain>] -t <target_user> -m <new_password> [-c <domain_controller>] [-l <target_server>]`
### Mandatory Arguments:

- `-t <target_account>`  
  Specify the target account whose password you want to modify. If you want to cnage the DSRM password specify `**DSRM**` (case sensitive) as target_account 

- `-m <new_password>`  
  Specify the new password for the target account.

### Optional Arguments:

- `-u <user>`  
  Specify the username for authentication (if different from the current user).

- `-p <password>`  
  Specify the password for authentication.

- `-d <domain>`  
  Specify the domain to authenticate to.

- `-c <domain_controller>`  
  Specify the name of the domain controller to connect to.
- `-l <server>`  
  Specify the name of the server to connect to.

## Example Usage

To change the password of a target user `target_account` using an alternate account:<br>
`chgpass.exe -t target_user -m newpassword123 -u admin -p adminpassword -d mydomain.local -c dc1.mydomain.local`
<br>
In this example:
- The username for authentication is `admin`.
- The password for authentication is `adminpassword`.
- The domain to connect to is `mydomain.local`.
- The domain controller to connect to is `dc1.mydomain.local`.
- The target account `target_user` will have their password changed to `newpassword123`.

<br><br>To change the password of a local account of  a remote domain joined machine:<br>
`chgpass.exe -t localuser1 -m Superp@ss! -l remoteserver`
<br><br>
To change the password of a local account of  a remote domain joined machine from a non domain joined machine:<br>
`chgpass.exe -t localuser1 -m newpassword123 -u admin -p adminpassword -d mydomain.local -c dc1.mydomain.local -l remoteserver` 
<br><br>
To change the password of DSRM mode, which is the local administrator account on the Domain Controllers stored in local SAM:<br>
`chgpass.exe -t **DSRM** -m "" -u admin -p adminpassword -d mydomain.local -c dc1.mydomain.local`
<br><br>
In this case the DSRM password will be set to empty as the password valdiation criteria are skipped ;)
<br>

## Warning
In case of resetting computer account password it will break the domain join.
## License

This tool is provided as-is with no warranty. Feel free to use and modify it as needed.
