# NTLM
A Java implementation of Microsoft [NTLM](https://learn.microsoft.com/fr-fr/windows-server/security/kerberos/ntlm-overview)

Since NTLM is not publicly documented, this project is the result of several weeks of effort, googling, coding and trial/errors.

NTLM is mainly used to authenticate users to proxies in windoze environments

This project does a little more than NTLM:
* it establishes local DB connection, performs SQL to retrieve some info
* it performs NTLM authentication
* sends
* data via a SSL tunnel
* 
Was developped inside a java Applet, refactoring needed to include in modern java apps
