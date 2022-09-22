# NTLM
A Java implementation of Microsoft [NTLM](https://learn.microsoft.com/fr-fr/windows-server/security/kerberos/ntlm-overview)

Since NTLM is not publicly documented, this project is the result of several weeks of effort, googling, coding and trial/errors.

NTLM is mainly used to authenticate users to proxies in windoze environments

This project does a little more than NTLM:
* it establishes local DB connection, executes SQL select to retrieve some info
* it performs NTLM authentication (challenge/response)
* sends the data outside via SSL tunnel

Since it was developped to execute into a java Applet some refactoring is needed to include in modern java apps
