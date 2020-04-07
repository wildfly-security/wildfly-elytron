This folder contains ssh keys generated using open-ssh command line tool

#Command used to generate id_ecdsa
$ ssh-keygen -t ecdsa
Generating public/private ecdsa key pair.
Enter file in which to save the key (/home/user/.ssh/id_ecdsa):
Enter passphrase (empty for no passphrase): secret
Enter same passphrase again: secret
Your identification has been saved in /home/user/.ssh/id_ecdsa.
Your public key has been saved in /home/user/.ssh/id_ecdsa.pub.

#Command used to generate ecdsa key in pkcs format:
$ ssh-keygen -t ecdsa -m pkcs8
Generating public/private ecdsa key pair.
Enter file in which to save the key (/home/user/.ssh/id_ecdsa): id_ecdsa_pkcs
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in id_ecdsa_pkcs.
Your public key has been saved in id_ecdsa_pkcs.pub.

#Command to convert public key to pkcs8 format:
$ ssh-keygen -f id_ecdsa_pkcs.pub -e -m pkcs8
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETwqaS+N07bvXhz1J09s9HlAJhImZ
VWCF/apVdSU3nZjPAQMK+hGATb/UICDGatGvMprD49ezxcNzHUufCn7IvA==
-----END PUBLIC KEY-----
