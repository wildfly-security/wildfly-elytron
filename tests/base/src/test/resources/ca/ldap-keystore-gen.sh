#!/bin/sh
# Script allowing generation of LDIF for LdapKeyStore.
# It use standard inetOrgPerson LDAP attributes.
#
# Using: ./ldap-keystore-gen.sh certs/01.pem cacert.pem jks/firefly.keystore > example.ldif
#
# Author: Jan Kalina <jkalina@redhat.com>
#

openssl x509 -in "$1" -outform DER -out /tmp/outcert.der
ldif -b "usercertificate" < /tmp/outcert.der

openssl crl2pkcs7 -nocrl -certfile "$1" -certfile "$2" -out /tmp/chain.p7b
ldif -b "userSMIMECertificate" < /tmp/chain.p7b

if [ ${3: -4} == ".pem" ]
then # from PEM
	openssl pkcs12 -export -out /tmp/keystore.p12 -inkey "$3" -in "$1" -in "$2"
else # from keystore
	keytool -importkeystore -srckeystore "$3" -srcstoretype jks -destkeystore /tmp/keystore.p12 -deststoretype pkcs12
fi
ldif -b "userPKCS12" < /tmp/keystore.p12

rm /tmp/outcert.der /tmp/chain.p7b /tmp/keystore.p12 

