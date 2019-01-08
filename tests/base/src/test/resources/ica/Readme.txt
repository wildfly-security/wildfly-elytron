This folder contains an openssl based intermediate certificate authority used for testing.

To execute OpenSSL operations as the certificate authority first configure your environment: -

    . openssl.env

The password for the certificate authorities private key is 'Elytron'.

# jks

The 'jks' folder contains a number of keystores as used during testing, all have the password 'Elytron', 
entries use the same password.

rove.keystore contains an alias 'rove'.

# crl

The 'crl' folder contains different CRL files for this ICA:

blank.pem is blank CRL for ICA.
blank-blank.pem is concatenation of blank CRL for ICA and blank CRL for CA.

# Creating a new keystore with CA signed certificates takes the following 5 steps: -
# generate keystore with PrivateKeyEntry
keytool -genkeypair -keystore jks/rove.keystore -alias rove -keyalg RSA -validity 3650
# generate request from keystore
keytool -certreq -file rove.csr -keystore jks/rove.keystore -alias rove
# sign by CA
openssl ca -in rove.csr
# import CA into keystore
keytool -importcert -alias ca -file ../ca/cacert.pem -keystore jks/rove.keystore
# import ICA into keystore
keytool -importcert -alias ica -file icacert.pem -keystore jks/rove.keystore
# import signed cert into keystore
keytool -importcert -trustcacerts -file certs/00.pem -alias rove -keystore jks/rove.keystore

