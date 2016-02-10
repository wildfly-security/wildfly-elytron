This folder contains an openssl based certificate authority used for testing.

To execute OpenSSL operations as the certificate authority first configure your environment: -

    . openssl.env

The password for the certificate authorities private key is 'Elytron'.

# jks

The 'jks' folder contains a number of keystores as used during testing, all have the password 'Elytron', 
entries use the same password.

ca.truststore - Contains the self signed root certificate of the certificate authority.

dung.keystore contains an alias 'dung'.
firefly.keystore contains an alias 'firefly'.
ladybird.keystore contains an alias 'ladybird'.
scarab.keystore contains an alias 'scarab'.

# Creating a new keystore with CA signed certificates takes the following 5 steps: -
keytool -genkeypair -keystore jks/scarab.keystore -alias scarab -keyalg RSA -validity 3650
keytool -certreq -file scarab.csr -keystore jks/scarab.keystore -alias scarab
openssl ca -in scarab.csr
keytool -importcert -alias ca -file cacert.pkcs7 -keystore jks/scarab.keystore
keytool -importcert -trustcacerts -file certs/04.pem -alias scarab -keystore jks/scarab.keystore


