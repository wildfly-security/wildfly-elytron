keystore created:
------------------
keytool -genseckey -alias test -storetype jceks -keystore vault-v1/vault-jceks.keystore -keyalg AES -keysize 128 -storepass secretsecret -keypass secretsecret

<vault>
  <vault-option name="KEYSTORE_URL" value="vault-jceks.keystore"/>
  <vault-option name="KEYSTORE_PASSWORD" value="MASK-2hKo56F1a3jYGnJwhPmiF5"/>
  <vault-option name="KEYSTORE_ALIAS" value="test"/>
  <vault-option name="SALT" value="12345678"/>
  <vault-option name="ITERATION_COUNT" value="34"/>
  <vault-option name="ENC_FILE_DIR" value="vault_data/"/>
</vault>

vault content created (from EAP6.1 dir):
-----------------------------------------
./bin/vault.sh -e vault-v1/vault_data/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b vb1 -a attr11 -x secret11
./bin/vault.sh -e vault-v1/vault_data/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b vb1 -a attr12 -x secret12

./bin/vault.sh -e vault-v1/vault_data_special_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b sc1 -a '@!#?$^*{}%+-<>&|()/' -x secret11
./bin/vault.sh -e vault-v1/vault_data_special_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b '@!#?$^*{}%+-<>&|()/' -a sc11 -x secret12
./bin/vault.sh -e vault-v1/vault_data_special_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b sc2 -a sc12 -x '@!#?$^*{}%+-<>&|()/'
./bin/vault.sh -e vault-v1/vault_data_special_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b '@!#?$^*{}%+-<>&|()/' -a '@!#?$^*{}%+-<>&|()/' -x '@!#?$^*{}%+-<>&|()/'

./bin/vault.sh -e vault-v1/vault_data_chinese_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b cn1 -a '用戶名' -x secret11
./bin/vault.sh -e vault-v1/vault_data_chinese_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b '用戶名' -a cn11 -x secret12
./bin/vault.sh -e vault-v1/vault_data_chinese_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b cn2 -a cn12 -x '用戶名'
./bin/vault.sh -e vault-v1/vault_data_chinese_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b '用戶名' -a '用戶名' -x '用戶名'

./bin/vault.sh -e vault-v1/vault_data_arabic_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b ar1 -a 'اسمالمستخدم' -x secret11
./bin/vault.sh -e vault-v1/vault_data_arabic_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b 'اسمالمستخدم' -a ar11 -x secret12
./bin/vault.sh -e vault-v1/vault_data_arabic_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b ar2 -a ar12 -x 'اسمالمستخدم'
./bin/vault.sh -e vault-v1/vault_data_arabic_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b 'اسمالمستخدم' -a 'اسمالمستخدم' -x 'اسمالمستخدم'

./bin/vault.sh -e vault-v1/vault_data_japanese_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b jp1 -a 'ユーザー名' -x secret11
./bin/vault.sh -e vault-v1/vault_data_japanese_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b 'ユーザー名' -a jp11 -x secret12
./bin/vault.sh -e vault-v1/vault_data_japanese_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b jp2 -a jp12 -x 'ユーザー名'
./bin/vault.sh -e vault-v1/vault_data_japanese_chars/ -k vault-v1/vault-jceks.keystore -v test -p secretsecret -i 34 -s 12345678 -b 'ユーザー名' -a 'ユーザー名' -x 'ユーザー名'

------------------
keystore created on IBM JDK (for ELY-1792):
------------------
keytool -genseckey -alias test -storetype jceks -keystore vault-v1/vault-jceks-ibm.keystore -keyalg AES -keysize 128 -storepass secretsecret -keypass secretsecret

<vault>
  <vault-option name="KEYSTORE_URL" value="vault-jceks-ibm.keystore"/>
  <vault-option name="KEYSTORE_PASSWORD" value="MASK-2hKo56F1a3jYGnJwhPmiF5"/>
  <vault-option name="KEYSTORE_ALIAS" value="test"/>
  <vault-option name="SALT" value="12345678"/>
  <vault-option name="ITERATION_COUNT" value="34"/>
  <vault-option name="ENC_FILE_DIR" value="vault_data_ibm/"/>
</vault>

vault content created (from EAP6.1 dir):
-----------------------------------------
./bin/vault.sh -e vault-v1/vault_data_ibm/ -k vault-v1/vault-jceks-ibm.keystore -v test -p secretsecret -i 34 -s 12345678 -b vb1 -a attr11 -x secret11
./bin/vault.sh -e vault-v1/vault_data_ibm/ -k vault-v1/vault-jceks-ibm.keystore -v test -p secretsecret -i 34 -s 12345678 -b vb1 -a attr12 -x secret12
