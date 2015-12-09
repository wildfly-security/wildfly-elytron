/*
 * JBoss, Home of Professional Open Source
 * Copyright 2015 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.credential.store;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.impl.KeystorePasswordStore;
import org.wildfly.security.credential.store.impl.SecretKeyWrap;
import org.wildfly.security.password.interfaces.ClearPassword;


/**
 * Utility class to help create {@code KeyStore} for credential store tests dynamically.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class KeystorePasswordStoreBuilder {

    private String type = "JCEKS";
    private String file;
    private char[] storagePassword;
    private char[] keyPassword;
    private String cryptoAlgorithm = "AES";
    private int keySize = 128;

    private ArrayList<Data> data = new ArrayList<>();

    public KeystorePasswordStoreBuilder() { }

    public static KeystorePasswordStoreBuilder get() {
        return new KeystorePasswordStoreBuilder();
    }

    static final class Data {
        private String alias;
        private char[] secret;

        public Data(String alias, char[] secret) {
            this.alias = alias;
            this.secret = secret;
        }

        public Data(String alias, String secret) {
            this.alias = alias;
            this.secret = secret.toCharArray();
        }

        public String getAlias() {
            return alias;
        }

        public char[] getSecret() {
            return secret;
        }
    }

    public KeystorePasswordStoreBuilder setKeyStoreType(String type) {
        this.type = type;
        return this;
    }

    public KeystorePasswordStoreBuilder setKeyStoreFile(String file) {
        this.file = file;
        return this;
    }

    public KeystorePasswordStoreBuilder setCryptoAlgorithm(String cryptoAlgorithm) {
        this.cryptoAlgorithm = cryptoAlgorithm;
        return this;
    }

    public KeystorePasswordStoreBuilder setKeySize(int keySize) {
        this.keySize = keySize;
        return this;
    }

    public KeystorePasswordStoreBuilder setKeyStorePassword(String storagePassword, String keyPassword) {
        this.storagePassword = storagePassword.toCharArray();
        this.keyPassword = keyPassword.toCharArray();
        return this;
    }

    public KeystorePasswordStoreBuilder setKeyStorePassword(char[] storagePassword, char[] keyPassword) {
        this.storagePassword = Arrays.copyOf(storagePassword, storagePassword.length);
        this.keyPassword = Arrays.copyOf(keyPassword, keyPassword.length);
        return this;
    }

    public KeystorePasswordStoreBuilder addSecret(String alias, String secret) {
        data.add(new Data(alias, secret));
        return this;
    }

    public KeystorePasswordStoreBuilder addSecret(String alias, char[] secret) {
        data.add(new Data(alias, secret));
        return this;
    }

    public void build() throws Exception {

        if (keyPassword == null) {
            throw new IllegalStateException("keyPassword has to be specified");
        }
        if (storagePassword == null) {
            throw new IllegalStateException("storagePassword has to be specified");
        }

        if (file == null) {
            throw new IllegalStateException("file has to be specified");
        }

        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(null, null);

        KeyGenerator generator = KeyGenerator.getInstance(cryptoAlgorithm);
        generator.init(keySize);
        SecretKey adminKey = generator.generateKey();

        KeyStore.ProtectionParameter keyPP = new KeyStore.PasswordProtection(keyPassword);
        keyStore.setEntry(KeystorePasswordStore.DEFAULT_ADMIN_KEY_ALIAS, new KeyStore.SecretKeyEntry(adminKey), keyPP);

        Cipher cipher = Cipher.getInstance(cryptoAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, adminKey);
        for (Data d : data) {
            byte[] plainData = Normalizer.normalize(new String(d.getSecret()), Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8);
            byte[] encryptedData = cipher.doFinal(plainData);
            KeystorePasswordStore.Entry entry = new KeystorePasswordStore.Entry(PasswordCredential.class.getName(), encryptedData);
            keyStore.setEntry(d.getAlias(), new KeyStore.SecretKeyEntry(new SecretKeyWrap(KeystorePasswordStore.Entry.serializeEntry(entry), ClearPassword.ALGORITHM_CLEAR)), keyPP);
        }

        keyStore.store(new FileOutputStream(file), storagePassword);
    }

}
