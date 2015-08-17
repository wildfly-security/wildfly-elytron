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
package org.wildfly.security.vault;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.wildfly.security.vault._private.KeystorePasswordStorage;
import org.wildfly.security.vault._private.SecretKeyWrap;

/**
 * Utility class to help create {@code KeyStore} for vault tests dynamically.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public class VaultBuilder {

    private String type = "JCEKS";
    private String file;
    private char[] storagePassword;
    private char[] keyPassword;
    private String cryptoAlgorithm = "AES";
    private int keySize = 128;

    private ArrayList<Data> data = new ArrayList<>();

    public VaultBuilder() { }

    public static VaultBuilder get() {
        return new VaultBuilder();
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

    public VaultBuilder keyStoreType(String type) {
        this.type = type;
        return this;
    }

    public VaultBuilder keyStoreFile(String file) {
        this.file = file;
        return this;
    }

    public VaultBuilder cryptoAlgorithm(String cryptoAlgorithm) {
        this.cryptoAlgorithm = cryptoAlgorithm;
        return this;
    }

    public VaultBuilder keySize(int keySize) {
        this.keySize = keySize;
        return this;
    }

    public VaultBuilder keyStorePasswords(String storagePassword, String keyPassword) {
        this.storagePassword = storagePassword.toCharArray();
        this.keyPassword = keyPassword.toCharArray();
        return this;
    }

    public VaultBuilder keyStorePasswords(char[] storagePassword, char[] keyPassword) {
        this.storagePassword = Arrays.copyOf(storagePassword, storagePassword.length);
        this.keyPassword = Arrays.copyOf(keyPassword, keyPassword.length);
        return this;
    }

    public VaultBuilder data(String alias, String secret) {
        data.add(new Data(alias, secret));
        return this;
    }

    public VaultBuilder data(String alias, char[] secret) {
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
        keyStore.setEntry(KeystorePasswordStorage.DEFAULT_ADMIN_KEY_ALIAS, new KeyStore.SecretKeyEntry(adminKey), keyPP);

        Cipher cipher = Cipher.getInstance(cryptoAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, adminKey);
        for (Data d : data) {
            byte[] plainData = Normalizer.normalize(new String(d.getSecret()), Normalizer.Form.NFKC).getBytes(StandardCharsets.UTF_8);
            byte[] encryptedData = cipher.doFinal(plainData);
            keyStore.setEntry(d.getAlias(), new KeyStore.SecretKeyEntry(new SecretKeyWrap(encryptedData)), keyPP);
        }

        keyStore.store(new FileOutputStream(file), storagePassword);
    }

    private static char[] byteArrayDecode(byte[] buffer) {
        return new String(buffer, StandardCharsets.UTF_8).toCharArray();
    }

}
