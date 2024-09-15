/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.PROTOCOL_CLASSPATH;

/**
 * A utility class to obtain the KeyPair from a keystore file.
 *
 * @author <a href="mailto:prpaul@redhat.com">Prarthona Paul</a>
 */

class JWTSigningUtils {

    public static KeyPair loadKeyPairFromKeyStore(String keyStoreFile, String storePassword, String keyPassword, String keyAlias, String keyStoreType) {
        InputStream stream = findFile(keyStoreFile);
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(stream, storePassword.toCharArray());
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
            if (privateKey == null) {
                throw log.unableToLoadKeyWithAlias(keyAlias);
            }
            PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw log.unableToLoadPrivateKey(e);
        }
    }

    public static InputStream findFile(String keystoreFile) {
        if (keystoreFile.startsWith(PROTOCOL_CLASSPATH)) {
            String classPathLocation = keystoreFile.replace(PROTOCOL_CLASSPATH, "");
            // try current class classloader first
            InputStream is = JWTSigningUtils.class.getClassLoader().getResourceAsStream(classPathLocation);
            if (is == null) {
                is = Thread.currentThread().getContextClassLoader().getResourceAsStream(classPathLocation);
            }
            if (is != null) {
                return is;
            } else {
                throw log.unableToFindKeystoreFile(keystoreFile);
            }
        } else {
            try {
                // fallback to file
                return new FileInputStream(keystoreFile);
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
