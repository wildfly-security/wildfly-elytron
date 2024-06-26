/*
 * Copyright 2024 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.ssl.test.util;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;

public abstract class CommonIdentity {

    protected final CAGenerationTool caGenerationTool;
    private final X509Certificate certificate;

    CommonIdentity(CAGenerationTool caGenerationTool, X509Certificate certificate) {
        this.caGenerationTool = caGenerationTool;
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        caGenerationTool.assertNotClosed();

        return certificate;
    }

    public abstract KeyStore loadKeyStore();

    public X509ExtendedKeyManager createKeyManager() {
        caGenerationTool.assertNotClosed();

        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(loadKeyStore(), CAGenerationTool.PASSWORD);

            for (KeyManager current : keyManagerFactory.getKeyManagers()) {
                if (current instanceof X509ExtendedKeyManager) {
                    return (X509ExtendedKeyManager) current;
                }
            }
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            throw new IllegalStateException("Unable to obtain X509ExtendedKeyManager.", e);
        }

        throw new IllegalStateException("Unable to obtain X509ExtendedKeyManager.");
    }

}
