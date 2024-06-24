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

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.wildfly.security.ssl.test.util.CAGenerationTool.Identity;
import org.wildfly.security.x500.cert.X509CertificateExtension;

public class DefinedCAIdentity extends DefinedIdentity {

    private final PrivateKey privateKey;

    DefinedCAIdentity(CAGenerationTool caGenerationTool, Identity identity,
        X509Certificate certificate, PrivateKey privateKey) {
        super(caGenerationTool, identity, certificate);
        this.privateKey = privateKey;
    }

    public CustomIdentity createIdentity(final String alias, final X500Principal principal,
        final String keyStoreName, final X509CertificateExtension... extensions) {
        caGenerationTool.assertNotClosed();

        return caGenerationTool.createCustomIdentity(alias, principal, keyStoreName, identity, extensions);
     }


     public PrivateKey getPrivateKey() {
        caGenerationTool.assertNotClosed();

        return privateKey;
    }

    public X509TrustManager createTrustManager() {
        caGenerationTool.assertNotClosed();

        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX");
            trustManagerFactory.init(caGenerationTool.loadKeyStore(identity));

            for (TrustManager current : trustManagerFactory.getTrustManagers()) {
                if (current instanceof X509TrustManager) {
                    return (X509TrustManager) current;
                }
            }
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new IllegalStateException("Unable to obtain X509TrustManager.", e);
        }

        throw new IllegalStateException("Unable to obtain X509TrustManager.");
    }
}
