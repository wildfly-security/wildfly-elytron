/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.x500;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * A credential containing a private key and an X.509 certificate chain.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class X509CertificateChainPrivateCredential {
    private final PrivateKey privateKey;
    private final X509Certificate[] certificateChain;

    /**
     * A constant array containing zero certificates.
     */
    public static final X509Certificate[] NO_CERTIFICATES = new X509Certificate[0];

    /**
     * Construct a new instance.
     *
     * @param privateKey the private key (not {@code null})
     * @param certificateChain the certificate chain (not {@code null}, cannot contain {@code null} elements)
     */
    public X509CertificateChainPrivateCredential(final PrivateKey privateKey, final X509Certificate... certificateChain) {
        this.privateKey = privateKey;
        this.certificateChain = certificateChain.clone();
    }

    /**
     * Get the private key.
     *
     * @return the private key
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Get a copy of the certificate chain.
     *
     * @return a copy of the certificate chain
     */
    public X509Certificate[] getCertificateChain() {
        return certificateChain.clone();
    }
}
