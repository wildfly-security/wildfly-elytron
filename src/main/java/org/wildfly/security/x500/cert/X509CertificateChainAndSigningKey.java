/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;


/**
 * An X.509 certificate chain and private key.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.5.0
 */
public final class X509CertificateChainAndSigningKey {

    private final X509Certificate[] certificateChain;
    private final PrivateKey signingKey;

    /**
     * Construct a new instance.
     *
     * @param certificateChain the X.509 certificate chain
     * @param signingKey the private key
     */
    public X509CertificateChainAndSigningKey(X509Certificate[] certificateChain, PrivateKey signingKey) {
        this.certificateChain = checkNotNullParam("certificateChain", certificateChain);
        this.signingKey = checkNotNullParam("signingKey", signingKey);
    }

    /**
     * Get the X.509 certificate chain.
     *
     * @return the X.509 certificate chain
     */
    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }

    /**
     * Get the private key.
     *
     * @return the private key
     */
    public PrivateKey getSigningKey() {
        return signingKey;
    }
}
