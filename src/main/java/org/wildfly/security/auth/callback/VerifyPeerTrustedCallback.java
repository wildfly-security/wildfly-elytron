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

package org.wildfly.security.auth.callback;

import java.io.Serializable;
import java.security.cert.X509Certificate;

/**
 * A callback to indicate the peer is trusted.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class VerifyPeerTrustedCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -2830410786419507677L;

    /**
     * @serial The certificate chain to verify.
     */
    private final X509Certificate[] chain;
    /**
     * @serial The authentication type.
     */
    private final String authType;
    /**
     * @serial A flag indicating whether the peer was verified.
     */
    private boolean verified = false;

    /**
     * Construct a new instance.
     *
     * @param chain the peer certificate chain
     * @param authType the authentication type based on the peer certificate
     */
    public VerifyPeerTrustedCallback(final X509Certificate[] chain, final String authType) {
        this.chain = chain;
        this.authType = authType;
    }

    /**
     * Get the peer certificate chain.
     *
     * @return the peer certificate chain
     */
    public X509Certificate[] getCertificateChain() {
        return chain;
    }

    /**
     * Get the authentication type.
     *
     * @return the authentication type based on the peer certificate
     */
    public String getAuthType() {
        return authType;
    }

    /**
     * Set whether the peer is trusted.
     *
     * @param verified {@code true} if the peer is trusted based on its certificate chain and
     * authentication type and {@code false} otherwise
     */
    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    /**
     * Determine whether the peer is trusted.
     *
     * @return {@code true} if the peer is trusted based on its certificate chain and
     * authentication type and {@code false} otherwise
     */
    public boolean isVerified() {
        return verified;
    }

    public boolean isOptional() {
        return false;
    }

    public boolean needsInformation() {
        return true;
    }
}
