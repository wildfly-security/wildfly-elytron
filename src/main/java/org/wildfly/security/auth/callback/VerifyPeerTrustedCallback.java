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
import java.security.Principal;

import org.wildfly.security.credential.Credential;

/**
 * A callback to indicate the peer is trusted.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class VerifyPeerTrustedCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = -2830410786419507677L;

    /**
     * @serial The peer principal (possibly {@code null}).
     */
    private final Principal principal;
    /**
     * @serial The peer credential (possibly {@code null}).
     */
    private final Credential credential;
    /**
     * @serial A flag indicating whether the peer was verified.
     */
    private boolean verified = false;

    /**
     * Construct a new instance.
     *
     * @param principal the peer principal (may be {@code null} if unknown)
     * @param credential the peer credential (may be {@code null} if unknown)
     */
    public VerifyPeerTrustedCallback(final Principal principal, final Credential credential) {
        this.principal = principal;
        this.credential = credential;
    }

    /**
     * Get the peer principal, if any is known.
     *
     * @return the peer principal, or {@code null} if unknown
     */
    public Principal getPrincipal() {
        return principal;
    }

    /**
     * Get the peer credential, if any is known.
     *
     * @return the peer credential, or {@code null} if unknown
     */
    public Credential getCredential() {
        return credential;
    }

    /**
     * Get the peer credential, if any is known and it is of the given type.
     *
     * @return the peer credential, or {@code null} if unknown or of a different type
     */
    public <C extends Credential> C getCredential(Class<C> credentialClass) {
        final Credential credential = this.credential;
        return credentialClass.isInstance(credential) ? credentialClass.cast(credential) : null;
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
