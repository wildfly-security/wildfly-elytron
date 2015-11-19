/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;

/**
 * A callback used to acquire credentials.  On the client side of an authentication mechanism, the callback handler is
 * required to supply a credential for use in outbound authentication.  On the server side, the callback handler is
 * required to supply a credential for use in inbound authentication, possibly for both verification as well as establishing
 * authentication parameters.
 * <p>
 * This callback must be handled if a default credential was not supplied.  The callback
 * handler is expected to provide a credential to this callback if one is not present.  If no credential is available,
 * {@code null} is set, and authentication may fail.  If an unsupported credential type is set, an exception is thrown.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class CredentialCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = 4756568346009259703L;

    /**
     * @serial The type of the supported credential.
     */
    private final Class<? extends Credential> credentialType;

    /**
     * @serial The algorithm of the required credential, or {@code null} if any algorithm is suitable or the credential
     *  type does not use algorithm names.
     */
    private final String algorithm;

    /**
     * @serial The credential itself.
     */
    private Credential credential;

    /**
     * Construct a new instance.
     *
     * @param credentialType the desired credential type (must not be {@code null})
     * @param algorithm the algorithm name, or {@code null} if any algorithm is suitable or the credential
     *  type does not use algorithm names
     */
    public CredentialCallback(final Class<? extends Credential> credentialType, final String algorithm) {
        Assert.checkNotNullParam("credentialType", credentialType);
        this.credentialType = credentialType;
        this.algorithm = algorithm;
    }

    /**
     * Construct a new instance which accepts any algorithm name.
     *
     * @param credentialType the desired credential type (must not be {@code null})
     */
    public CredentialCallback(final Class<? extends Credential> credentialType) {
        this(credentialType, null);
    }

    /**
     * Get the acquired credential.
     *
     * @return the acquired credential, or {@code null} if it wasn't set yet.
     */
    public Credential getCredential() {
        return credential;
    }

    /**
     * Set the credential.  The credential must be of the supported type and algorithm.
     *
     * @param credential the credential, or {@code null} to indicate that no credential is available
     * @throws IllegalArgumentException if the given credential is not supported
     */
    public void setCredential(final Credential credential) {
        if (credential != null && ! isCredentialSupported(credential)) {
            throw ElytronMessages.log.credentialNotSupported();
        }
        this.credential = credential;
    }

    /**
     * Determine whether the given credential type is supported.  Will be {@code false} if the credential type requires
     * an algorithm name; in this case, use {@link #isCredentialTypeSupported(Class, String)} instead.
     *
     * @param credentialType the credential type (must not be {@code null})
     * @return {@code true} if the credential type is supported, {@code false} otherwise
     */
    public boolean isCredentialTypeSupported(final Class<? extends Credential> credentialType) {
        return isCredentialTypeSupported(credentialType, null);
    }

    /**
     * Determine whether the given credential type is supported for the given algorithm name.
     *
     * @param credentialType the credential type (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} to indicate that no algorithm name will be available
     * @return {@code true} if the credential type is supported, {@code false} otherwise
     */
    public boolean isCredentialTypeSupported(final Class<? extends Credential> credentialType, final String algorithmName) {
        Assert.checkNotNullParam("credentialType", credentialType);
        return this.credentialType.isAssignableFrom(credentialType) && (algorithm == null || AlgorithmCredential.class.isAssignableFrom(credentialType) && algorithm.equals(algorithmName));
    }

    /**
     * Determine whether the given credential can be set on this callback.
     *
     * @param credential the credential (must not be {@code null})
     * @return {@code true} if the credential matches the type and optional algorithm of this callback, {@code false} otherwise
     */
    public boolean isCredentialSupported(final Credential credential) {
        Assert.checkNotNullParam("credential", credential);
        return credentialType.isInstance(credential) && (algorithm == null || credential instanceof AlgorithmCredential && algorithm.equals(((AlgorithmCredential) credential).getAlgorithm()));
    }

    /**
     * Get the supported credential type.
     *
     * @return the supported credential type (not {@code null})
     */
    public Class<? extends Credential> getCredentialType() {
        return credentialType;
    }

    /**
     * Get the algorithm name, if any.
     *
     * @return the algorithm name, or {@code null} if any algorithm is suitable or the credential
     *  type does not use algorithm names
     */
    public String getAlgorithm() {
        return algorithm;
    }

    public boolean isOptional() {
        return credential != null;
    }

    public boolean needsInformation() {
        return true;
    }
}
