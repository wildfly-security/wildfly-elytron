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

import java.security.spec.AlgorithmParameterSpec;

/**
 * A callback which provides information about the available credential algorithms
 * and their parameters.  More than one instance of this callback may be present in
 * the callback array, and they may pertain to the same or different algorithm(s).
 * <p>
 * The credential <em>kind</em> is the security provider service type name for the
 * credential.  For example:
 * <ul>
 *     <li>{@code Password}</li>
 *     <li>{@code SecretKey}</li>
 *     <li>{@code PrivateKey}</li>
 * </ul>
 * <p>
 * The algorithm name corresponds to the credential algorithm.  The parameters apply to
 * the specific algorithm type.  These parameters may be used to help a client decide
 * which credential to supply to the authentication.
 * <p>
 * This callback type is <em>optional</em>, meaning {@link #isOptional()} always returns
 * {@code true}, which in turn means that this callback type may be safely ignored.  If
 * this callback type is unsupported by a callback handler, the authentication process
 * must retry the callback handler without it.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class CredentialParameterCallback implements ExtendedCallback {

    private final String credentialKind;
    private final String algorithmName;
    private final AlgorithmParameterSpec algorithmParameterSpec;

    /**
     * Construct a new instance.
     *
     * @param credentialKind the kind of credential (e.g. {@code Password}, {@code PrivateKey}, etc.)
     * @param algorithmName the credential algorithm
     * @param algorithmParameterSpec a set of parameters for the credential algorithm
     */
    public CredentialParameterCallback(final String credentialKind, final String algorithmName, final AlgorithmParameterSpec algorithmParameterSpec) {
        this.credentialKind = credentialKind;
        this.algorithmName = algorithmName;
        this.algorithmParameterSpec = algorithmParameterSpec;
    }

    /**
     * Get the credential kind.
     *
     * @return the credential kind
     */
    public String getCredentialKind() {
        return credentialKind;
    }

    /**
     * Get the credential algorithm name.
     *
     * @return the algorithm name
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    /**
     * Get the credential algorithm parameter specification.
     *
     * @return the algorithm parameter specification
     */
    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return algorithmParameterSpec;
    }

    @Override
    public boolean isOptional() {
        return true;
    }

    @Override
    public boolean needsInformation() {
        return false;
    }
}
