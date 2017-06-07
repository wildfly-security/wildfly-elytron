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

import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.security.credential.Credential;

/**
 * A callback used to acquire the server (or "host") credential.  This callback is only used on the server side of
 * authentication mechanisms; client callback handlers do not need to recognize this callback.  The callback handler is
 * expected to provide a credential to this callback.  If no credential is available, {@code null} is set, and
 * authentication may fail.  If an unsupported credential type is set, an exception is thrown.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ServerCredentialCallback extends AbstractCredentialCallback {

    /**
     * Construct a new instance.
     *
     * @param credentialType the desired credential type (must not be {@code null})
     * @param algorithm the algorithm name, or {@code null} if any algorithm is suitable or the credential
     *  type does not use algorithm names
     * @param parameterSpec the parameters to use or {@code null} for no parameters
     */
    public ServerCredentialCallback(final Class<? extends Credential> credentialType, final String algorithm, final AlgorithmParameterSpec parameterSpec) {
        super(credentialType, algorithm, parameterSpec);
    }

    /**
     * Construct a new instance.
     *
     * @param credentialType the desired credential type (must not be {@code null})
     * @param algorithm the algorithm name, or {@code null} if any algorithm is suitable or the credential
     *  type does not use algorithm names
     */
    public ServerCredentialCallback(final Class<? extends Credential> credentialType, final String algorithm) {
        this(credentialType, algorithm, null);
    }

    /**
     * Construct a new instance which accepts any algorithm name.
     *
     * @param credentialType the desired credential type (must not be {@code null})
     */
    public ServerCredentialCallback(final Class<? extends Credential> credentialType) {
        this(credentialType, null, null);
    }

    public boolean isOptional() {
        return false;
    }
}
