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

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A callback used to acquire credentials, either for outbound or inbound authentication.  This callback
 * is required only if a default credential was not supplied.  The callback handler is expected to provide
 * a credential to this callback if one is not present.  The supplied credential should be of a <em>supported</em>
 * type; the {@link #isCredentialSupported(Object)} and {@link #isCredentialTypeSupported(Class)} methods can be
 * used to query the types that are supported.  If no credential is available, {@code null} is set, and
 * authentication may fail.  If an unsupported credential type is set, authentication may fail.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class CredentialCallback implements ExtendedCallback {

    private final Set<Class<?>> allowedTypes;
    private Object credential;

    /**
     * Construct a new instance.
     *
     * @param allowedTypes the allowed types of credential
     */
    public CredentialCallback(final Class<?>... allowedTypes) {
        if (allowedTypes.length == 0) {
            this.allowedTypes = Collections.emptySet();
        } else if (allowedTypes.length == 1) {
            this.allowedTypes = Collections.<Class<?>>singleton(allowedTypes[0]);
        } else {
            final Set<Class<?>> set = new LinkedHashSet<>(allowedTypes.length);
            Collections.addAll(set, allowedTypes);
            this.allowedTypes = Collections.unmodifiableSet(set);
        }
    }

    /**
     * Construct a new instance.
     *
     * @param credential the default credential value, if any
     * @param allowedTypes the allowed types of credential
     */
    public CredentialCallback(final Object credential, final Class<?>... allowedTypes) {
        this(allowedTypes);
        this.credential = credential;
    }

    /**
     * Get the acquired credential.
     *
     * @return the acquired credential, or {@code null} if it wasn't set yet.
     */
    public Object getCredential() {
        return credential;
    }

    /**
     * Set the credential.
     *
     * @param credential the credential, or {@code null} if no credential is available
     */
    public void setCredential(final Object credential) {
        if (! isCredentialSupported(credential)) {
            throw new IllegalArgumentException("Invalid credential type specified");
        }
        this.credential = credential;
    }

    /**
     * Determine whether a credential would be supported by the authentication.
     *
     * @param credential the credential to test
     * @return {@code true} if the credential is non-{@code null} and supported, {@code false} otherwise
     */
    public boolean isCredentialSupported(final Object credential) {
        return credential != null && isCredentialTypeSupported(credential.getClass());
    }

    /**
     * Determine whether a credential type would be supported by the authentication.  A credential type is supported if
     * the given class is equal to, or a subtype of, any of the allowed credential types.
     *
     * @param credentialType the credential type to test
     * @return {@code true} if the credential type is supported, {@code false} otherwise
     */
    public boolean isCredentialTypeSupported(final Class<?> credentialType) {
        return credentialType != null && (allowedTypes.contains(credentialType) || isCredentialTypeSupported(credentialType.getSuperclass()) || isCredentialTypeSupportedArray(credentialType.getInterfaces()));
    }

    private boolean isCredentialTypeSupportedArray(final Class<?>... credentialTypes) {
        for (Class<?> credentialType : credentialTypes) {
            if (isCredentialTypeSupported(credentialType)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get the set of allowed types for this credential.
     *
     * @return the (immutable) set of allowed types
     */
    public Set<Class<?>> getAllowedTypes() {
        return allowedTypes;
    }

    public boolean isOptional() {
        return credential != null;
    }

    public boolean needsInformation() {
        return true;
    }
}
