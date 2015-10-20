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
import java.util.Map;
import java.util.Set;
import org.wildfly.security.credential.Credential;

/**
 * A callback used to acquire credentials, either for outbound or inbound authentication.  This callback
 * is required only if a default credential was not supplied.  The callback handler is expected to provide
 * a credential to this callback if one is not present.  The supplied credential should be of a <em>supported</em>
 * type; the {@link #isCredentialSupported(Class, String)} method can be
 * used to query the types that are supported.  If no credential is available, {@code null} is set, and
 * authentication may fail.  If an unsupported credential type is set, authentication may fail.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class CredentialCallback implements ExtendedCallback, Serializable {

    private static final long serialVersionUID = 4756568346009259703L;

    /**
     * @serial The map of allowed credential types.
     */
    private final Map<Class<? extends Credential>, Set<String>> allowedTypes;
    /**
     * @serial The credential itself.
     */
    private Credential credential;

    /**
     * Construct a new instance.
     *
     * @param allowedTypes the allowed types of credential
     */
    public CredentialCallback(final Map<Class<? extends Credential>, Set<String>> allowedTypes) {
        this.allowedTypes = allowedTypes;
    }

    /**
     * Construct a new instance.
     *
     * @param credential the default credential value, if any
     * @param allowedTypes the allowed types of credential
     */
    public CredentialCallback(final Credential credential, final Map<Class<? extends Credential>, Set<String>> allowedTypes) {
        this(allowedTypes);
        this.credential = credential;
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
     * Set the credential.
     *
     * @param credential the credential, or {@code null} if no credential is available
     */
    public void setCredential(final Credential credential) {
        this.credential = credential;
    }

    /**
     * Determine whether a credential type would be supported by the authentication.
     * The credential type is defined by its {@code Class} and an optional {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param credentialType the credential type to test
     * @param algorithm the algorithm of the credential to test, or {@code null} to test for any algorithm
     * @return {@code true} if the credential is non-{@code null} and supported, {@code false} otherwise
     */
    public boolean isCredentialSupported(final Class<? extends Credential> credentialType, final String algorithm) {
        final Set<String> set = allowedTypes.get(credentialType);
        if (set != null) {
            return algorithm == null || set.isEmpty() || set.contains(algorithm);
        } else {
            final Class<?> superclass = credentialType.getSuperclass();
            if (Credential.class.isAssignableFrom(superclass)) {
                if (isCredentialSupported(superclass.asSubclass(Credential.class), algorithm)) {
                    return true;
                }
            }
            final Class<?>[] interfaces = credentialType.getInterfaces();
            for (Class<?> clazz : interfaces) {
                if (Credential.class.isAssignableFrom(superclass) && isCredentialSupported(clazz.asSubclass(Credential.class), algorithm)) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Get the set of allowed types for this credential.
     *
     * @return the (immutable) set of allowed types
     */
    public Set<Class<? extends Credential>> getAllowedTypes() {
        return allowedTypes.keySet();
    }

    /**
     * Get the allowed algorithms for the given exact credential type.  The returned set may be empty, indicating that
     * no algorithm is required for the given credential, or {@code null} indicating that the credential type is not
     * supported.
     *
     * @param type the credential type
     * @return the (immutable) set of allowed algorithms
     */
    public Set<String> getAllowedAlgorithms(Class<? extends Credential> type) {
        return allowedTypes.get(type);
    }

    public boolean isOptional() {
        return credential != null;
    }

    public boolean needsInformation() {
        return true;
    }
}
