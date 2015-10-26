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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
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
     * @serial The map of supported credential types.
     */
    private final Map<Class<? extends Credential>, Set<String>> supportedTypes;
    /**
     * @serial The credential itself.
     */
    private Credential credential;

    /**
     * Construct a new instance.
     *
     * @param supportedTypes the supported types of credential
     */
    private CredentialCallback(final Map<Class<? extends Credential>, Set<String>> supportedTypes) {
        this.supportedTypes = supportedTypes;
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
        final Set<String> set = supportedTypes.get(credentialType);
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
     * Get the set of supported types for this credential.
     *
     * @return the (immutable) set of supported types
     */
    public Set<Class<? extends Credential>> getSupportedTypes() {
        return Collections.unmodifiableSet(supportedTypes.keySet());
    }

    /**
     * Get the supported algorithms for the given exact credential type.  The returned set may be empty, indicating that
     * no algorithm is required for the given credential, or {@code null} indicating that the credential type is not
     * supported.
     *
     * @param type the credential type
     * @return the (immutable) set of supported algorithms
     */
    public Set<String> getSupportedAlgorithms(Class<? extends Credential> type) {
        return supportedTypes.get(type);
    }

    /**
     * Get the map of supported types along with the supported algorithms for each of those types.
     *
     * @return the map of supported types along with the supported algorithms for each of those types
     */
    public Map<Class<? extends Credential>, Set<String>> getSupportedTypesWithAlgorithms() {
        return Collections.unmodifiableMap(supportedTypes);
    }

    public boolean isOptional() {
        return credential != null;
    }

    public boolean needsInformation() {
        return true;
    }

    /**
     * Factory method to create a builder for a {@link CredentialCallback}.
     *
     * @return A builder for a {@link CredentialCallback}.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The non-Thread safe builder of {@link CredentialCallback} instances.
     */
    public static class Builder {

        private final Map<Class<? extends Credential>, Set<String>> supportedTypes = new HashMap<>();
        private boolean built = false;

        private Builder() {};

        private void assertNotBuilt() {
            if (built) {
                throw new IllegalStateException("CredentialCallback has already been built.");
            }
        }

        /**
         * Add a credential type to be supported by the {@link CredentialCallback}.
         *
         * The specified credential type is considered supported for all algorithms.
         *
         * @param credentialType the supported {@link Credential} type.
         * @return This {@link Builder} to allow additional types to be added.
         */
        public Builder addSupportedCredentialType(final Class<? extends Credential> credentialType) {
            assertNotBuilt();
            if (supportedTypes.containsKey(credentialType)) {
                throw new IllegalStateException("Credential type already added.");
            }

            supportedTypes.put(credentialType, Collections.emptySet());

            return this;
        }

        /**
         * Add a credential type to be supported by the {@link CredentialCallback} along with the list of algorithms it is supported with.
         *
         * @param credentialType credentialType the supported {@link Credential} type.
         * @param supportedAlgorithms the names of the algorithms the credential type is supported with.
         * @return This {@link Builder} to allow additional types to be added.
         */
        public Builder addSupportedCredentialType(final Class<? extends Credential> credentialType, final String... supportedAlgorithms) {
            assertNotBuilt();
            if (supportedTypes.containsKey(credentialType)) {
                throw new IllegalStateException("Credential type already added.");
            }

            supportedTypes.put(credentialType, Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(supportedAlgorithms))));

            return this;
        }

        /**
         * Build the {@link CredentialCallback} with the set of supported credential types added to this builder.
         *
         * Once this builder is built no further modifications are allowed.
         *
         * @return The {@link CredentialCallback} with the set of supported credential types added to this builder.
         */
        public CredentialCallback build() {
            assertNotBuilt();
            built = true;

            return new CredentialCallback(supportedTypes);
        }

    }


}
