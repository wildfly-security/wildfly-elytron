/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.credential.source;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Function;

import org.wildfly.common.Assert;
import org.wildfly.security.OneTimeSecurityFactory;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.key.KeyUtil;
import org.wildfly.security.auth.server._private.ElytronMessages;

/**
 * A source for credentials.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface CredentialSource {

    /**
     * Determine whether a given credential is definitely obtainable, possibly obtainable, or definitely not obtainable.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type does
     *  not support algorithm names
     * @param parameterSpec the algorithm parameters to match, or {@code null} if any parameters are acceptable or the credential type
     *  does not support algorithm parameters
     * @return the level of support for this credential type (not {@code null})
     *
     * @throws IOException if the credential source failed to determine the support level
     */
    SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException;

    /**
     * Determine whether a given credential is definitely obtainable, possibly obtainable, or definitely not obtainable.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does
     * not support algorithm names
     * @return the level of support for this credential type (not {@code null})
     * @throws IOException if the credential source failed to determine the support level
     */
    default SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws IOException {
        Assert.checkNotNullParam("credentialType", credentialType);
        return getCredentialAcquireSupport(credentialType, algorithmName, null);
    }

    /**
     * Determine whether a given credential is definitely obtainable, possibly obtainable, or definitely not obtainable.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @return the level of support for this credential type (not {@code null})
     * @throws IOException if the credential source failed to determine the support level
     */
    default SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType) throws IOException {
        Assert.checkNotNullParam("credentialType", credentialType);
        return getCredentialAcquireSupport(credentialType, null, null);
    }

    /**
     * Acquire a credential of the given type.  The credential type is defined by its {@code Class} and an optional {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type does
     *  not support algorithm names
     * @param parameterSpec the algorithm parameters to match, or {@code null} if any parameters are acceptable or the credential type
     *  does not support algorithm parameters
     * @param <C> the credential type
     *
     * @return the credential, or {@code null} if the principal has no credential of that type
     *
     * @throws IOException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws IOException;

    /**
     * Acquire a credential of the given type.  The credential type is defined by its {@code Class} and an optional
     * {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does
     * not support algorithm names
     * @param <C> the credential type
     * @return the credential, or {@code null} if the principal has no credential of that type
     * @throws IOException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    default <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName) throws IOException {
        Assert.checkNotNullParam("credentialType", credentialType);
        return getCredential(credentialType, algorithmName, null);
    }

    /**
     * Acquire a credential of the given type.  The credential type is defined by its {@code Class} and an optional
     * {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param <C> the credential type
     * @return the credential, or {@code null} if the principal has no credential of that type
     * @throws IOException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    default <C extends Credential> C getCredential(Class<C> credentialType) throws IOException {
        Assert.checkNotNullParam("credentialType", credentialType);
        return getCredential(credentialType, null, null);
    }

    /**
     * Apply the given function to the acquired credential, if it is set and of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param function the function to apply (must not be {@code null})
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     *
     * @throws IOException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    default <C extends Credential, R> R applyToCredential(Class<C> credentialType, Function<C, R> function) throws IOException {
        final Credential credential = getCredential(credentialType);
        return credential == null ? null : credential.castAndApply(credentialType, function);
    }

    /**
     * Apply the given function to the acquired credential, if it is set and of the given type and algorithm.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name
     * @param function the function to apply (must not be {@code null})
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     * @throws IOException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    default <C extends Credential, R> R applyToCredential(Class<C> credentialType, String algorithmName, Function<C, R> function) throws IOException {
        final Credential credential = getCredential(credentialType, algorithmName);
        return credential == null ? null : credential.castAndApply(credentialType, algorithmName, function);
    }

    /**
     * Apply the given function to the acquired credential, if it is set and of the given type and algorithm with the
     * given parameters.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name
     * @param parameterSpec the parameter specification or {@code null} if any parameter specification is acceptable
     * @param function the function to apply (must not be {@code null})
     * @param <C> the credential type
     * @param <R> the return type
     * @return the result of the function, or {@code null} if the criteria are not met
     * @throws IOException if the realm is not able to handle requests for any reason
     * @throws IllegalStateException if no authentication has been initiated or authentication is already completed
     */
    default <C extends Credential, R> R applyToCredential(Class<C> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec, Function<C, R> function) throws IOException {
        final Credential credential = getCredential(credentialType, algorithmName, parameterSpec);
        return credential == null ? null : credential.castAndApply(credentialType, algorithmName, parameterSpec, function);
    }

    /**
     * Aggregate this credential source with another.
     *
     * @param other the other credential source (must not be {@code null})
     * @return the aggregated credential source (not {@code null})
     */
    default CredentialSource with(CredentialSource other) {
        final CredentialSource self = this;
        return new CredentialSource() {
            public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
                return SupportLevel.max(self.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec), other.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec));
            }

            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
                C credential = self.getCredential(credentialType, algorithmName, parameterSpec);
                if (credential != null) {
                    return credential;
                } else {
                    return other.getCredential(credentialType, algorithmName, parameterSpec);
                }
            }

            public CredentialSource without(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
                final CredentialSource filteredSelf = self.without(credentialType, algorithmName, parameterSpec);
                final CredentialSource filteredOther = other.without(credentialType, algorithmName, parameterSpec);
                if (filteredSelf == NONE || filteredSelf == IdentityCredentials.NONE) {
                    if (filteredOther == NONE || filteredOther == IdentityCredentials.NONE) {
                        return NONE;
                    } else {
                        return filteredOther;
                    }
                } else if (filteredOther == NONE || filteredOther == IdentityCredentials.NONE) {
                    return filteredSelf;
                } else if (filteredSelf == self && filteredOther == other) {
                    return this;
                } else {
                    return filteredSelf.with(filteredOther);
                }
            }
        };
    }

    /**
     * Get a derived credential source which excludes credentials of the given type.
     *
     * @param credentialType the credential type to exclude (must not be {@code null})
     * @return the derived credential source (not {@code null})
     */
    default CredentialSource without(Class<? extends Credential> credentialType) {
        return without(credentialType, null, null);
    }

    /**
     * Get a derived credential source which excludes credentials of the given type and optional algorithm.
     *
     * @param credentialType the credential type to exclude (must not be {@code null})
     * @param algorithmName the algorithm name to exclude, or {@code null} to exclude all algorithms (or for credential types which do not use algorithms)
     * @return the derived credential source (not {@code null})
     */
    default CredentialSource without(Class<? extends Credential> credentialType, String algorithmName) {
        return without(credentialType, null, null);
    }

    /**
     * Get a derived credential source which excludes credentials of the given type and optional algorithm.
     *
     * @param credentialType the credential type to exclude (must not be {@code null})
     * @param algorithmName the algorithm name to exclude, or {@code null} to exclude all algorithms (or for credential types which do not use algorithms)
     * @param parameterSpec the parameter specification or {@code null} if any parameter specification is acceptable
     * @return the derived credential source (not {@code null})
     */
    default CredentialSource without(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) {
        return new CredentialSource() {
            public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
                if (isUnsupported(credentialType, algorithmName, parameterSpec)) {
                    return SupportLevel.UNSUPPORTED;
                } else {
                    return CredentialSource.this.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
                }
            }

            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
                if (isUnsupported(credentialType, algorithmName, parameterSpec)) {
                    return null;
                } else {
                    return CredentialSource.this.getCredential(credentialType, algorithmName, parameterSpec);
                }
            }

            private boolean isUnsupported(final Class<? extends Credential> testCredentialType, final String testAlgorithmName, final AlgorithmParameterSpec testParameterSpec) {
                return credentialType.isAssignableFrom(testCredentialType) && (algorithmName == null || algorithmName.equals(testAlgorithmName)) && (parameterSpec == null || KeyUtil.parametersEqual(parameterSpec, testParameterSpec));
            }

            public CredentialSource without(final Class<? extends Credential> testCredentialType, final String testAlgorithmName, final AlgorithmParameterSpec testParameterSpec) {
                final CredentialSource without = CredentialSource.this.without(testCredentialType, testAlgorithmName, testParameterSpec);
                if (without == NONE || without == IdentityCredentials.NONE) {
                    return NONE;
                }
                if (without == CredentialSource.this) {
                    return this;
                }
                return CredentialSource.super.without(credentialType, algorithmName, parameterSpec);
            }
        };
    }

    /**
     * An empty credential source.
     */
    CredentialSource NONE = new CredentialSource() {
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
            return SupportLevel.UNSUPPORTED;
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
            return null;
        }
    };

    /**
     * Get a credential source from the given security factory.  The factory is queried on each request.  If the value
     * should be cached after the first request, use {@link OneTimeSecurityFactory}.
     *
     * @param credentialFactory the credential factory (must not be {@code null})
     * @return the credential source (not {@code null})
     */
    static CredentialSource fromSecurityFactory(SecurityFactory<? extends Credential> credentialFactory) {
        Assert.checkNotNullParam("credentialFactory", credentialFactory);
        return new CredentialSource() {
            public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
                return SupportLevel.POSSIBLY_SUPPORTED;
            }

            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
                final Credential credential;
                try {
                    credential = credentialFactory.create();
                } catch (GeneralSecurityException e) {
                    throw ElytronMessages.log.cannotObtainCredentialFromFactory(e);
                }
                return credential.matches(credentialType, algorithmName, parameterSpec) ? credentialType.cast(credential) : null;
            }
        };
    }
}
