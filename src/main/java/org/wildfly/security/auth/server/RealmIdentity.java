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

package org.wildfly.security.auth.server;

import static org.wildfly.security._private.ElytronMessages.log;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;

/**
 * A representation of a pre-authentication identity.
 *
 * The life of a {@code RealmIdentity} is short and is for a specific authentication attempt. A {@link SecurityRealm} creating a
 * {@code RealmIdentity} does not confirm the existence of the identity.
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface RealmIdentity {

    /**
     * Get the identity's name within the realm.
     *
     * @return the name of the identity within the realm
     */
    String getName();

    /**
     * Determine whether a given credential is definitely supported, possibly supported, or definitely not supported for this
     * identity.  The credential type is defined by its {@code Class} and an optional {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param credentialType the credential type
     * @param algorithmName the optional algorithm name for the credential type
     * @return the level of support for this credential type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    CredentialSupport getCredentialSupport(Class<?> credentialType, String algorithmName) throws RealmUnavailableException;

    /**
     * Acquire a credential of the given type.  The credential type is defined by its {@code Class} and an optional {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param <C> the credential type
     * @param credentialType the credential type class
     * @param algorithmName the optional algorithm name for the credential type
     * @return the credential, or {@code null} if the principal has no credential of that type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    <C> C getCredential(Class<C> credentialType, final String algorithmName) throws RealmUnavailableException;

    /**
     * Verify the given credential.
     *
     * @param credential the credential to verify
     * @return {@code true} if verification was successful, {@code false} otherwise
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    boolean verifyCredential(Object credential) throws RealmUnavailableException;

    /**
     * Determine if the identity exists in lieu of verifying or acquiring a credential.  This method is intended to be
     * used to verify an identity for non-authentication purposes only.
     *
     * @return {@code true} if the identity exists in this realm, {@code false} otherwise
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    boolean exists() throws RealmUnavailableException;

    /**
     * Dispose this realm identity after a completed authentication attempt.
     */
    default void dispose() {
    }

    /**
     * Get an authorization identity for this pre-authenticated identity.
     *
     * @return the authorization identity (may not be {@code null})
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException;

    /**
     * Get the attributes for the realm identity
     *
     * @return the Attributes
     * @throws IndexOutOfBoundsException if {@code idx} is less than 0 or greater than or equal to {@code size(key)}
     * @throws UnsupportedOperationException if the implementing class does not support getting attributes
     * @throws RealmUnavailableException if accessing the attributes fails for some reason
     */
    default Attributes getAttributes() throws RealmUnavailableException {
        throw ElytronMessages.log.attributesNotSupportedByRealm();
    }

    /**
     * The anonymous realm identity.
     */
    RealmIdentity ANONYMOUS = new RealmIdentity() {

        public String getName() {
            return "anonymous";
        }

        public CredentialSupport getCredentialSupport(final Class<?> credentialType, final String algorithmName) throws RealmUnavailableException {
            return CredentialSupport.UNSUPPORTED;
        }

        public <C> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return null;
        }

        public boolean verifyCredential(final Object credential) throws RealmUnavailableException {
            return false;
        }

        public boolean exists() throws RealmUnavailableException {
            return true;
        }

        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            return AuthorizationIdentity.EMPTY;
        }
    };

    /**
     * An identity for a non-existent user.
     *
     * @param name the identity name
     * @return the realm identity
     */
    static RealmIdentity nonExistentIdentity(String name) {
        Assert.checkNotNullParam("name", name);
        return new RealmIdentity() {

            public String getName() {
                return name;
            }

            public CredentialSupport getCredentialSupport(final Class<?> credentialType, final String algorithmName) throws RealmUnavailableException {
                return CredentialSupport.UNSUPPORTED;
            }

            public <C> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
                return null;
            }

            public boolean verifyCredential(final Object credential) throws RealmUnavailableException {
                return false;
            }

            public boolean exists() throws RealmUnavailableException {
                return false;
            }

            public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
                // todo: exception hierarchy
                throw log.userDoesNotExist();
            }
        };
    }
}
