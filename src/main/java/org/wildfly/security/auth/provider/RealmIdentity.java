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

package org.wildfly.security.auth.provider;

import java.security.Principal;

import org.wildfly.security.password.AugmentedPassword;

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
     * Get the {@link Principal} for this identity.
     *
     * This method can return {@code null} if there is no mapping from the identity to a {@link Principal}
     *
     * @return The {@link Principal} for this identity.
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason.
     */
    Principal getPrincipal() throws RealmUnavailableException;

    /**
     * Determine level of credential support for this identity.
     *
     * @param credentialType the credential type
     * @return the level of support for this credential type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason.
     */
    CredentialSupport getCredentialSupport(Class<?> credentialType) throws RealmUnavailableException;

    /**
     * Determine level of credential support for this identity.
     *
     * @param credentialType the credential type
     * @param metaData additional credential specific meta-data.
     * @return the level of support for this credential type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason.
     */
    default <M> CredentialSupport getCredentialSupport(Class<? extends AugmentedPassword<M>> credentialType, M metaData) throws RealmUnavailableException {
        return getCredentialSupport(credentialType);
    }

    /**
     * Acquire a credential of the given type.
     *
     * @param credentialType the credential type class
     * @param <C> the credential type
     * @return the credential, or {@code null} if the principal has no credential of that type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason.
     */
    <C> C getCredential(Class<C> credentialType) throws RealmUnavailableException;

    /**
     * Acquire a credential of the given type.
     *
     * @param credentialType the credential type class
     * @param <C> the credential type
     * @param metaData additional credential specific meta-data.
     * @return the credential, or {@code null} if the principal has no credential of that type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason.
     */
    default <C extends AugmentedPassword<M>, M> C getCredential(Class<C> credentialType, M metaData) throws RealmUnavailableException {
        return getCredential(credentialType);
    }

    /**
     * Verify the given credential.
     *
     * @param credential the credential to verify
     * @return {@code true} if verification was successful, {@code false} otherwise.
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason.
     */
    boolean verifyCredential(Object credential) throws RealmUnavailableException;

    /**
     * Dispose this realm identity after a completed authentication attempt.
     */
    void dispose();

    /**
     * Get an authenticated realm identity for this pre-authenticated identity.
     *
     * @return the authenticated realm identity (may not be {@code null})
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason.
     */
    AuthenticatedRealmIdentity getAuthenticatedRealmIdentity() throws RealmUnavailableException;

}
