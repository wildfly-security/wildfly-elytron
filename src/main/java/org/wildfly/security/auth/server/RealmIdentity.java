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

import java.security.Principal;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * A representation of a pre-authentication identity.
 *
 * The life of a {@code RealmIdentity} is short and is for a specific authentication attempt. A {@link SecurityRealm} creating a
 * {@code RealmIdentity} does not confirm the existence of the identity.  The {@link #exists()} method must be used
 * for that purpose.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface RealmIdentity {

    /**
     * Get the decoded principal for this realm identity, if any.  This method <em>may</em> return the principal object
     * which was passed in as a parameter to {@link SecurityRealm#getRealmIdentity(String, Principal, Evidence)}, but
     * is not required to do so.  Any existent realm identity (i.e. any identity which returns {@code true} on invocation
     * of {@link #exists()}) which was not provided with a name or principal <em>must</em> return a non-{@code null}
     * principal (which should have been decoded from the evidence provided to the {@code getRealmIdentity} method).
     *
     * @return the decoded principal for this realm identity, or {@code null} if no special decoding is in use
     */
    default Principal getRealmIdentityPrincipal() {
        return null;
    }

    /**
     * Determine whether a given credential type is definitely obtainable, possibly obtainable, or definitely not
     * obtainable for this identity.
     *
     * @param credentialType the exact credential type (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type does
     *  not support algorithm names
     * @return the level of support for this credential type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException;

    /**
     * Acquire a credential of the given type.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param <C> the credential type
     * @return the credential, or {@code null} if no such credential exists
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException;

    /**
     * Acquire a credential of the given type and algorithm name.
     *
     * @param credentialType the credential type class (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type
     * does not support algorithm names
     * @param <C> the credential type
     *
     * @return the credential, or {@code null} if no such credential exists
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    default <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName) throws RealmUnavailableException {
        if (algorithmName != null) {
            final C credential = getCredential(credentialType);
            return credential instanceof AlgorithmCredential && algorithmName.equals(((AlgorithmCredential) credential).getAlgorithm()) ? credential : null;
        } else {
            return getCredential(credentialType);
        }
    }

    /**
     * Determine whether a given type of evidence is definitely verifiable, possibly verifiable, or definitely not verifiable.
     *
     * @param evidenceType the type of evidence to be verified (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the evidence type does
     *  not support algorithm names
     * @return the level of support for this evidence type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException;

    /**
     * Verify the given evidence against a credential of this identity.  The credential to be used is selected based on
     * the evidence type.
     *
     * @param evidence the evidence to verify
     * @return {@code true} if verification was successful, {@code false} otherwise
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException;

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
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    default AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
        if (exists()) {
            return AuthorizationIdentity.EMPTY;
        } else {
            throw log.userDoesNotExist();
        }
    }

    /**
     * Determine if this realm identity was created by the given security realm.
     *
     * @param securityRealm the security realm to check
     * @return {@code true} if this realm identity was created by the given security realm, {@code false} otherwise
     */
    boolean createdBySecurityRealm(SecurityRealm securityRealm);

    /**
     * The anonymous realm identity.
     */
    RealmIdentity ANONYMOUS = new RealmIdentity() {
        public Principal getRealmIdentityPrincipal() {
            return AnonymousPrincipal.getInstance();
        }

        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            return SupportLevel.UNSUPPORTED;
        }

        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);
            return SupportLevel.UNSUPPORTED;
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            return null;
        }

        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);
            return false;
        }

        public boolean exists() throws RealmUnavailableException {
            return true;
        }

        public boolean createdBySecurityRealm(final SecurityRealm securityRealm) {
            return SecurityRealm.EMPTY_REALM == securityRealm;
        }
    };

    /**
     * An identity for a non-existent user.
     */
    RealmIdentity NON_EXISTENT = new RealmIdentity() {
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            return SupportLevel.UNSUPPORTED;
        }

        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);
            return SupportLevel.UNSUPPORTED;
        }

        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            return null;
        }

        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);
            return false;
        }

        public boolean exists() throws RealmUnavailableException {
            return false;
        }

        public boolean createdBySecurityRealm(final SecurityRealm securityRealm) {
            return false;
        }
    };
}
