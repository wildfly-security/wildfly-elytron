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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import java.security.cert.X509Certificate;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.X509CertificateChainCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.evidence.X509PeerCertificateEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;

/**
 * A representation of a pre-authentication identity.
 *
 * The life of a {@code RealmIdentity} is short and is for a specific authentication attempt. A {@link SecurityRealm} creating a
 * {@code RealmIdentity} does not confirm the existence of the identity.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface RealmIdentity {

    /**
     * Determine whether a given credential is definitely supported, possibly supported, or definitely not supported for this
     * identity.  The credential type is defined by its {@code Class} and an optional {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param credentialName the name of the credential
     * @return the level of support for this credential type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    CredentialSupport getCredentialSupport(String credentialName) throws RealmUnavailableException;

    /**
     * Acquire a credential of the given type.  The credential type is defined by its {@code Class} and an optional {@code algorithmName}.  If the
     * algorithm name is not given, then the query is performed for any algorithm of the given type.
     *
     * @param <C> the type to which should be credential casted
     * @param credentialName the name of the credential
     * @param credentialType the class of type to which should be credential casted
     * @return the credential, or {@code null} if the principal has no credential of that name or cannot be casted to that type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    <C extends Credential> C getCredential(String credentialName, Class<C> credentialType) throws RealmUnavailableException;

    /**
     * Verify the given credential.
     *
     * @param evidence the evidence to verify
     *
     * @return {@code true} if verification was successful, {@code false} otherwise
     *
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    default boolean verifyEvidence(String credentialName, Evidence evidence) throws RealmUnavailableException {
        if (evidence instanceof PasswordGuessEvidence) {
            char[] passwordGuess = ((PasswordGuessEvidence) evidence).getGuess();
            final PasswordCredential credential = getCredential(credentialName, PasswordCredential.class);
            if (credential != null) try {
                final Password password = credential.getPassword();
                final PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
                final Password translated = passwordFactory.translate(password);
                return passwordFactory.verify(translated, passwordGuess);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                return false;
            }
        } else if (evidence instanceof X509PeerCertificateEvidence) {
            final X509Certificate certificate = ((X509PeerCertificateEvidence) evidence).getPeerCertificate();
            final X509CertificateChainCredential credential = getCredential(credentialName, X509CertificateChainCredential.class);
            if (credential != null) {
                final X509Certificate[] certificateChain = credential.getCertificateChain();
                if (certificateChain.length > 0) {
                    return certificateChain[0].equals(certificate);
                }
            }
        }
        return false;
    }

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
     * The anonymous realm identity.
     */
    RealmIdentity ANONYMOUS = new RealmIdentity() {

        public String getName() {
            return "anonymous";
        }

        public CredentialSupport getCredentialSupport(final String credentialName) throws RealmUnavailableException {
            return CredentialSupport.UNSUPPORTED;
        }

        public <C extends Credential> C getCredential(final String credentialName, final Class<C> credentialType) throws RealmUnavailableException {
            return null;
        }

        public boolean exists() throws RealmUnavailableException {
            return true;
        }
    };

    /**
     * An identity for a non-existent user.
     */
    RealmIdentity NON_EXISTENT = new RealmIdentity() {

        public CredentialSupport getCredentialSupport(final String credentialName) throws RealmUnavailableException {
            return CredentialSupport.UNSUPPORTED;
        }

        public <C extends Credential> C getCredential(final String credentialName, final Class<C> credentialType) throws RealmUnavailableException {
            return null;
        }

        public boolean exists() throws RealmUnavailableException {
            return false;
        }
    };
}
