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
import static org.wildfly.common.Assert.checkNotNullParam;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.credential.AlgorithmCredential;
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
     * Determine whether a given credential is definitely obtainable, possibly obtainable, or definitely not obtainable for this
     * identity.
     *
     * @param credentialName the name of the credential
     * @return the level of support for this credential type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    SupportLevel getCredentialSupport(String credentialName) throws RealmUnavailableException;

    /**
     * Acquire a credential of the given name.
     *
     * @param credentialName the name of the credential
     * @return the credential, or {@code null} if the principal has no credential of that name
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    Credential getCredential(String credentialName) throws RealmUnavailableException;

    /**
     * Acquire a credential of the given name, cast to the given type.
     *
     * @param credentialName the name of the credential
     * @param <C> the type to which should be credential casted
     * @param credentialType the class of type to which should be credential casted
     * @return the credential, or {@code null} if the principal has no credential of that name or cannot be casted to that type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    default <C extends Credential> C getCredential(String credentialName, Class<C> credentialType) throws RealmUnavailableException {
        Credential c = getCredential(checkNotNullParam("credentialName", credentialName));
        if (checkNotNullParam("credentialType", credentialType).isInstance(c)) {
            return credentialType.cast(c);
        }

        return null;
    }

    /**
     * Acquire a credential of the given name, if the {@link Credential} instance also implements {@link AlgorithmCredential}
     * verify that the algorithm is also in the list of supported algorithms, then cast to the given type.
     *
     * @param credentialName the name of the credential
     * @param <C> the type to which should be credential casted
     * @param supportedAlgorithms the Set of algorithm names with which the algorithm of the credential must match if it has one.
     * @return the credential, or {@code null} if the principal has no credential of that name, or the algorithm of the available credential was not available, or cannot be casted to that type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    default <C extends Credential> C getCredential(String credentialName, Class<C> credentialType, Set<String> supportedAlgorithms) throws RealmUnavailableException {
        checkNotNullParam("supportedAlgorithms", supportedAlgorithms);
        C c = getCredential(credentialName, credentialType);
        if (c != null && ( c instanceof AlgorithmCredential == false || supportedAlgorithms.contains(((AlgorithmCredential)c).getAlgorithm()))) {
            return c;
        }

        return null;
    }

    /**
     * Acquire a credential after resolving a List of possible credential names against a Map of supported credential types against Sets of supported algorithms for each of those types.
     *
     * @param credentialNames the list of credential names to attempt to load and cross reference against the Map of supported credentials along with their supported algorithms
     * @param supportedTypesWithAlgorithms the mapping of supported credential types associated with a set of supported algorithms for each of those types.
     * @return the credential resolved by the realm
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    default Credential getCredential(List<String> credentialNames, Map<Class<? extends Credential>, Set<String>> supportedTypesWithAlgorithms) throws RealmUnavailableException {
        for (String credentialName : credentialNames) {
            Credential c = getCredential(credentialName);
            if (c != null) {
                for (Entry<Class<? extends Credential>, Set<String>> currentEntry : supportedTypesWithAlgorithms.entrySet()) {
                    if (currentEntry.getKey().isInstance(c)) {
                        if (  c instanceof AlgorithmCredential == false || currentEntry.getValue().isEmpty() || currentEntry.getValue().contains(((AlgorithmCredential)c).getAlgorithm())) {
                            return c;
                        }
                    }
                }
            }
        }

        return null;
    }

    /**
     * Determine whether a given piece of evidence is definitely verifiable, possibly verifiable, or definitely not verifiable for this
     * identity.
     *
     * @param credentialName the name of the credential that the evidence is to be verified against
     * @return the level of support for this credential type
     * @throws RealmUnavailableException if the realm is not able to handle requests for any reason
     */
    default SupportLevel getEvidenceSupport(String credentialName) throws RealmUnavailableException {
        if (getCredentialSupport(credentialName) != SupportLevel.UNSUPPORTED) {
            return SupportLevel.POSSIBLY_SUPPORTED;
        }

        return SupportLevel.UNSUPPORTED;
    }

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

        public SupportLevel getCredentialSupport(final String credentialName) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }

        public Credential getCredential(String credentialName) {
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

        public SupportLevel getCredentialSupport(final String credentialName) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }

        public Credential getCredential(String credentialName) {
            return null;
        }

        public boolean exists() throws RealmUnavailableException {
            return false;
        }
    };
}
