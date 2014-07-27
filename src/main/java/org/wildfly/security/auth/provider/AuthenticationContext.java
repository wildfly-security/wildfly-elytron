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

import org.wildfly.security.auth.verifier.Verifier;
import org.wildfly.security.auth.login.AuthenticationException;

/**
 * Server-side authentication context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class AuthenticationContext {

    private final SecurityDomain domain;

    private String establishedRealmName;
    private RealmIdentity establishedRealmIdentity;

    AuthenticationContext(final SecurityDomain domain) {
        this.domain = domain;
    }

    /**
     * Establish the realm identity for this authentication by mapping the given name using the security domain configured name
     * rewriting rules and realm mapping.
     *
     * @param name the name to map.
     * @throws IllegalStateException if a different realm name has already been set for this authentication.
     */
    public void establishRealmIdentity(String name) throws IllegalStateException {
        final RealmIdentity realmIdentity = domain.mapName(name);
        if (establishedRealmName != null && realmIdentity.getRealmName().equals(establishedRealmName) == false) {
            // TODO If a realm name has been specified maybe we should be using it instead? e.g. final opportunity for ambiguous names.
            throw new IllegalStateException();
        }
        establishedRealmIdentity = realmIdentity;
    }

    /**
     * Establish the realm for this authentication.
     *
     * @param realmName the realm name
     *
     * @throws IllegalStateException if a different realm was already set for this authenticator
     */
    public void establishRealm(String realmName) throws IllegalStateException {
        if (establishedRealmName != null && !establishedRealmName.equals(realmName)) {
            throw new IllegalStateException();
        }
        establishedRealmName = realmName;
    }

    /**
     * Establish the realm identity for this authentication based on the supplied Principal.
     *
     * @param principal the principal to set
     *
     * @throws IllegalStateException if no realm is established or of an identity with a different principal has already been
     *         established.
     */
    public void establishRealmIdentity(Principal principal) throws IllegalStateException {
        if (establishedRealmName == null || establishedRealmIdentity != null
                && establishedRealmIdentity.getPrincipal().equals(principal) == false) {
            throw new IllegalStateException();
        }

        SecurityRealm realm = domain.getRealm(establishedRealmName);
        establishedRealmIdentity = realm.createRealmIdentity(principal);
    }

    /**
     * Get the established principal for this authentication.
     *
     * @return the established principal, or {@code null} if no principal was established yet
     */
    public Principal getEstablishedPrincipal() {
        return establishedRealmIdentity != null ? establishedRealmIdentity.getPrincipal() : null;
    }

    /**
     * Get the name of the established realm.
     *
     * @return the name of the established realm, or {@code null} if no realm was established yet
     */
    public String getEstablishedRealmName() {
        return establishedRealmName;
    }

    /**
     * Prove authenticity based on evidence which is delivered to the identity store for verification. The proof of verification
     * is returned. If the mechanism does not support any proof, such as simple password verification, then the proof type
     * should be {@link Void} and the result will always be {@code null}. Otherwise, if proof is expected but {@code null} is
     * returned, the authentication should be rejected.
     *
     * @param verifier the verifier of the evidence
     * @param <P> the type of proof
     *
     * @return the proof of verification, or {@code null} if no such proof is available
     *
     * @throws AuthenticationException if verification failed
     * @throws IllegalStateException if the realm name and/or principal has not been established
     */
    public <P> P proveAuthentic(Verifier<P> verifier) throws AuthenticationException {
        if (establishedRealmIdentity == null) {
            throw new IllegalStateException("No realm identity established");
        }
        return establishedRealmIdentity.proveAuthentic(verifier);
    }

    /**
     * Get the level of support for the given credential type. Note that establishing more information (such as realm name or
     * principal) may provide a more definite result.
     *
     * @param credentialType the credential type
     * @return the level of credential support
     */
    public CredentialSupport getCredentialSupport(Class<?> credentialType) {
        if (establishedRealmName == null) {
            return domain.getCredentialSupport(credentialType);
        }
        if (establishedRealmIdentity == null) {
            return domain.getCredentialSupport(establishedRealmName, credentialType);
        }
        return establishedRealmIdentity.getCredentialSupport(credentialType);
    }
}
