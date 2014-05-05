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
import java.util.Set;
import org.wildfly.security.auth.verifier.Verifier;
import org.wildfly.security.auth.login.AuthenticationException;

/**
 * Server-side authentication context.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationContext {

    private final SecurityDomain domain;

    private String establishedRealmName;
    private Principal establishedPrincipal;

    AuthenticationContext(final SecurityDomain domain) {
        this.domain = domain;
    }

    /**
     * Establish the principal and realm for this authentication by mapping the given name using the security
     * domain-configured name rewriting rules and realm mapping.
     *
     * @param name the name to map
     *
     * @throws IllegalStateException if a different principal or realm was already set for this authenticator
     */
    public void establishMappedName(String name) throws IllegalStateException {
        final PrincipalAndRealmName principalAndRealm = domain.mapName(name);
        if (establishedRealmName != null && ! principalAndRealm.getRealmName().equals(establishedRealmName)) {
            throw new IllegalStateException();
        } else {
            establishedRealmName = principalAndRealm.getRealmName();
        }
    }

    /**
     * Establish the principal for this authentication.
     *
     * @param principal the principal to set
     *
     * @throws IllegalStateException if a different principal was already set for this authenticator
     */
    public void establishPrincipal(Principal principal) throws IllegalStateException {
        if (establishedPrincipal != null && ! establishedPrincipal.equals(principal)) {
            throw new IllegalStateException();
        } else {
            establishedPrincipal = principal;
        }
    }

    /**
     * Get the established principal for this authentication.
     *
     * @return the established principal, or {@code null} if no principal was established yet
     */
    public Principal getEstablishedPrincipal() {
        return establishedPrincipal;
    }

    /**
     * Establish the realm for this authentication.
     *
     * @param realmName the realm name
     *
     * @throws IllegalStateException if a different realm was already set for this authenticator
     */
    public void establishRealm(String realmName) throws IllegalStateException {
        if (establishedRealmName != null && ! establishedRealmName.equals(realmName)) {
            throw new IllegalStateException();
        } else {
            establishedRealmName = realmName;
        }
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
     * Prove authenticity based on evidence which is delivered to the identity store for verification.  The proof of
     * verification is returned.  If the mechanism does not support any proof, such as simple password verification,
     * then the proof type should be {@link Void} and the result will always be {@code null}.  Otherwise, if proof is
     * expected but {@code null} is returned, the authentication should be rejected.
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
        if (establishedRealmName == null) {
            throw new IllegalStateException("No realm established");
        }
        if (establishedPrincipal == null) {
            throw new IllegalStateException("No principal established");
        }
        final SecurityRealm realm = domain.getRealm(establishedRealmName);
        return realm.proveAuthentic(establishedPrincipal, verifier);
    }

    /**
     * Get the level of support for the given credential type.  Note that establishing more information (such as realm
     * name or principal) may provide a more definite result.
     *
     * @param credentialType the credential type
     * @return the level of credential support
     */
    public CredentialSupport getCredentialSupport(Class<?> credentialType) {
        if (establishedRealmName == null) {
            return domain.getCredentialSupport(credentialType);
        }
        if (establishedPrincipal == null) {
            return domain.getCredentialSupport(establishedRealmName, credentialType);
        }
        return domain.getCredentialSupport(establishedRealmName, establishedPrincipal, credentialType);
    }
}
