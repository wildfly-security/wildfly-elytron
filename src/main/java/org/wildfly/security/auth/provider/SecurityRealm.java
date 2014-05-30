/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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
import org.wildfly.security.auth.SecurityIdentity;
import org.wildfly.security.auth.verifier.Verifier;
import org.wildfly.security.auth.login.AuthenticationException;

/**
 * A single authentication realm.  A realm is backed by a single homogeneous store of identities and credentials.
 */
public interface SecurityRealm {

    /**
     * Perform a realm-specific mapping of the given name to a principal.  This may include rewriting of the
     * given name.
     *
     * @param name the original name
     * @return the principal
     */
    Principal mapNameToPrincipal(String name);

    /**
     * Acquire a credential of the given type from the realm.
     *
     * @param credentialType the credential type class
     * @param principal the principal to examine
     * @param <C> the credential type
     * @return the credential, or {@code null} if the principal has no credential of that type
     */
    <C> C getCredential(Class<C> credentialType, Principal principal);

    /**
     * Use a verifier to acquire proof of authentication.
     *
     * @param principal the principal to authenticate
     * @param verifier the verifier containing evidence of authenticity
     * @param <P> the type of proof returned by the verifier, or {@link Void} if the verifier cannot return proof
     * @return the proof, or {@code null} if the verifier cannot return proof
     * @throws AuthenticationException if the authentication of the principal cannot be verified based on the evidence
     */
    <P> P proveAuthentic(Principal principal, Verifier<P> verifier) throws AuthenticationException;

    /**
     * Determine whether a given credential is definitely supported, possibly supported (for some identities), or
     * definitely not supported.
     *
     * @param credentialType the credential type
     * @return the level of support for this credential type
     */
    CredentialSupport getCredentialSupport(Class<?> credentialType);

    /**
     * Determine whether a given credential is definitely supported, possibly supported, or
     * definitely not supported for a specific identity.
     *
     * @param principal the identity's principal
     * @param credentialType the credential type
     * @return the level of support for this credential type
     */
    CredentialSupport getCredentialSupport(Principal principal, Class<?> credentialType);

    SecurityIdentity createSecurityIdentity(Principal principal);
}
