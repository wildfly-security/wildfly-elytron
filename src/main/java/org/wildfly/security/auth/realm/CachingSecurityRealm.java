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

package org.wildfly.security.auth.realm;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.cache.RealmIdentityCache;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * <p>A wrapper class that provides caching capabilities for a {@link SecurityRealm} and its identities.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class CachingSecurityRealm implements SecurityRealm {

    private final CacheableSecurityRealm realm;
    private final RealmIdentityCache cache;

    /**
     * Creates a new instance.
     *
     * @param realm the {@link SecurityRealm} whose {@link RealmIdentity} should be cached.
     * @param cache the {@link RealmIdentityCache} instance
     */
    public CachingSecurityRealm(CacheableSecurityRealm realm, RealmIdentityCache cache) {
        this.realm = checkNotNullParam("realm", realm);
        this.cache = checkNotNullParam("cache", cache);

        if (realm instanceof CacheableSecurityRealm) {
            CacheableSecurityRealm cacheable = CacheableSecurityRealm.class.cast(realm);
            cacheable.registerIdentityChangeListener(this::removeFromCache);
        } else {
            throw ElytronMessages.log.realmCacheUnexpectedType(realm, CacheableSecurityRealm.class);
        }
    }

    @Override
    public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
        RealmIdentity cached = cache.get(principal);

        if (cached != null) {
            return cached;
        }

        RealmIdentity realmIdentity = getCacheableRealm().getRealmIdentity(principal);

        if (!realmIdentity.exists()) {
            return realmIdentity;
        }

        RealmIdentity cachedIdentity = new RealmIdentity() {
            final RealmIdentity identity = realmIdentity;

            AuthorizationIdentity authorizationIdentity = null;
            Attributes attributes = null;
            IdentityCredentials credentials = IdentityCredentials.NONE;

            @Override
            public Principal getRealmIdentityPrincipal() {
                return identity.getRealmIdentityPrincipal();
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                if (credentials.contains(credentialType, algorithmName, parameterSpec)) {
                    return credentials.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
                }
                Credential credential = identity.getCredential(credentialType, algorithmName, parameterSpec);
                if (credential != null) {
                    credentials = credentials.withCredential(credential);
                }
                return credentials.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                if (credentials.contains(credentialType)) {
                    return credentials.getCredential(credentialType);
                }
                Credential credential = identity.getCredential(credentialType);
                if (credential != null) {
                    credentials = credentials.withCredential(credential);
                }
                return credentials.getCredential(credentialType);
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName) throws RealmUnavailableException {
                if (credentials.contains(credentialType, algorithmName)) {
                    return credentials.getCredential(credentialType, algorithmName);
                }
                Credential credential = identity.getCredential(credentialType, algorithmName);
                if (credential != null) {
                    credentials = credentials.withCredential(credential);
                }
                return credentials.getCredential(credentialType, algorithmName);
            }

            @Override
            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                if (credentials.contains(credentialType, algorithmName, parameterSpec)) {
                    return credentials.getCredential(credentialType, algorithmName, parameterSpec);
                }
                Credential credential = identity.getCredential(credentialType, algorithmName, parameterSpec);
                if (credential != null) {
                    credentials = credentials.withCredential(credential);
                }
                return credentials.getCredential(credentialType, algorithmName, parameterSpec);
            }

            @Override
            public void updateCredential(Credential credential) throws RealmUnavailableException {
                try {
                    identity.updateCredential(credential);
                } finally {
                    removeFromCache(identity.getRealmIdentityPrincipal());
                }
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                if (PasswordGuessEvidence.class.isAssignableFrom(evidenceType)) {
                    if (credentials.canVerify(evidenceType, algorithmName)) {
                        return SupportLevel.SUPPORTED;
                    }
                    Credential credential = identity.getCredential(PasswordCredential.class);
                    if (credential != null) {
                        credentials = credentials.withCredential(credential);
                        if (credential.canVerify(evidenceType, algorithmName)) {
                            return SupportLevel.SUPPORTED;
                        }
                    }
                }
                return identity.getEvidenceVerifySupport(evidenceType, algorithmName);
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                if (evidence instanceof PasswordGuessEvidence) {
                    if (credentials.canVerify(evidence)) {
                        return credentials.verify(evidence);
                    }
                    Credential credential = identity.getCredential(PasswordCredential.class);
                    if (credential != null) {
                        credentials = credentials.withCredential(credential);
                        if (credential.canVerify(evidence)) {
                            return credential.verify(evidence);
                        }
                    }
                    char[] guess = ((PasswordGuessEvidence) evidence).getGuess();
                    Password password = ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, guess);
                    if (identity.verifyEvidence(evidence)) {
                        credentials = credentials.withCredential(new PasswordCredential(password));
                        return true;
                    }
                    return false;
                }
                return identity.verifyEvidence(evidence);
            }

            @Override
            public boolean exists() throws RealmUnavailableException {
                return true; // non-existing identities will not be wrapped
            }

            @Override
            public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
                if (authorizationIdentity == null) {
                    authorizationIdentity = identity.getAuthorizationIdentity();
                }
                return authorizationIdentity;
            }

            @Override
            public Attributes getAttributes() throws RealmUnavailableException {
                if (attributes == null) {
                    attributes = identity.getAttributes();
                }
                return attributes;
            }

            @Override
            public void dispose() {
                identity.dispose();
            }
        };

        cache.put(principal, cachedIdentity);

        return cachedIdentity;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        return getCacheableRealm().getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        return getCacheableRealm().getEvidenceVerifySupport(evidenceType, algorithmName);
    }

    @Override
    public void handleRealmEvent(RealmEvent event) {
        getCacheableRealm().handleRealmEvent(event);
    }

    /**
     * Removes a {@link RealmIdentity} referenced by the specified {@link Principal} from the cache.
     *
     * @param principal the {@link Principal} that references a previously cached realm identity
     */
    public void removeFromCache(Principal principal) {
        cache.remove(principal);
    }

    /**
     * Removes all cached identities from the cache.
     */
    public void removeAllFromCache() {
        cache.clear();
    }

    /**
     * Gets wrapped backing realm.
     *
     * @return the wrapped backing realm
     */
    protected CacheableSecurityRealm getCacheableRealm() {
        return realm;
    }
}
