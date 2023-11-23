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
import static org.wildfly.security.auth.realm.ElytronMessages.log;
import static org.wildfly.security.provider.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.security.Principal;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Supplier;

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

    private final Supplier<Provider[]> providerSupplier;
    private final SecurityRealm realm;
    private final RealmIdentityCache cache;

    /**
     * Creates a new instance.
     *
     * @param realm the {@link SecurityRealm} whose {@link RealmIdentity} should be cached.
     * @param cache the {@link RealmIdentityCache} instance
     */
    public CachingSecurityRealm(SecurityRealm realm, RealmIdentityCache cache) {
        this(realm, cache, INSTALLED_PROVIDERS);
    }

    /**
     * Creates a new instance.
     *
     * @param realm the {@link SecurityRealm} whose {@link RealmIdentity} should be cached.
     * @param cache the {@link RealmIdentityCache} instance
     * @param providerSupplier the provider supplier to use for verification purposes (must not be {@code null})
     */
    public CachingSecurityRealm(SecurityRealm realm, RealmIdentityCache cache, Supplier<Provider[]> providerSupplier) {
        this.realm = checkNotNullParam("realm", realm);
        this.cache = checkNotNullParam("cache", cache);
        this.providerSupplier = checkNotNullParam("providers", providerSupplier);

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
            log.tracef("Returning cached RealmIdentity for '%s'", principal);
            return cached;
        }

        RealmIdentity realmIdentity = getCacheableRealm().getRealmIdentity(principal);

        if (!realmIdentity.exists()) {
            log.tracef("RealmIdentity for '%s' does not exist, skipping cache.'", principal);
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
                    if (log.isTraceEnabled()) {
                        log.tracef("getCredentialAcquireSupport credentialType='%s' with algorithmName='%' known for pincipal='%s'", credentialType.getName(), algorithmName, principal.getName());
                    }
                    return credentials.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
                }
                Credential credential = identity.getCredential(credentialType, algorithmName, parameterSpec);
                if (credential != null) {
                    if (log.isTraceEnabled()) {
                        log.tracef("getCredentialAcquireSupport Credential for credentialType='%s' with algorithmName='%' obtained from identity - caching for principal='%s'",
                                credentialType.getName(), algorithmName, principal.getName());
                    }
                    credentials = credentials.withCredential(credential);
                }
                return credentials.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                if (credentials.contains(credentialType)) {
                    if (log.isTraceEnabled()) {
                        log.tracef("getCredential credentialType='%s' cached, returning cached credential for principal='%s'", credentialType.getName(), principal.getName());
                    }
                    return credentials.getCredential(credentialType);
                }
                Credential credential = identity.getCredential(credentialType);
                if (credential != null) {
                    if (log.isTraceEnabled()) {
                        log.tracef("getCredential credentialType='%s' obtained from identity - caching for principal='%s'", credentialType.getName(), principal.getName());
                    }
                    credentials = credentials.withCredential(credential);
                }
                return credentials.getCredential(credentialType);
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType, String algorithmName) throws RealmUnavailableException {
                if (credentials.contains(credentialType, algorithmName)) {
                    if (log.isTraceEnabled()) {
                        log.tracef("getCredential credentialType='%s' with algorithmName='%' cached, returning cached credential for principal='%s'", credentialType.getName(), algorithmName, principal.getName());
                    }
                    return credentials.getCredential(credentialType, algorithmName);
                }
                Credential credential = identity.getCredential(credentialType, algorithmName);
                if (credential != null) {
                    if (log.isTraceEnabled()) {
                        log.tracef("getCredential credentialType='%s' with algorithmName='%' obtained from identity - caching.", credentialType.getName(), algorithmName);
                    }
                    credentials = credentials.withCredential(credential);
                }
                return credentials.getCredential(credentialType, algorithmName);
            }

            @Override
            public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                if (credentials.contains(credentialType, algorithmName, parameterSpec)) {
                    if (log.isTraceEnabled()) {
                        log.tracef("getCredential credentialType='%s' with algorithmName='%' cached, returning cached credential for principal='%s'", credentialType.getName(), algorithmName, principal.getName());
                    }
                    return credentials.getCredential(credentialType, algorithmName, parameterSpec);
                }
                Credential credential = identity.getCredential(credentialType, algorithmName, parameterSpec);
                if (credential != null) {
                    if (log.isTraceEnabled()) {
                        log.tracef("getCredential credentialType='%s' with algorithmName='%' obtained from identity - caching for principal='%s'", credentialType.getName(), algorithmName, principal.getName());
                    }
                    credentials = credentials.withCredential(credential);
                }
                return credentials.getCredential(credentialType, algorithmName, parameterSpec);
            }

            @Override
            public void updateCredential(Credential credential) throws RealmUnavailableException {
                log.tracef("updateCredential For principal='%s'", principal);
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
                        if (log.isTraceEnabled()) {
                            log.tracef("getEvidenceVerifySupport evidenceType='%s' with algorithmName='%' can verify from cache for principal='%s'", evidenceType.getName(), algorithmName, principal.getName());
                        }
                        return SupportLevel.SUPPORTED;
                    }
                    Credential credential = identity.getCredential(PasswordCredential.class);
                    if (credential != null) {
                        if (log.isTraceEnabled()) {
                            log.tracef("getEvidenceVerifySupport evidenceType='%s' with algorithmName='%' credential obtained from identity and cached for principal='%s'",
                                    evidenceType.getName(), algorithmName, principal.getName());
                        }
                        credentials = credentials.withCredential(credential);
                        if (credential.canVerify(evidenceType, algorithmName)) {
                            return SupportLevel.SUPPORTED;
                        }
                    }
                }
                if (log.isTraceEnabled()) {
                    log.tracef("getEvidenceVerifySupport evidenceType='%s' with algorithmName='%' falling back to direct support of identity for principal='%s'",
                            evidenceType.getName(), algorithmName, principal.getName());
                }
                return identity.getEvidenceVerifySupport(evidenceType, algorithmName);
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                if (evidence instanceof PasswordGuessEvidence) {
                    if (credentials.canVerify(evidence)) {
                        log.tracef("verifyEvidence For principal='%s' using cached credential", principal);
                        boolean credentialsVerified = credentials.verify(providerSupplier, evidence);
                        if (!credentialsVerified) {
                            // since verification failed then verify evidence directly on an identity
                            log.tracef("verifyEvidence for principal='%1$s' using cached credential failed, so trying verifyEvidence for principal='%1$s' using underlying security realm", principal);
                            char[] guess = ((PasswordGuessEvidence) evidence).getGuess();
                            Password password = ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, guess);
                            if (identity.verifyEvidence(evidence)) {
                                credentials = credentials.without(PasswordCredential.class);
                                credentials = credentials.withCredential(new PasswordCredential(password));
                                attributes = null;
                                authorizationIdentity = null;
                                return true;
                            }
                        }
                        return credentialsVerified;
                    }
                    Credential credential = identity.getCredential(PasswordCredential.class);
                    if (credential != null) {
                        log.tracef("verifyEvidence Credential obtained from identity and cached for principal='%s'", principal);
                        credentials = credentials.withCredential(credential);
                        if (credential.canVerify(evidence)) {
                            return credential.verify(providerSupplier, evidence);
                        }
                    }
                    char[] guess = ((PasswordGuessEvidence) evidence).getGuess();
                    Password password = ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, guess);
                    log.tracef("verifyEvidence Falling back to direct support of identity for principal='%s'", principal);
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
                    log.tracef("getAuthorizationIdentity Caching AuthorizationIdentity for principal='%s'", principal);
                    authorizationIdentity = identity.getAuthorizationIdentity();
                }
                return authorizationIdentity;
            }

            @Override
            public Attributes getAttributes() throws RealmUnavailableException {
                if (attributes == null) {
                    log.tracef("getAttributes Caching Attributes for principal='%s'", principal);
                    attributes = identity.getAttributes();
                }
                return attributes;
            }

            @Override
            public void dispose() {
                identity.dispose();
            }
        };

        log.tracef("Created wrapper RealmIdentity for '%s' and placing in cache.", principal);
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
    protected SecurityRealm getCacheableRealm() {
        return realm;
    }
}
