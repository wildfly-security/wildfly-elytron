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

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.cache.RealmIdentityCache;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * <p>A wrapper class that provides caching capabilities for a {@link org.wildfly.security.auth.server.SecurityRealm} and its identities.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class CachingSecurityRealm implements SecurityRealm {

    private final CacheableSecurityRealm realm;
    private final RealmIdentityCache cache;

    /**
     * Creates a new instance.
     *
     * @param realm the {@link SecurityRealm} whose {@link RealmIdentity} should be cached..
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
        return cache.computeIfAbsent(principal, principal1 -> {
            try {
                return getCacheableRealm().getRealmIdentity(principal1);
            } catch (RealmUnavailableException cause) {
                throw ElytronMessages.log.realmCacheFailedObtainIdentityFromCache(cause);
            }
        });
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
        return getCacheableRealm().getCredentialAcquireSupport(credentialType, algorithmName);
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

    protected CacheableSecurityRealm getCacheableRealm() {
        return realm;
    }
}
