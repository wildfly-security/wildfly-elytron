/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.cache;

import static org.wildfly.common.Assert.checkMinimumParameter;

import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import org.wildfly.security.auth.server.RealmIdentity;

/**
 * A {@link RealmIdentityCache} implementation providing a LRU cache.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class LRURealmIdentityCache implements RealmIdentityCache {

    /**
     * The load factor.
     */
    private static final float DEFAULT_LOAD_FACTOR = 0.75f;

    /**
     * Holds the cached identitys where the key is the domain principal, the one used to lookup the identity
     */
    private final LinkedHashMap<Principal, CacheEntry> identityCache;

    /**
     * Holds a mapping between a realm principal and domain principals
     */
    private final Map<Principal, Set<Principal>> domainPrincipalMap;

    private final ReentrantLock lock = new ReentrantLock();

    private final int maxEntries;
    private final long maxAge;

    /**
     * Creates a new instance.
     *
     * @param maxEntries the maximum number of entries to keep in the cache
     */
    public LRURealmIdentityCache(int maxEntries) {
        this(maxEntries, -1);
    }

    /**
     * Creates a new instance.
     *
     * @param maxEntries the maximum number of entries to keep in the cache
     * @param maxAge the time in milliseconds that an entry can stay in the cache. If {@code -1}, entries never expire
     */
    public LRURealmIdentityCache(int maxEntries, long maxAge) {
        checkMinimumParameter("maxEntries", 1, maxEntries);
        checkMinimumParameter("maxAge", -1, maxAge);
        identityCache = new LinkedHashMap<>(16, DEFAULT_LOAD_FACTOR, true);
        domainPrincipalMap = new HashMap<>(16);
        this.maxEntries = maxEntries;
        this.maxAge = maxAge;
    }

    @Override
    public void put(Principal key, RealmIdentity newValue) {
        lock.lock();
        try {
            CacheEntry entry = identityCache.get(key);

            if (entry == null) {
                entry = new CacheEntry(newValue, maxAge);
                identityCache.put(key, entry);
            }

            domainPrincipalMap.computeIfAbsent(entry.value().getRealmIdentityPrincipal(), ignored -> new HashSet<>()).add(key);
            evictIfNecessary();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public RealmIdentity get(Principal key) {
        lock.lock();
        try {
            CacheEntry cached = identityCache.get(key);

            if (cached != null) {
                return removeIfExpired(cached);
            }

            Set<Principal> domainPrincipals = domainPrincipalMap.get(key);

            if (domainPrincipals != null) {
                for (Principal domainPrincipal : new HashSet<>(domainPrincipals)) {
                    CacheEntry associated = identityCache.get(domainPrincipal);

                    if (associated == null) {
                        removeDomainPrincipal(domainPrincipal, key);
                        continue;
                    }

                    return removeIfExpired(associated);
                }
            }

            return null;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void remove(Principal key) {
        lock.lock();
        try {
            CacheEntry cached = identityCache.get(key);

            if (cached != null) {
                if (! removeAllDomainPrincipals(cached.value().getRealmIdentityPrincipal())) {
                    identityCache.remove(key);
                }
            } else {
                removeAllDomainPrincipals(key);
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void clear() {
        lock.lock();
        try {
            identityCache.clear();
            domainPrincipalMap.clear();
        } finally {
            lock.unlock();
        }
    }

    private RealmIdentity removeIfExpired(CacheEntry cached) {
        if (cached == null) {
            return null;
        }

        if (cached.isExpired()) {
            removeAllDomainPrincipals(cached.value().getRealmIdentityPrincipal());
            return null;
        }

        return cached.value();
    }

    private void evictIfNecessary() {
        while (identityCache.size() > maxEntries) {
            Iterator<Entry<Principal, CacheEntry>> iterator = identityCache.entrySet().iterator();

            if (! iterator.hasNext()) {
                return;
            }

            Entry<Principal, CacheEntry> eldest = iterator.next();
            iterator.remove();
            removeDomainPrincipal(eldest.getKey(), eldest.getValue().value().getRealmIdentityPrincipal());
        }
    }

    private boolean removeAllDomainPrincipals(Principal realmPrincipal) {
        Set<Principal> domainPrincipals = domainPrincipalMap.remove(realmPrincipal);

        if (domainPrincipals == null) {
            return false;
        }

        for (Principal domainPrincipal : domainPrincipals) {
            identityCache.remove(domainPrincipal);
        }

        return true;
    }

    private void removeDomainPrincipal(Principal domainPrincipal, Principal realmPrincipal) {
        Set<Principal> domainPrincipals = domainPrincipalMap.get(realmPrincipal);

        if (domainPrincipals == null) {
            return;
        }

        domainPrincipals.remove(domainPrincipal);

        if (domainPrincipals.isEmpty()) {
            domainPrincipalMap.remove(realmPrincipal);
        }
    }

    private static final class CacheEntry {

        final RealmIdentity value;
        final long expiration;

        CacheEntry(RealmIdentity value, long maxAge) {
            this.value = value;
            if(maxAge == -1) {
                expiration = -1;
            } else {
                expiration = System.currentTimeMillis() + maxAge;
            }
        }

        RealmIdentity value() {
            return value;
        }

        boolean isExpired() {
            return expiration != -1 ? System.currentTimeMillis() > expiration : false;
        }
    }
}
