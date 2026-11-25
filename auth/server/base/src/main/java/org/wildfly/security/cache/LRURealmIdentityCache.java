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
    private final Map<Principal, CacheEntry> identityCache;

    /**
     * Holds a mapping between a realm principal and domain principals
     */
    private final Map<Principal, Set<Principal>> domainPrincipalMap;

    /**
     * ELY-3093 - Guards all access to {@link #identityCache} and {@link #domainPrincipalMap}. Neither map is thread-safe and,
     * since {@code identityCache} is an access-order {@link LinkedHashMap}, even a {@code get} mutates its internal
     * linked list, so reads cannot be allowed to run concurrently with each other or with writes.
     */
    private final ReentrantLock lock = new ReentrantLock();

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
        identityCache = new LinkedHashMap<Principal, CacheEntry>(16, DEFAULT_LOAD_FACTOR, true) {
            @Override
            protected boolean removeEldestEntry(Entry<Principal, CacheEntry> eldest) {
                return identityCache.size()  > maxEntries;
            }
        };
        domainPrincipalMap = new HashMap<>(16);
        this.maxAge = maxAge;
    }

    @Override
    public void put(Principal key, RealmIdentity newValue) {
        lock.lock();
        try {
            CacheEntry entry = identityCache.computeIfAbsent(key, principal -> {
                domainPrincipalMap.computeIfAbsent(newValue.getRealmIdentityPrincipal(), principal1 -> {
                    Set<Principal> principals = new HashSet<>();

                    principals.add(key);

                    return principals;
                });
                return new CacheEntry(key, newValue, maxAge);
            });

            if (entry != null) {
                domainPrincipalMap.get(entry.value().getRealmIdentityPrincipal()).add(key);
            }
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

            Set<Principal> domainPrincipal = domainPrincipalMap.get(key);

            if (domainPrincipal != null) {
                return removeIfExpired(identityCache.get(domainPrincipal.iterator().next()));
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
            if (identityCache.containsKey(key)) {
                domainPrincipalMap.remove(identityCache.remove(key).value().getRealmIdentityPrincipal()).forEach(identityCache::remove);
            } else if (domainPrincipalMap.containsKey(key)) {
                domainPrincipalMap.remove(key).forEach(identityCache::remove);
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

    /**
     * Must be called while holding {@link #lock}.
     */
    private RealmIdentity removeIfExpired(CacheEntry cached) {
        if (cached == null) {
            return null;
        }

        if (cached.isExpired()) {
            remove(cached.key());
            return null;
        }

        return cached.value();
    }

    private static final class CacheEntry {

        final Principal key;
        final RealmIdentity value;
        final long expiration;

        CacheEntry(Principal key, RealmIdentity value, long maxAge) {
            this.key = key;
            this.value = value;
            if(maxAge == -1) {
                expiration = -1;
            } else {
                expiration = System.currentTimeMillis() + maxAge;
            }
        }

        Principal key() {
            return key;
        }

        RealmIdentity value() {
            return value;
        }

        boolean isExpired() {
            return expiration != -1 ? System.currentTimeMillis() > expiration : false;
        }
    }
}
