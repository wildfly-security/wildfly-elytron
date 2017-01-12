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
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;

import org.wildfly.security.auth.server.RealmIdentity;

/**
 * A {@link RealmIdentityCache} implementation providing a LRU cache.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class LRURealmIdentityCache implements RealmIdentityCache {

    /**
     * The load factor. Th
     */
    private static final float DEFAULT_LOAD_FACTOR = 0.75f;

    /**
     * Holds the cached identitys where the key is the domain principal, the one used to lookup the identity
     */
    private final Map<Principal, RealmIdentity> identityCache;

    /**
     * Holds a mapping between a realm principal and domain principals
     */
    private final Map<Principal, Set<Principal>> domainPrincipalMap;

    private final AtomicBoolean writing = new AtomicBoolean(false);

    public LRURealmIdentityCache(int maxEntries) {
        checkMinimumParameter("maxEntries", 1, maxEntries);
        identityCache = new LinkedHashMap<Principal, RealmIdentity>(16, DEFAULT_LOAD_FACTOR, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry eldest) {
                return identityCache.size()  > maxEntries;
            }
        };
        domainPrincipalMap = new HashMap<>(16);
    }

    @Override
    public void put(Principal key, RealmIdentity newValue) {
        try {
            if (parkForWriteAndCheckInterrupt()) {
                return;
            }

            RealmIdentity realmIdentity = identityCache.computeIfAbsent(key, principal -> {
                domainPrincipalMap.computeIfAbsent(newValue.getRealmIdentityPrincipal(), principal1 -> {
                    Set<Principal> principals = new HashSet<>();

                    principals.add(key);

                    return principals;
                });
                return newValue;
            });

            if (realmIdentity != null) {
                domainPrincipalMap.get(realmIdentity.getRealmIdentityPrincipal()).add(key);
            }
        } finally {
            writing.lazySet(false);
        }
    }

    @Override
    public RealmIdentity get(Principal key) {
        if (parkForReadAndCheckInterrupt()) {
            return null;
        }

        RealmIdentity cached = identityCache.get(key);

        if (cached != null) {
            return cached;
        }

        Set<Principal> domainPrincipal = domainPrincipalMap.get(key);

        if (domainPrincipal != null) {
            return identityCache.get(domainPrincipal.iterator().next());
        }

        return null;
    }

    @Override
    public void remove(Principal key) {
        try {
            if (parkForWriteAndCheckInterrupt()) {
                return;
            }

            if (identityCache.containsKey(key)) {
                domainPrincipalMap.remove(identityCache.remove(key).getRealmIdentityPrincipal()).forEach(identityCache::remove);
            } else if (domainPrincipalMap.containsKey(key)) {
                domainPrincipalMap.remove(key).forEach(identityCache::remove);
            }
        } finally {
            writing.lazySet(false);
        }
    }

    @Override
    public void clear() {
        try {
            parkForWriteAndCheckInterrupt();
            identityCache.clear();
            domainPrincipalMap.clear();
        } finally {
            writing.lazySet(false);
        }
    }

    private boolean parkForWriteAndCheckInterrupt() {
        while (!writing.compareAndSet(false, true)) {
            LockSupport.parkNanos(1L);
            if (Thread.interrupted()) {
                return true;
            }
        }
        return false;
    }

    private boolean parkForReadAndCheckInterrupt() {
        while (writing.get()) {
            LockSupport.parkNanos(1L);
            if (Thread.interrupted()) {
                return true;
            }
        }
        return false;
    }
}
