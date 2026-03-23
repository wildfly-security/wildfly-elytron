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

package org.wildfly.security.auth.realm.cache;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.cache.LRURealmIdentityCache;
import org.wildfly.security.cache.RealmIdentityCache;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class LRURealmIdentityCacheTest {

    private static int count = 0;

    private RealmIdentityCache cache;
    private List<Principal> principals = new LinkedList<>();

    @Before
    public void onBefore() {
        for (int i = 0; i < 5; i++) {
            createPrincipal(principals);
        }

        cache = new LRURealmIdentityCache(5);

        cache.put(principals.get(0), createRealmIdentity());
        cache.put(principals.get(1), createRealmIdentity());
        cache.put(principals.get(2), createRealmIdentity());
        cache.put(principals.get(3), createRealmIdentity());
        cache.put(principals.get(4), createRealmIdentity());
    }

    private Principal createPrincipal(List<Principal> principals) {
        String name = String.valueOf(count++);
        Principal principal = new Principal() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public String toString() {
                return name;
            }
        };

        principals.add(principal);

        return principal;
    }

    @Test
    public void testMaxEntries() {
        LinkedList<Principal> expected = new LinkedList<>();

        cache.put(createPrincipal(expected), createRealmIdentity());

        assertNull(cache.get(principals.get(0)));
        assertNotNull(cache.get(principals.get(1)));
        assertNotNull(cache.get(principals.get(2)));
        assertNotNull(cache.get(principals.get(3)));
        assertNotNull(cache.get(principals.get(4)));

        cache.put(createPrincipal(expected), createRealmIdentity());
        cache.put(createPrincipal(expected), createRealmIdentity());

        assertNull(cache.get(principals.get(0)));
        assertNull(cache.get(principals.get(1)));
        assertNotNull(cache.get(principals.get(2)));
        assertNotNull(cache.get(principals.get(3)));
        assertNotNull(cache.get(principals.get(4)));

        cache.put(createPrincipal(expected), createRealmIdentity());
        cache.put(createPrincipal(expected), createRealmIdentity());
        cache.put(createPrincipal(expected), createRealmIdentity());

        assertNull(cache.get(principals.get(0)));
        assertNull(cache.get(principals.get(1)));
        assertNull(cache.get(principals.get(2)));
        assertNotNull(cache.get(principals.get(3)));
        assertNotNull(cache.get(principals.get(4)));

        cache.put(createPrincipal(expected), createRealmIdentity());
        cache.put(createPrincipal(expected), createRealmIdentity());
        cache.put(createPrincipal(expected), createRealmIdentity());
        cache.put(createPrincipal(expected), createRealmIdentity());
        cache.put(createPrincipal(expected), createRealmIdentity());

        assertNull(cache.get(principals.get(0)));
        assertNull(cache.get(principals.get(1)));
        assertNull(cache.get(principals.get(2)));
        assertNull(cache.get(principals.get(3)));
        assertNull(cache.get(principals.get(4)));

        for (int i = expected.size() - 1; i >= expected.size() - 5; i--) {
            assertNotNull(cache.get(expected.get(i)));
        }

        for (int i = 0; i < expected.size() - 5; i++) {
            assertNull(cache.get(expected.get(i)));
        }

        for (int i = 0; i < principals.size(); i++) {
            assertNull(cache.get(principals.get(i)));
        }
    }

    @Test
    public void testRemove() {
        cache.remove(principals.get(3));
        assertNull(cache.get(principals.get(3)));

        cache.remove(principals.get(0));
        assertNull(cache.get(principals.get(0)));

        cache.remove(principals.get(4));
        assertNull(cache.get(principals.get(4)));
    }

    @Test
    public void testClear() {
        cache.clear();

        for (Principal principal : principals) {
            assertNull(cache.get(principal));
        }
    }

    @Test
    public void testRemoveInvalidatesAllDomainPrincipalsForRealmIdentity() {
        LRURealmIdentityCache cache = new LRURealmIdentityCache(5);
        Principal realmPrincipal = createPrincipal(new LinkedList<>());
        Principal firstDomainPrincipal = createPrincipal(new LinkedList<>());
        Principal secondDomainPrincipal = createPrincipal(new LinkedList<>());

        cache.put(firstDomainPrincipal, createRealmIdentity(realmPrincipal));
        cache.put(secondDomainPrincipal, createRealmIdentity(realmPrincipal));

        assertNotNull(cache.get(realmPrincipal));

        cache.remove(firstDomainPrincipal);

        assertNull(cache.get(firstDomainPrincipal));
        assertNull(cache.get(secondDomainPrincipal));
        assertNull(cache.get(realmPrincipal));
    }

    @Test
    public void testMaxEntriesCleanupRealmPrincipalMapping() throws Exception {
        LRURealmIdentityCache cache = new LRURealmIdentityCache(1);
        Principal evictedRealmPrincipal = createPrincipal(new LinkedList<>());
        Principal survivingRealmPrincipal = createPrincipal(new LinkedList<>());
        Principal evictedDomainPrincipal = createPrincipal(new LinkedList<>());
        Principal survivingDomainPrincipal = createPrincipal(new LinkedList<>());

        cache.put(evictedDomainPrincipal, createRealmIdentity(evictedRealmPrincipal));
        cache.put(survivingDomainPrincipal, createRealmIdentity(survivingRealmPrincipal));

        assertFalse(getDomainPrincipalMap(cache).containsKey(evictedRealmPrincipal));
        assertNull(cache.get(evictedDomainPrincipal));
        assertNotNull(cache.get(survivingDomainPrincipal));
        assertNotNull(cache.get(survivingRealmPrincipal));
    }

    @Test
    public void testExpirationCleanupRealmPrincipalMapping() throws Exception {
        LRURealmIdentityCache cache = new LRURealmIdentityCache(1, 1);
        Principal realmPrincipal = createPrincipal(new LinkedList<>());
        Principal domainPrincipal = createPrincipal(new LinkedList<>());

        cache.put(domainPrincipal, createRealmIdentity(realmPrincipal));

        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);

        while (cache.get(domainPrincipal) != null && System.nanoTime() < deadline) {
            TimeUnit.MILLISECONDS.sleep(10);
        }

        assertNull(cache.get(domainPrincipal));
        assertNull(cache.get(realmPrincipal));
        assertFalse(getDomainPrincipalMap(cache).containsKey(realmPrincipal));
    }

    @Test
    public void testConcurrentAccessMaintainsConsistentMappings() throws Exception {
        LRURealmIdentityCache cache = new LRURealmIdentityCache(16);
        List<Principal> domainPrincipals = new ArrayList<>();
        List<Principal> realmPrincipals = new ArrayList<>();

        for (int i = 0; i < 16; i++) {
            domainPrincipals.add(createPrincipal(new LinkedList<>()));
        }
        for (int i = 0; i < 4; i++) {
            realmPrincipals.add(createPrincipal(new LinkedList<>()));
        }

        ExecutorService executor = Executors.newFixedThreadPool(4);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();

        try {
            for (int thread = 0; thread < 4; thread++) {
                final int offset = thread;
                futures.add(executor.submit(() -> {
                    start.await();

                    for (int i = 0; i < 250; i++) {
                        int index = offset + ((i % 4) * 4);
                        Principal domainPrincipal = domainPrincipals.get(index);
                        Principal realmPrincipal = realmPrincipals.get(index % realmPrincipals.size());

                        cache.put(domainPrincipal, createRealmIdentity(realmPrincipal));
                        cache.get(domainPrincipal);
                        cache.get(realmPrincipal);

                        if ((i % 5) == 0) {
                            cache.remove(domainPrincipal);
                        }
                    }

                    return null;
                }));
            }

            start.countDown();

            for (Future<?> future : futures) {
                future.get(10, TimeUnit.SECONDS);
            }
        } finally {
            executor.shutdownNow();
        }

        assertMappingConsistency(cache);
    }

    private RealmIdentity createRealmIdentity() {
        return createRealmIdentity(null);
    }

    private RealmIdentity createRealmIdentity(Principal realmPrincipal) {
        return new RealmIdentity() {
            @Override
            public Principal getRealmIdentityPrincipal() {
                return realmPrincipal;
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                return null;
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                return null;
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return null;
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                return false;
            }

            @Override
            public boolean exists() throws RealmUnavailableException {
                return false;
            }
        };
    }

    @SuppressWarnings("unchecked")
    private Map<Principal, Set<Principal>> getDomainPrincipalMap(LRURealmIdentityCache cache) throws Exception {
        Field field = LRURealmIdentityCache.class.getDeclaredField("domainPrincipalMap");
        field.setAccessible(true);
        return (Map<Principal, Set<Principal>>) field.get(cache);
    }

    @SuppressWarnings("unchecked")
    private Map<Principal, Object> getIdentityCache(LRURealmIdentityCache cache) throws Exception {
        Field field = LRURealmIdentityCache.class.getDeclaredField("identityCache");
        field.setAccessible(true);
        return new HashMap<>((Map<Principal, Object>) field.get(cache));
    }

    private RealmIdentity getRealmIdentity(Object cacheEntry) throws Exception {
        Field valueField = cacheEntry.getClass().getDeclaredField("value");
        valueField.setAccessible(true);
        return (RealmIdentity) valueField.get(cacheEntry);
    }

    private void assertMappingConsistency(LRURealmIdentityCache cache) throws Exception {
        Map<Principal, Object> identityCache = getIdentityCache(cache);
        Map<Principal, Set<Principal>> domainPrincipalMap = getDomainPrincipalMap(cache);

        for (Map.Entry<Principal, Set<Principal>> mapping : domainPrincipalMap.entrySet()) {
            for (Principal domainPrincipal : mapping.getValue()) {
                Object cacheEntry = identityCache.get(domainPrincipal);

                assertNotNull(cacheEntry);
                assertSame(mapping.getKey(), getRealmIdentity(cacheEntry).getRealmIdentityPrincipal());
            }
        }

        for (Map.Entry<Principal, Object> entry : identityCache.entrySet()) {
            Principal realmPrincipal = getRealmIdentity(entry.getValue()).getRealmIdentityPrincipal();
            Set<Principal> domainPrincipals = domainPrincipalMap.get(realmPrincipal);

            assertNotNull(domainPrincipals);
            assertTrue(domainPrincipals.contains(entry.getKey()));
        }
    }
}
