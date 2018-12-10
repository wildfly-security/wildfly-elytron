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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.LinkedList;
import java.util.List;

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

    private RealmIdentity createRealmIdentity() {
        return new RealmIdentity() {
            @Override
            public Principal getRealmIdentityPrincipal() {
                return null;
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
}
