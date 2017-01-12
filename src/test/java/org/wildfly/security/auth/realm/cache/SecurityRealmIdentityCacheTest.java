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

package org.wildfly.security.auth.realm.cache;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.CacheableSecurityRealm;
import org.wildfly.security.auth.realm.CachingSecurityRealm;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.cache.LRURealmIdentityCache;
import org.wildfly.security.cache.RealmIdentityCache;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class SecurityRealmIdentityCacheTest {

    private AtomicInteger realmHitCount = new AtomicInteger();

    @Before
    public void onBefore() {
        Security.addProvider(new WildFlyElytronProvider());
    }

    @Test
    public void testRealmIdentitySimpleJavaMapCache() throws Exception {
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", createSecurityRealm(createRealmIdentityLRUCache())).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        for (int i = 0; i < 10; i++) {
            assertAuthenticationAndAuthorization("joe", securityDomain);
            assertEquals(1, realmHitCount.get());
        }

        for (int i = 0; i < 10; i++) {
            assertAuthenticationAndAuthorization("bob", securityDomain);
            assertEquals(2, realmHitCount.get());
        }
    }

    @Test
    public void testRealmIdentityNoCache() throws Exception {
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", createSecurityRealm(null)).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        for (int i = 0; i < 10; i++) {
            assertAuthenticationAndAuthorization("joe", securityDomain);
        }

        assertEquals(10, realmHitCount.get());
    }

    private SecurityRealm createSecurityRealm(RealmIdentityCache cache) {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();

        addUser(users, "joe", "User");
        addUser(users, "bob", "User");

        realm.setPasswordMap(users);

        if (cache == null) {
            cache = new RealmIdentityCache() {
                @Override
                public void put(Principal principal, RealmIdentity realmIdentity) {

                }

                @Override
                public RealmIdentity get(Principal principal) {
                    return null;
                }

                @Override
                public void remove(Principal principal) {

                }

                @Override
                public void clear() {

                }
            };
        }

        return new CachingSecurityRealm(new CacheableSecurityRealm() {
            @Override
            public void registerIdentityChangeListener(Consumer<Principal> listener) {

            }

            @Override
            public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
                realmHitCount.incrementAndGet();
                return realm.getRealmIdentity(principal);
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
                return realm.getCredentialAcquireSupport(credentialType, algorithmName);
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return getEvidenceVerifySupport(evidenceType, algorithmName);
            }
        }, cache) {
        };
    }

    private void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName, String roles) {
        List<Credential> credentials;
        try {
            credentials = Collections.singletonList(
                    new PasswordCredential(
                            PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).generatePassword(
                                    new ClearPasswordSpec("password".toCharArray()))));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));
        securityRealm.put(userName, new SimpleRealmEntry(credentials, attributes));
    }

    private void assertAuthenticationAndAuthorization(String username, SecurityDomain securityDomain) throws RealmUnavailableException {
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();

        sac.setAuthenticationName(username);
        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("password".toCharArray())));
        assertTrue(sac.authorize(username));

        SecurityIdentity securityIdentity = sac.getAuthorizedIdentity();
        assertNotNull(securityIdentity);
        assertEquals(username, securityIdentity.getPrincipal().getName());
    }

    private RealmIdentityCache createRealmIdentityLRUCache() {
        return new LRURealmIdentityCache(1);
    }
}
