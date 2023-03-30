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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
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
// has dependency on auth-realm
public class SecurityRealmIdentityCacheTest {

    private AtomicInteger realmHitCount = new AtomicInteger();

    @Before
    public void onBefore() {
        Security.addProvider(WildFlyElytronPasswordProvider.getInstance());
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

    @Test
    public void testMaxAge() throws Exception {
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", createSecurityRealm(createRealmIdentityLRUCache(2000))).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        assertAuthenticationAndAuthorization("joe", securityDomain);
        assertAuthenticationAndAuthorization("joe", securityDomain);
        assertAuthenticationAndAuthorization("joe", securityDomain);

        assertEquals(1, realmHitCount.get());

        Thread.sleep(3000);

        assertAuthenticationAndAuthorization("joe", securityDomain);
        assertAuthenticationAndAuthorization("joe", securityDomain);
        assertAuthenticationAndAuthorization("joe", securityDomain);
        assertEquals(2, realmHitCount.get());
    }

    @Test
    public void testPasswordUpdatedExternallyShouldPass() throws Exception {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();
        addUser(users, "joe", "User", "originalPassword");
        realm.setIdentityMap(users);

        CachingSecurityRealm cachingSecurityRealm = getSimpleLRUCachingSecurityRealm(realm);
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", cachingSecurityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        sac.setAuthenticationName("joe");
        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("originalPassword".toCharArray())));
        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("originalPassword".toCharArray())));
        users = new HashMap<>();
        addUser(users, "joe", "User", "updatedPassword");
        realm.setIdentityMap(users);
        ServerAuthenticationContext secondAuthentication = securityDomain.createNewAuthenticationContext();
        secondAuthentication.setAuthenticationName("joe");
        assertTrue(secondAuthentication.verifyEvidence(new PasswordGuessEvidence("originalPassword".toCharArray()))); // will pass because old credential is cached
        assertTrue(secondAuthentication.verifyEvidence(new PasswordGuessEvidence("updatedPassword".toCharArray()))); // will pass because caching realm will invoke underlying realm when auth fails with cached credential
    }

    @Test
    public void testAuthorizationIdentityAndAttributesWereUpdated() throws Exception {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();
        addUser(users, "joe", "User", "originalPassword");
        realm.setIdentityMap(users);

        CachingSecurityRealm cachingSecurityRealm = getSimpleLRUCachingSecurityRealm(realm);
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", cachingSecurityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        sac.setAuthenticationName("joe");
        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("originalPassword".toCharArray())));
        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("originalPassword".toCharArray())));
        users = new HashMap<>();
        addUser(users, "joe", Arrays.asList("UpdatedUserRole", "UpdatedUserRole2"), "updatedPassword");
        realm.setIdentityMap(users);
        ServerAuthenticationContext secondAuthentication = securityDomain.createNewAuthenticationContext();
        secondAuthentication.setAuthenticationName("joe");
        assertTrue(secondAuthentication.verifyEvidence(new PasswordGuessEvidence("updatedPassword".toCharArray()))); // will pass because caching realm will invoke underlying realm when auth fails with cached credential

        //check that attributes in authorization identity were updated
        Attributes joeUpdatedAttributes = realm.getRealmIdentity(new NamePrincipal("joe")).getAuthorizationIdentity().getAttributes();
        assertEquals("Only Roles attribute should be configured", joeUpdatedAttributes.size(), 1); // no attributes other than Roles were configured
        assertEquals("Attribute were not updated properly", joeUpdatedAttributes.get("Roles").size(), 2);
        assertEquals("Attribute were not updated properly", joeUpdatedAttributes.get("Roles").get(0), "UpdatedUserRole");
        assertEquals("Attribute were not updated properly", joeUpdatedAttributes.get("Roles").get(1), "UpdatedUserRole2");
    }

    @Test
    public void testPasswordUpdatedExternallyShouldPass2() throws Exception {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();
        addUser(users, "joe", "User", "originalPassword");
        realm.setIdentityMap(users);

        CachingSecurityRealm cachingSecurityRealm = getSimpleLRUCachingSecurityRealm(realm);
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", cachingSecurityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        sac.setAuthenticationName("joe");
        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("originalPassword".toCharArray()))); // will cache credential "originalPassword"
        users = new HashMap<>();
        addUser(users, "joe", "User", "updatedPassword");
        realm.setIdentityMap(users);
        ServerAuthenticationContext secondAuthentication = securityDomain.createNewAuthenticationContext();
        secondAuthentication.setAuthenticationName("joe");
        assertTrue(secondAuthentication.verifyEvidence(new PasswordGuessEvidence("originalPassword".toCharArray()))); // will pass because originalPassword credential is still cached
        assertFalse(secondAuthentication.verifyEvidence(new PasswordGuessEvidence("wrongPassword".toCharArray()))); // wrong password will fail
        assertTrue(secondAuthentication.verifyEvidence(new PasswordGuessEvidence("updatedPassword".toCharArray()))); // updated password should pass because caching realm will invoke underlying realm if authentication with cached credential failed
    }

    @Test
    public void testUpdatedPasswordWillBeCachedAndOutdatedWillFail() throws Exception {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();
        addUser(users, "joe", "User", "originalPassword");
        realm.setIdentityMap(users);

        CachingSecurityRealm cachingSecurityRealm = getSimpleLRUCachingSecurityRealm(realm);
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", cachingSecurityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        sac.setAuthenticationName("joe");
        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("originalPassword".toCharArray()))); // will cache credential "originalPassword"
        users = new HashMap<>();
        addUser(users, "joe", "User", "updatedPassword");
        realm.setIdentityMap(users);
        ServerAuthenticationContext secondAuthentication = securityDomain.createNewAuthenticationContext();
        secondAuthentication.setAuthenticationName("joe");
        assertTrue(secondAuthentication.verifyEvidence(new PasswordGuessEvidence("updatedPassword".toCharArray()))); // externally updated will pass
        assertFalse(secondAuthentication.verifyEvidence(new PasswordGuessEvidence("originalPassword".toCharArray()))); // outdated password will fail because new credential was cached in previous auth
    }

    private CachingSecurityRealm getSimpleLRUCachingSecurityRealm(SimpleMapBackedSecurityRealm realm) {
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
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                return realm.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return getEvidenceVerifySupport(evidenceType, algorithmName);
            }
        }, createRealmIdentityLRUCache());
    }

    private SecurityRealm createSecurityRealm(RealmIdentityCache cache) {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();

        addUser(users, "joe", "User");
        addUser(users, "bob", "User");

        realm.setIdentityMap(users);

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
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                return realm.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return getEvidenceVerifySupport(evidenceType, algorithmName);
            }
        }, cache) {
        };
    }

    private void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName, String roles) {
        addUser(securityRealm, userName, roles, null);
    }

    private void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName, String roles, String password) {
        addUser(securityRealm, userName, Collections.singletonList(roles), password);
    }

    private void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName, List<String> roles, String password) {
        if (password == null) {
            password = "password";
        }
        List<Credential> credentials;
        try {
            credentials = Collections.singletonList(
                    new PasswordCredential(
                            PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).generatePassword(
                                    new ClearPasswordSpec(password.toCharArray()))));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, roles);
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

    private RealmIdentityCache createRealmIdentityLRUCache(int maxAge) {
        return new LRURealmIdentityCache(1, maxAge);
    }

    private RealmIdentityCache createRealmIdentityLRUCache() {
        return createRealmIdentityLRUCache(-1);
    }
}