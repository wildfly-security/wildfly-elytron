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

package org.wildfly.security.ldap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.wildfly.common.Assert.assertNotNull;
import static org.wildfly.common.Assert.assertTrue;

import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.junit.Test;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.CacheableSecurityRealm;
import org.wildfly.security.auth.realm.CachingModifiableSecurityRealm;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.CloseableIterator;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.cache.RealmIdentityCache;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class LdapSecurityRealmIdentityCacheSuiteChild {

    private CountDownLatch waitServerNotification = new CountDownLatch(1);
    private AtomicInteger realmHitCount = new AtomicInteger();
    private AtomicInteger credentialHitCount = new AtomicInteger();
    private AtomicInteger attributesHitCount = new AtomicInteger();
    private AtomicInteger evidencesHitCount = new AtomicInteger();

    @Test
    public void testCacheUpdateAfterChangeNotificationFromServer() throws Exception {
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", createSecurityRealm(true, false)).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        for (int i = 0; i < 10; i++) {
            assertAuthenticationAndAuthorization("plainUser", securityDomain);
            assertEquals(1, realmHitCount.get());
            assertEquals(1, credentialHitCount.get());
            assertEquals(1, attributesHitCount.get());
            assertEquals(0, evidencesHitCount.get());
        }

        ExceptionSupplier<DirContext, NamingException> supplier = LdapTestSuite.dirContextFactory.create();
        DirContext dirContext = supplier.get();
        ModificationItem[] mods = new ModificationItem[1];

        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("sn", "Changed SN"));

        dirContext.modifyAttributes("uid=plainUser,dc=elytron,dc=wildfly,dc=org", mods);

        waitServerNotification.await(5, TimeUnit.SECONDS);

        assertAuthenticationAndAuthorization("plainUser", securityDomain);

        assertEquals(2, realmHitCount.get());
        assertEquals(2, credentialHitCount.get());
        assertEquals(2, attributesHitCount.get());
        assertEquals(0, evidencesHitCount.get());
        dirContext.close();
    }

    @Test
    public void testCacheUpdateAfterRemoveNotificationFromServer() throws Exception {
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", createSecurityRealm(true, false)).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        assertAuthenticationAndAuthorization("userToRemove", securityDomain);
        assertAuthenticationAndAuthorization("userToRemove", securityDomain);
        assertEquals(1, realmHitCount.get());

        ExceptionSupplier<DirContext, NamingException> supplier = LdapTestSuite.dirContextFactory.create();
        DirContext dirContext = supplier.get();

        dirContext.destroySubcontext("uid=userToRemove,dc=elytron,dc=wildfly,dc=org");

        waitServerNotification.await(5, TimeUnit.SECONDS);

        ServerAuthenticationContext sac = createServerAuthenticationContext("userToRemove", securityDomain);

        assertFalse(sac.exists());
        dirContext.close();
    }

    @Test
    public void testDirectVerificationCaching() throws Exception {
        SecurityDomain securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", createSecurityRealm(false, true)).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .build();

        for (int i = 0; i < 5; i++) {
            ServerAuthenticationContext sac = createServerAuthenticationContext("plainUser", securityDomain);
            assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("plainPassword".toCharArray())));

            assertEquals(1, realmHitCount.get());
            assertEquals(1, credentialHitCount.get());
            assertEquals(0, attributesHitCount.get());
            assertEquals(1, evidencesHitCount.get());
        }
    }

    private void assertAuthenticationAndAuthorization(String username, SecurityDomain securityDomain) throws RealmUnavailableException {
        ServerAuthenticationContext sac = createServerAuthenticationContext(username, securityDomain);

        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("plainPassword".toCharArray())));
        assertEquals(SupportLevel.SUPPORTED, sac.getCredentialAcquireSupport(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR));
        assertEquals("plainPassword", new String(sac.getCredential(PasswordCredential.class).getPassword().castAs(ClearPassword.class, ClearPassword.ALGORITHM_CLEAR).getPassword()));
        assertTrue(sac.verifyEvidence(new PasswordGuessEvidence("plainPassword".toCharArray())));

        assertTrue(sac.authorize(username));

        SecurityIdentity securityIdentity = sac.getAuthorizedIdentity();
        assertNotNull(securityIdentity);
        assertNotNull(securityIdentity.getAttributes());
        assertEquals(username, securityIdentity.getPrincipal().getName());
    }

    private ServerAuthenticationContext createServerAuthenticationContext(String username, SecurityDomain securityDomain) throws RealmUnavailableException {
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();

        sac.setAuthenticationName(username);

        return sac;
    }

    private ModifiableSecurityRealm createSecurityRealm(boolean credentialLoader, boolean directVerification) {
        LdapSecurityRealmBuilder builder = LdapSecurityRealmBuilder.builder()
                .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                .identityMapping()
                    .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                    .setRdnIdentifier("uid")
                    .build();
        if (credentialLoader) builder.userPasswordCredentialLoader().build();
        if (directVerification) builder.addDirectEvidenceVerification();
        return new CachingModifiableSecurityRealm(new MockCacheableModifiableSecurityRealm(builder.build()),
                createRealmIdentitySimpleJavaMapCache());
    }

    private class MockCacheableModifiableSecurityRealm implements ModifiableSecurityRealm, CacheableSecurityRealm {
        private final ModifiableSecurityRealm realm;

        public MockCacheableModifiableSecurityRealm(ModifiableSecurityRealm realm) {
            this.realm = realm;
        }

        @Override
        public void registerIdentityChangeListener(Consumer<Principal> listener) {
            ((CacheableSecurityRealm) realm).registerIdentityChangeListener(principal -> {
                listener.accept(principal);
                waitServerNotification.countDown();
            });
        }

        @Override
        public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
            realmHitCount.incrementAndGet();
            return new RealmIdentity() {
                RealmIdentity identity = realm.getRealmIdentity(principal);

                @Override
                public Principal getRealmIdentityPrincipal() {
                    return identity.getRealmIdentityPrincipal();
                }

                @Override
                public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                    credentialHitCount.incrementAndGet();
                    return identity.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
                }

                @Override
                public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                    credentialHitCount.incrementAndGet();
                    return identity.getCredential(credentialType);
                }

                @Override
                public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                    evidencesHitCount.incrementAndGet();
                    return identity.getEvidenceVerifySupport(evidenceType, algorithmName);
                }

                @Override
                public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                    evidencesHitCount.incrementAndGet();
                    return identity.verifyEvidence(evidence);
                }

                @Override
                public boolean exists() throws RealmUnavailableException {
                    return identity.exists();
                }

                @Override
                public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
                    attributesHitCount.incrementAndGet();
                    return identity.getAuthorizationIdentity();
                }

                @Override
                public Attributes getAttributes() throws RealmUnavailableException {
                    attributesHitCount.incrementAndGet();
                    return identity.getAttributes();
                }
            };
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            return realm.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            return realm.getEvidenceVerifySupport(evidenceType, algorithmName);
        }

        @Override
        public ModifiableRealmIdentity getRealmIdentityForUpdate(Principal principal) throws RealmUnavailableException {
            return realm.getRealmIdentityForUpdate(principal);
        }

        @Override
        public CloseableIterator<ModifiableRealmIdentity> getRealmIdentityIterator() throws RealmUnavailableException {
            return realm.getRealmIdentityIterator();
        }
    }

    private RealmIdentityCache createRealmIdentitySimpleJavaMapCache() {
        return new RealmIdentityCache() {
            private Map<Principal, RealmIdentity> cache = new HashMap<>();

            @Override
            public void put(Principal principal, RealmIdentity realmIdentity) {
                cache.put(principal, realmIdentity);
            }

            @Override
            public RealmIdentity get(Principal principal) {
                return cache.get(principal);
            }

            @Override
            public void remove(Principal principal) {
                cache.remove(principal);
            }

            @Override
            public void clear() {
                cache.clear();
            }
        };
    }
}
