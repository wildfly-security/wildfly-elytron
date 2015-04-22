/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.provider.AuthenticatedRealmIdentity;
import org.wildfly.security.auth.provider.CredentialSupport;
import org.wildfly.security.auth.provider.RealmIdentity;
import org.wildfly.security.auth.provider.RealmUnavailableException;
import org.wildfly.security.auth.provider.SecurityRealm;
import org.wildfly.security.auth.provider.SupportLevel;
import org.wildfly.security.password.AugmentedPassword;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.impl.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.interfaces.DigestPassword.MetaData;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;

/**
 * Test case to verify that a digest based authentication mechanism can follow a couple of different approaches when it comes to
 * selecting a realm name to use for authentication.
 *
 * For the purpose of this test I am deliberately not covering clear text representations, these need to be considered in some
 * form of translation layer - this test is specifically about the additional information specified to identify if there is a
 * stored representation for a specific realm.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class DigestRealmSelectionTest {

    private static final Provider provider = new WildFlyElytronPasswordProvider();

    @BeforeClass
    public static void registerProvider() {
        Security.addProvider(provider);
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }

    /**
     * Test case where all users in a realm are associated with a single realm name and the authentication mechanism is able to
     * discover that using the Elytron APIs.
     *
     * @throws GeneralSecurityException
     */
    @Test
    public void testSingleRealm() throws GeneralSecurityException {
        SecurityRealm realm = RealmBuilder.newInstance()
                .addUser("user1").addPassword(digestPassword("user1", "realm1", "password")).build()
                .addUser("user2").addPassword(digestPassword("user2", "realm1", "password")).build()
                .addUser("user3").addPassword(digestPassword("user3", "realm1", "password")).build()
                .build();

        assertEquals("General Credential Support", CredentialSupport.FULLY_SUPPORTED, realm.getCredentialSupport(DigestPassword.class));
        assertEquals("realm1 Support", CredentialSupport.FULLY_SUPPORTED, realm.getCredentialSupport(DigestPassword.class, new MetaData("realm1", null)));
        assertEquals("realm2 Support", CredentialSupport.UNSUPPORTED, realm.getCredentialSupport(DigestPassword.class, new MetaData("realm2", null)));

        RealmIdentity identity2 = realm.createRealmIdentity("user2");
        assertEquals("General Credential Support", CredentialSupport.FULLY_SUPPORTED, identity2.getCredentialSupport(DigestPassword.class));
        assertEquals("realm1 support", CredentialSupport.FULLY_SUPPORTED, identity2.getCredentialSupport(DigestPassword.class, new MetaData("realm1", null)));
        assertEquals("realm2 support", CredentialSupport.UNSUPPORTED, identity2.getCredentialSupport(DigestPassword.class, new MetaData("realm2", null)));

        DigestPassword digestPassword = identity2.getCredential(DigestPassword.class);
        assertEquals("user2", digestPassword.getUsername());
        assertEquals("realm1", digestPassword.getRealm());
        digestPassword = identity2.getCredential(DigestPassword.class, new MetaData("realm1", null));
        assertEquals("user2", digestPassword.getUsername());
        assertEquals("realm1", digestPassword.getRealm());
        digestPassword = identity2.getCredential(DigestPassword.class, new MetaData("realm2", null));
        assertNull(digestPassword);
    }

    /**
     * Test case where users have multiple credentials, each for a different realm but all users share the same set.
     */
    @Test
    public void testMultipleConsistentRealms() throws GeneralSecurityException {
        SecurityRealm realm = RealmBuilder.newInstance()
                .addUser("user1").addPassword(digestPassword("user1", "realm1", "password")).addPassword(digestPassword("user1", "realm2", "password")).build()
                .addUser("user2").addPassword(digestPassword("user2", "realm1", "password")).addPassword(digestPassword("user2", "realm2", "password")).build()
                .addUser("user3").addPassword(digestPassword("user3", "realm1", "password")).addPassword(digestPassword("user3", "realm2", "password")).build()
                .build();

        assertEquals("General Credential Support", CredentialSupport.FULLY_SUPPORTED, realm.getCredentialSupport(DigestPassword.class));
        assertEquals("realm1 Support", CredentialSupport.FULLY_SUPPORTED, realm.getCredentialSupport(DigestPassword.class, new MetaData("realm1", null)));
        assertEquals("realm2 Support", CredentialSupport.FULLY_SUPPORTED, realm.getCredentialSupport(DigestPassword.class, new MetaData("realm2", null)));
        assertEquals("realm3 Support", CredentialSupport.UNSUPPORTED, realm.getCredentialSupport(DigestPassword.class, new MetaData("realm3", null)));

        RealmIdentity identity2 = realm.createRealmIdentity("user2");
        assertEquals("General Credential Support", CredentialSupport.FULLY_SUPPORTED, identity2.getCredentialSupport(DigestPassword.class));
        assertEquals("realm1 support", CredentialSupport.FULLY_SUPPORTED, identity2.getCredentialSupport(DigestPassword.class, new MetaData("realm1", null)));
        assertEquals("realm2 support", CredentialSupport.FULLY_SUPPORTED, identity2.getCredentialSupport(DigestPassword.class, new MetaData("realm2", null)));
        assertEquals("realm3 support", CredentialSupport.UNSUPPORTED, identity2.getCredentialSupport(DigestPassword.class, new MetaData("realm3", null)));

        DigestPassword digestPassword = identity2.getCredential(DigestPassword.class);
        assertEquals("user2", digestPassword.getUsername());
        assertTrue("Realm Name", "realm1".equals(digestPassword.getRealm()) || "realm2".equals(digestPassword.getRealm()));
        digestPassword = identity2.getCredential(DigestPassword.class, new MetaData("realm1", null));
        assertEquals("user2", digestPassword.getUsername());
        assertEquals("realm1", digestPassword.getRealm());
        digestPassword = identity2.getCredential(DigestPassword.class, new MetaData("realm2", null));
        assertEquals("user2", digestPassword.getUsername());
        assertEquals("realm2", digestPassword.getRealm());
        digestPassword = identity2.getCredential(DigestPassword.class, new MetaData("realm3", null));
        assertNull(digestPassword);
    }

    /**
     * Test case where different users have different realms.
     *
     * For this test there will be one common realm in addition.
     */
    @Test
    public void testRealmVariety() throws GeneralSecurityException {
        SecurityRealm realm = RealmBuilder.newInstance()
                .addUser("user1").addPassword(digestPassword("user1", "realm1", "password")).addPassword(digestPassword("user1", "realm2", "password")).build()
                .addUser("user2").addPassword(digestPassword("user2", "realm1", "password")).addPassword(digestPassword("user2", "realm2", "password")).build()
                .addUser("user3").addPassword(digestPassword("user3", "realm1", "password")).addPassword(digestPassword("user3", "realm3", "password")).build()
                .build();

        assertEquals("General Credential Support", CredentialSupport.FULLY_SUPPORTED, realm.getCredentialSupport(DigestPassword.class));
        assertEquals("realm1 Support", CredentialSupport.FULLY_SUPPORTED, realm.getCredentialSupport(DigestPassword.class, new MetaData("realm1", null)));
        assertEquals("realm2 Support", CredentialSupport.UNKNOWN, realm.getCredentialSupport(DigestPassword.class, new MetaData("realm2", null)));
        assertEquals("realm3 Support", CredentialSupport.UNKNOWN, realm.getCredentialSupport(DigestPassword.class, new MetaData("realm3", null)));
        assertEquals("realm4 Support", CredentialSupport.UNSUPPORTED, realm.getCredentialSupport(DigestPassword.class, new MetaData("realm4", null)));

        RealmIdentity identity2 = realm.createRealmIdentity("user2");
        assertEquals("General Credential Support", CredentialSupport.FULLY_SUPPORTED, identity2.getCredentialSupport(DigestPassword.class));
        assertEquals("realm1 support", CredentialSupport.FULLY_SUPPORTED, identity2.getCredentialSupport(DigestPassword.class, new MetaData("realm1", null)));
        assertEquals("realm2 support", CredentialSupport.FULLY_SUPPORTED, identity2.getCredentialSupport(DigestPassword.class, new MetaData("realm2", null)));
        assertEquals("realm3 support", CredentialSupport.UNSUPPORTED, identity2.getCredentialSupport(DigestPassword.class, new MetaData("realm3", null)));

        DigestPassword digestPassword = identity2.getCredential(DigestPassword.class);
        assertEquals("user2", digestPassword.getUsername());
        assertTrue("Realm Name", "realm1".equals(digestPassword.getRealm()) || "realm2".equals(digestPassword.getRealm()));
        digestPassword = identity2.getCredential(DigestPassword.class, new MetaData("realm1", null));
        assertEquals("user2", digestPassword.getUsername());
        assertEquals("realm1", digestPassword.getRealm());
        digestPassword = identity2.getCredential(DigestPassword.class, new MetaData("realm2", null));
        assertEquals("user2", digestPassword.getUsername());
        assertEquals("realm2", digestPassword.getRealm());
        digestPassword = identity2.getCredential(DigestPassword.class, new MetaData("realm3", null));
        assertNull(digestPassword);
    }

    private static DigestPassword digestPassword(String username, String realm, String password) throws GeneralSecurityException {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(DigestPassword.ALGORITHM_DIGEST_MD5);

        DigestPasswordAlgorithmSpec dpas = new DigestPasswordAlgorithmSpec(DigestPassword.ALGORITHM_DIGEST_MD5, username, realm);
        EncryptablePasswordSpec encryptable = new EncryptablePasswordSpec(password.toCharArray(), dpas);

        return (DigestPassword) passwordFactory.generatePassword(encryptable);
    }

    private interface CredentialMatcher {
        boolean matches(final String realmName, final String algorithm);
    }

    private static class RealmBuilder {

        private Map<String, List<DigestPassword>> userPasswordsMap = new HashMap<String, List<DigestPassword>>();

        private RealmBuilder() {

        }

        public static RealmBuilder newInstance() {
            return new RealmBuilder();
        }

        public UserBuilder addUser(final String username) {
            return new UserBuilder(this, username);
        }

        private void storeUser(final String username, final List<DigestPassword> passwords) {
            userPasswordsMap.put(username, passwords);
        }

        public SecurityRealm build() {
            return new SecurityRealm() {

                private boolean matches(DigestPassword password, CredentialMatcher credentialMatcher) {
                    return credentialMatcher.matches(password.getRealm(), password.getAlgorithm());
                }

                private boolean obtainable(List<DigestPassword> passwords, CredentialMatcher credentialMatcher) {
                    for (DigestPassword current : passwords) {
                        if (matches(current, credentialMatcher)) {
                            return true;
                        }
                    }

                    return false;
                }

                private SupportLevel obtainable(CredentialMatcher credentialMatcher) {
                    SupportLevel obtainable = null;
                    for (List<DigestPassword> entry : userPasswordsMap.values()) {
                        if (obtainable(entry, credentialMatcher)) {
                            if (obtainable == null) {
                                obtainable = SupportLevel.SUPPORTED;
                            } else if (obtainable == SupportLevel.UNSUPPORTED) {
                                obtainable = SupportLevel.POSSIBLY_SUPPORTED;
                            }
                        } else if (obtainable == null) {
                            obtainable = SupportLevel.UNSUPPORTED;
                        } else if (obtainable == SupportLevel.SUPPORTED) {
                            obtainable = SupportLevel.POSSIBLY_SUPPORTED;
                        }
                    }

                    return obtainable;
                }

                private CredentialSupport getCredentialSupport(Class<?> credentialType, CredentialMatcher credentialMatcher) {
                    CredentialSupport support = CredentialSupport.UNSUPPORTED;
                    if (credentialType.isAssignableFrom(DigestPassword.class)) {
                        SupportLevel obtainable = obtainable(credentialMatcher);

                        support = CredentialSupport.getCredentialSupport(obtainable, obtainable);
                    }
                    return support;
                }

                @Override
                public CredentialSupport getCredentialSupport(Class<?> credentialType) throws RealmUnavailableException {
                    return getCredentialSupport(credentialType, (String realmName, String algorithm) -> true);
                }

                @Override
                public <M> CredentialSupport getCredentialSupport(Class<? extends AugmentedPassword<M>> credentialType, M metaData) throws RealmUnavailableException {
                    final String requiredRealm;
                    final String requiredAlgorithm;
                    if (credentialType.isAssignableFrom(DigestPassword.class)) {
                        MetaData digestMetaData = (MetaData) metaData;
                        requiredRealm = digestMetaData.getRealm();
                        requiredAlgorithm = digestMetaData.getAlgorithm();
                    } else {
                        requiredRealm = null;
                        requiredAlgorithm = null;
                    }

                    return getCredentialSupport(credentialType, (CredentialMatcher)
                            (String realmName, String algorithm) -> (requiredRealm == null || requiredRealm.equals(realmName))
                                    && (requiredAlgorithm == null || requiredAlgorithm.equals(algorithm)));
                }

                @Override
                public RealmIdentity createRealmIdentity(Principal principal) throws RealmUnavailableException {
                    throw new UnsupportedOperationException();
                }

                @Override
                public RealmIdentity createRealmIdentity(final String name) throws RealmUnavailableException {
                    final List<DigestPassword> passwords = userPasswordsMap.containsKey(name) ? userPasswordsMap.get(name) : Collections.emptyList();

                    return new RealmIdentity() {

                        @Override
                        public Principal getPrincipal() throws RealmUnavailableException {
                            return new NamePrincipal(name);
                        }

                        @Override
                        public CredentialSupport getCredentialSupport(Class<?> credentialType) throws RealmUnavailableException {
                            CredentialSupport support = CredentialSupport.UNSUPPORTED;
                            if (credentialType.isAssignableFrom(DigestPassword.class)) {
                                support = getCredentialSupport((Class<DigestPassword>)credentialType, new MetaData(null, null));
                            }
                            return support;
                        }

                        @Override
                        public <M> CredentialSupport getCredentialSupport(Class<? extends AugmentedPassword<M>> credentialType, M metaData) throws RealmUnavailableException {
                            CredentialSupport support = CredentialSupport.UNSUPPORTED;
                            if (credentialType.isAssignableFrom(DigestPassword.class)) {
                                MetaData digestMetaData = (MetaData)metaData;
                                final String requiredRealm = digestMetaData.getRealm();
                                final String requiredAlgorithm = digestMetaData.getAlgorithm();

                                if (obtainable(passwords, (String realmName, String algorithm) -> (requiredRealm == null || requiredRealm.equals(realmName))
                                        && (requiredAlgorithm == null || requiredAlgorithm.equals(algorithm)))) {
                                    support = CredentialSupport.FULLY_SUPPORTED;
                                }

                            }
                            return support;
                        }

                        private DigestPassword getCredential(CredentialMatcher credentialMatcher) {
                            for (DigestPassword current : passwords) {
                                if (matches(current, credentialMatcher)) {
                                    return current;
                                }
                            }

                            return null;
                        }

                        @Override
                        public <C> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                            if (credentialType.isAssignableFrom(DigestPassword.class)) {
                                return credentialType.cast(getCredential( (Class<DigestPassword>)credentialType , new MetaData(null, null) ));
                            }
                            return null;
                        }

                        @Override
                        public <C extends AugmentedPassword<M>, M> C getCredential(Class<C> credentialType, M metaData)
                                throws RealmUnavailableException {
                            if (credentialType.isAssignableFrom(DigestPassword.class)) {
                                MetaData digestMetaData = (MetaData)metaData;
                                final String requiredRealm = digestMetaData.getRealm();
                                final String requiredAlgorithm = digestMetaData.getAlgorithm();

                                return credentialType.cast(getCredential((String realmName, String algorithm) -> (requiredRealm == null || requiredRealm.equals(realmName))
                                        && (requiredAlgorithm == null || requiredAlgorithm.equals(algorithm))));
                            }
                            return null;
                        }

                        @Override
                        public AuthenticatedRealmIdentity getAuthenticatedRealmIdentity() throws RealmUnavailableException {
                            throw new UnsupportedOperationException();
                        }

                        @Override
                        public boolean verifyCredential(Object credential) throws RealmUnavailableException {
                            throw new UnsupportedOperationException();
                        }

                        @Override
                        public void dispose() {
                            throw new UnsupportedOperationException();
                        }
                    };
                }

            };
        }
    }

    private static class UserBuilder {

        private final RealmBuilder realmBuilder;
        private final String username;
        private final List<DigestPassword> passwords = new ArrayList<DigestPassword>();

        private UserBuilder(RealmBuilder realmBuilder, final String username) {
            this.realmBuilder = realmBuilder;
            this.username = username;
        }

        public UserBuilder addPassword(final DigestPassword password) {
            passwords.add(password);

            return this;
        }

        public RealmBuilder build() {
            realmBuilder.storeUser(username, passwords);
            return realmBuilder;
        }
    }
}
