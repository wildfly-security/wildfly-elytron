/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.provider.ldap.DirContextFactory;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.provider.ldap.SimpleDirContextFactoryBuilder;
import org.wildfly.security.auth.spi.RealmIdentity;
import org.wildfly.security.auth.spi.RealmUnavailableException;
import org.wildfly.security.auth.spi.SecurityRealm;

import javax.security.auth.x500.X500Principal;
import java.security.Principal;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Test case to test different principal mapping configurations.
 *
 * As a test case it is indented this is only executed as part of the {@link LdapTestSuite} so that the required LDAP server is running.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PrincipalMappingSuiteChild {

    private static DirContextFactory dirContextFactory;

    @BeforeClass
    public static void beforeClass() {
        dirContextFactory = SimpleDirContextFactoryBuilder.builder()
                .setProviderUrl(String.format("ldap://localhost:%d/", LdapTestSuite.LDAP_PORT))
                .setSecurityPrincipal(LdapTestSuite.SERVER_DN)
                .setSecurityCredential(LdapTestSuite.SERVER_CREDENTIAL)
                .build();
    }

    @AfterClass
    public static void afterClass() {
        dirContextFactory = null;
    }

    @Test
    public void testSimpleToDn() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                        .useX500Principal()
                        .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                        .setNameAttribute("uid").build())
                .build();

        RealmIdentity identity = realm.createRealmIdentity("plainUser");
        Principal principal = identity.getPrincipal();
        assertNotNull(principal);
        assertTrue("Principal Type", principal instanceof X500Principal);
        assertTrue("Mapped DN", "uid=plainUser,dc=elytron,dc=wildfly,dc=org".equalsIgnoreCase(principal.getName()));

        identity = realm.createRealmIdentity("nobody");
        principal = identity.getPrincipal();
        assertNull(principal);
    }

    @Test
    public void testDnToSimple() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                        .setNameAttribute("uid")
                        .build())
                .build();

        RealmIdentity identity = realm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");
        Principal principal = identity.getPrincipal();
        assertNotNull(principal);
        assertTrue("Principal Type", principal instanceof NamePrincipal);
        assertTrue("Mapped DN", "plainUser".equalsIgnoreCase(principal.getName()));

        identity = realm.createRealmIdentity("uid=nobody,dc=elytron,dc=wildfly,dc=org");
        principal = identity.getPrincipal();
        assertNull(principal);
    }

//    @Test
//    public void testSimpleToSimpleNoLookup() {
//        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
//                .setDirContextFactory(dirContextFactory)
//                .principalMapping()
//                .setNameIsDn(false)
//                .useX500Principal(false)
//                .setValidatePresence(false)
//                .cachePrincipal(false)
//                .build()
//                .build();
//
//        /*
//         * This user does not exist in LDAP but in this case we want to verify the directory is not hit.
//         */
//
//        RealmIdentity identity = realm.createRealmIdentity("otherUser");
//        Principal principal = identity.getPrincipal();
//        assertNotNull(principal);
//        assertTrue("Principal Type", principal instanceof NamePrincipal);
//        assertTrue("Mapped DN", "otherUser".equalsIgnoreCase(principal.getName()));
//    }

    @Test
    public void testSimpleToSimpleValidate() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                        .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                        .setNameAttribute("uid")
                        .build()
                )
                .build();

        RealmIdentity identity = realm.createRealmIdentity("PlainUser");
        Principal principal = identity.getPrincipal();
        assertNotNull(principal);
        assertTrue("Principal Type", principal instanceof NamePrincipal);
        assertTrue("Mapped DN", "PlainUser".equalsIgnoreCase(principal.getName()));

        identity = realm.createRealmIdentity("nobody");
        principal = identity.getPrincipal();
        assertNull(principal);
    }

    @Test
    public void testSimpleToSimpleReload() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .setNameAttribute("uid")
                                .cachePrincipal()
                                .build()
                )
                .build();

        RealmIdentity identity = realm.createRealmIdentity("PlainUser");
        Principal principal = identity.getPrincipal();
        assertNotNull(principal);
        assertTrue("Principal Type", principal instanceof NamePrincipal);
        assertTrue("Mapped DN", "plainUser".equalsIgnoreCase(principal.getName()));

        identity = realm.createRealmIdentity("nobody");
        principal = identity.getPrincipal();
        assertNull(principal);
    }

    @Test
    public void testDnToDnNoLookup() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setNameAttribute("uid")
                                .useX500Principal()
                                .cachePrincipal()
                                .build()
                )
                .build();

        RealmIdentity identity = realm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");
        Principal principal = identity.getPrincipal();

        assertNotNull(principal);

        Principal cachedPrincipal = identity.getPrincipal();

        Assert.assertSame(principal, cachedPrincipal);
    }

    @Test
    public void testDnToDnVerify() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                    .setNameAttribute("uid")
                    .useX500Principal()
                    .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                    .cachePrincipal()
                    .build()
                )
                .build();

        RealmIdentity identity = realm.createRealmIdentity("uid=PlainUser,dc=elytron,dc=wildfly,dc=org");
        Principal principal = identity.getPrincipal();
        assertNotNull(principal);
        assertTrue("Principal Type", principal instanceof X500Principal);
        assertTrue("Mapped DN", "UID=plainUser,DC=elytron,DC=wildfly,DC=org".equals(principal.getName()));

        identity = realm.createRealmIdentity("uid=nobody,dc=elytron,dc=wildfly,dc=org");
        principal = identity.getPrincipal();
        assertNull(principal);
    }

}
