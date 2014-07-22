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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.Principal;

import javax.security.auth.x500.X500Principal;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.provider.RealmIdentity;
import org.wildfly.security.auth.provider.SecurityRealm;
import org.wildfly.security.auth.provider.ldap.DirContextFactory;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.provider.ldap.SimpleDirContextFactoryBuilder;

/**
 * Test case to test different principal mapping configurations.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PrincipalMappingTests {

    private static DirContextFactory dirContextFactory;

    @BeforeClass
    public static void beforeClass() {
        dirContextFactory = SimpleDirContextFactoryBuilder.builder()
                .setProviderUrl(String.format("ldap://localhost:%d/", LdapTest.LDAP_PORT))
                .setSecurityPrincipal(LdapTest.SERVER_DN)
                .setSecurityCredential(LdapTest.SERVER_CREDENTIAL)
                .build();
    }

    @AfterClass
    public static void afterClass() {
        dirContextFactory = null;
    }

    @Test
    public void testSimpleToDn() {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping()
                .setNameIsDn(false)
                .setPrincipalUseDn(true)
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setNameAttribute("uid")
                .build()
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
    public void testDnToSimple() {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping()
                .setNameIsDn(true)
                .setPrincipalUseDn(false)
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setNameAttribute("uid")
                .build()
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
//                .setPrincipalUseDn(false)
//                .setValidatePresence(false)
//                .setReloadPrincipalName(false)
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
    public void testSimpleToSimpleValidate() {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping()
                .setNameIsDn(false)
                .setPrincipalUseDn(false)
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setNameAttribute("uid")
                .setReloadPrincipalName(false)
                .setValidatePresence(true)
                .build()
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
    public void testSimpleToSimpleReload() {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping()
                .setNameIsDn(false)
                .setPrincipalUseDn(false)
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setNameAttribute("uid")
                .setReloadPrincipalName(true)
                .setValidatePresence(true)
                .build()
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
    public void testDnToDnNoLookup() {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping()
                .setNameIsDn(true)
                .setPrincipalUseDn(true)
                .setValidatePresence(false)
                .setReloadPrincipalName(false)
                .build()
                .build();

        /*
         * This user does not exist in LDAP but in this case we want to verify the directory is not hit.
         */

        RealmIdentity identity = realm.createRealmIdentity("uid=otherUser,dc=elytron,dc=wildfly,dc=org");
        Principal principal = identity.getPrincipal();
        assertNotNull(principal);
        assertTrue("Principal Type", principal instanceof X500Principal);
        assertTrue("Mapped DN", "uid=otherUser,dc=elytron,dc=wildfly,dc=org".equalsIgnoreCase(principal.getName()));
    }

    @Test
    public void testDnToDnVerify() {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping()
                .setNameIsDn(true)
                .setPrincipalUseDn(true)
                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                .setReloadPrincipalName(false)
                .setValidatePresence(true)
                .build()
                .build();

        RealmIdentity identity = realm.createRealmIdentity("uid=PlainUser,dc=elytron,dc=wildfly,dc=org");
        Principal principal = identity.getPrincipal();
        assertNotNull(principal);
        assertTrue("Principal Type", principal instanceof X500Principal);
        assertTrue("Mapped DN", "UID=PlainUser,DC=elytron,DC=wildfly,DC=org".equals(principal.getName()));

        identity = realm.createRealmIdentity("uid=nobody,dc=elytron,dc=wildfly,dc=org");
        principal = identity.getPrincipal();
        assertNull(principal);
    }

}
