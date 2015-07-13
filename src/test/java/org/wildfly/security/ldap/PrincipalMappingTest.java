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

import org.junit.ClassRule;
import org.junit.Test;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test case to test different principal mapping configurations.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PrincipalMappingTest {

    @ClassRule
    public static DirContextFactoryRule dirContextFactory = new DirContextFactoryRule();

    @Test
    public void testSimpleToDn() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                        .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                        .setRdnIdentifier("uid").build())
                .build();

        RealmIdentity identity = realm.createRealmIdentity("plainUser");
        assertTrue("Exists", identity.exists());

        identity = realm.createRealmIdentity("nobody");
        assertFalse("Exists", identity.exists());
    }

    @Test
    public void testDnToSimple() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                        .setRdnIdentifier("uid")
                        .build())
                .build();

        RealmIdentity identity = realm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");
        assertTrue("Exists", identity.exists());

        identity = realm.createRealmIdentity("uid=nobody,dc=elytron,dc=wildfly,dc=org");
        assertFalse("Exists", identity.exists());
    }

    @Test
    public void testSimpleToSimpleValidate() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .setRdnIdentifier("uid")
                                .build()
                )
                .build();

        RealmIdentity identity = realm.createRealmIdentity("PlainUser");
        assertTrue("Exists", identity.exists());

        identity = realm.createRealmIdentity("nobody");
        assertFalse("Exists", identity.exists());
    }

    @Test
    public void testSimpleToSimpleReload() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder().setSearchDn("dc=elytron,dc=wildfly,dc=org").setRdnIdentifier("uid").build())
                .build();

        RealmIdentity identity = realm.createRealmIdentity("PlainUser");
        assertTrue("Exists", identity.exists());

        identity = realm.createRealmIdentity("nobody");
        assertFalse("Exists", identity.exists());
    }

    @Test
    public void testDnToDnNoLookup() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setRdnIdentifier("uid")
                                .build()
                )
                .build();

        RealmIdentity identity = realm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");
        assertTrue("Exists", identity.exists());
    }

    @Test
    public void testDnToDnVerify() throws RealmUnavailableException {
        SecurityRealm realm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setRdnIdentifier("uid")
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .build()
                )
                .build();

        RealmIdentity identity = realm.createRealmIdentity("uid=PlainUser,dc=elytron,dc=wildfly,dc=org");
        assertTrue("Exists", identity.exists());

        identity = realm.createRealmIdentity("uid=nobody,dc=elytron,dc=wildfly,dc=org");
        assertFalse("Exists", identity.exists());
    }

}
