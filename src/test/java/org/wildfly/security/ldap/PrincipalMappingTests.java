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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.Principal;

import javax.security.auth.x500.X500Principal;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
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

        Principal principal = realm.mapNameToPrincipal("plainUser");
        assertNotNull(principal);
        assertTrue(principal instanceof X500Principal);
        assertTrue("Mapped DN", "uid=plainUser,dc=elytron,dc=wildfly,dc=org".equalsIgnoreCase(principal.getName()));

        principal = realm.mapNameToPrincipal("nobody");
        assertNull(principal);
    }

}
