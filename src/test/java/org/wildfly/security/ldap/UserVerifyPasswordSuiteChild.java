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

import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.auth.provider.ldap.DirContextFactory;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.provider.ldap.SimpleDirContextFactoryBuilder;
import org.wildfly.security.auth.spi.RealmIdentity;
import org.wildfly.security.auth.spi.SecurityRealm;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UserVerifyPasswordSuiteChild {

    private DirContextFactory dirContextFactory;

    @Before
    public void createRealm() {
        dirContextFactory = SimpleDirContextFactoryBuilder.builder()
                .setProviderUrl(String.format("ldap://localhost:%d/", LdapTestSuite.LDAP_PORT))
                .setSecurityPrincipal(LdapTestSuite.SERVER_DN)
                .setSecurityCredential(LdapTestSuite.SERVER_CREDENTIAL)
                .build();
    }

    @Test
    public void testPlainUserWithSimpleName() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .setNameAttribute("uid")
                                .build()
                )
                .build();

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity("plainUser");
        ClearPasswordSpec passwordSpec = new ClearPasswordSpec("plainPassword".toCharArray());
        PasswordFactory instance = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Password password = instance.generatePassword(passwordSpec);

        assertTrue(realmIdentity.verifyCredential(password));
    }

    @Test
    public void testPlainUserWithX500Name() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setNameAttribute("uid")
                                .build()
                )
                .build();

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");
        ClearPasswordSpec passwordSpec = new ClearPasswordSpec("plainPassword".toCharArray());
        PasswordFactory instance = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Password password = instance.generatePassword(passwordSpec);

        assertTrue(realmIdentity.verifyCredential(password));
    }

    @Test
    public void testVerifyStringPassword() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .useX500Principal()
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .setNameAttribute("uid")
                                .build()
                )
                .build();

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");

        assertTrue(realmIdentity.verifyCredential("plainPassword"));
    }

    @Test
    public void testVerifyCharArrayPassword() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .useX500Principal()
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .setNameAttribute("uid")
                                .build()
                )
                .build();

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");

        assertTrue(realmIdentity.verifyCredential("plainPassword".toCharArray()));
    }

    @Test (expected = RuntimeException.class)
    public void testVerifyInvalidPasswordType() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactory)
                .principalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .useX500Principal()
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .setNameAttribute("uid")
                                .build()
                )
                .build();

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");

        assertTrue(realmIdentity.verifyCredential(Integer.valueOf(123456)));
    }
}
