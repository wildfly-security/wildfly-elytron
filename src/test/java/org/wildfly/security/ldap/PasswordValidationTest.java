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
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PasswordValidationTest {

    @ClassRule
    public static DirContextFactoryRule dirContextFactoryRule = new DirContextFactoryRule();

    @Test
    public void testPlainUserWithSimpleName() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactoryRule.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .setRdnIdentifier("uid")
                                .build()
                )
                .build();

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity("plainUser");
        ClearPasswordSpec passwordSpec = new ClearPasswordSpec("plainPassword".toCharArray());
        PasswordFactory instance = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Password password = instance.generatePassword(passwordSpec);

        CredentialSupport credentialSupport = realmIdentity.getCredentialSupport("ldap-verifiable");
        assertEquals("Identity level support", CredentialSupport.VERIFIABLE_ONLY, credentialSupport);

        assertTrue(realmIdentity.verifyCredential("ldap-verifiable", password));
    }

    @Test
    public void testPlainUserWithX500Name() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactoryRule.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setRdnIdentifier("uid")
                                .build()
                )
                .build();

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");
        ClearPasswordSpec passwordSpec = new ClearPasswordSpec("plainPassword".toCharArray());
        PasswordFactory instance = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        Password password = instance.generatePassword(passwordSpec);

        CredentialSupport credentialSupport = realmIdentity.getCredentialSupport("ldap-verifiable");
        assertEquals("Identity level support", CredentialSupport.VERIFIABLE_ONLY, credentialSupport);

        assertTrue(realmIdentity.verifyCredential("ldap-verifiable", password));
    }

    @Test
    public void testVerifyCharArrayPassword() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactoryRule.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .setRdnIdentifier("uid")
                                .build()
                )
                .build();

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");

        assertTrue(realmIdentity.verifyCredential("ldap-verifiable", "plainPassword".toCharArray()));
    }

    @Test (expected = RuntimeException.class)
    public void testVerifyInvalidPasswordType() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(dirContextFactoryRule.create())
                .setPrincipalMapping(LdapSecurityRealmBuilder.PrincipalMappingBuilder.builder()
                                .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                .setRdnIdentifier("uid")
                                .build()
                )
                .build();

        RealmIdentity realmIdentity = securityRealm.createRealmIdentity("uid=plainUser,dc=elytron,dc=wildfly,dc=org");

        realmIdentity.verifyCredential("ldap-verifiable", Integer.valueOf(123456));
    }
}
