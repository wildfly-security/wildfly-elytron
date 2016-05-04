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
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.IdentityLocator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.evidence.PasswordGuessEvidence;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PasswordValidationSuiteChild {

    @Test
    public void testPlainUserWithSimpleName() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(LdapTestSuite.dirContextFactory.create())
                .identityMapping()
                    .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                    .setRdnIdentifier("uid")
                    .build()
                .addDirectEvidenceVerification()
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(IdentityLocator.fromName("plainUser"));

        SupportLevel credentialSupport = realmIdentity.getEvidenceVerifySupport(PasswordGuessEvidence.class, null);
        assertEquals("Identity verification level support", SupportLevel.SUPPORTED, credentialSupport);

        assertTrue(realmIdentity.verifyEvidence(new PasswordGuessEvidence("plainPassword".toCharArray())));
    }

    @Test
    public void testPlainUserWithX500Name() throws Exception {
        SecurityRealm securityRealm = LdapSecurityRealmBuilder.builder()
                .setDirContextFactory(LdapTestSuite.dirContextFactory.create())
                .identityMapping()
                    .setRdnIdentifier("uid")
                    .build()
                .addDirectEvidenceVerification()
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(IdentityLocator.fromName("uid=plainUser,dc=elytron,dc=wildfly,dc=org"));

        SupportLevel credentialSupport = realmIdentity.getEvidenceVerifySupport(PasswordGuessEvidence.class, null);
        assertEquals("Identity verification level support", SupportLevel.SUPPORTED, credentialSupport);

        assertTrue(realmIdentity.verifyEvidence(new PasswordGuessEvidence("plainPassword".toCharArray())));
    }

}
