/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.ClassRule;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealm.Attribute;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.Attributes;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class AbstractAttributeMappingTest {

    @ClassRule
    public static DirContextFactoryRule dirContextFactory = new DirContextFactoryRule();

    protected void assertAttributeValue(Attributes.Entry lastName, String... expectedValues) {
        assertNotNull("Attribute [" + lastName.getKey() + "] not found.", lastName);

        for (String expectedValue : expectedValues) {
            assertTrue("Value [" + expectedValue + "] for attribute [" + lastName.getKey() + "] not found.", lastName.contains(expectedValue));
        }
    }

    protected void assertAttributes(AssertResultHandler handler, Attribute... expectedAttributes) throws RealmUnavailableException {
        assertAttributes("plainUser", handler, expectedAttributes);
    }

    protected void assertAttributes(String principalName, AssertResultHandler handler, Attribute... expectedAttributes) throws RealmUnavailableException {
        SecurityDomain.Builder builder = SecurityDomain.builder();

        builder.setDefaultRealmName("default")
                .addRealm("default",
                        LdapSecurityRealmBuilder.builder()
                                .setDirContextFactory(this.dirContextFactory.create())
                                .identityMapping()
                                        .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                        .searchRecursive()
                                        .setRdnIdentifier("uid")
                                        .map(expectedAttributes)
                                        .build()
                                        .build());

        SecurityDomain securityDomain = builder.build();

        ServerAuthenticationContext serverAuthenticationContext = securityDomain.createNewAuthenticationContext();

        serverAuthenticationContext.setAuthenticationName(principalName);

        assertTrue("Principal [" + principalName + "] does not exist.", serverAuthenticationContext.exists());

        assertTrue("Authorization failed", serverAuthenticationContext.authorize(principalName));

        SecurityIdentity securityIdentity = serverAuthenticationContext.getAuthorizedIdentity();
        Attributes attributes = securityIdentity.getAttributes();

        if (expectedAttributes.length == 0) {
            assertTrue("No attributes expected.", attributes.isEmpty());
        }

        assertFalse("No attributes found for principal [" + principalName + "].", attributes.isEmpty());

        handler.assertAttributes(attributes);
    }

    protected interface AssertResultHandler {
        void assertAttributes(Attributes attributes);
    }
}
