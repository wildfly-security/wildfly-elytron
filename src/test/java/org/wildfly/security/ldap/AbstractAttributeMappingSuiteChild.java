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

import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.ldap.AttributeMapping;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.permission.PermissionVerifier;

import java.util.Arrays;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class AbstractAttributeMappingSuiteChild {

    protected void assertAttributeValue(Attributes.Entry values, String... expectedValues) {
        assertNotNull("Attribute values are null.", values);

        for (String expectedValue : expectedValues) {
            assertTrue("Value [" + expectedValue + "] for attribute [" + values.getKey() + "] not found in " + Arrays.toString(values.toArray()), values.contains(expectedValue));
        }

        for (Object value : values.toArray()) {
            assertTrue("Value [" + value + "] for attribute [" + values.getKey() + "] was not expected", Arrays.asList(expectedValues).contains(value));
        }
    }

    protected void assertAttributes(AssertResultHandler handler, AttributeMapping... expectedAttributes) throws RealmUnavailableException {
        assertAttributes("plainUser", handler, expectedAttributes);
    }

    protected void assertAttributes(String principalName, AssertResultHandler handler, AttributeMapping... expectedAttributes) throws RealmUnavailableException {
        SecurityDomain.Builder builder = SecurityDomain.builder();

        builder.setDefaultRealmName("default")
                .addRealm("default",
                        LdapSecurityRealmBuilder.builder()
                                .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                                .identityMapping()
                                        .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                                        .searchRecursive()
                                        .setRdnIdentifier("uid")
                                        .map(expectedAttributes)
                                        .build()
                                        .build()).build();

        builder.setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.from(new LoginPermission()));

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
