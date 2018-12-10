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

import org.junit.Test;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.AggregateSecurityRealm;
import org.wildfly.security.auth.realm.LegacyPropertiesSecurityRealm;
import org.wildfly.security.auth.realm.ldap.AttributeMapping;
import org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class RoleMappingSuiteChild extends AbstractAttributeMappingSuiteChild {

    @Test
    public void testRoleMappingWithMemberOf() throws Exception {
        assertAttributes("userWithMemberOfRoles", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "roleByMemberOf");
        }, AttributeMapping.fromIdentity().from("memberOf").extractRdn("CN").to(RoleDecoder.KEY_ROLES).build());
    }

    @Test
    public void testRoleMappingWithMemberOfAttribute() throws Exception {
        assertAttributes("userWithMemberOfRoles", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "roleByMemberOfDescription");
        }, AttributeMapping.fromReference("memberOf").from("description").to(RoleDecoder.KEY_ROLES).build());
    }

    @Test
    public void testRoleMappingWithMemberOfRecursive() throws Exception {
        assertAttributes("userWithMemberOfRoles", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "roleByMemberOfDescription", "roleOfRoleByMemberOfDescription");
        }, AttributeMapping.fromReference("memberOf").roleRecursion(3).from("description").to(RoleDecoder.KEY_ROLES).build());
    }

    @Test
    public void testRoleMappingFromSpecificBaseDN() throws Exception {
        assertAttributes("userWithRoles", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "RoleFromRolesOu");
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").from("CN").searchDn("ou=Roles,dc=elytron,dc=wildfly,dc=org").to(RoleDecoder.KEY_ROLES).build()) ;
    }

    @Test
    public void testRoleMappingRecursiveFromBaseDN() throws Exception {
        assertAttributes("userWithRoles", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "RoleFromRolesOu", "RoleFromBaseDN");
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").from("CN").to(RoleDecoder.KEY_ROLES).build());
    }

    @Test
    public void testRoleMappingNoRecursiveOnlyFromBaseDN() throws Exception {
        assertAttributes("userWithRoles", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "RoleFromBaseDN");
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").from("CN").to(RoleDecoder.KEY_ROLES).searchRecursively(false).build());
    }

    @Test
    public void testRecursiveRoles() throws Exception {
        assertAttributes("jduke", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "R1", "R2");
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").from("cn").roleRecursion(1).to(RoleDecoder.KEY_ROLES).build());
    }


    @Test
    public void testRecursiveRolesCycle() throws Exception {
        assertAttributes("jduke", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "R1", "R2","R3");
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").from("cn").roleRecursion(10).to(RoleDecoder.KEY_ROLES).build());
    }

    @Test
    public void testRecursiveRolesMoreWaysToOneRole() throws Exception {
        assertAttributes("ranvir", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "MWR1", "MWR2","MWR3");
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").from("cn").roleRecursion(1).to(RoleDecoder.KEY_ROLES).build());
    }

    @Test
    public void testRecursiveRolesByName() throws Exception {
        assertAttributes("falith", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "RN1", "RN2");
        }, AttributeMapping.fromFilter("description={0}").from("cn").roleRecursionName("cn").roleRecursion(1).to(RoleDecoder.KEY_ROLES).build());
    }

    @Test
    public void testAuthorizationWithDifferentAuthenticationRealm() throws Exception {
        SecurityDomain.Builder builder = SecurityDomain.builder()
            .setDefaultRealmName("default")
            .addRealm("default",
                new AggregateSecurityRealm(
                    LegacyPropertiesSecurityRealm.builder() // authentication realm
                        .setUsersStream(this.getClass().getResourceAsStream("/org/wildfly/security/auth/realm/nonldap.properties"))
                        .setPlainText(true)
                        .build(),
                    LdapSecurityRealmBuilder.builder() // authorization realm
                        .setDirContextSupplier(LdapTestSuite.dirContextFactory.create())
                        .identityMapping()
                            .setSearchDn("dc=elytron,dc=wildfly,dc=org")
                            .searchRecursive()
                            .setRdnIdentifier("uid")
                            .map(AttributeMapping.fromFilter("description={0}").from("cn").roleRecursionName("cn").roleRecursion(2).to(RoleDecoder.KEY_ROLES).build())
                            .build()
                        .build()
                )
            ).build();
        builder.setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.from(new LoginPermission()));

        assertAttributes(builder.build(), "hybridUser", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "RN3");
        });
    }
}
