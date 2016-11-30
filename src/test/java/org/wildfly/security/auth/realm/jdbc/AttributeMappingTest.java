/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.auth.realm.jdbc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.wildfly.security.auth.realm.jdbc.mapper.AttributeMapper;
import org.wildfly.security.auth.realm.jdbc.mapper.AttributeMapper.Type;
import org.wildfly.security.auth.realm.jdbc.mapper.PasswordKeyMapper;
import org.wildfly.security.auth.server.IdentityLocator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmIdentityStringKey;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AttributeMappingTest extends AbstractJdbcSecurityRealmTest {

    @Test
    public void testNoAttributes() throws Exception {
        createUserTable();
        insertUser(1, "plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");

        PasswordKeyMapper passwordKeyMapper = PasswordKeyMapper.builder()
            .setDefaultAlgorithm(ClearPassword.ALGORITHM_CLEAR)
            .setHashColumn(1)
            .build();

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password, firstName, lastName, email FROM user_table WHERE name = ?")
                    .withMapper(passwordKeyMapper)
                    .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.getRealmIdentity(IdentityLocator.fromName("plainUser"));
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();
        Attributes attributes = authorizationIdentity.getAttributes();

        assertTrue(attributes.isEmpty());
    }

    @Test
    public void testObtainFromSingleQuery() throws Exception {
        createUserTable();
        insertUser(1, "plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");

        PasswordKeyMapper passwordKeyMapper = PasswordKeyMapper.builder()
            .setDefaultAlgorithm(ClearPassword.ALGORITHM_CLEAR)
            .setHashColumn(1)
            .build();

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password, firstName, lastName, email FROM user_table WHERE name = ?")
                    .withMapper(passwordKeyMapper)
                    .withMapper(new AttributeMapper(2, "firstName"))
                    .withMapper(new AttributeMapper(3, "lastName"))
                    .withMapper(new AttributeMapper(4, "email"))
                    .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.getRealmIdentity(IdentityLocator.fromName("plainUser"));
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();
        Attributes attributes = authorizationIdentity.getAttributes();

        assertAttributeValue(attributes.get("firstName"), "John");
        assertAttributeValue(attributes.get("lastName"), "Smith");
        assertAttributeValue(attributes.get("email"), "jsmith@elytron.org");
    }

    @Test
    public void testObtainFromSingleQueryWithId() throws Exception {
        createUserTable();
        insertUser(1, "plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");

        PasswordKeyMapper passwordKeyMapper = PasswordKeyMapper.builder()
                .setDefaultAlgorithm(ClearPassword.ALGORITHM_CLEAR)
                .setHashColumn(1)
                .build();

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password, firstName, lastName, email, id FROM user_table WHERE name = ?")
                .withMapper(passwordKeyMapper)
                .withMapper(new AttributeMapper(2, "firstName"))
                .withMapper(new AttributeMapper(3, "lastName"))
                .withMapper(new AttributeMapper(4, "email"))
                .withMapper(new AttributeMapper(5, "id", Type.IDENTIFIER))
                .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.getRealmIdentity(IdentityLocator.fromName("plainUser"));
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();
        Attributes attributes = authorizationIdentity.getAttributes();

        assertEquals("1", plainUser.getKey().asString());
        assertAttributeValue(attributes.get("firstName"), "John");
        assertAttributeValue(attributes.get("lastName"), "Smith");
        assertAttributeValue(attributes.get("email"), "jsmith@elytron.org");
    }

    @Test
    public void testObtainFromSingleQueryUsingId() throws Exception {
        createUserTable();
        insertUser(1, "plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");

        PasswordKeyMapper passwordKeyMapper = PasswordKeyMapper.builder()
                .setDefaultAlgorithm(ClearPassword.ALGORITHM_CLEAR)
                .setHashColumn(1)
                .build();

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password, firstName, lastName, email, id, name FROM user_table WHERE (name = ? or id = ?)")
                    .withMapper(passwordKeyMapper)
                    .withMapper(new AttributeMapper(2, "firstName"))
                    .withMapper(new AttributeMapper(3, "lastName"))
                    .withMapper(new AttributeMapper(4, "email"))
                    .withMapper(new AttributeMapper(5, "id", Type.IDENTIFIER))
                    .withMapper(new AttributeMapper(6, "name", Type.PRINCIPAL_NAME))
                    .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.getRealmIdentity(IdentityLocator.builder().setKey(new RealmIdentity.Key() {
            @Override
            public Integer getValue() {
                return 1;
            }
        }).build());
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();
        Attributes attributes = authorizationIdentity.getAttributes();

        assertEquals("1", plainUser.getKey().asString());
        assertAttributeValue(attributes.get("firstName"), "John");
        assertAttributeValue(attributes.get("lastName"), "Smith");
        assertAttributeValue(attributes.get("email"), "jsmith@elytron.org");
    }

    @Test
    public void testRealmIdentityIdPrecedence() throws Exception {
        createUserTable();
        insertUser(1, "plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");

        PasswordKeyMapper passwordKeyMapper = PasswordKeyMapper.builder()
                .setDefaultAlgorithm(ClearPassword.ALGORITHM_CLEAR)
                .setHashColumn(1)
                .build();

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password, firstName, lastName, email, id, name FROM user_table WHERE (name = ? or id = ?)")
                .withMapper(passwordKeyMapper)
                .withMapper(new AttributeMapper(2, "firstName"))
                .withMapper(new AttributeMapper(3, "lastName"))
                .withMapper(new AttributeMapper(4, "email"))
                .withMapper(new AttributeMapper(5, "id", Type.IDENTIFIER))
                .withMapper(new AttributeMapper(6, "name", Type.PRINCIPAL_NAME))
                .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.getRealmIdentity(IdentityLocator.builder().setKey(new RealmIdentityStringKey("1")).setName("plainUser23").build());
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();
        Attributes attributes = authorizationIdentity.getAttributes();

        assertEquals("1", plainUser.getKey().asString());
        assertAttributeValue(attributes.get("firstName"), "John");
        assertAttributeValue(attributes.get("lastName"), "Smith");
        assertAttributeValue(attributes.get("email"), "jsmith@elytron.org");
    }

    @Test
    public void testObtainFromDifferentQuerieSameTable() throws Exception {
        createUserTable();
        insertUser(1, "plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");

        PasswordKeyMapper passwordKeyMapper = PasswordKeyMapper.builder()
            .setDefaultAlgorithm(ClearPassword.ALGORITHM_CLEAR)
            .setHashColumn(1)
            .build();

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password FROM user_table WHERE name = ?")
                    .withMapper(passwordKeyMapper)
                    .from(getDataSource())
                .principalQuery("SELECT firstName, lastName, email FROM user_table WHERE name = ?")
                    .withMapper(new AttributeMapper(1, "firstName"))
                    .withMapper(new AttributeMapper(2, "lastName"))
                    .withMapper(new AttributeMapper(3, "email"))
                    .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.getRealmIdentity(IdentityLocator.fromName("plainUser"));
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();
        Attributes attributes = authorizationIdentity.getAttributes();

        assertAttributeValue(attributes.get("firstName"), "John");
        assertAttributeValue(attributes.get("lastName"), "Smith");
        assertAttributeValue(attributes.get("email"), "jsmith@elytron.org");
    }

    @Test
    public void testObtainFromDifferentQueriesDifferentTables() throws Exception {
        createUserTable();
        createRoleTable();
        createRoleMappingTable();

        insertUser(1, "plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");
        insertUserRole("plainUser", "admin");

        PasswordKeyMapper passwordKeyMapper = PasswordKeyMapper.builder()
            .setDefaultAlgorithm(ClearPassword.ALGORITHM_CLEAR)
            .setHashColumn(1)
            .build();

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password FROM user_table WHERE name = ?")
                    .withMapper(passwordKeyMapper)
                    .from(getDataSource())
                .principalQuery("SELECT role_name FROM role_mapping_table WHERE user_name = ?")
                    .withMapper(new AttributeMapper(1, RoleDecoder.KEY_ROLES))
                    .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.getRealmIdentity(IdentityLocator.fromName("plainUser"));
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();
        Attributes attributes = authorizationIdentity.getAttributes();

        assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "admin");
    }

    @Test
    public void testObtainMultivaluedAttribute() throws Exception {
        createUserTable();
        createRoleTable();
        createRoleMappingTable();

        insertUser(1, "plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");
        insertUserRole("plainUser", "admin");
        insertUserRole("plainUser", "manager");
        insertUserRole("plainUser", "user");

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT role_name FROM role_mapping_table WHERE user_name = ?")
                .withMapper(new AttributeMapper(1, RoleDecoder.KEY_ROLES))
                .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.getRealmIdentity(IdentityLocator.fromName("plainUser"));
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();
        Attributes attributes = authorizationIdentity.getAttributes();

        assertAttributeValue(attributes.get(RoleDecoder.KEY_ROLES), "admin", "manager", "user");
    }

    @Test
    public void testObtainMultivaluedAttributeFromDifferentTables() throws Exception {
        createUserTable();
        createRoleTable();
        createRoleMappingTable();

        insertUser(1, "plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");
        insertUserRole("plainUser", "admin");
        insertUserRole("plainUser", "manager");
        insertUserRole("plainUser", "user");

        String allInOneAttributeName = "all-in-one";

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT role_name FROM role_mapping_table WHERE user_name = ?")
                    .withMapper(new AttributeMapper(1, allInOneAttributeName))
                    .from(getDataSource())
                .principalQuery("SELECT firstName, lastName, email FROM user_table WHERE name = ?")
                    .withMapper(new AttributeMapper(1, allInOneAttributeName))
                    .withMapper(new AttributeMapper(2, allInOneAttributeName))
                    .withMapper(new AttributeMapper(3, allInOneAttributeName))
                    .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.getRealmIdentity(IdentityLocator.fromName("plainUser"));
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();
        Attributes attributes = authorizationIdentity.getAttributes();

        assertAttributeValue(attributes.get(allInOneAttributeName), "admin", "manager", "user", "John", "Smith", "jsmith@elytron.org");
    }

    protected void assertAttributeValue(Attributes.Entry attribute, String... expectedValues) {
        assertNotNull("Attribute [" + attribute.getKey() + "] not found.", attribute);

        for (String expectedValue : expectedValues) {
            assertTrue("Value [" + expectedValue + "] for attribute [" + attribute.getKey() + "] not found.", attribute.contains(expectedValue));
        }
    }
}