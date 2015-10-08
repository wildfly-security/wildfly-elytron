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
package org.wildfly.security.auth.provider.jdbc;

import org.junit.Test;
import org.wildfly.security.auth.provider.jdbc.mapper.PasswordKeyMapper;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.password.interfaces.ClearPassword;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationIdentityTest extends AbstractJdbcSecurityRealmTest {

    @Test
    public void testInvalidIdentity() throws Exception {
        createUserTable();
        insertUser("plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password, firstName, lastName, email FROM user_table WHERE name = ?")
                    .withMapper(new PasswordKeyMapper("clear", ClearPassword.ALGORITHM_CLEAR, 1))
                    .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.createRealmIdentity("invalidUser");
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();

        assertSame(AuthorizationIdentity.EMPTY, authorizationIdentity);
        assertFalse(plainUser.exists());
    }

    @Test
    public void testValidIdentity() throws Exception {
        createUserTable();
        insertUser("plainUser", "plainPassword", "John", "Smith", "jsmith@elytron.org");

        JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder()
                .principalQuery("SELECT password, firstName, lastName, email FROM user_table WHERE name = ?")
                    .withMapper(new PasswordKeyMapper("clear", ClearPassword.ALGORITHM_CLEAR, 1))
                    .from(getDataSource())
                .build();

        RealmIdentity plainUser = securityRealm.createRealmIdentity("plainUser");
        AuthorizationIdentity authorizationIdentity = plainUser.getAuthorizationIdentity();

        assertNotSame(AuthorizationIdentity.EMPTY, authorizationIdentity);
        assertTrue(plainUser.exists());
    }
}