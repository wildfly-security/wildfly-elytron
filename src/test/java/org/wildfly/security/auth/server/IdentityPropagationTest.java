/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.wildfly.common.Assert.assertTrue;

import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.AuthenticationException;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.authz.AuthorizationException;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Simple tests for propagating an identity from one domain to another.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class IdentityPropagationTest {

    private static final Provider provider = new WildFlyElytronProvider();
    private static SecurityDomain domain1;
    private static SecurityDomain domain2;

    @BeforeClass
    public static void setupSecurityDomains() throws Exception {
        Security.addProvider(provider);

        // Create some realms
        SimpleMapBackedSecurityRealm realm1 = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();
        addUser(users, "joe", "User");
        addUser(users, "bob", "User");
        realm1.setPasswordMap(users);

        SimpleMapBackedSecurityRealm realm2 = new SimpleMapBackedSecurityRealm();
        users = new HashMap<>();
        addUser(users, "sam", "Manager");
        realm2.setPasswordMap(users);

        // domain1 contains both realms
        SecurityDomain.Builder builder = SecurityDomain.builder();
        builder.addRealm("users", realm1).build();
        builder.addRealm("managers", realm2).build();
        builder.setDefaultRealmName("users");
        builder.setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()));
        domain1 = builder.build();

        // domain2 contains one of the realms
        builder = SecurityDomain.builder();
        builder.addRealm("usersRealm", realm1).setRoleMapper(rolesToMap -> Roles.of("UserRole")).build();
        builder.setDefaultRealmName("usersRealm");
        builder.setPermissionMapper((principal, roles) -> {
            if (principal.getName().equals("joe")) {
                return PermissionVerifier.from(new LoginPermission());
            }
            return PermissionVerifier.NONE;
        });
        domain2 = builder.build();
    }

    @Test
    public void testInflowFromTrustedIdentity() throws Exception {
        SecurityIdentity establishedIdentity = getIdentityFromDomain(domain1, "joe");
        SecurityIdentity inflowedIdentity = domain2.inflowFromSecurityIdentity(establishedIdentity);
        assertEquals("joe", inflowedIdentity.getPrincipal().getName());
        assertEquals(domain2, inflowedIdentity.getSecurityDomain());
        assertTrue(inflowedIdentity.getRoles().contains("UserRole"));
    }

    @Test
    public void testInflowFromUntrustedIdentity() throws Exception {
        SecurityIdentity establishedIdentity = getIdentityFromDomain(domain1, "sam");
        try {
            SecurityIdentity inflowedIdentity = domain2.inflowFromSecurityIdentity(establishedIdentity);
            fail("Expected AuthenticationException not thrown");
        } catch (AuthenticationException expected) {
        }
    }

    @Test
    public void testUnauthorizedInflowedIdentity() throws Exception {
        SecurityIdentity establishedIdentity = getIdentityFromDomain(domain1, "bob");
        try {
            SecurityIdentity inflowedIdentity = domain2.inflowFromSecurityIdentity(establishedIdentity);
            fail("Expected AuthorizationException not thrown");
        } catch (AuthorizationException expected) {
        }
    }

    @Test
    public void testInflowFromAnonymousIdentity() throws Exception {
        SecurityIdentity inflowedIdentity = domain2.inflowFromSecurityIdentity(domain1.getCurrentSecurityIdentity());
        assertEquals(domain2.getAnonymousSecurityIdentity(), inflowedIdentity);
    }

    @Test
    public void testInflowFromSameDomain() throws Exception {
        SecurityIdentity establishedIdentity = getIdentityFromDomain(domain2, "joe");
        SecurityIdentity inflowedIdentity = domain2.inflowFromSecurityIdentity(establishedIdentity);
        assertEquals(establishedIdentity, inflowedIdentity);
    }

    private static void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName, String roles) {
        List<Credential> credentials;
        try {
            credentials = Collections.singletonList(
                    new PasswordCredential(
                            PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR).generatePassword(
                                    new ClearPasswordSpec("password".toCharArray()))));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));
        securityRealm.put(userName, new SimpleRealmEntry(credentials, attributes));
    }

    private SecurityIdentity getIdentityFromDomain(final SecurityDomain securityDomain, final String userName) throws Exception {
        final ServerAuthenticationContext authenticationContext = securityDomain.createNewAuthenticationContext();
        authenticationContext.setAuthenticationName(userName);
        authenticationContext.succeed();
        return authenticationContext.getAuthorizedIdentity();
    }
}

