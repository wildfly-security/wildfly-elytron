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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.permission.PermissionVerifier;

/**
 * Simple tests for propagating an identity from one domain to another.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
// has dependency on wildfly-elytron-realm
public class IdentityPropagationTest {

    private static SecurityDomain domain1;
    private static SecurityDomain domain2;
    private static SecurityDomain domain3;

    @BeforeClass
    public static void setupSecurityDomains() {
        // Create some realms
        SimpleMapBackedSecurityRealm realm1 = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();
        addUser(users, "joe", "User");
        addUser(users, "bob", "User");
        realm1.setIdentityMap(users);

        SimpleMapBackedSecurityRealm realm2 = new SimpleMapBackedSecurityRealm();
        users = new HashMap<>();
        addUser(users, "sam", "Manager");
        addUser(users, "bob", "Manager");
        realm2.setIdentityMap(users);

        // domain1 contains both realms
        SecurityDomain.Builder builder = SecurityDomain.builder();
        builder.addRealm("users", realm1).build();
        builder.addRealm("managers", realm2).build();
        builder.setDefaultRealmName("users");
        builder.setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.from(new LoginPermission()));
        domain1 = builder.build();

        // domain2 contains one of the realms
        builder = SecurityDomain.builder();
        builder.addRealm("usersRealm", realm1).setRoleMapper(rolesToMap -> Roles.of("UserRole")).build();
        builder.setDefaultRealmName("usersRealm");
        builder.setPermissionMapper((permissionMappable, roles) -> {
            if (permissionMappable.getPrincipal().getName().equals("joe")) {
                return PermissionVerifier.from(new LoginPermission());
            }
            return PermissionVerifier.NONE;
        });
        domain2 = builder.build();

        // domain3 contains one of the realms and it trusts domain2
        builder = SecurityDomain.builder();
        builder.addRealm("managersRealm", realm2).setRoleMapper(rolesToMap -> Roles.of("ManagerRole")).build();
        builder.setDefaultRealmName("managersRealm");
        builder.setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.from(new LoginPermission()));
        HashSet<SecurityDomain> trustedSecurityDomains = new HashSet<>();
        trustedSecurityDomains.add(domain2);
        builder.setTrustedSecurityDomainPredicate(trustedSecurityDomains::contains);
        domain3 = builder.build();
    }

    @Test
    public void testInflowFromTrustedIdentityWithCommonRealm() throws Exception {
        ServerAuthenticationContext context = domain2.createNewAuthenticationContext();
        SecurityIdentity establishedIdentity = getIdentityFromDomain(domain1, "joe");
        assertTrue(context.importIdentity(establishedIdentity));

        SecurityIdentity inflowedIdentity = context.getAuthorizedIdentity();
        assertEquals("joe", inflowedIdentity.getPrincipal().getName());
        assertEquals(domain2, inflowedIdentity.getSecurityDomain());
        assertTrue(inflowedIdentity.getRoles().contains("UserRole"));
    }

    @Test
    public void testInflowFromTrustedIdentityWithoutCommonRealm() throws Exception {
        ServerAuthenticationContext context = domain3.createNewAuthenticationContext();
        SecurityIdentity establishedIdentity = getIdentityFromDomain(domain2, "bob");
        assertTrue(context.importIdentity(establishedIdentity));

        SecurityIdentity inflowedIdentity = context.getAuthorizedIdentity();
        assertEquals("bob", inflowedIdentity.getPrincipal().getName());
        assertEquals(domain3, inflowedIdentity.getSecurityDomain());
        assertTrue(inflowedIdentity.getRoles().contains("ManagerRole"));
    }

    @Test
    public void testInflowFromUntrustedIdentity() throws Exception {
        final ServerAuthenticationContext context = domain2.createNewAuthenticationContext();
        SecurityIdentity establishedIdentity = getIdentityFromDomain(domain3, "bob");
        assertFalse(context.importIdentity(establishedIdentity));

        try {
            context.getAuthorizedIdentity();
            fail("Expected IllegalStateException not thrown");
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    public void testInflowFromAnonymousIdentity() throws Exception {
        final ServerAuthenticationContext context = domain2.createNewAuthenticationContext();
        final SecurityIdentity establishedIdentity = domain1.getCurrentSecurityIdentity();
        assertTrue(context.importIdentity(establishedIdentity));
        SecurityIdentity inflowedIdentity = context.getAuthorizedIdentity();
        assertEquals(domain2.getAnonymousSecurityIdentity(), inflowedIdentity);
    }

    @Test
    public void testInflowFromSameDomain() throws Exception {
        final ServerAuthenticationContext context = domain2.createNewAuthenticationContext();
        SecurityIdentity establishedIdentity = getIdentityFromDomain(domain2, "joe");
        assertTrue(context.importIdentity(establishedIdentity));
        SecurityIdentity inflowedIdentity = context.getAuthorizedIdentity();
        assertEquals(establishedIdentity.getSecurityDomain(), inflowedIdentity.getSecurityDomain());
        assertEquals(establishedIdentity.getPrincipal().getName(), inflowedIdentity.getPrincipal().getName());
        assertEquals(establishedIdentity.getRealmInfo(), inflowedIdentity.getRealmInfo());
        assertTrue(inflowedIdentity.getAttributes().get("roles").containsAll(establishedIdentity.getAttributes().get("roles")));
    }

    private static void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName, String roles) {
        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));
        securityRealm.put(userName, new SimpleRealmEntry(Collections.emptyList(), attributes));
    }

    private SecurityIdentity getIdentityFromDomain(final SecurityDomain securityDomain, final String userName) {
        return securityDomain.getAnonymousSecurityIdentity().createRunAsIdentity(userName, false);
    }
}
