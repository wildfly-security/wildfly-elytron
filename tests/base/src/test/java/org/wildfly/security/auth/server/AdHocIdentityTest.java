/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.auth.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.authz.RoleMapper;
import org.wildfly.security.authz.Roles;

/**
 * Tests for creating ad hoc identities.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class AdHocIdentityTest {

    @Test
    public void testAdHocIdentityWithoutSecurityIdentityTransformer() {
        SecurityDomain domain = getSecurityDomain(null);
        SecurityIdentity identity = domain.createAdHocIdentity("alice");
        assertNotNull(identity);
        assertEquals("alice", identity.getPrincipal().getName());
        assertTrue(identity.getRoles().isEmpty());
    }

    @Test
    public void testAdHocIdentityWithSecurityIdentityTransformer() {
        SecurityDomain domain = getSecurityDomain(securityIdentity -> securityIdentity.withDefaultRoleMapper(RoleMapper.constant(Roles.of("constantRole"))));
        SecurityIdentity identity = domain.createAdHocIdentity("alice");
        assertNotNull(identity);
        assertEquals("alice", identity.getPrincipal().getName());
        assertTrue(identity.getRoles().contains("constantRole"));
    }

    @Test
    public void testAdHocIdentityWithComplexSecurityIdentityTransformer() {
        SecurityDomain outflowDomain = getSecurityDomain(getRealm(), null);
        SecurityDomain domain = getSecurityDomain(securityIdentity -> outflow(securityIdentity, outflowDomain));

        SecurityIdentity identity = domain.createAdHocIdentity("joe");
        assertNotNull(identity);
        assertEquals("joe", identity.getPrincipal().getName());
        assertEquals(domain, identity.getSecurityDomain());

        assertEquals(outflowDomain.getAnonymousSecurityIdentity(), outflowDomain.getCurrentSecurityIdentity());
        SecurityIdentity outflowDomainIdentity = identity.runAsSupplierEx(() -> outflowDomain.getCurrentSecurityIdentity());
        assertEquals("joe", outflowDomainIdentity.getPrincipal().getName());
        assertTrue(outflowDomainIdentity.getRoles().contains("User"));
    }

    @Test
    public void testAdHocIdentityWithComplexSecurityIdentityTransformerAndDefaultRoleMapper() {
        SecurityDomain outflowDomain = getSecurityDomain(getRealm(), null);

        SecurityDomain domain = getSecurityDomain(securityIdentity -> outflow(securityIdentity, outflowDomain));
        SecurityIdentity identity = domain.createAdHocIdentity("joe");
        assertNotNull(identity);
        assertEquals("joe", identity.getPrincipal().getName());
        assertEquals(domain, identity.getSecurityDomain());

        identity = identity.withDefaultRoleMapper(RoleMapper.constant(Roles.of("constantRole")));
        assertTrue(identity.getRoles().contains("constantRole"));
        assertEquals(outflowDomain.getAnonymousSecurityIdentity(), outflowDomain.getCurrentSecurityIdentity());
        SecurityIdentity outflowDomainIdentity = identity.runAsSupplierEx(() -> outflowDomain.getCurrentSecurityIdentity());
        assertEquals("joe", outflowDomainIdentity.getPrincipal().getName());
        assertTrue(outflowDomainIdentity.getRoles().contains("User"));
        assertFalse(outflowDomainIdentity.getRoles().contains("constantRole"));
    }

    private static void addUser(Map<String, SimpleRealmEntry> securityRealm, String userName, String roles) {
        MapAttributes attributes = new MapAttributes();
        attributes.addAll(RoleDecoder.KEY_ROLES, Collections.singletonList(roles));
        securityRealm.put(userName, new SimpleRealmEntry(Collections.emptyList(), attributes));
    }

    private static SecurityDomain getSecurityDomain(UnaryOperator<SecurityIdentity> securityIdentityTransformer) {
        return getSecurityDomain(null, securityIdentityTransformer);
    }

    private static SecurityDomain getSecurityDomain(SecurityRealm realm, UnaryOperator<SecurityIdentity> securityIdentityTransformer) {
        SecurityDomain.Builder securityDomainBuilder = SecurityDomain.builder();
        if (realm != null) {
            securityDomainBuilder.addRealm("default", realm).build();
            securityDomainBuilder.setDefaultRealmName("default");
            securityDomainBuilder.setTrustedSecurityDomainPredicate(securityDomain -> true); // trusts all other domains
        }
        securityDomainBuilder.setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance());
        if (securityIdentityTransformer != null) {
            securityDomainBuilder.setSecurityIdentityTransformer(securityIdentityTransformer);
        }
        return securityDomainBuilder.build();
    }

    private static SecurityRealm getRealm() {
        SimpleMapBackedSecurityRealm realm = new SimpleMapBackedSecurityRealm();
        Map<String, SimpleRealmEntry> users = new HashMap<>();
        addUser(users, "joe", "User");
        addUser(users, "bob", "User");
        realm.setIdentityMap(users);
        return realm;
    }

    private SecurityIdentity outflow(SecurityIdentity securityIdentity, SecurityDomain outflowDomain) {
        return securityIdentity.withSecurityIdentitySupplier(performOutflow(securityIdentity, outflowDomain));
    }

    private static Supplier<SecurityIdentity[]> performOutflow(SecurityIdentity securityIdentity, SecurityDomain securityDomain) {
        return () -> {
            ServerAuthenticationContext context = securityDomain.createNewAuthenticationContext();
            try {
                Assert.assertTrue(context.importIdentity(securityIdentity));
            } catch (RealmUnavailableException e) {
                Assert.fail("Unable to import identity");
            }
            SecurityIdentity outflowedIdentity = context.getAuthorizedIdentity();
            return new SecurityIdentity[] { outflowedIdentity };
        };
    }
}
