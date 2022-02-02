/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.oidc;

import org.jboss.resteasy.plugins.server.embedded.SimplePrincipal;
import org.jose4j.jwt.JwtClaims;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.wildfly.security.auth.SupportLevel.POSSIBLY_SUPPORTED;
import static org.wildfly.security.auth.SupportLevel.UNSUPPORTED;
import static org.wildfly.security.auth.server.RealmIdentity.NON_EXISTENT;
import static org.wildfly.security.authz.RoleDecoder.KEY_ROLES;

/**
 * Tests the {@link OidcSecurityRealm} implementation.
 *
 * @author <a href="mailto:patrick@reini.net">Patrick Reinhart</a>
 */
public class OidcSecurityRealmTest {
    private OidcSecurityRealm realm;

    @Before
    public void setUp() {
        realm = new OidcSecurityRealm();
    }

    @Test
    public void testGetCredentialAcquireSupport() throws RealmUnavailableException {
        assertEquals(UNSUPPORTED, realm.getCredentialAcquireSupport(null, null, null));
    }

    @Test
    public void testGetEvidenceVerifySupport() throws RealmUnavailableException {
        assertEquals(POSSIBLY_SUPPORTED, realm.getEvidenceVerifySupport(null, null));
    }

    @Test
    public void testGetRealmIdentityWithNonOidcPrincipal() throws RealmUnavailableException {
        Principal nonOidcPricipal = new SimplePrincipal("john");
        assertEquals(NON_EXISTENT, realm.getRealmIdentity(nonOidcPricipal));
    }

    @Test
    public void testGetRealmIdentityNoRoles() throws RealmUnavailableException {
        // setup
        RefreshableOidcSecurityContext securityContext = new RefreshableOidcSecurityContext();
        securityContext.setCurrentRequestInfo(new OidcClientConfiguration(), null);
        OidcPrincipal principal = new OidcPrincipal("john", securityContext);

        // test
        RealmIdentity identity = realm.getRealmIdentity(principal);

        // verification
        assertNotEquals(NON_EXISTENT, identity);
        assertEquals(principal, identity.getRealmIdentityPrincipal());
        assertEquals(UNSUPPORTED, identity.getCredentialAcquireSupport(null, null, null));
        assertNull(identity.getCredential(null));
        assertEquals(SupportLevel.SUPPORTED, identity.getEvidenceVerifySupport(null, null));
        assertTrue(identity.verifyEvidence(null));
        assertTrue(identity.exists());
        AuthorizationIdentity authorizationIdentity = identity.getAuthorizationIdentity();
        assertNotNull(authorizationIdentity);
        final Attributes.Entry roles = authorizationIdentity.getAttributes().get(KEY_ROLES);
        assertTrue(roles.isEmpty());
    }

    @Test
    public void testGetRealmIdentityRolesCombined() throws RealmUnavailableException {
        // setup
        final OidcClientConfiguration clientConfiguration = new OidcClientConfiguration();
        clientConfiguration.setClientId("SpecialResource");
        clientConfiguration.setUseRealmRoleMappings(true);
        clientConfiguration.setUseResourceRoleMappings(true);
        final JwtClaims jwtClaims = new JwtClaims();
        final Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("SomeResource", createRoles("roleA"));
        resourceAccess.put("SpecialResource", createRoles("roleB", "roleC"));
        jwtClaims.setClaim("resource_access", resourceAccess);
        jwtClaims.setClaim("realm_access", createRoles("roleC", "roleD"));

        RefreshableOidcSecurityContext securityContext = new RefreshableOidcSecurityContext(clientConfiguration,
                null, null, new AccessToken(jwtClaims), null, null, null);
        OidcPrincipal principal = new OidcPrincipal("john", securityContext);

        // test
        RealmIdentity identity = realm.getRealmIdentity(principal);
        AuthorizationIdentity authorizationIdentity = identity.getAuthorizationIdentity();
        final Attributes.Entry roles = authorizationIdentity.getAttributes().get(KEY_ROLES);

        // verification
        assertEquals(3, roles.size());
        assertTrue(roles.contains("roleB"));
        assertTrue(roles.contains("roleC"));
        assertTrue(roles.contains("roleD"));
    }

    @Test
    public void testGetRealmIdentityOnlyRealmRoles() throws RealmUnavailableException {
        // setup
        final OidcClientConfiguration clientConfiguration = new OidcClientConfiguration();
        clientConfiguration.setClientId("SpecialResource");
        clientConfiguration.setUseRealmRoleMappings(true);
        final JwtClaims jwtClaims = new JwtClaims();
        final Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("SpecialResource", createRoles("roleB", "roleC"));
        jwtClaims.setClaim("resource_access", resourceAccess);
        jwtClaims.setClaim("realm_access", createRoles("roleC", "roleD"));

        RefreshableOidcSecurityContext securityContext = new RefreshableOidcSecurityContext(clientConfiguration,
                null, null, new AccessToken(jwtClaims), null, null, null);
        OidcPrincipal principal = new OidcPrincipal("john", securityContext);

        // test
        AuthorizationIdentity authorizationIdentity = realm.getRealmIdentity(principal).getAuthorizationIdentity();
        final Attributes.Entry roles = authorizationIdentity.getAttributes().get(KEY_ROLES);

        // verification
        assertEquals(2, roles.size());
        assertTrue(roles.contains("roleC"));
        assertTrue(roles.contains("roleD"));
    }

    @Test
    public void testGetRealmIdentityOnlyResourceRoles() throws RealmUnavailableException {
        // setup
        final OidcClientConfiguration clientConfiguration = new OidcClientConfiguration();
        clientConfiguration.setClientId("SpecialResource");
        clientConfiguration.setUseRealmRoleMappings(false);
        clientConfiguration.setUseResourceRoleMappings(true);
        final JwtClaims jwtClaims = new JwtClaims();
        final Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("SpecialResource", createRoles("roleB", "roleC"));
        jwtClaims.setClaim("resource_access", resourceAccess);
        jwtClaims.setClaim("", new RealmAccessClaim(createRoles("roleC", "roleD")));

        RefreshableOidcSecurityContext securityContext = new RefreshableOidcSecurityContext(clientConfiguration,
                null, null, new AccessToken(jwtClaims), null, null, null);
        OidcPrincipal principal = new OidcPrincipal("john", securityContext);

        // test
        AuthorizationIdentity authorizationIdentity = realm.getRealmIdentity(principal).getAuthorizationIdentity();
        final Attributes.Entry roles = authorizationIdentity.getAttributes().get(KEY_ROLES);

        // verification
        assertEquals(2, roles.size());
        assertTrue(roles.contains("roleB"));
        assertTrue(roles.contains("roleC"));
    }


    @Test
    public void testGetRealmIdentityNoMappings() throws RealmUnavailableException {
        // setup
        final OidcClientConfiguration clientConfiguration = new OidcClientConfiguration();
        clientConfiguration.setClientId("SpecialResource");
        clientConfiguration.setUseRealmRoleMappings(false);
        clientConfiguration.setUseResourceRoleMappings(false);
        final JwtClaims jwtClaims = new JwtClaims();
        final Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("SpecialResource", createRoles("roleB", "roleC"));
        jwtClaims.setClaim("resource_access", resourceAccess);
        jwtClaims.setClaim("", new RealmAccessClaim(createRoles("roleC", "roleD")));

        RefreshableOidcSecurityContext securityContext = new RefreshableOidcSecurityContext(clientConfiguration,
                null, null, new AccessToken(jwtClaims), null, null, null);
        OidcPrincipal principal = new OidcPrincipal("john", securityContext);

        // test
        AuthorizationIdentity authorizationIdentity = realm.getRealmIdentity(principal).getAuthorizationIdentity();
        final Attributes.Entry roles = authorizationIdentity.getAttributes().get(KEY_ROLES);

        // verification
        assertTrue(roles.isEmpty());
    }

    static Map<String, Object> createRoles(String... roleNames) {
        final ArrayList<String> value = new ArrayList<>();
        for (String role : roleNames) {
            value.add(role);
        }
        final Map<String, Object> roles = new HashMap<>();
        roles.put("roles", value);
        return roles;
    }
}
