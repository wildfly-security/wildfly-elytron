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
import org.jose4j.jwt.consumer.InvalidJwtException;
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
        RefreshableOidcSecurityContext securityContext = new RefreshableOidcSecurityContext(new OidcClientConfiguration(),
                null, null, new AccessToken(new JwtClaims()), null, null, null);
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
        // standard roles claim not present
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
        // standard roles claim not present
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
        // standard roles claim not present
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

    @Test
    public void testRolesWithEmptyRolesClaim() throws Exception {
        OidcClientConfiguration clientConfiguration = new OidcClientConfiguration();
        clientConfiguration.setClientId("rolesClient");

        // use only realm role mappings
        clientConfiguration.setUseRealmRoleMappings(true);
        clientConfiguration.setUseResourceRoleMappings(false);
        JwtClaims jwtClaims = populateBasicJwtClaims(true); // empty roles claim
        Attributes.Entry roles = getRealmIdentityRoles(clientConfiguration, jwtClaims);

        assertEquals(2, roles.size());
        assertTrue(roles.contains("roleC"));
        assertTrue(roles.contains("roleD"));

        // use only resource role mappings
        clientConfiguration.setUseRealmRoleMappings(false);
        clientConfiguration.setUseResourceRoleMappings(true);
        jwtClaims = populateBasicJwtClaims(true); // empty roles claim
        roles = getRealmIdentityRoles(clientConfiguration, jwtClaims);

        assertEquals(2, roles.size());
        assertTrue(roles.contains("roleB"));
        assertTrue(roles.contains("roleC"));

        // use both realm role mappings and resource role mappings
        clientConfiguration.setUseRealmRoleMappings(true);
        clientConfiguration.setUseResourceRoleMappings(true);
        jwtClaims = populateBasicJwtClaims(true); // empty roles claim
        roles = getRealmIdentityRoles(clientConfiguration, jwtClaims);

        assertEquals(3, roles.size());
        assertTrue(roles.contains("roleB"));
        assertTrue(roles.contains("roleC"));
        assertTrue(roles.contains("roleD"));

        // neither realm role mappings nor resource role mappings are included in the token
        clientConfiguration.setUseRealmRoleMappings(true);
        clientConfiguration.setUseResourceRoleMappings(true);
        jwtClaims = populateBasicJwtClaims(true, false); // empty roles claim
        roles = getRealmIdentityRoles(clientConfiguration, jwtClaims);
        assertEquals(0, roles.size());
    }

    @Test
    public void testRolesWithNonEmptyRolesClaim() throws Exception {
        OidcClientConfiguration clientConfiguration = new OidcClientConfiguration();
        clientConfiguration.setClientId("rolesClient");

        // use only the standard roles claim
        clientConfiguration.setUseRealmRoleMappings(false);
        clientConfiguration.setUseResourceRoleMappings(false);
        JwtClaims jwtClaims = populateBasicJwtClaims(false); // non-empty roles claim
        Attributes.Entry roles = getRealmIdentityRoles(clientConfiguration, jwtClaims);

        assertEquals(2, roles.size());
        assertTrue(roles.contains("roleE"));
        assertTrue(roles.contains("roleF"));

        // use realm role mappings and the standard roles claim
        clientConfiguration = new OidcClientConfiguration();
        clientConfiguration.setClientId("rolesClient");
        clientConfiguration.setUseRealmRoleMappings(true);
        clientConfiguration.setUseResourceRoleMappings(false);
        jwtClaims = populateBasicJwtClaims(false); // non-empty roles claim
        roles = getRealmIdentityRoles(clientConfiguration, jwtClaims);

        assertEquals(4, roles.size());
        assertTrue(roles.contains("roleC"));
        assertTrue(roles.contains("roleD"));
        assertTrue(roles.contains("roleE"));
        assertTrue(roles.contains("roleF"));

        // use resource role mappings and the standard roles claim
        clientConfiguration = new OidcClientConfiguration();
        clientConfiguration.setClientId("rolesClient");
        clientConfiguration.setUseRealmRoleMappings(false);
        clientConfiguration.setUseResourceRoleMappings(true);
        jwtClaims = populateBasicJwtClaims(false); // non-empty roles claim
        roles = getRealmIdentityRoles(clientConfiguration, jwtClaims);

        assertEquals(4, roles.size());
        assertTrue(roles.contains("roleB"));
        assertTrue(roles.contains("roleC"));
        assertTrue(roles.contains("roleE"));
        assertTrue(roles.contains("roleF"));

        // use realm role mappings, resource role mappings, and the standard roles claim
        clientConfiguration = new OidcClientConfiguration();
        clientConfiguration.setClientId("rolesClient");
        clientConfiguration.setUseRealmRoleMappings(true);
        clientConfiguration.setUseResourceRoleMappings(true);
        jwtClaims = populateBasicJwtClaims(false); // non-empty roles claim
        roles = getRealmIdentityRoles(clientConfiguration, jwtClaims);

        assertEquals(5, roles.size());
        assertTrue(roles.contains("roleB"));
        assertTrue(roles.contains("roleC"));
        assertTrue(roles.contains("roleD"));
        assertTrue(roles.contains("roleE"));
        assertTrue(roles.contains("roleF"));

        // neither realm role mappings nor resource role mappings are included in the token
        clientConfiguration.setUseRealmRoleMappings(true);
        clientConfiguration.setUseResourceRoleMappings(true);
        jwtClaims = populateBasicJwtClaims(false, false); // non-empty-roles
        roles = getRealmIdentityRoles(clientConfiguration, jwtClaims);

        assertEquals(2, roles.size());
        assertTrue(roles.contains("roleE"));
        assertTrue(roles.contains("roleF"));
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

    private static JwtClaims populateBasicJwtClaims(boolean useEmptyRoles) throws InvalidJwtException {
        return populateBasicJwtClaims(useEmptyRoles, true);
    }

    private static JwtClaims populateBasicJwtClaims(boolean useEmptyRoles, boolean includeRealmAndResourcesRoles) throws InvalidJwtException {
        return JwtClaims.parse("{\n" +
                "  \"exp\": 1686249550,\n" +
                "  \"iat\": 1686249490,\n" +
                "  \"auth_time\": 1686249477,\n" +
                "  \"jti\": \"8c883880-e9ec-4e96-a2d2-ee32460e0d6c\",\n" +
                "  \"iss\": \"http://localhost:8080/realms/master\",\n" +
                "  \"aud\": \"account\",\n" +
                "  \"sub\": \"4f229262-88d4-4a23-9fa5-2f5a0aadf16c\",\n" +
                "  \"typ\": \"Bearer\",\n" +
                "  \"azp\": \"account-console\",\n" +
                "  \"nonce\": \"50d8b172-15fd-4510-889e-c66c21e13176\",\n" +
                "  \"session_state\": \"7128671b-3f29-4971-8115-1ee743bbcd55\",\n" +
                "  \"acr\": \"0\",\n" +
                getRealmAndResourceRolesClaims(includeRealmAndResourcesRoles) +
                "  \"scope\": \"openid email profile\",\n" +
                "  \"sid\": \"7128671b-3f29-4971-8115-1ee743bbcd55\",\n" +
                "  \"email_verified\": false,\n" +
                getStandardRolesClaim(useEmptyRoles) +
                "  \"preferred_username\": \"alice\",\n" +
                "  \"given_name\": \"\",\n" +
                "  \"family_name\": \"\"\n" +
                "}\n");
    }

    private static String getStandardRolesClaim(boolean useEmptyRoles) {
        return useEmptyRoles ? "  \"roles\": [\n" +
                "  ],\n" :
                "  \"roles\": [\n" +
                        "    \"roleE\",\n" +
                        "    \"roleF\"\n" +
                        "  ],\n";
    }

    private static String getRealmAndResourceRolesClaims(boolean includeRealmAndResourceRoles) {
        return includeRealmAndResourceRoles ? "  \"realm_access\": {\n" +
                "      \"roles\": [\n" +
                "        \"roleC\",\n" +
                "        \"roleD\"\n" +
                "      ]\n" +
                "  },\n" +
                "  \"resource_access\": {\n" +
                "    \"SomeResource\": {\n" +
                "      \"roles\": [\n" +
                "        \"roleA\"\n" +
                "      ]\n" +
                "    },\n" +
                "    \"rolesClient\": {\n" +
                "      \"roles\": [\n" +
                "        \"roleB\",\n" +
                "        \"roleC\"\n" +
                "      ]\n" +
                "    }\n" +
                "  },\n" :
                "";
    }

    private Attributes.Entry getRealmIdentityRoles(OidcClientConfiguration clientConfiguration, JwtClaims jwtClaims) throws RealmUnavailableException {
        RefreshableOidcSecurityContext securityContext = new RefreshableOidcSecurityContext(clientConfiguration,
                null, null, new AccessToken(jwtClaims), null, null, null);
        OidcPrincipal principal = new OidcPrincipal("john", securityContext);

        RealmIdentity identity = realm.getRealmIdentity(principal);
        AuthorizationIdentity authorizationIdentity = identity.getAuthorizationIdentity();
        return authorizationIdentity.getAttributes().get(KEY_ROLES);
    }

}
