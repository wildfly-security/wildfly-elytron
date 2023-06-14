/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security.http.oidc.ElytronMessages.log;

import java.security.Principal;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

public class OidcSecurityRealm implements SecurityRealm {

    @Override
    public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
        if (principal instanceof OidcPrincipal) {
            return createRealmIdentity((OidcPrincipal) principal);
        }
        return RealmIdentity.NON_EXISTENT;
    }

    private RealmIdentity createRealmIdentity(OidcPrincipal principal) {
        return new RealmIdentity() {
            @Override
            public Principal getRealmIdentityPrincipal() {
                return principal;
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
                return SupportLevel.UNSUPPORTED;
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                return null;
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return SupportLevel.SUPPORTED;
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                return principal != null;
            }

            @Override
            public boolean exists() throws RealmUnavailableException {
                return principal != null;
            }

            @Override
            public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
                RefreshableOidcSecurityContext securityContext = (RefreshableOidcSecurityContext) principal.getOidcSecurityContext();
                Attributes attributes = new MapAttributes();
                Set<String> roles = getRolesFromSecurityContext(securityContext);
                attributes.addAll(RoleDecoder.KEY_ROLES, roles);
                return AuthorizationIdentity.basicIdentity(attributes);
            }
        };
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName, AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    private static Set<String> getRolesFromSecurityContext(RefreshableOidcSecurityContext session) {
        final Set<String> roles = new HashSet<>();
        final AccessToken accessToken = session.getToken();
        final OidcClientConfiguration oidcClientConfig = session.getOidcClientConfiguration();
        if (oidcClientConfig.isUseResourceRoleMappings()) {
            if (log.isTraceEnabled()) {
                log.trace("use resource role mappings");
            }
            RealmAccessClaim resourceAccessClaim = accessToken.getResourceAccessClaim(oidcClientConfig.getResourceName());
            if (resourceAccessClaim != null) {
                roles.addAll(resourceAccessClaim.getRoles());
            }
        }
        if (oidcClientConfig.isUseRealmRoleMappings()) {
            if (log.isTraceEnabled()) {
                log.trace("use realm role mappings");
            }
            RealmAccessClaim realmAccessClaim = accessToken.getRealmAccessClaim();
            if (realmAccessClaim != null) {
                roles.addAll(realmAccessClaim.getRoles());
            }
        }
        // include roles from the standard "roles" claim if present
        List<String> rolesClaim = accessToken.getRolesClaim();
        if (! rolesClaim.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("use roles claim");
            }
            roles.addAll(rolesClaim);
        }
        if (log.isTraceEnabled()) {
            log.trace("Setting roles: ");
            for (String role : roles) {
                log.trace("   role: " + role);
            }
        }
        return roles;
    }
}
