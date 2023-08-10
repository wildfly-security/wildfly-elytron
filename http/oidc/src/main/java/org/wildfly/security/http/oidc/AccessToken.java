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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jose4j.jwt.JwtClaims;

/**
 * Representation of an access token.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class AccessToken extends JsonWebToken {

    private static final String ALLOWED_ORIGINS = "allowed-origins";
    private static final String REALM_ACCESS = "realm_access";
    private static final String RESOURCE_ACCESS = "resource_access";
    private static final String ROLES = "roles";
    private static final String TRUSTED_CERTS = "trusted-certs";

    /**
     * Construct a new instance.
     *
     * @param jwtClaims the JWT claims for this instance (may not be {@code null})
     */
    public AccessToken(JwtClaims jwtClaims) {
        super(jwtClaims);
    }

    /**
     * Get the allowed-origins claim.
     *
     * @return the allowed-origins claim
     */
    public List<String> getAllowedOrigins() {
        return getStringListClaimValue(ALLOWED_ORIGINS);
    }

    /**
     * Get the realm_access claim.
     *
     * @return the realm_access claim
     * @throws IllegalArgumentException if the realm_access claim is malformed
     */
    public RealmAccessClaim getRealmAccessClaim() {
        Object realmAccessValue = getClaimValue(REALM_ACCESS);
        return realmAccessValue == null ? null : new RealmAccessClaim((Map<String, Object>) realmAccessValue);
    }

    /**
     * Get the resource_access claim.
     *
     * @return the resource_access claim
     * @throws IllegalArgumentException if the resource_access claim is malformed
     */
    public Map<String, RealmAccessClaim> getResourceAccessClaim() {
        Object resourceAccessValue = getClaimValue(RESOURCE_ACCESS);
        if (resourceAccessValue == null) {
            return null;
        }
        Map<String, Object> resourceAccessValueMap = (Map<String, Object>) resourceAccessValue;
        Map<String, RealmAccessClaim> resourceAccessClaim = new HashMap<>(resourceAccessValueMap.size());
        for (String key : resourceAccessValueMap.keySet()) {
            Object val = resourceAccessValueMap.get(key);
            resourceAccessClaim.put(key, val == null ? null : new RealmAccessClaim((Map<String, Object>)val));
        }
        return resourceAccessClaim;
    }

    /**
     * Get the resource_access claim.
     *
     * @param resource the resource
     * @return the resource_access claim
     * @throws IllegalArgumentException if the resource_access claim is malformed
     */
    public RealmAccessClaim getResourceAccessClaim(String resource) {
        Map<String, RealmAccessClaim> realmAccessClaimMap = getResourceAccessClaim();
        return realmAccessClaimMap == null ? null : realmAccessClaimMap.get(resource);
    }

    /**
     * Get the trusted-certs claim.
     *
     * @return the trusted-certs claim
     */
    public List<String> getTrustedCertsClaim() {
        return getStringListClaimValue(TRUSTED_CERTS);
    }

    /**
     * Get the roles claim.
     *
     * @return the roles claim
     */
    public List<String> getRolesClaim() {
        return getStringListClaimValue(ROLES);
    }
}
