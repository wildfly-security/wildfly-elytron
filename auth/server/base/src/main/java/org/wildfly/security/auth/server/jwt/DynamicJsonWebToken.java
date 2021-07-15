/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.server.jwt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.Subject;
import org.eclipse.microprofile.jwt.Claims;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.wildfly.security.auth.server._private.ElytronMessages;

/**
 * A JsonWebToken that was dynamically generated
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class DynamicJsonWebToken implements org.eclipse.microprofile.jwt.JsonWebToken {
    private final JwtClaims claimsSet;

    /**
     * Create a DynamicJsonWebToken with a given claim set
     *
     * @param claimsSet - the claims set
     */
    public DynamicJsonWebToken(JwtClaims claimsSet) {
        this.claimsSet = claimsSet;
    }

    @Override
    public String getName() {
        String principalName = getClaim(Claims.upn.name());
        if (principalName == null) {
            principalName = getClaim(Claims.preferred_username.name());
            if (principalName == null) {
                principalName = getClaim(Claims.sub.name());
            }
        }
        return principalName;
    }

    @Override
    public Set<String> getClaimNames() {
        return new HashSet<>(claimsSet.getClaimNames());
    }

    @Override
    public <T> T getClaim(String claimName) {
        Claims claimType = getClaimType(claimName);
        Object claim = null;

        // Handle the jose4j NumericDate types and
        switch (claimType) {
            case exp:
            case iat:
            case auth_time:
            case nbf:
            case updated_at:
                try {
                    claim = claimsSet.getClaimValue(claimType.name(), Long.class);
                    if (claim == null) {
                        claim = 0L;
                    }
                } catch (MalformedClaimException e) {
                    ElytronMessages.log.invalidClaimValue(e, claimType.name());
                }
                break;
            case groups:
            case aud:
                try {
                    claim = new HashSet<>(claimsSet.getClaimValue(claimType.name(), ArrayList.class));
                } catch (MalformedClaimException e) {
                    /**
                     * TODO probably need better handling here. This is in place because when parsing the payload for these claims,
                     * if the claim has a single value, it parses it as a string as opposed to a list.
                     */
                    if (e.getCause() instanceof ClassCastException) {
                        try {
                            claim = new HashSet(Arrays.asList(claimsSet.getClaimValue(claimType.name(), String.class)));
                        } catch (MalformedClaimException malformedClaimException) {

                        }
                        ElytronMessages.log.invalidClaimValue(e, claimType.name());
                    }
                }
                break;
            case UNKNOWN:
                claim = claimsSet.getClaimValue(claimName);
                break;
            default:
                claim = claimsSet.getClaimValue(claimType.name());
        }
        return (T) claim;
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }

    protected Claims getClaimType(String claimName) {
        Claims claimType;
        try {
            claimType = Claims.valueOf(claimName);
        } catch (IllegalArgumentException e) {
            claimType = Claims.UNKNOWN;
        }
        return claimType;
    }
}
