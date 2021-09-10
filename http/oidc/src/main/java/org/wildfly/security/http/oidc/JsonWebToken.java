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

import static org.wildfly.security.http.oidc.ElytronMessages.log;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.wildfly.common.Assert;

/**
 * Representation of a JSON Web Token, as per <a href="https://tools.ietf.org/html/rfc7519">RFC 7519</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class JsonWebToken {

    public static final String EXP = "exp";
    public static final String NBF = "nbf";
    public static final String IAT = "iat";


    private final JwtClaims jwtClaims;

    /**
     * Construct a new instance.
     *
     * @param jwtClaims the JWT claims for this instance (may not be {@code null})
     */
    public JsonWebToken(JwtClaims jwtClaims) {
        Assert.checkNotNullParam("jwtClaims", jwtClaims);
        this.jwtClaims = jwtClaims;
    }

    /**
     * Get the issuer claim.
     *
     * @return the issuer claim
     * @throws IllegalArgumentException if the issuer claim is malformed
     */
    public String getIssuer() {
        try {
            return jwtClaims.getIssuer();
        } catch (MalformedClaimException e) {
            throw log.invalidTokenClaimValue();
        }
    }

    /**
     * Get the subject claim.
     *
     * @return the subject claim
     * @throws IllegalArgumentException if the subject claim is malformed
     */
    public String getSubject() {
        try {
            return jwtClaims.getSubject();
        } catch (MalformedClaimException e) {
            throw log.invalidTokenClaimValue();
        }
    }

    /**
     * Get the audience claim.
     *
     * @return the audience claim
     * @throws IllegalArgumentException if the audience claim is malformed
     */
    public List<String> getAudience() {
        try {
            return jwtClaims.getAudience();
        } catch (MalformedClaimException e) {
            throw log.invalidTokenClaimValue();
        }
    }

    /**
     * Get the expiration claim.
     *
     * @return the expiration claim
     * @throws IllegalArgumentException if the expiration claim is malformed
     */
    public Long getExpiration() {
        return getClaimValueAsLong(EXP);
    }

    /**
     * Return whether this JWT is expired.
     *
     * @return {@code true} if this JWT is expired and {@code false} otherwise
     * @throws IllegalArgumentException if the issuer claim is malformed
     */
    public boolean isExpired() {
        Long expiration = getExpiration();
        return expiration != null && expiration != 0 ? getCurrentTimeInSeconds() > expiration : false;
    }

    /**
     * Get the not before claim.
     *
     * @return the not before claim
     * @throws IllegalArgumentException if the not before claim is malformed
     */
    public Long getNotBefore() {
        return getClaimValueAsLong(NBF);
    }

    /**
     * Return whether the current time is greater than or equal to the value of the
     * not before claim.
     *
     * @return {@code true} if the not before claim is null or if the current time is greater than or equal to the value
     * of the not before claim and {@code false} otherwise
     * @throws IllegalArgumentException if the not before claim is malformed
     */
    public boolean isNotBefore() {
        Long notBefore = getNotBefore();
        return notBefore != null ? getCurrentTimeInSeconds() >= notBefore : true;
    }

    /**
     * Checks that the token is not expired and isn't prior to the not before time.
     *
     * @return {@code true} if the token is active and {@code false} otherwise
     */
    public boolean isActive() {
        return ! isExpired() && isNotBefore();
    }

    /**
     * Get the issued at claim.
     *
     * @return the issued at claim
     * @throws IllegalArgumentException if the issued at claim is malformed
     */
    public Long getIssuedAt() {
        return getClaimValueAsLong(IAT);
    }

    /**
     * Get the ID claim.
     *
     * @return the ID claim
     * @throws IllegalArgumentException if the ID claim is malformed
     */
    public String getID() {
        try {
            return jwtClaims.getJwtId();
        } catch (MalformedClaimException e) {
            throw log.invalidTokenClaimValue();
        }
    }

    /**
     * Get the claim names.
     *
     * @return the claim names
     */
    public Set<String> getClaimNames() {
        return new HashSet<>(jwtClaims.getClaimNames());
    }

    /**
     * Return whether this token has the given claim.
     *
     * @param claimName the claim name to check
     * @return {@code true} if this token has the given claim and {@code false} otherwise
     */
    public boolean hasClaim(String claimName) {
        Assert.checkNotNullParam("claimName", claimName);
        return jwtClaims.hasClaim(claimName);
    }

    /**
     * Get the value of the given claim.
     *
     * @param claimName the claim to retrieve
     * @return the value of the given claim
     */
    public Object getClaimValue(String claimName) {
        Assert.checkNotNullParam("claimName", claimName);
        return jwtClaims.getClaimValue(claimName);
    }

    /**
     * Get the value of the given claim.
     *
     * @param claimName the claim to retrieve
     * @param type the type that should be returned
     * @param <T> the type of the value
     * @return the value of the given claim
     * @throws IllegalArgumentException if the claim is malformed
     */
    public <T> T getClaimValue(String claimName, Class<T> type) {
        Assert.checkNotNullParam("claimName", claimName);
        try {
            return jwtClaims.getClaimValue(claimName, type);
        } catch (MalformedClaimException e) {
            throw log.invalidTokenClaimValue();
        }
    }

    /**
     * Get the value of the given claim.
     *
     * @param claimName the claim to retrieve
     * @return the value of the given claim as a string
     */
    public String getClaimValueAsString(String claimName) {
        Assert.checkNotNullParam("claimName", claimName);
        return jwtClaims.getClaimValueAsString(claimName);
    }

    /**
     * Get the value of the given claim as a string list.
     *
     * @param claimName the claim to retrieve
     * @return the value of the given claim as a string list
     */
    public List<String> getStringListClaimValue(String claimName) {
        Assert.checkNotNullParam("claimName", claimName);
        try {
        return jwtClaims.getStringListClaimValue(claimName);
        } catch (MalformedClaimException e) {
            throw log.invalidTokenClaimValue();
        }
    }

    private static int getCurrentTimeInSeconds() {
        return ((int) (System.currentTimeMillis() / 1000));
    }

    Long getClaimValueAsLong(String claimName) {
        try {
            Long claimValue = jwtClaims.getClaimValue(claimName, Long.class);
            if (claimValue == null) {
                claimValue = 0L;
            }
            return claimValue;
        } catch (MalformedClaimException e) {
            throw log.invalidTokenClaimValue();
        }
    }

    public static JsonValue wrapValue(Object value) {
        JsonValue jsonValue = null;
        if (value instanceof JsonValue) {
            // This may already be a JsonValue
            jsonValue = (JsonValue) value;
        } else if (value instanceof String) {
            jsonValue = Json.createValue(value.toString());
        } else if ((value instanceof Long) || (value instanceof Integer)) {
            jsonValue = Json.createValue(((Number) value).longValue());
        } else if (value instanceof Number) {
            jsonValue = Json.createValue(((Number) value).doubleValue());
        } else if (value instanceof Boolean) {
            jsonValue = (Boolean) value ? JsonValue.TRUE : JsonValue.FALSE;
        } else if (value instanceof Collection) {
            jsonValue = toJsonArray((Collection<?>) value);
        } else if (value instanceof Map) {
            JsonObject entryJsonObject = replaceMap((Map<String, Object>) value);
            jsonValue = entryJsonObject;
        }
        return jsonValue;
    }

    public static JsonObject replaceMap(Map<String, Object> map) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object entryValue = entry.getValue();
            if (entryValue instanceof Map) {
                JsonObject entryJsonObject = replaceMap((Map<String, Object>) entryValue);
                builder.add(entry.getKey(), entryJsonObject);
            } else if (entryValue instanceof List) {
                JsonArray array = (JsonArray) wrapValue(entryValue);
                builder.add(entry.getKey(), array);
            } else if (entryValue instanceof Long || entryValue instanceof Integer) {
                long lvalue = ((Number) entryValue).longValue();
                builder.add(entry.getKey(), lvalue);
            } else if (entryValue instanceof Double || entryValue instanceof Float) {
                double dvalue = ((Number) entryValue).doubleValue();
                builder.add(entry.getKey(), dvalue);
            } else if (entryValue instanceof Boolean) {
                boolean flag = ((Boolean) entryValue).booleanValue();
                builder.add(entry.getKey(), flag);
            } else if (entryValue instanceof String) {
                builder.add(entry.getKey(), entryValue.toString());
            }
        }
        return builder.build();
    }

    private static JsonArray toJsonArray(Collection<?> collection) {
        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        for (Object element : collection) {
            if (element instanceof String) {
                arrayBuilder.add(element.toString());
            } else if (element == null) {
                arrayBuilder.add(JsonValue.NULL);
            } else {
                JsonValue jvalue = wrapValue(element);
                arrayBuilder.add(jvalue);
            }
        }
        return arrayBuilder.build();
    }

}
