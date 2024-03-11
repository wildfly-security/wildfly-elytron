/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.jose4j.jwt.JwtClaims;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.wildfly.common.Assert.assertNotNull;

/**
 * Tests for ID Token.
 */
public class IDTokenTest {

    @Test
    public void testIDTokenWithAddressClaim() {
        JwtClaims jwtClaims = new JwtClaims();
        JsonObject jsonObject = Json.createObjectBuilder()
                .add("address", Json.createObjectBuilder()
                        .add("region", "US")
                        .add("country", "New York")
                        .add("locality", "NY")
                        .add("postal_code", "10021"))
                .build();
        jwtClaims.setClaim("given_name", "Alice");
        jwtClaims.setClaim("family_name", "Smith");
        jwtClaims.setClaim("address", jsonObject.get("address"));
        IDToken idToken = new IDToken(jwtClaims);
        assertNotNull(idToken);
        assertEquals("NY", idToken.getAddress().getLocality());
        assertEquals("10021", idToken.getAddress().getPostalCode());
        assertEquals("US", idToken.getAddress().getRegion());
        assertEquals("New York", idToken.getAddress().getCountry());
        assertEquals("Alice", idToken.getGivenName());
        assertEquals("Smith", idToken.getFamilyName());
    }
}
