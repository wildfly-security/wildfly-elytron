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

package org.wildfly.security.http.oidc;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests for typ claim validation.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class TypClaimValidationEnabledTest extends TypClaimValidationBaseTest {

    private static String ISSUER_URL = "http://localhost:8080/realms/myrealm";

    @BeforeClass
    public static void setUp() {
        mockIssuerUrl(ISSUER_URL);
    }

    @Test
    public void testTokenWithoutTypClaimWithTypClaimValidationEnabled() throws Exception {
        try {
            testTokenValidationWithoutTypClaim();
            fail("Expected exception not thrown");
        } catch (OidcException e) {
            assertTrue(e.getMessage().contains("Invalid bearer token"));
        }
    }
}
