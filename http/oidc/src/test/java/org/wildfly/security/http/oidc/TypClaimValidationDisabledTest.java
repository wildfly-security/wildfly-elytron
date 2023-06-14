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

import static org.junit.Assert.assertEquals;
import static org.wildfly.common.Assert.assertNotNull;
import static org.wildfly.security.http.oidc.Oidc.DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests for disabling typ claim validation.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class TypClaimValidationDisabledTest extends TypClaimValidationBaseTest {

    private static String DISABLE_TYP_CLAIM_VALIDATION_PROPERTY;

    @BeforeClass
    public static void setUp() {
        mockIssuerUrl(ISSUER_URL);
        DISABLE_TYP_CLAIM_VALIDATION_PROPERTY = System.setProperty(DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME, "true");
    }

    @AfterClass
    public static void tearDown() {
        if (DISABLE_TYP_CLAIM_VALIDATION_PROPERTY == null) {
            System.clearProperty(DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME);
        } else {
            System.setProperty(DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME, DISABLE_TYP_CLAIM_VALIDATION_PROPERTY);
        }
    }

    @Test
    public void testTokenWithoutTypClaimWithTypClaimValidationDisabled() throws Exception {
        AccessToken accessToken = testTokenValidationWithoutTypClaim();
        assertNotNull(accessToken);
        assertEquals(ISSUER_URL, accessToken.getIssuer());
        assertEquals(SUBJECT, accessToken.getSubject());
    }
}
