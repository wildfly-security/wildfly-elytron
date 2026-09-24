/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.Oidc.LOGOUT_EVENTS_CLAIM_MEMBER_NAME;

import org.jose4j.jwt.consumer.InvalidJwtException;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.wildfly.security.http.oidc.Oidc.DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME;

/**
 * Tests for claim validation for back channel logout.
 */
public class TypBackChannelLogoutClaimValidationTest extends TypClaimValidationBaseTest {

    private static final String ISSUER_URL = "http://localhost:8080/realms/myrealm";
    private static final String MYACCOUNT = "myAccount";
    private static String DISABLE_TYP_CLAIM_VALIDATION_PROPERTY;
    private static JsonObjectBuilder claimsBuilder;

    @BeforeClass
    public static void setUp() {
        mockIssuerUrl(ISSUER_URL);
        DISABLE_TYP_CLAIM_VALIDATION_PROPERTY = System.setProperty(DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME, "true");
    }

    @Before
    public void createDefaultClaims() {
        // default set of claims
        JsonObject eventPayload = createEventsClaim();
        claimsBuilder = createClaims(60 * 10);
        claimsBuilder.add("sid", "mySid")
            .add("aud", MYACCOUNT)    // override previous value
            .add("iat", (System.currentTimeMillis() / 1000))
            .add("events", eventPayload);
    }

    @AfterClass
    public static void tearDown() {
        if (DISABLE_TYP_CLAIM_VALIDATION_PROPERTY == null) {
            System.clearProperty(DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME);
        } else {
            System.setProperty(DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME, DISABLE_TYP_CLAIM_VALIDATION_PROPERTY);
        }
    }

    private static JsonObject createEventsClaim() {
        return Json.createObjectBuilder()
            .add(LOGOUT_EVENTS_CLAIM_MEMBER_NAME,"" )
            .build();
    }

    private static void assertInvalidLogoutToken(OidcException exception, String expectedValidationMessage) {
        assertTrue(exception.getMessage().contains("Invalid logout token"));
        assertTrue(exception.getCause() instanceof InvalidJwtException);
        assertTrue(exception.getCause().getMessage().contains(expectedValidationMessage));
    }

    @Test
    public void allClaimsValidationTest() throws Exception {
        try {
            testBackChannelLogoutClaim(claimsBuilder, MYACCOUNT);
        } catch (OidcException e) {
            assertTrue(e.getMessage().contains("Invalid logout claims"));
        }
    }

    @Test
    public void emptyAudClaimValidationTest() throws Exception {
        try {
            // override default value
            claimsBuilder.add("aud", "");
            testBackChannelLogoutClaim(claimsBuilder, MYACCOUNT);
            fail("Expected an invalid logout token exception");
        } catch (OidcException e) {
            assertInvalidLogoutToken(e, "No matching value found");
        }
    }

    @Test
    public void noIatClaimValidationTest() throws Exception {
        try {
            claimsBuilder.remove("iat");
            testBackChannelLogoutClaim(claimsBuilder, MYACCOUNT);
            fail("Expected an invalid logout token exception");
        } catch (OidcException e) {
            assertInvalidLogoutToken(e, "Required logout claim, iat, is missing");
        }
    }

    @Test
    public void invalidDataTypeIatClaimValidationTest() throws Exception {
        try {
            // override default value
            claimsBuilder.add("iat", "bad-value");
            testBackChannelLogoutClaim(claimsBuilder, MYACCOUNT);
            fail("Expected an invalid logout token exception");
        } catch (OidcException e) {
            assertInvalidLogoutToken(e, "The value of the 'iat' claim is not the expected type");
        }
    }

    @Test
    public void invalidValueIatClaimValidationTest() throws Exception {
        try {
            // override default value
            claimsBuilder.add("iat", (System.currentTimeMillis()));
            testBackChannelLogoutClaim(claimsBuilder, MYACCOUNT);
            fail("Expected an invalid logout token exception");
        } catch (OidcException e) {
            assertInvalidLogoutToken(e, "claim value cannot be before");
        }
    }

    @Test
    public void noEventsClaimValidationTest() throws Exception {
        try {
            claimsBuilder.remove("events");
            testBackChannelLogoutClaim(claimsBuilder, MYACCOUNT);
            fail("Expected an invalid logout token exception");
        } catch (OidcException e) {
            assertInvalidLogoutToken(e, "Required logout claim, events, is missing");
        }
    }

    @Test
    public void invalidEventsClaimValidationTest() throws Exception {
        try {
            JsonObject eventPayload = Json.createObjectBuilder()
                .add("invalid-logout-event-claim-member-name","" )
                .build();

            // override default value
            claimsBuilder.add("events", eventPayload);
            testBackChannelLogoutClaim(claimsBuilder, MYACCOUNT);
            fail("Expected an invalid logout token exception");
        } catch (OidcException e) {
            assertInvalidLogoutToken(e, "Events claim does not contain the required member name");
        }
    }

    @Test
    public void noSidClaimValidationTest() throws Exception {
        try {
            claimsBuilder.remove("sid");
            testBackChannelLogoutClaim(claimsBuilder, MYACCOUNT);
        } catch (OidcException e) {
            fail("invalid exception: " + e);
        }
    }
}
