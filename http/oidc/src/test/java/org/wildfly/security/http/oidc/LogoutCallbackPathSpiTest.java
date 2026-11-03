/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.http.oidc;

import static org.junit.Assert.assertEquals;
import static org.wildfly.security.http.oidc.Oidc.DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME;
import static org.wildfly.security.http.oidc.Oidc.LOGOUT_EVENTS_CLAIM_MEMBER_NAME;
import static org.wildfly.security.http.oidc.Oidc.OIDC_NAME;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Collections;

import javax.security.auth.callback.CallbackHandler;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerRequestWrapper;

/**
 * Tests driven exclusively through the public {@link HttpServerAuthenticationMechanism#evaluateRequest(HttpServerRequest)}
 * entry point, for {@code logout-callback-path} matching against a request whose {@code getRequestPath()} is context-stripped
 * while {@code getRequestURI()} keeps the deployment's context segment (as a real Undertow request).
 */
public class LogoutCallbackPathSpiTest extends OidcBaseTest {

    private static final String ISSUER_URL = "http://localhost:8080/realms/myrealm";
    private static String disableTypClaimValidationPreviousValue;

    @BeforeClass
    public static void setUpClass() {
        TypClaimValidationBaseTest.mockIssuerUrl(ISSUER_URL);
        disableTypClaimValidationPreviousValue = System.setProperty(DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME, "true");
    }

    @AfterClass
    public static void tearDownClass() {
        if (disableTypClaimValidationPreviousValue == null) {
            System.clearProperty(DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME);
        } else {
            System.setProperty(DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME, disableTypClaimValidationPreviousValue);
        }
    }

    // ----------------------------------------------------------------------------------------
    // Front-channel (GET, bearer-authenticated session)
    // ----------------------------------------------------------------------------------------

    @Test
    public void absoluteUriMatchesFullRequestPathWithContextStrippedRequestPath() throws Exception {
        assertFrontChannelResult(Status.IN_PROGRESS,
                getClientUrl() + "/callback", "/callback",
                getClientUrl() + "/callback");
    }

    @Test
    public void absoluteUriWithDifferentContextDoesNotMatch() throws Exception {
        assertFrontChannelResult(Status.COMPLETE,
                getClientUrl() + "/callback", "/callback",
                "http://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT + "/otherApp/callback");
    }

    @Test
    public void relativePathWithoutContextPrefixMatches() throws Exception {
        assertFrontChannelResult(Status.IN_PROGRESS,
                getClientUrl() + "/callback", "/callback",
                "/callback");
    }

    @Test
    public void rootContextAbsoluteUriMatches() throws Exception {
        assertFrontChannelResult(Status.IN_PROGRESS,
                "http://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT + "/callback", "/callback",
                "http://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT + "/callback");
    }

    @Test
    public void multiSegmentContextAbsoluteUriMatches() throws Exception {
        assertFrontChannelResult(Status.IN_PROGRESS,
                "http://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT + "/sso/" + CLIENT_APP + "/callback", "/callback",
                "http://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT + "/sso/" + CLIENT_APP + "/callback");
    }

    @Test
    public void absoluteUriDoesNotMatchOnPathSegmentPrefixOnly() throws Exception {
        // The request context ("clientApp2") starts with the configured context ("clientApp") but is a different one.
        assertFrontChannelResult(Status.COMPLETE,
                getClientUrl() + "2/callback", "/callback",
                getClientUrl() + "/callback");
    }

    @Test
    public void absoluteUriWithNoPathDoesNotMatchAndDoesNotThrow() throws Exception {
        assertFrontChannelResult(Status.COMPLETE,
                getClientUrl() + "/callback", "/callback",
                "http://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT);
    }

    @Test
    public void absoluteUriMatchesWithQueryStringOnRequest() throws Exception {
        assertFrontChannelResult(Status.IN_PROGRESS,
                getClientUrl() + "/callback?sid=abc&iss=" + ISSUER_URL, "/callback",
                getClientUrl() + "/callback");
    }

    @Test
    public void absoluteUriMatchesPercentEncodedSegmentRawToRaw() throws Exception {
        // Both sides compared in their raw (encoded) form.
        assertFrontChannelResult(Status.IN_PROGRESS,
                getClientUrl() + "/call%20back", "/call back",
                getClientUrl() + "/call%20back");
    }

    @Test
    public void unresolvableRequestUriDoesNotMatchAndDoesNotThrow() throws Exception {
        // An unresolvable request URI (unknown protocol) must not match and must not throw.
        TestingHttpServerRequest delegate = new TestingHttpServerRequest(
                new String[] {"Bearer " + signAccessToken()},
                new URI("unresolvable://" + CLIENT_HOST_NAME + ":" + CLIENT_PORT + "/" + CLIENT_APP + "/callback"));
        HttpServerRequest request = new HttpServerRequestWrapper(delegate) {
            @Override
            public String getRequestPath() {
                return "/callback";
            }
        };

        HttpServerAuthenticationMechanism mechanism = buildMechanism(buildClientConfiguration(getClientUrl() + "/callback", false));
        mechanism.evaluateRequest(request);

        assertEquals(Status.COMPLETE, delegate.getResult());
    }

    // ----------------------------------------------------------------------------------------
    // Back-channel (POST, logout_token) coverage: same matcher, different call site.
    // ----------------------------------------------------------------------------------------

    @Test
    public void backChannelAbsoluteUriMatchesFullRequestPath() throws Exception {
        String logoutToken = signLogoutToken("session-1");
        TestingHttpServerRequest delegate = new TestingHttpServerRequest(
                "POST", null, new URI(getClientUrl() + "/callback"));
        HttpServerRequest request = new HttpServerRequestWrapper(delegate) {
            @Override
            public String getRequestPath() {
                return "/callback";
            }

            @Override
            public String getFirstParameterValue(String name) {
                return "logout_token".equals(name) ? logoutToken : super.getFirstParameterValue(name);
            }
        };

        HttpServerAuthenticationMechanism mechanism = buildMechanism(buildClientConfiguration(getClientUrl() + "/callback", true));
        mechanism.evaluateRequest(request);

        assertEquals(Status.IN_PROGRESS, delegate.getResult());
    }

    // ----------------------------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------------------------

    private void assertFrontChannelResult(Status expected, String requestUri, String requestPath, String configuredLogoutCallbackPath) throws Exception {
        String accessToken = signAccessToken();
        TestingHttpServerRequest delegate = new TestingHttpServerRequest(
                new String[] {"Bearer " + accessToken}, new URI(requestUri));
        HttpServerRequest request = new HttpServerRequestWrapper(delegate) {
            @Override
            public String getRequestPath() {
                return requestPath;
            }
        };

        HttpServerAuthenticationMechanism mechanism = buildMechanism(buildClientConfiguration(configuredLogoutCallbackPath, false));
        mechanism.evaluateRequest(request);

        assertEquals(expected, delegate.getResult());
    }

    private static OidcClientConfiguration buildClientConfiguration(String logoutCallbackPath, boolean logoutSessionRequired) throws Exception {
        OidcClientConfiguration config = new OidcClientConfiguration();
        config.setClientId(CLIENT_ID);
        config.setPublicKeyLocator(new HardcodedPublicKeyLocator(keyPair().getPublic()));
        config.setProviderUrl(ISSUER_URL);
        config.setPublicClient(true);
        config.setPrincipalAttribute("sub");
        config.setSSLRequired(Oidc.SSLRequired.EXTERNAL);
        config.setLogoutCallbackPath(logoutCallbackPath);
        config.setLogoutSessionRequired(logoutSessionRequired);
        return config;
    }

    private HttpServerAuthenticationMechanism buildMechanism(OidcClientConfiguration config) throws HttpAuthenticationException {
        OidcClientContext oidcClientContext = new OidcClientContext(config);
        OidcMechanismFactory factory = new OidcMechanismFactory(oidcClientContext);
        CallbackHandler callbackHandler = getCallbackHandler();
        return factory.createAuthenticationMechanism(OIDC_NAME, Collections.emptyMap(), callbackHandler);
    }

    private static String signAccessToken() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        JsonObjectBuilder claims = Json.createObjectBuilder()
                .add("sub", "test-subject")
                .add("iss", ISSUER_URL)
                .add("iat", now)
                .add("exp", now + 300);
        return sign(claims.build());
    }

    private static String signLogoutToken(String sid) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        JsonObject events = Json.createObjectBuilder().add(LOGOUT_EVENTS_CLAIM_MEMBER_NAME, "").build();
        JsonObjectBuilder claims = Json.createObjectBuilder()
                .add("sub", "test-subject")
                .add("iss", ISSUER_URL)
                .add("aud", CLIENT_ID)
                .add("iat", now)
                .add("exp", now + 300)
                .add("sid", sid)
                .add("events", events);
        return sign(claims.build());
    }

    private static String sign(JsonObject claims) throws Exception {
        PrivateKey privateKey = keyPair().getPrivate();
        JWSSigner signer = new RSASSASigner(privateKey);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("jwt"))
                .keyID("1")
                .build();
        JWSObject jwsObject = new JWSObject(header, new Payload(claims.toString()));
        jwsObject.sign(signer);
        return jwsObject.serialize();
    }

    private static volatile KeyPair keyPair;

    private static KeyPair keyPair() throws Exception {
        if (keyPair == null) {
            synchronized (LogoutCallbackPathSpiTest.class) {
                if (keyPair == null) {
                    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
                }
            }
        }
        return keyPair;
    }
}
