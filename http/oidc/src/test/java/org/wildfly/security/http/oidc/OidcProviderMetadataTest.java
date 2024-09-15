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

import org.wildfly.security.jose.util.JsonSerialization;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Test OIDC json config class to return of values.
 */
public class OidcProviderMetadataTest {
    private static OidcProviderMetadata oidcProviderMetadata;
    private static OidcProviderMetadata emptyOidcProviderMetadata;
    private static OidcProviderMetadata withoutOptionalsOidcProviderMetadata;

    @BeforeClass
    public static void setUp() throws IOException {
        // load the control data
        ByteArrayInputStream is = new ByteArrayInputStream(providerMetaData.getBytes());
        oidcProviderMetadata =  JsonSerialization.readValue(is, OidcProviderMetadata.class);
        is.close();

        // control data to check variable inits in OidcProviderMetadata
        is = new ByteArrayInputStream(emptyProviderMetaData.getBytes());
        emptyOidcProviderMetadata =  JsonSerialization.readValue(is, OidcProviderMetadata.class);
        is.close();

        is = new ByteArrayInputStream(withoutOptionalsProviderMetaData.getBytes());
        withoutOptionalsOidcProviderMetadata =  JsonSerialization.readValue(is, OidcProviderMetadata.class);
        is.close();
    }

    @Test
    public void testIssuer() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm".equals(oidcProviderMetadata.getIssuer()));
        assertTrue("http://localhost:8080/realms/myrealm".equals(withoutOptionalsOidcProviderMetadata.getIssuer()));
        assertNull(emptyOidcProviderMetadata.getIssuer());
    }

    @Test
    public void testAuthorizationEndpoint() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm/protocol/openid-connect/auth".equals(oidcProviderMetadata.getAuthorizationEndpoint()));
        assertTrue("http://localhost:8080/auth".equals(withoutOptionalsOidcProviderMetadata.getAuthorizationEndpoint()));
        assertNull(emptyOidcProviderMetadata.getAuthorizationEndpoint());
    }

    @Test
    public void testTokenEndpoint() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm/protocol/openid-connect/token".equals(oidcProviderMetadata.getTokenEndpoint()));
        assertTrue("http://localhost:8080/token".equals(withoutOptionalsOidcProviderMetadata.getTokenEndpoint()));
        assertNull(emptyOidcProviderMetadata.getTokenEndpoint());
    }

    @Test
    public void testIntrospectionEndpoint() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm/protocol/openid-connect/token/introspect".equals(oidcProviderMetadata.getIntrospectionEndpoint()));
        assertTrue("http://localhost:8080/introspect".equals(withoutOptionalsOidcProviderMetadata.getIntrospectionEndpoint()));
        assertNull(emptyOidcProviderMetadata.getIntrospectionEndpoint());
    }

    @Test
    public void testUserinfoEndpoint() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm/protocol/openid-connect/userinfo".equals(oidcProviderMetadata.getUserinfoEndpoint()));
        assertTrue("http://localhost:8080/userinfo".equals(withoutOptionalsOidcProviderMetadata.getUserinfoEndpoint()));
        assertNull(emptyOidcProviderMetadata.getUserinfoEndpoint());
    }

    @Test
    public void testLogoutEndpoint() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm/protocol/openid-connect/logout".equals(oidcProviderMetadata.getLogoutEndpoint()));
        assertTrue("http://localhost:8080/logout".equals(withoutOptionalsOidcProviderMetadata.getLogoutEndpoint()));
        assertNull(emptyOidcProviderMetadata.getLogoutEndpoint());
    }

    @Test
    public void testJwksUri() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm/protocol/openid-connect/certs".equals(oidcProviderMetadata.getJwksUri()));
        assertTrue("http://localhost:8080/certs".equals(withoutOptionalsOidcProviderMetadata.getJwksUri()));
        assertNull(emptyOidcProviderMetadata.getJwksUri());
    }

    @Test
    public void testCheckSessionIframe() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm/protocol/openid-connect/login-status-iframe.html".equals(oidcProviderMetadata.getCheckSessionIframe()));
        assertTrue("http://localhost:8080/login-status-iframe.html".equals(withoutOptionalsOidcProviderMetadata.getCheckSessionIframe()));
        assertNull(emptyOidcProviderMetadata.getCheckSessionIframe());
    }

    @Test
    public void testGrantTypesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getGrantTypesSupported();
        assertTrue(l.contains("refresh_token"));
        assertNull(emptyOidcProviderMetadata.getGrantTypesSupported());
    }

    @Test
    public void testResponseTypesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getResponseTypesSupported();
        assertTrue(l.contains("code id_token"));
        assertNull(emptyOidcProviderMetadata.getResponseTypesSupported());
    }

    @Test
    public void testSubjectTypesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getSubjectTypesSupported();
        assertTrue(l.contains("pairwise"));
        assertNull(emptyOidcProviderMetadata.getSubjectTypesSupported());
    }

    @Test
    public void testIdTokenSigningAlgValuesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getIdTokenSigningAlgValuesSupported();
        assertTrue(l.contains("HS256"));
        assertNull(emptyOidcProviderMetadata.getIdTokenSigningAlgValuesSupported());
    }

    @Test
    public void testIdTokenEncryptionAlgValuesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getIdTokenEncryptionAlgValuesSupported();
        assertTrue(l.contains("RSA1_5"));
        assertNull(emptyOidcProviderMetadata.getIdTokenEncryptionAlgValuesSupported());
    }

    @Test
    public void testIdTokenEncryptionEncValuesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getIdTokenEncryptionEncValuesSupported();
        assertTrue(l.contains("A128CBC-HS256"));
        assertNull(emptyOidcProviderMetadata.getIdTokenEncryptionEncValuesSupported());
    }

    @Test
    public void testUserInfoSigningAlgValuesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getUserInfoSigningAlgValuesSupported();
        assertTrue(l.contains("EdDSA"));
        assertNull(emptyOidcProviderMetadata.getUserInfoSigningAlgValuesSupported());
    }

    @Test
    public void testRequestObjectSigningAlgValuesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getRequestObjectSigningAlgValuesSupported();
        assertTrue(l.contains("RS384"));
        assertNull(emptyOidcProviderMetadata.getRequestObjectSigningAlgValuesSupported());
        assertNull(withoutOptionalsOidcProviderMetadata.getRequestObjectSigningAlgValuesSupported());
    }

    @Test
    public void testResponseModesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getResponseModesSupported();
        assertTrue(l.contains("query.jwt"));
        assertNull(emptyOidcProviderMetadata.getResponseModesSupported());
    }

    @Test
    public void testRegistrationEndpoint() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm/clients-registrations/openid-connect".equals(oidcProviderMetadata.getRegistrationEndpoint()));
        assertTrue("http://localhost:8080/openid-connect".equals(withoutOptionalsOidcProviderMetadata.getRegistrationEndpoint()));
        assertNull(emptyOidcProviderMetadata.getRegistrationEndpoint());
    }

    @Test
    public void testTokenEndpointAuthMethodsSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getTokenEndpointAuthMethodsSupported();
        assertTrue(l.contains("client_secret_basic"));
        assertNull(emptyOidcProviderMetadata.getTokenEndpointAuthMethodsSupported());
    }

    @Test
    public void testTokenEndpointAuthSigningAlgValuesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getTokenEndpointAuthSigningAlgValuesSupported();
        assertTrue(l.contains("PS384"));
        assertNull(emptyOidcProviderMetadata.getTokenEndpointAuthSigningAlgValuesSupported());
    }

    @Test
    public void testClaimsSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getClaimsSupported();
        assertTrue(l.contains("given_name"));
        assertNull(emptyOidcProviderMetadata.getClaimsSupported());
    }

    @Test
    public void testClaimTypesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getClaimTypesSupported();
        assertTrue(l.contains("normal"));
        assertNull(emptyOidcProviderMetadata.getClaimTypesSupported());
    }

    @Test
    public void testClaimsParameterSupported() throws Exception {
        assertTrue(oidcProviderMetadata.getClaimsParameterSupported());
        assertFalse(withoutOptionalsOidcProviderMetadata.getClaimsParameterSupported());
    }

    @Test
    public void testScopesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getScopesSupported();
        assertTrue(l.contains("offline_access"));
        assertNull(emptyOidcProviderMetadata.getScopesSupported());
    }

    @Test
    public void testRequestParameterSupported() throws Exception {
        assertTrue(oidcProviderMetadata.getRequestParameterSupported());
        assertFalse(withoutOptionalsOidcProviderMetadata.getRequestParameterSupported());
    }

    @Test
    public void testRequestUriParameterSupported() throws Exception {
        assertTrue(oidcProviderMetadata.getRequestUriParameterSupported());
        assertFalse(withoutOptionalsOidcProviderMetadata.getRequestUriParameterSupported());
    }

    @Test
    public void testPushedAuthorizationRequestEndpoint() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm/protocol/openid-connect/ext/par/request".equals(oidcProviderMetadata.getPushedAuthorizationRequestEndpoint()));
        assertNull(emptyOidcProviderMetadata.getPushedAuthorizationRequestEndpoint());
        assertNull(withoutOptionalsOidcProviderMetadata.getPushedAuthorizationRequestEndpoint());
    }

    @Test
    public void testRevocationEndpoint() throws Exception {
        assertTrue("http://localhost:8080/realms/myrealm/protocol/openid-connect/revoke".equals(oidcProviderMetadata.getRevocationEndpoint()));
        assertTrue("http://localhost:8080/revoke".equals(withoutOptionalsOidcProviderMetadata.getRevocationEndpoint()));
        assertNull(emptyOidcProviderMetadata.getRevocationEndpoint());
    }

    @Test
    public void testRevocationEndpointAuthMethodsSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getRevocationEndpointAuthMethodsSupported();
        assertTrue(l.contains("client_secret_basic"));
        assertNull(emptyOidcProviderMetadata.getRevocationEndpointAuthMethodsSupported());
    }

    @Test
    public void testRevocationEndpointAuthSigningAlgValuesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getRevocationEndpointAuthSigningAlgValuesSupported();
        assertTrue(l.contains("RS384"));
        assertNull(emptyOidcProviderMetadata.getRevocationEndpointAuthSigningAlgValuesSupported());
    }

    @Test
    public void testBackchannelLogoutSupported() throws Exception {
        assertTrue(oidcProviderMetadata.getBackchannelLogoutSupported());
        assertFalse(withoutOptionalsOidcProviderMetadata.getBackchannelLogoutSupported());
    }

    @Test
    public void testBackchannelLogoutSessionSupported() throws Exception {
        assertTrue(oidcProviderMetadata.getBackchannelLogoutSessionSupported());
        assertFalse(withoutOptionalsOidcProviderMetadata.getBackchannelLogoutSessionSupported());
    }

    @Test
    public void testCodeChallengeMethodsSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getCodeChallengeMethodsSupported();
        assertTrue(l.contains("S256"));
        assertNull(emptyOidcProviderMetadata.getCodeChallengeMethodsSupported());
    }

    @Test
    public void testTlsClientCertificateBoundAccessTokens() throws Exception {
        assertTrue(oidcProviderMetadata.getTlsClientCertificateBoundAccessTokens());
        assertFalse(withoutOptionalsOidcProviderMetadata.getTlsClientCertificateBoundAccessTokens());
    }

    @Test
    public void testRequestObjectEncryptionEncValuesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getRequestObjectEncryptionEncValuesSupported();
        assertTrue(l.contains("A192GCM"));
        assertNull(emptyOidcProviderMetadata.getRequestObjectEncryptionEncValuesSupported());
        assertNull(withoutOptionalsOidcProviderMetadata.getRequestObjectEncryptionEncValuesSupported());
    }

    @Test
    public void testRequestObjectEncryptionAlgValuesSupported() throws Exception {
        List<String> l = oidcProviderMetadata.getRequestObjectEncryptionAlgValuesSupported();
        assertTrue(l.contains("RSA1_5"));
        assertNull(emptyOidcProviderMetadata.getRequestObjectEncryptionAlgValuesSupported());
        assertNull(withoutOptionalsOidcProviderMetadata.getRequestObjectEncryptionAlgValuesSupported());
    }

    // Control data taken from keycloak
    private static final String providerMetaData = "{\n" +
            "\"issuer\":\"http://localhost:8080/realms/myrealm\"\n" +
            ",\"authorization_endpoint\":\"http://localhost:8080/realms/myrealm/protocol/openid-connect/auth\"\n" +
            ",\"token_endpoint\":\"http://localhost:8080/realms/myrealm/protocol/openid-connect/token\"\n" +
            ",\"introspection_endpoint\":\"http://localhost:8080/realms/myrealm/protocol/openid-connect/token/introspect\"\n" +
            ",\"userinfo_endpoint\":\"http://localhost:8080/realms/myrealm/protocol/openid-connect/userinfo\"\n" +
            ",\"end_session_endpoint\":\"http://localhost:8080/realms/myrealm/protocol/openid-connect/logout\"\n" +
            ",\"jwks_uri\":\"http://localhost:8080/realms/myrealm/protocol/openid-connect/certs\"\n" +
            ",\"check_session_iframe\":\"http://localhost:8080/realms/myrealm/protocol/openid-connect/login-status-iframe.html\"\n" +
            ",\"grant_types_supported\":[\"authorization_code\",\"implicit\",\"refresh_token\",\"password\",\"client_credentials\",\"urn:openid:params:grant-type:ciba\",\"urn:ietf:params:oauth:grant-type:device_code\"]\n" +
            ",\"response_types_supported\":[\"code\",\"none\",\"id_token\",\"token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"]\n" +
            ",\"subject_types_supported\":[\"public\",\"pairwise\"]\n" +
            ",\"id_token_signing_alg_values_supported\":[\"PS384\",\"RS384\",\"EdDSA\",\"ES384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"]\n" +
            ",\"id_token_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"]\n" +
            ",\"id_token_encryption_enc_values_supported\":[\"A256GCM\",\"A192GCM\",\"A128GCM\",\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\"]\n" +
            ",\"userinfo_signing_alg_values_supported\":[\"PS384\",\"RS384\",\"EdDSA\",\"ES384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\",\"none\"]\n" +
            ",\"request_object_signing_alg_values_supported\":[\"PS384\",\"RS384\",\"EdDSA\",\"ES384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\",\"none\"]\n" +
            ",\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\",\"query.jwt\",\"fragment.jwt\",\"form_post.jwt\",\"jwt\"]\n" +
            ",\"registration_endpoint\":\"http://localhost:8080/realms/myrealm/clients-registrations/openid-connect\"\n" +
            ",\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\",\"tls_client_auth\",\"client_secret_jwt\"]\n" +
            ",\"token_endpoint_auth_signing_alg_values_supported\":[\"PS384\",\"RS384\",\"EdDSA\",\"ES384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"]\n" +
            ",\"claims_supported\":[\"aud\",\"sub\",\"iss\",\"auth_time\",\"name\",\"given_name\",\"family_name\",\"preferred_username\",\"email\",\"acr\"]\n" +
            ",\"claim_types_supported\":[\"normal\"]\n" +
            ",\"claims_parameter_supported\":true\n" +
            ",\"scopes_supported\":[\"openid\",\"address\",\"profile\",\"offline_access\",\"microprofile-jwt\",\"acr\",\"web-origins\",\"basic\",\"email\",\"roles\",\"phone\"]\n" +
            ",\"request_parameter_supported\":true\n" +
            ",\"request_uri_parameter_supported\":true\n" +
            ",\"pushed_authorization_request_endpoint\":\"http://localhost:8080/realms/myrealm/protocol/openid-connect/ext/par/request\"\n" +
            ",\"revocation_endpoint\":\"http://localhost:8080/realms/myrealm/protocol/openid-connect/revoke\"\n" +
            ",\"revocation_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\",\"client_secret_post\",\"tls_client_auth\",\"client_secret_jwt\"]\n" +
            ",\"revocation_endpoint_auth_signing_alg_values_supported\":[\"PS384\",\"RS384\",\"EdDSA\",\"ES384\",\"HS256\",\"HS512\",\"ES256\",\"RS256\",\"HS384\",\"ES512\",\"PS256\",\"PS512\",\"RS512\"]\n" +
            ",\"backchannel_logout_supported\":true\n" +
            ",\"backchannel_logout_session_supported\":true\n" +
            ",\"code_challenge_methods_supported\":[\"plain\",\"S256\"]\n" +
            ",\"tls_client_certificate_bound_access_tokens\":true\n" +
            ",\"request_object_encryption_enc_values_supported\":[\"A256GCM\",\"A192GCM\",\"A128GCM\",\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\"]\n" +
            ",\"request_object_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"]\n" +
            "}";

    private static final String emptyProviderMetaData = "{}";

    private static final String withoutOptionalsProviderMetaData = "{\n" +
            "\"issuer\":\"http://localhost:8080/realms/myrealm\"\n" +
            ",\"authorization_endpoint\":\"http://localhost:8080/auth\"\n" +
            ",\"token_endpoint\":\"http://localhost:8080/token\"\n" +
            ",\"introspection_endpoint\":\"http://localhost:8080/introspect\"\n" +
            ",\"userinfo_endpoint\":\"http://localhost:8080/userinfo\"\n" +
            ",\"end_session_endpoint\":\"http://localhost:8080/logout\"\n" +
            ",\"jwks_uri\":\"http://localhost:8080/certs\"\n" +
            ",\"check_session_iframe\":\"http://localhost:8080/login-status-iframe.html\"\n" +
            ",\"grant_types_supported\":[\"authorization_code\",\"implicit\"]\n" +
            ",\"response_types_supported\":[\"code\",\"none\",\"id_token\",\"token\"]\n" +
            ",\"subject_types_supported\":[\"public\",\"pairwise\"]\n" +
            ",\"id_token_signing_alg_values_supported\":[\"PS384\"]\n" +
            ",\"id_token_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA-OAEP-256\",\"RSA1_5\"]\n" +
            ",\"id_token_encryption_enc_values_supported\":[\"A256GCM\"]\n" +
            ",\"userinfo_signing_alg_values_supported\":[\"PS384\",\"none\"]\n" +
            ",\"response_modes_supported\":[\"query\",\"fragment\",\"form_post.jwt\",\"jwt\"]\n" +
            ",\"registration_endpoint\":\"http://localhost:8080/openid-connect\"\n" +
            ",\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\",\"client_secret_basic\"]\n" +
            ",\"token_endpoint_auth_signing_alg_values_supported\":[\"PS384\",\"RS384\"]\n" +
            ",\"claims_supported\":[\"aud\",\"sub\"]\n" +
            ",\"claim_types_supported\":[\"normal\"]\n" +
            ",\"scopes_supported\":[\"openid\",\"address\",\"profile\"]\n" +
            ",\"revocation_endpoint\":\"http://localhost:8080/revoke\"\n" +
            ",\"revocation_endpoint_auth_methods_supported\":[\"private_key_jwt\"]\n" +
            ",\"revocation_endpoint_auth_signing_alg_values_supported\":[\"PS384\",\"RS384\",\"EdDSA\"]\n" +
            ",\"code_challenge_methods_supported\":[\"plain\",\"S256\"]\n" +
            "}";
}
