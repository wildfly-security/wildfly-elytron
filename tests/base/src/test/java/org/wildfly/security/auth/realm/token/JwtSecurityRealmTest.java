/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.realm.token;

import com.nimbusds.jose.Payload;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.PlainObject;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import mockit.integration.junit4.JMockit;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.QueueDispatcher;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.token.validator.JwtValidator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.realm.token.test.util.RsaJwk;
import org.wildfly.security.ssl.builder.SSLContextBuilder;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.wildfly.security.realm.token.test.util.JwtTestUtil.createClaims;
import static org.wildfly.security.realm.token.test.util.JwtTestUtil.createJwt;
import static org.wildfly.security.realm.token.test.util.JwtTestUtil.createRsaJwk;
import static org.wildfly.security.realm.token.test.util.JwtTestUtil.createTokenDispatcher;
import static org.wildfly.security.realm.token.test.util.JwtTestUtil.jwksToJson;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
// dependent on wildfly-security-ssl
@RunWith(JMockit.class)
public class JwtSecurityRealmTest {

    private static final MockWebServer server = new MockWebServer();
    private static final MockWebServer nonTlsServer = new MockWebServer();

    private static final String CA_JKS_LOCATION = "./target/test-classes/jwt/ca/jks/";
    private static char[] PASSWORD = "password".toCharArray();

    private static KeyPair keyPair1;
    private static KeyPair keyPair2;
    private static KeyPair keyPair3;


    private static RsaJwk jwk1 = new RsaJwk();
    private static RsaJwk jwk2 = new RsaJwk();
    private static RsaJwk jwk3 = new RsaJwk();

    private static File trustStoreFile;

    private static String jwksResponse;

    @BeforeClass
    public static void setup() throws GeneralSecurityException, IOException {
        System.setProperty("wildfly.config.url", JwtSecurityRealmTest.class.getResource("wildfly-jwt-test-config.xml").toExternalForm());

        keyPair1 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        jwk1 = createRsaJwk(keyPair1, "1");

        keyPair2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        jwk2 = createRsaJwk(keyPair2, "2");

        keyPair3 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        jwk3 = createRsaJwk(keyPair3, "3");

        JsonObject jwks = jwksToJson(jwk1, jwk2);

        File dir = new File(CA_JKS_LOCATION);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        trustStoreFile = new File(CA_JKS_LOCATION + "ca.truststore");
        if (trustStoreFile.exists()) trustStoreFile.delete();

        KeyStore mockKeyStore = KeyStore.getInstance("JKS");
        KeyStore trustStore = KeyStore.getInstance("JKS");
        mockKeyStore.load(null, null);
        trustStore.load(null, null);

        String alg = KeyManagerFactory.getDefaultAlgorithm();

        SelfSignedX509CertificateAndSigningKey issuerSelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal("CN=localhost, ST=Elytron, C=UK, EMAILADDRESS=elytron@wildfly.org, O=Root Certificate Authority"))
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA256withRSA")
                .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
                .build();

        X509Certificate issuerCertificate = issuerSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();

        mockKeyStore.setKeyEntry("ca", issuerSelfSignedX509CertificateAndSigningKey.getSigningKey(), PASSWORD, new X509Certificate[]{issuerCertificate});

        trustStore.setCertificateEntry("ca", issuerCertificate);
        trustStore.store(new FileOutputStream(trustStoreFile), PASSWORD);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(alg);
        keyManagerFactory.init(mockKeyStore, PASSWORD);

        X509ExtendedKeyManager keyManager = null;
        for (KeyManager km : keyManagerFactory.getKeyManagers()) {
            if (km instanceof X509ExtendedKeyManager) {
                keyManager = X509ExtendedKeyManager.class.cast(km);
                break;
            }
        }

        SSLContext sslContext = new SSLContextBuilder().setKeyManager(keyManager).build().create();

        jwksResponse = jwks.toString();

        server.useHttps(sslContext.getSocketFactory(), false);
        server.setDispatcher(createTokenDispatcher(jwksResponse));
        nonTlsServer.setDispatcher(createTokenDispatcher(jwksResponse));
        server.start(50831);
        nonTlsServer.start(50832);
    }

    @AfterClass
    public static void cleanup() throws IOException {
        server.shutdown();
        nonTlsServer.shutdown();
    }

    @Test
    public void testChangedKeys() throws Exception {
        QueueDispatcher dispatcher = new QueueDispatcher();
        dispatcher.enqueueResponse(new MockResponse().setBody(jwksToJson(jwk1).toString()));
        dispatcher.enqueueResponse(new MockResponse().setBody(jwksToJson(jwk1).toString()));
        dispatcher.enqueueResponse(new MockResponse().setBody(jwksToJson(jwk2).toString()));
        dispatcher.enqueueResponse(new MockResponse().setBody(jwksToJson(jwk2).toString()));
        dispatcher.enqueueResponse(new MockResponse().setBody(jwksToJson(jwk3.setKid("1")).toString()));
        dispatcher.enqueueResponse(new MockResponse().setBody(jwksToJson(jwk3).toString()));
        jwk3.setKid("3");
        server.setDispatcher(dispatcher);

        BearerTokenEvidence evidence1 = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, "1", new URI("https://localhost:50831")));
        BearerTokenEvidence evidence2 = new BearerTokenEvidence(createJwt(keyPair2, 60, -1, "2", new URI("https://localhost:50831")));
        BearerTokenEvidence evidence3 = new BearerTokenEvidence(createJwt(keyPair3, 60, -1, "1", new URI("https://localhost:50831")));

        X509TrustManager tm = getTrustManager();
        SSLContext sslContext = new SSLContextBuilder().setTrustManager(tm).setClientMode(true).setSessionTimeout(10).build().create();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50831")
                        .setJkuTimeout(0) //refresh jwks every time
                        .setJkuMinTimeBetweenRequests(0)
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true).build())
                .build();

        assertIdentityExist(securityRealm, evidence1);
        assertIdentityNotExist(securityRealm, evidence2);
        assertIdentityExist(securityRealm, evidence2);
        assertIdentityNotExist(securityRealm, evidence3);
        assertIdentityExist(securityRealm, evidence3);
        assertIdentityNotExist(securityRealm, evidence1);

        server.setDispatcher(createTokenDispatcher(jwksResponse));
    }

    @Test
    public void testNewRotationKeys() throws Exception {
        // set the jku url only with key 1
        server.setDispatcher(createTokenDispatcher(jwksToJson(jwk1).toString()));

        BearerTokenEvidence evidence1 = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, "1", new URI("https://localhost:50831")));

        X509TrustManager tm = getTrustManager();
        SSLContext sslContext = new SSLContextBuilder().setTrustManager(tm).setClientMode(true).setSessionTimeout(10).build().create();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50831")
                        .setJkuTimeout(60000L) // 60s of cache
                        .setJkuMinTimeBetweenRequests(0) // no time betweeen requests
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true).build())
                .build();

        // key 1 should exist
        assertIdentityExist(securityRealm, evidence1);

        // add a new key 2 to the url using normal response
        server.setDispatcher(createTokenDispatcher(jwksResponse));
        BearerTokenEvidence evidence2 = new BearerTokenEvidence(createJwt(keyPair2, 60, -1, "2", new URI("https://localhost:50831")));

        // key 1 and 2 should exist now because time between requests is 0
        assertIdentityExist(securityRealm, evidence1);
        assertIdentityExist(securityRealm, evidence2);
    }

    @Test
    public void testNewRotationKeysTimeBetweenRequests() throws Exception {
        // set the jku url only with key 1
        server.setDispatcher(createTokenDispatcher(jwksToJson(jwk1).toString()));

        BearerTokenEvidence evidence1 = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, "1", new URI("https://localhost:50831")));

        X509TrustManager tm = getTrustManager();
        SSLContext sslContext = new SSLContextBuilder().setTrustManager(tm).setClientMode(true).setSessionTimeout(10).build().create();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50831")
                        .setJkuTimeout(60000L) // 60s of cache
                        .setJkuMinTimeBetweenRequests(10000) // 10s between calls
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true).build())
                .build();

        // key 1 should exist
        assertIdentityExist(securityRealm, evidence1);

        // add a new key 2 to the url using normal response
        server.setDispatcher(createTokenDispatcher(jwksResponse));
        BearerTokenEvidence evidence2 = new BearerTokenEvidence(createJwt(keyPair2, 60, -1, "2", new URI("https://localhost:50831")));

        // Same result because the minimum time between request avoids the call
        assertIdentityExist(securityRealm, evidence1);
        assertIdentityNotExist(securityRealm, evidence2);
    }

    @Test
    public void testMultipleTokenTypes() throws Exception {
        BearerTokenEvidence evidence1 = new BearerTokenEvidence(createJwt(keyPair3, 60, -1, "1", null));
        BearerTokenEvidence evidence2 = new BearerTokenEvidence(createJwt(keyPair3, 60, -1, "2", null));
        BearerTokenEvidence evidence3 = new BearerTokenEvidence(createJwt(keyPair2, 60, -1, "1", null));

        BearerTokenEvidence evidence4 = new BearerTokenEvidence(createJwt(keyPair2, 60, -1, "2", new URI("https://localhost:50831")));
        BearerTokenEvidence evidence5 = new BearerTokenEvidence(createJwt(keyPair3, 60, -1, "2", new URI("https://localhost:50831")));
        BearerTokenEvidence evidence6 = new BearerTokenEvidence(createJwt(keyPair2, 60, -1, "1", new URI("https://localhost:50831")));

        BearerTokenEvidence evidence7 = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, "3", null));
        BearerTokenEvidence evidence8 = new BearerTokenEvidence(createJwt(keyPair3, 60, -1));
        BearerTokenEvidence evidence9 = new BearerTokenEvidence(createJwt(keyPair1, 60, -1));

        Map<String, PublicKey> namedKeys = new LinkedHashMap<>();
        namedKeys.put("1", keyPair3.getPublic());

        X509TrustManager tm = getTrustManager();
        SSLContext sslContext = new SSLContextBuilder().setTrustManager(tm).setClientMode(true).setSessionTimeout(10).build().create();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50831")
                        .publicKeys(namedKeys)
                        .publicKey(keyPair3.getPublic())
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true)
                        .build())
                .build();

        assertIdentityExist(securityRealm, evidence1);
        assertIdentityNotExist(securityRealm, evidence2);
        assertIdentityNotExist(securityRealm, evidence3);
        assertIdentityExist(securityRealm, evidence4);
        assertIdentityNotExist(securityRealm, evidence5);
        assertIdentityNotExist(securityRealm, evidence6);
        assertIdentityNotExist(securityRealm, evidence7);
        assertIdentityExist(securityRealm, evidence8);
        assertIdentityNotExist(securityRealm, evidence9);
    }

    @Test
    public void testUnsecuredJkuEndpoint() throws Exception {
        checkIdentityDoesNotExist("1", 50832);
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, "1", new URI("https://localhost:50832")));

        X509TrustManager tm = getTrustManager();
        SSLContext sslContext = new SSLContextBuilder().setTrustManager(tm).setClientMode(true).setSessionTimeout(10).build().create();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50832")
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true).build())
                .build();

        assertIdentityNotExist(securityRealm, evidence);

    }

    @Test
    public void testKid() throws Exception {
        BearerTokenEvidence evidence1 = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, "1", null));
        BearerTokenEvidence evidence2 = new BearerTokenEvidence(createJwt(keyPair2, 60, -1, "2", null));
        BearerTokenEvidence evidence3 = new BearerTokenEvidence(createJwt(keyPair2, 60, -1, "3", null));

        Map<String, PublicKey> namedKeys = new LinkedHashMap<>();
        namedKeys.put("1", keyPair1.getPublic());
        namedKeys.put("2", keyPair2.getPublic());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .publicKeys(namedKeys)
                        .build())
                .build();

        assertIdentityExist(securityRealm, evidence1);
        assertIdentityExist(securityRealm, evidence2);
        assertIdentityNotExist(securityRealm, evidence3);

    }

    @Test
    public void testStoppedJkuEndpoint() throws Exception {
        server.setDispatcher(createOneTimeDispatcher(jwksResponse)); //Server will provide the keys only once

        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, "1", new URI("https://localhost:50831")));

        X509TrustManager tm = getTrustManager();
        SSLContext sslContext = new SSLContextBuilder().setTrustManager(tm).setClientMode(true).setSessionTimeout(10).build().create();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50831")
                        .setJkuTimeout(0) //Keys will be downloaded on every request
                        .setJkuMinTimeBetweenRequests(0)
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true).build())
                .build();

        assertIdentityExist(securityRealm, evidence);

        //Now the keys need to be re-cached

        assertIdentityNotExist(securityRealm, evidence);

        server.setDispatcher(createTokenDispatcher(jwksResponse));
    }

    @Test
    public void testJkuMultipleKeys() throws Exception {
        BearerTokenEvidence evidence1 = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, "1", new URI("https://localhost:50831")));
        BearerTokenEvidence evidence2 = new BearerTokenEvidence(createJwt(keyPair2, 60, -1, "2", new URI("https://localhost:50831")));

        X509TrustManager tm = getTrustManager();
        SSLContext sslContext = new SSLContextBuilder().setTrustManager(tm).setClientMode(true).setSessionTimeout(10).build().create();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50831")
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true).build())
                .build();

        assertIdentityExist(securityRealm, evidence1);
        assertIdentityExist(securityRealm, evidence2);
    }

    @Test
    public void testInvalidJku() throws Exception {
        checkIdentityDoesNotExist("1", 80);
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, "1", new URI("https://localhost:80")));

        X509TrustManager tm = getTrustManager();
        SSLContext sslContext = new SSLContextBuilder().setTrustManager(tm).setClientMode(true).setSessionTimeout(10).build().create();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:80")
                        .useSslContext(sslContext).useSslHostnameVerifier((a,b) -> true).build())
                .build();

        assertIdentityNotExist(securityRealm, evidence);

    }

    @Test
    public void testInvalidKid() throws Exception {
        checkIdentityDoesNotExist("badkid", 50831);
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, "badkid", new URI("https://localhost:50831")));

        X509TrustManager tm = getTrustManager();
        SSLContext sslContext = new SSLContextBuilder().setTrustManager(tm).setClientMode(true).setSessionTimeout(10).build().create();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50831")
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true).build())
                .build();

        assertIdentityNotExist(securityRealm, evidence);

    }

    @Test
    public void testUsingGeneratedPublicKey() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();

        Pem.generatePemPublicKey(publicKeyPem, keyPair.getPublic());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .publicKey(publicKeyPem.toArray()).build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new BearerTokenEvidence(createJwt(keyPair, 10, 0)));

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    @Test
    public void testEmptyConfiguration() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        ByteStringBuilder publicKeyPem = new ByteStringBuilder();

        Pem.generatePemPublicKey(publicKeyPem, keyPair.getPublic());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder().build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new BearerTokenEvidence(createJwt(keyPair, 10, 0)));

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    @Test
    public void testWithMultipleAudience() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("third-app", "another-app-valid", "my-app")
                        .publicKey(keyPair.getPublic()).build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(new BearerTokenEvidence(createJwt(keyPair)));

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    @Test
    public void testInvalidSignature() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair));
        KeyPair anotherKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .publicKey(anotherKeyPair.getPublic()).build())
                .build();

        assertIdentityNotExist(securityRealm, evidence);
    }

    @Test
    public void testInvalidIssuer() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair));

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("different-issuer")
                        .audience("my-app-valid")
                        .publicKey(keyPair.getPublic()).build())
                .build();

        assertIdentityNotExist(securityRealm, evidence);
    }

    @Test
    public void testInvalidAudience() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair));

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("different-audience")
                        .publicKey(keyPair.getPublic()).build())
                .build();

        assertIdentityNotExist(securityRealm, evidence);
    }

    @Test
    public void testTokenExpired() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair, -1));

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("different-audience")
                        .publicKey(keyPair.getPublic()).build())
                .build();

        assertIdentityNotExist(securityRealm, evidence);
    }

    @Test
    public void testTokenNotBefore() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair, 10, 10));

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("different-audience")
                        .publicKey(keyPair.getPublic()).build())
                .build();

        assertIdentityNotExist(securityRealm, evidence);
    }

    @Test
    public void testUnsecuredJwt() throws Exception {
        PlainObject plainObject = new PlainObject(new PlainHeader(), new Payload(createClaims(10, 0).build().toString()));
        BearerTokenEvidence evidence = new BearerTokenEvidence(plainObject.serialize());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid").build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(evidence);

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    /**
     * Test using a claim mapping function to extract the token principal name
     * @throws Exception
     */
    @Test
    public void testAltPrincipaNames() throws Exception {
        JsonObjectBuilder altBuilder = Json.createObjectBuilder()
                .add("upn", "upn:elytron@jboss.org");
        PlainObject plainObject = new PlainObject(new PlainHeader(), new Payload(createClaims(10, 0, altBuilder.build()).build().toString()));
        BearerTokenEvidence evidence = new BearerTokenEvidence(plainObject.serialize());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .claimToPrincipal((Attributes claims) -> {
                    // This is the MP-JWT spec logic
                    String pn = claims.getFirst("upn");
                    if (pn == null) {
                        pn = claims.getFirst("preferred_name");
                    }
                    if (pn == null) {
                        pn = claims.getFirst("sub");
                    }
                    return new NamePrincipal(pn);
                })
                .validator(JwtValidator.builder()
                                   .issuer("elytron-oauth2-realm")
                                   .audience("my-app-valid").build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(evidence);

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("upn:elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }
    /**
     * Test using a claim mapping function to extract the token principal name that returns null to validate
     * fallback to the {@linkplain TokenSecurityRealm.Builder#principalClaimName(String)} setting.
     * @throws Exception
     */
    @Test
    public void testAltPrincipaNamesSubFallback() throws Exception {
        PlainObject plainObject = new PlainObject(new PlainHeader(), new Payload(createClaims(10, 0).build().toString()));
        BearerTokenEvidence evidence = new BearerTokenEvidence(plainObject.serialize());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                                   .issuer("elytron-oauth2-realm")
                                   .audience("my-app-valid").build())
                .build();

        RealmIdentity realmIdentity = securityRealm.getRealmIdentity(evidence);

        assertNotNull(realmIdentity);
        assertTrue(realmIdentity.exists());
        assertEquals("elytron@jboss.org", realmIdentity.getRealmIdentityPrincipal().getName());
    }

    @Test
    public void testTokenWithJkuValueAllowed() throws Exception {
        BearerTokenEvidence evidence = new BearerTokenEvidence(
                createJwt(keyPair1, 60, -1, "1", new URI("https://localhost:50831")));

        SSLContext sslContext = getSSLContext();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50832", "https://localhost:50831")
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true).build())
                .build();

        // token validation should succeed
        assertIdentityExist(securityRealm, evidence);
    }

    @Test
    public void testTokenWithJkuValueNotAllowed() throws Exception {
        BearerTokenEvidence evidence = new BearerTokenEvidence(
                createJwt(keyPair1, 60, -1, "1", new URI("https://localhost:50834")));

        SSLContext sslContext = getSSLContext();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50832", "https://localhost:50831")
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true).build())
                .build();

        // token validation should fail
        assertIdentityNotExist(securityRealm, evidence);
    }

    @Test
    public void testAllowedJkuValuesNotConfigured() throws Exception {
        BearerTokenEvidence evidence = new BearerTokenEvidence(
                createJwt(keyPair1, 60, -1, "1", new URI("https://localhost:50831")));

        SSLContext sslContext = getSSLContext();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .useSslContext(sslContext)
                        .useSslHostnameVerifier((a,b) -> true).build())
                .build();

        // token validation should fail
        assertIdentityNotExist(securityRealm, evidence);
    }

    @Test
    public void testTokenWithoutJkuValue() throws Exception {
        BearerTokenEvidence evidence1 = new BearerTokenEvidence(
                createJwt(keyPair1, 60, -1, "1", null));
        BearerTokenEvidence evidence2 = new BearerTokenEvidence(
                createJwt(keyPair2, 60, -1, "2", null));

        Map<String, PublicKey> namedKeys = new LinkedHashMap<>();
        namedKeys.put("1", keyPair1.getPublic());
        namedKeys.put("2", keyPair2.getPublic());

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .setAllowedJkuValues("https://localhost:50832", "https://localhost:50831")
                        .publicKeys(namedKeys)
                        .build())
                .build();

        // token validation should succeed
        assertIdentityExist(securityRealm, evidence1);
        assertIdentityExist(securityRealm, evidence2);
    }

    private void assertIdentityNotExist(SecurityRealm realm, Evidence evidence) throws RealmUnavailableException {
        RealmIdentity identity = realm.getRealmIdentity(evidence);
        assertNotNull(identity);
        assertFalse(identity.exists());
    }

    private void assertIdentityExist(SecurityRealm realm, Evidence evidence) throws RealmUnavailableException {
        RealmIdentity identity = realm.getRealmIdentity(evidence);
        assertNotNull(identity);
        assertTrue(identity.exists());
    }

    private X509TrustManager getTrustManager() throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream(trustStoreFile), PASSWORD);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        X509TrustManager tm = null;
        for (TrustManager tm1 : tmf.getTrustManagers()) {
            if (tm1 instanceof X509TrustManager) {
                tm = X509TrustManager.class.cast(tm1);
                break;
            }
        }
        assertNotNull(tm);
        return tm;
    }

    private SSLContext getSSLContext() throws Exception {
        X509TrustManager trustManager = getTrustManager();
        return new SSLContextBuilder()
                .setTrustManager(trustManager)
                .setClientMode(true)
                .setSessionTimeout(10)
                .build()
                .create();
    }

    private static Dispatcher createOneTimeDispatcher(String response) {
        return new Dispatcher() {
            boolean used = false;
            @Override
            public MockResponse dispatch(RecordedRequest recordedRequest) {
                if (!used) {
                    used = true;
                    return new MockResponse().setBody(response);
                } else {
                    return new MockResponse().setResponseCode(HttpsURLConnection.HTTP_NOT_FOUND);
                }
            }
        };
    }

    private void checkIdentityDoesNotExist(String kid, int port) throws Exception {
        BearerTokenEvidence evidence = new BearerTokenEvidence(createJwt(keyPair1, 60, -1, kid, new URI("https://localhost:" + port)));

        X509TrustManager tm = getTrustManager();
        SSLContext sslContext = new SSLContextBuilder().setTrustManager(tm).setClientMode(true).setSessionTimeout(10).build().create();

        TokenSecurityRealm securityRealm = TokenSecurityRealm.builder()
                .principalClaimName("sub")
                .validator(JwtValidator.builder()
                        .issuer("elytron-oauth2-realm")
                        .audience("my-app-valid")
                        .useSslContext(sslContext).useSslHostnameVerifier((a,b) -> true).build())
                .build();

        assertIdentityNotExist(securityRealm, evidence);
    }
}
