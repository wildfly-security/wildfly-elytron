/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert.acme;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.wildfly.security.x500.cert.acme.Acme.BASE64_URL;

import org.apache.commons.io.IOUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.x500.cert.X509CertificateChainAndSigningKey;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CRLReason;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import mockit.Mock;
import mockit.MockUp;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;


/**
 * Tests for the Automatic Certificate Management Environment (ACME) client SPI. These tests simulate a mock Let's Encrypt
 * server by using messages that were actually sent from Boulder (Let's Encrypt's testing server) to our ACME client.
 * Wireshark was used to record the messages. The use of these recorded messages prevents us from having to integrate the
 * complex Boulder setup into the Elytron testsuite.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class AcmeClientSpiTest {

    private static AcmeAccount.Builder populateBasicBuilder() throws Exception {
        AcmeAccount.Builder builder = AcmeAccount.builder()
                .setTermsOfServiceAgreed(true)
                .setContactUrls(new String[] { "mailto:admin@example.com" } )
                .setServerUrl("http://localhost:4001/directory");
        return builder;
    }

    private static AcmeAccount.Builder populateBuilder() throws Exception {
        AcmeAccount.Builder builder = AcmeAccount.builder()
                .setTermsOfServiceAgreed(true)
                .setContactUrls(new String[] { "mailto:admin@myexample.com" } )
                .setServerUrl("http://localhost:4001/directory");
        return builder;
    }

    private static final String KEYSTORE = "account.keystore";
    private static final char[] KEYSTORE_PASSWORD = "elytron".toCharArray();
    private static final String ACCOUNT_1 = "account1";
    private static final String ACCOUNT_2 = "account2";
    private static final String ACCOUNT_3 = "account3";
    private static final String ACCOUNT_4 = "account4";
    private static final String ACCOUNT_5 = "account5";
    private static final String ACCOUNT_6 = "account6";
    private static final String ACCOUNT_7 = "account7";
    private static final String ACCOUNT_8 = "account8";
    private static final String ACCOUNT_9 = "account9";
    private static final String REVOKE_ALIAS = "revokealias";
    private static final String REVOKE_WITH_REASON_ALIAS = "revokewithreasonalias";
    private static final String NEW_KEY_ALIAS = "newkey";
    private static final String NEW_EC_KEY_ALIAS = "neweckey";
    private static HashMap<String, X509Certificate> aliasToCertificateMap;
    private static HashMap<String, PrivateKey> aliasToPrivateKeyMap;
    private static ClientAndServer server; // used to simulate a Let's Encrypt server instance
    private static MockWebServer client; // used to simulate a WildFly instance

    private final SimpleAcmeClient acmeClient = new SimpleAcmeClient();

    private static void mockRetryAfter() {
        Class<?> classToMock;
        try {
            classToMock = Class.forName("org.wildfly.security.x500.cert.acme.AcmeClientSpi", true, AcmeAccount.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new NoClassDefFoundError(e.getMessage());
        }
        new MockUp<Object>(classToMock) {
            @Mock
            private long getRetryAfter(HttpURLConnection connection, boolean useDefaultIfHeaderNotPresent) throws AcmeException {
                return 0;
            }
        };
    }

    @BeforeClass
    public static void setUp() throws Exception {
        mockRetryAfter(); // no need to sleep in between polling attempts during testing
        KeyStore keyStore = KeyStore.getInstance("jks");
        try (InputStream is = AcmeClientSpiTest.class.getResourceAsStream(KEYSTORE)) {
            keyStore.load(is, KEYSTORE_PASSWORD);
        }

        int numAliases = keyStore.size();
        aliasToCertificateMap = new HashMap<>(numAliases);
        aliasToPrivateKeyMap = new HashMap<>(numAliases);
        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            aliasToCertificateMap.put(alias, (X509Certificate) keyStore.getCertificate(alias));
            aliasToPrivateKeyMap.put(alias, (PrivateKey) keyStore.getKey(alias, KEYSTORE_PASSWORD));
        }
        server = new ClientAndServer(4001);
        client = new MockWebServer();
        client.start(5002); // this is the port our mock Let's Encrypt server will use to access the client
    }

    @AfterClass
    public static void shutdownMockClientAndServer() throws Exception {
        if (client != null) {
            client.shutdown();
        }
        if (server != null) {
            server.stop();
        }
    }

    @Test
    public void testCreateAccount() throws Exception {
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/384";
        server = setupTestCreateAccount();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1);
        assertNull(account.getAccountUrl());
        acmeClient.createAccount(account, false);
        assertEquals(NEW_ACCT_LOCATION, account.getAccountUrl());
    }

    @Test
    public void testCreateAccountOnlyReturnExisting() throws Exception {
        final String NEW_ACCT_LOCATION_1 = "http://localhost:4001/acme/acct/387";
        server = setupTestCreateAccountOnlyReturnExisting();
        AcmeAccount account = populateBasicAccount(ACCOUNT_2);
        acmeClient.createAccount(account, false);
        assertEquals(NEW_ACCT_LOCATION_1, account.getAccountUrl());
        AcmeAccount sameAccount = populateBasicAccount(ACCOUNT_2);

        // the key corresponding to ACCOUNT_2 is associated with an already registered account
        acmeClient.createAccount(sameAccount, false, true);
        assertEquals(account.getAccountUrl(), sameAccount.getAccountUrl());

        AcmeAccount newAccount = populateBasicAccount(ACCOUNT_3);
        try {
            // the key corresponding to ACCOUNT_3 is not associated with an already registered account
            acmeClient.createAccount(newAccount, false, true);
            fail("Expected AcmeException not thrown");
        } catch (AcmeException expected) {
        }
    }

    @Test
    public void testCreateAccountWithECPublicKey() throws Exception {
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/389";
        server = setupTestCreateAccountWithECPublicKey();
        AcmeAccount account = populateBasicAccount(ACCOUNT_4);
        assertNull(account.getAccountUrl());
        acmeClient.createAccount(account, false);
        assertEquals(NEW_ACCT_LOCATION, account.getAccountUrl());
    }

    @Test
    public void testUpdateAccount() throws Exception {
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/1";
        server = setupTestUpdateAccount();
        AcmeAccount account = populateAccount(ACCOUNT_1);
        account.setAccountUrl(ACCT_LOCATION);
        String[] contacts = new String[] { "mailto:certificates@examples.com", "mailto:admin@examples.com"};
        acmeClient.updateAccount(account, false, false, contacts);
        assertFalse(account.isTermsOfServiceAgreed());

        String[] updatedContacts = acmeClient.queryAccountContactUrls(account, false);
        assertArrayEquals(contacts, updatedContacts);

        acmeClient.updateAccount(account, false, false, null);
        updatedContacts = acmeClient.queryAccountContactUrls(account, false);
        assertArrayEquals(contacts, updatedContacts);
    }

    @Test
    public void testDeactivateAccount() throws Exception {
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/4";
        server = setupTestDeactivateAccount();
        AcmeAccount account = populateAccount(ACCOUNT_5);
        account.setAccountUrl(ACCT_LOCATION);
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));

        acmeClient.deactivateAccount(account, false);
        try {
            acmeClient.obtainCertificateChain(account, false, "172.17.0.1");
            fail("Expected AcmeException not thrown");
        } catch (AcmeException e) {
            assertTrue(e.getMessage().contains("deactivated"));
        }
    }

    @Test
    public void testGetNonce() throws Exception {
        final String NEW_NONCE_RESPONSE = "d4o3tdwrnpzwi9xgI21EqNdDyInvLcrENqTXthWD0qg";
        server = setupTestGetNonce();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1);
        account.setNonce(CodePointIterator.ofString("rtJAy_mcjDFGnnzCOAbGMGM6w8P3qU0bRDMf8sjt5IU").base64Decode(BASE64_URL, false).drain());
        String nonce = ByteIterator.ofBytes(account.getNonce()).base64Encode(BASE64_URL, false).drainToString();
        assertNotNull(nonce);

        String newNonce = ByteIterator.ofBytes(acmeClient.getNewNonce(account, false)).base64Encode(BASE64_URL, false).drainToString();
        assertFalse(nonce.equals(newNonce));
        assertEquals(NEW_NONCE_RESPONSE, newNonce);
    }

    @Test
    public void testObtainCertificateChain() throws Exception {
        server = setupTestObtainCertificate();
        AcmeAccount account = populateAccount(ACCOUNT_1);
        String domainName = "fjsljghasldfjgk.com"; // randomly generated domain name
        obtainCertificateChain(null, -1, account, domainName);
    }

    @Test
    public void testObtainCertificateChainWithKeySize() throws Exception {
        server = setupTestObtainCertificateWithKeySize();
        AcmeAccount account = populateAccount(ACCOUNT_6);
        String domainName = "inlneseppwkfwew.com"; // randomly generated domain name
        obtainCertificateChain("RSA", 4096, account, domainName);
    }

    @Test
    public void testObtainCertificateChainWithECPublicKey() throws Exception {
        server = setupTestObtainCertificateWithECPublicKey();
        AcmeAccount account = populateAccount(ACCOUNT_7);
        String domainName = "mndelkdnbcilohg.com"; // randomly generated domain name
        obtainCertificateChain("EC", 256, account, domainName);
    }

    @Test
    public void testObtainCertificateChainWithUnsupportedPublicKey() throws Exception {
        try {
            server = setupTestObtainCertificateWithUnsupportedPublicKey();
            AcmeAccount account = populateAccount(ACCOUNT_7);
            String domainName = "iraclzlcqgaymrc.com";
            obtainCertificateChain("DSA", 2048, account, domainName);
            fail("Expected AcmeException not thrown");
        } catch (AcmeException expected) {
        }
    }

    private void obtainCertificateChain(String keyAlgorithmName, int keySize, AcmeAccount account, String domainName) throws Exception {
        X509CertificateChainAndSigningKey certificateChainAndSigningKey = acmeClient.obtainCertificateChain(account, false, keyAlgorithmName, keySize, domainName);
        PrivateKey privateKey = certificateChainAndSigningKey.getSigningKey();

        X509Certificate[] replyCertificates = certificateChainAndSigningKey.getCertificateChain();
        assertTrue(replyCertificates.length == 2);
        X509Certificate signedCert = replyCertificates[0];
        X509Certificate caCert = replyCertificates[1];
        assertTrue(signedCert.getSubjectDN().getName().contains(domainName));
        assertEquals(caCert.getSubjectDN(), signedCert.getIssuerDN());
        assertEquals("CN=cackling cryptographer fake ROOT", caCert.getIssuerDN().getName());
        if (keyAlgorithmName != null && keySize != -1) {
            assertEquals(keyAlgorithmName, privateKey.getAlgorithm());
            assertEquals(keyAlgorithmName, signedCert.getPublicKey().getAlgorithm());
            if (keyAlgorithmName.equals("EC")) {
                assertEquals(keySize, ((ECPublicKey) signedCert.getPublicKey()).getParams().getCurve().getField().getFieldSize());
            } else if (keyAlgorithmName.equals("RSA")) {
                assertEquals(keySize, ((RSAPublicKey) signedCert.getPublicKey()).getModulus().bitLength());
            }
        } else {
            if (signedCert.getPublicKey().getAlgorithm().equals("RSA")) {
                assertEquals(AcmeClientSpi.DEFAULT_KEY_SIZE, ((RSAPublicKey) signedCert.getPublicKey()).getModulus().bitLength());
                assertEquals("RSA", privateKey.getAlgorithm());
            } else if (signedCert.getPublicKey().getAlgorithm().equals("EC")) {
                assertEquals(AcmeClientSpi.DEFAULT_EC_KEY_SIZE, ((RSAPublicKey) signedCert.getPublicKey()).getModulus().bitLength());
                assertEquals("EC", privateKey.getAlgorithm());
            }
        }
    }

    @Test
    public void testRevokeCertificateWithoutReason() throws Exception {
        server = setupTestRevokeCertificate();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1);
        revokeCertificate(account, null);
    }

    @Test
    public void testRevokeCertificateWithReason() throws Exception {
        server = setupTestRevokeCertificateWithReason();
        AcmeAccount account = populateBasicAccount(ACCOUNT_1);
        revokeCertificate(account, CRLReason.AA_COMPROMISE);
    }

    private void revokeCertificate(AcmeAccount account, CRLReason reason) throws Exception {
        X509Certificate certificateToRevoke;
        if (reason == null) {
            certificateToRevoke = aliasToCertificateMap.get(REVOKE_ALIAS);
        } else {
            certificateToRevoke = aliasToCertificateMap.get(REVOKE_WITH_REASON_ALIAS);
        }
        acmeClient.revokeCertificate(account, false, certificateToRevoke, reason);
    }

    @Test
    public void testChangeAccountKey() throws Exception {
        server = setupTestChangeAccountKey();
        AcmeAccount account = populateAccount(ACCOUNT_6);
        X509Certificate oldCertificate = account.getCertificate();
        X500Principal oldDn = account.getDn();
        acmeClient.changeAccountKey(account, false);
        assertTrue(! oldCertificate.equals(account.getCertificate()));
        assertEquals(oldDn, account.getDn());
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));
    }

    @Test
    public void testChangeAccountKeySpecifyCertificateAndPrivateKey() throws Exception {
        server = setupTestChangeAccountKeySpecifyCertificateAndPrivateKey();
        AcmeAccount account = populateAccount(ACCOUNT_8);
        X500Principal oldDn = account.getDn();

        // RSA account key
        X509Certificate newCertificate = aliasToCertificateMap.get(NEW_KEY_ALIAS);
        PrivateKey newPrivateKey = aliasToPrivateKeyMap.get(NEW_KEY_ALIAS);
        acmeClient.changeAccountKey(account, false, newCertificate, newPrivateKey);
        assertEquals(newCertificate, account.getCertificate());
        assertEquals(newPrivateKey, account.getPrivateKey());
        assertEquals(oldDn, account.getDn());
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));

        // ECDSA account key
        newCertificate = aliasToCertificateMap.get(NEW_EC_KEY_ALIAS);
        newPrivateKey = aliasToPrivateKeyMap.get(NEW_EC_KEY_ALIAS);
        acmeClient.changeAccountKey(account, false, newCertificate, newPrivateKey);
        assertEquals(newCertificate, account.getCertificate());
        assertEquals(newPrivateKey, account.getPrivateKey());
        assertEquals(oldDn, account.getDn());
        assertEquals(Acme.VALID, acmeClient.queryAccountStatus(account, false));

        // attempting to change the account key to a key that is already in use for a different account should fail
        account = populateAccount(ACCOUNT_9);
        X509Certificate oldCertificate = account.getCertificate();
        PrivateKey oldPrivateKey = account.getPrivateKey();
        try {
            acmeClient.changeAccountKey(account, false, newCertificate, newPrivateKey);
            fail("Expected AcmeException not thrown");
        } catch (AcmeException expected) {
        }
        assertEquals(oldCertificate, account.getCertificate());
        assertEquals(oldPrivateKey, account.getPrivateKey());
    }

    @Test
    public void testGetMetadata() throws Exception {
        server = setupTestGetMetadata();
        AcmeAccount account = populateBasicAccount(ACCOUNT_8);
        AcmeMetadata metadata = acmeClient.getMetadata(account, false);
        assertNotNull(metadata);
        assertEquals("https://boulder:4431/terms/v7", metadata.getTermsOfServiceUrl());
        assertEquals("https://github.com/letsencrypt/boulder", metadata.getWebsiteUrl());
        assertArrayEquals(new String[] { "happy-hacker-ca.invalid", "happy-hacker2-ca.invalid" }, metadata.getCAAIdentities());
        assertTrue(metadata.isExternalAccountRequired());

        metadata = acmeClient.getMetadata(account, false);
        assertNotNull(metadata);
        assertEquals("https://boulder:4431/terms/v7", metadata.getTermsOfServiceUrl());
        assertNull(metadata.getWebsiteUrl());
        assertNull(metadata.getCAAIdentities());
        assertFalse(metadata.isExternalAccountRequired());

        metadata = acmeClient.getMetadata(account, false);
        assertNull(metadata);
    }

    private class SimpleAcmeClient extends AcmeClientSpi {

        public AcmeChallenge proveIdentifierControl (AcmeAccount account, List <AcmeChallenge> challenges) throws AcmeException {
            AcmeChallenge selectedChallenge = null;
            for (AcmeChallenge challenge : challenges) {
                if (challenge.getType() == AcmeChallenge.Type.HTTP_01) {
                    client.setDispatcher(createChallengeResponse(account, challenge));
                    selectedChallenge = challenge;
                    break;
                }
            }
            return selectedChallenge;
        }

        public void cleanupAfterChallenge(AcmeAccount account, AcmeChallenge challenge) throws AcmeException {
            // do nothing
        }

        private Dispatcher createChallengeResponse(AcmeAccount account, AcmeChallenge challenge) {
            return new Dispatcher() {
                @Override
                public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
                    String path = recordedRequest.getPath();
                    if (path.equals("/.well-known/acme-challenge/" + challenge.getToken())) {
                        try {
                            return new MockResponse()
                                    .setHeader("Content-Type", "application/octet-stream")
                                    .setBody(challenge.getKeyAuthorization(account));
                        } catch (AcmeException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    return new MockResponse()
                            .setBody("");
                }
            };
        }
    }

    /**
     * Class used to build up a mock Let's Encrypt server instance.
     */
    private class AcmeMockServerBuilder {

        ClientAndServer server;

        AcmeMockServerBuilder(ClientAndServer server) {
            this.server = (ClientAndServer) server.reset();
        }

        public AcmeMockServerBuilder addDirectoryResponseBody(String directoryResponseBody) {
            server.when(
                    request()
                            .withMethod("GET")
                            .withPath("/directory")
                            .withBody(""),
                    Times.once())
                    .respond(
                            response()
                                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                    .withHeader("Content-Type", "application/json")
                                    .withBody(directoryResponseBody));
            return this;
        }

        public AcmeMockServerBuilder addNewNonceResponse(String newNonce) {
            server.when(
                    request()
                            .withMethod("HEAD")
                            .withPath("/acme/new-nonce")
                            .withBody(""),
                    Times.once())
                    .respond(
                            response()
                                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                    .withHeader("Replay-Nonce", newNonce)
                                    .withStatusCode(204));
            return this;
        }

        public AcmeMockServerBuilder addNewAccountRequestAndResponse(String expectedNewAccountRequestBody, String newAccountResponseBody,
                                                                     String newAccountReplayNonce, String newAccountLocation, int newAccountStatusCode) {
            return addNewAccountRequestAndResponse(expectedNewAccountRequestBody, newAccountResponseBody, newAccountReplayNonce, newAccountLocation,
                    newAccountStatusCode, false);
        }

        public AcmeMockServerBuilder addNewAccountRequestAndResponse(String expectedNewAccountRequestBody, String newAccountResponseBody, String newAccountReplayNonce,
                                                                     String newAccountLocation, int newAccountStatusCode, boolean useProblemContentType) {
            String link = "<https://boulder:4431/terms/v7>;rel=\"terms-of-service\"";
            return addPostRequestAndResponse(expectedNewAccountRequestBody, "/acme/new-acct", newAccountResponseBody, newAccountReplayNonce,
                    link, newAccountLocation, newAccountStatusCode, useProblemContentType);
        }

        public AcmeMockServerBuilder updateAccountRequestAndResponse(String expectedUpdateAccountRequestBody, String updateAccountResponseBody, String updateAccountReplayNonce,
                                                                     String accountUrl, int updateAccountStatusCode) {
            String link = "<https://boulder:4431/terms/v7>;rel=\"terms-of-service\"";
            return addPostRequestAndResponse(expectedUpdateAccountRequestBody, accountUrl, updateAccountResponseBody, updateAccountReplayNonce,
                    link, "", updateAccountStatusCode, false);
        }

        public AcmeMockServerBuilder orderCertificateRequestAndResponse(String expectedOrderCertificateRequestBody, String orderCertificateResponseBody, String orderCertificateReplayNonce,
                                                                        String orderLocation, int orderCertificateStatusCode, boolean useProblemContentType) {
            return addPostRequestAndResponse(expectedOrderCertificateRequestBody, "/acme/new-order", orderCertificateResponseBody, orderCertificateReplayNonce,
                    "", orderLocation, orderCertificateStatusCode, useProblemContentType);
        }

        public AcmeMockServerBuilder addAuthorizationResponseBody(String expectedAuthorizationUrl, String expectedAuthorizationRequestBody, String authorizationResponseBody, String authorizationReplayNonce) {
            server.when(
                    request()
                            .withMethod("POST")
                            .withPath(expectedAuthorizationUrl)
                            .withBody(expectedAuthorizationRequestBody == null ? "" : expectedAuthorizationRequestBody),
                    Times.exactly(10))
                    .respond(
                            response()
                                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                    .withHeader("Content-Type", "application/json")
                                    .withHeader("Replay-Nonce", authorizationReplayNonce)
                                    .withBody(authorizationResponseBody));
            return this;
        }

        public AcmeMockServerBuilder addChallengeRequestAndResponse(String expectedChallengeRequestBody, String expectedChallengeUrl, String challengeResponseBody,
                                                                    String challengeReplayNonce, String challengeLocation, String challengeLink,
                                                                    int challengeStatusCode, boolean useProblemContentType, String verifyChallengePath,
                                                                    String challengeFileContents, String expectedAuthorizationUrl, String authorizationResponseBody,
                                                                    String authorizationReplayNonce) {
            server.when(
                    request()
                            .withMethod("POST")
                            .withPath(expectedChallengeUrl)
                            .withHeader("Content-Type", "application/jose+json")
                            .withBody(expectedChallengeRequestBody),
                    Times.once())
                    .respond(request -> {
                        HttpResponse response = response()
                                .withHeader("Cache-Control", "public, max-age=0, no-cache")
                                .withHeader("Content-Type", useProblemContentType ? "application/problem+json" : "application/json")
                                .withHeader("Replay-Nonce", challengeReplayNonce)
                                .withBody(challengeResponseBody)
                                .withStatusCode(challengeStatusCode);
                        if (! challengeLocation.isEmpty()) {
                            response = response.withHeader("Location", challengeLocation);
                        }
                        if (! challengeLink.isEmpty()) {
                            response = response.withHeader("Link", challengeLink);
                        }

                        byte[] challengeResponseBytes = null;
                        try {
                            URL verifyChallengeUrl = new URL(client.url(verifyChallengePath).toString());
                            HttpURLConnection connection = (HttpURLConnection) verifyChallengeUrl.openConnection();
                            connection.setRequestMethod("GET");
                            connection.connect();
                            try (InputStream inputStream = new BufferedInputStream(connection.getResponseCode() < 400 ? connection.getInputStream() : connection.getErrorStream())) {
                                challengeResponseBytes = IOUtils.toByteArray(inputStream);
                            }
                        } catch (Exception e) {
                            //
                        }
                        if (challengeFileContents.equals(new String(challengeResponseBytes, StandardCharsets.UTF_8))) {
                            addAuthorizationResponseBody(expectedAuthorizationUrl, null, authorizationResponseBody, authorizationReplayNonce);
                        }
                        return response;
                    });
            return this;
        }

        public AcmeMockServerBuilder addFinalizeRequestAndResponse(String finalResponseBody, String finalizeReplayNonce,
                                                                   String finalizeUrl, String finalizeOrderLocation, int finalizeStatusCode) {
            return addFinalizeRequestAndResponse(finalResponseBody, finalizeReplayNonce, finalizeUrl, finalizeOrderLocation, finalizeStatusCode, false);
        }

        public AcmeMockServerBuilder addFinalizeRequestAndResponse(String finalResponseBody, String finalizeReplayNonce,
                                                                   String finalizeUrl, String orderLocation, int finalizeStatusCode, boolean useProblemContentType) {
            return addPostRequestAndResponse("", finalizeUrl, finalResponseBody, finalizeReplayNonce, "",
                    orderLocation, finalizeStatusCode, useProblemContentType);
        }

        public AcmeMockServerBuilder addCertificateRequestAndResponse(String certificateUrl, String expectedCertificateRequestBody, String certificateResponseBody, String certificateReplayNonce, int certificateStatusCode) {
            HttpResponse response = response()
                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                    .withHeader("Content-Type", "application/pem-certificate-chain")
                    .withHeader("Replay-Nonce", certificateReplayNonce)
                    .withBody(certificateResponseBody)
                    .withStatusCode(certificateStatusCode);
            server.when(
                    request()
                            .withMethod("POST")
                            .withPath(certificateUrl)
                            .withBody(expectedCertificateRequestBody),
                    Times.once())
                    .respond(response);

            return this;
        }

        public AcmeMockServerBuilder addCheckOrderRequestAndResponse(String orderUrl, String expectedCheckCertificateRequestBody, String checkCertificateResponseBody, String checkOrderReplayNonce, int checkCertificateStatusCode) {
            HttpResponse response = response()
                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                    .withHeader("Content-Type", "application/json")
                    .withHeader("Replay-Nonce", checkOrderReplayNonce)
                    .withBody(checkCertificateResponseBody)
                    .withStatusCode(checkCertificateStatusCode);
            server.when(
                    request()
                            .withMethod("POST")
                            .withPath(orderUrl)
                            .withBody(expectedCheckCertificateRequestBody),
                    Times.once())
                    .respond(response);

            return this;
        }

        public AcmeMockServerBuilder addRevokeCertificateRequestAndResponse(String expectedRevokeCertificateRequestBody, String revokeCertificateReplayNonce, int revokeCertificateStatusCode) {
            return addPostRequestAndResponse(expectedRevokeCertificateRequestBody, "/acme/revoke-cert", "", revokeCertificateReplayNonce,
                    "", "", revokeCertificateStatusCode, false);
        }

        public AcmeMockServerBuilder addChangeKeyRequestAndResponse(String expectedChangeKeyRequestBody, String changeKeyResponseBody, String changeKeyReplaceNonce, int changeKeyResponseCode) {
            return addPostRequestAndResponse(expectedChangeKeyRequestBody, "/acme/key-change", changeKeyResponseBody, changeKeyReplaceNonce,
                    "", "", changeKeyResponseCode, false);
        }

        public AcmeMockServerBuilder addPostRequestAndResponse(String expectedPostRequestBody, String postPath, String responseBody, String replayNonce, String link, String location, int responseCode, boolean useProblemContentType) {
            HttpResponse response = response()
                    .withHeader("Cache-Control", "public, max-age=0, no-cache")
                    .withHeader("Replay-Nonce", replayNonce)
                    .withStatusCode(responseCode);
            if (! responseBody.isEmpty()) {
                response = response
                        .withHeader("Content-Type", useProblemContentType ? "application/problem+json" : "application/json")
                        .withBody(responseBody);

            }
            if (! link.isEmpty()) {
                response = response.withHeader("Link", link);
            }
            if (! location.isEmpty()) {
                response = response.withHeader("Location", location);
            }
            HttpRequest request = request()
                    .withMethod("POST")
                    .withPath(postPath) ;
            if (! expectedPostRequestBody.isEmpty()) {
                request = request.withBody(expectedPostRequestBody);
            }
            server.when(
                    request,
                    Times.once())
                    .respond(response);

            return this;
        }

        public ClientAndServer build() {
            return server;
        }
    }

    /* -- Helper methods used to set up the messages that should be sent from the mock Let's Encrypt server to our ACME client. -- */

    private ClientAndServer setupTestCreateAccount() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"TrOIFke5bdM\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE = "8-k95dsqpJLtOQapuL-0XGrBH0UM6lcfdop9OUp05_I";

        final String NEW_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJwdUwtV2NNWVVKMkFqZHkxVXNVZ056am42ZWNEeGlXZDdOR1VHcTI2N1NPTHdoS2pTV1dNd2tvcGZjZzVWTWpQSldFRTM4SUlYeWpXNW5GS0NxRkFJZjNabGloXzFTTGNqZ1ZGYmlibi1vTUdGTFpzOWdncjJialJHSnNic0pRSU9LbWdWczJ5M2w1UmNJeUYyTS1VT3g0R3RBVVFKc1lpdHRjaEJMeHFqczBTQmpXZHRwV3phWDRmd1RDeng0OFJYdVpoa3lfbUtBeUtiaEFZbklHZERoY1ZJWnNmZjZ6ekVNMWJwSkVENk9CWmg2cHlQLU4wa094Y0dtUFBDSE1mME16d2puSzhWckZQRWFJSWZRQWJVQzFyVGF1aXFaWDdnbEVuTjJrWXFPd2w4ZzNuZjVmYlg2c1V1RFUxNWZWMGNtZFV0aHk4X0dIeUUycWR6alBSTHcifSwibm9uY2UiOiI4LWs5NWRzcXBKTHRPUWFwdUwtMFhHckJIMFVNNmxjZmRvcDlPVXAwNV9JIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXX0\",\"signature\":\"Js_fvpkTcDkWhJqwYNMdDqQKz6pWTxT0I5XzT0PrF0hTupSMc0uvUBc19xD64_x4fFsEZMlv1l_d2jm1pt-7nySWcYQFbkYh-tdRuxygzCCXdFhsXsw3MGh13KghkgiawjW37TFw8DrIWSwlsuGEIjofF2TqExecX0mkyF-vl6VA7Gm9oiqxfRiKx-X4YaO7-ijUnG7EMyesSKfu3PmBcaPsO9gIjRQ4FHrOb1RTSmTupskb4pZ0D2tkwKZcWWmXwO2XnLPjF5ZZi6c0p7GA_f578r665toyqP9n7PV6Vlf8w8XrM_EsF201r4oCFyVTEuAYx9fozKYIEhZe-PDWdw\"}";

        final String NEW_ACCT_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"id\": 384," + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"RSA\"," + System.lineSeparator()  +
                "    \"n\": \"puL-WcMYUJ2Ajdy1UsUgNzjn6ecDxiWd7NGUGq267SOLwhKjSWWMwkopfcg5VMjPJWEE38IIXyjW5nFKCqFAIf3Zlih_1SLcjgVFbibn-oMGFLZs9ggr2bjRGJsbsJQIOKmgVs2y3l5RcIyF2M-UOx4GtAUQJsYittchBLxqjs0SBjWdtpWzaX4fwTCzx48RXuZhky_mKAyKbhAYnIGdDhcVIZsff6zzEM1bpJED6OBZh6pyP-N0kOxcGmPPCHMf0MzwjnK8VrFPEaIIfQAbUC1rTauiqZX7glEnN2kYqOwl8g3nf5fbX6sUuDU15fV0cmdUthy8_GHyE2qdzjPRLw\"," + System.lineSeparator()  +
                "    \"e\": \"AQAB\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:admin@example.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2018-04-23T11:10:28.490176768-04:00\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE = "20y41JJoZ3Rn0VCEKDRa5AzT0kjcz6b6FushFyVS4zY";
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/384";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY, NEW_ACCT_RESPONSE_BODY, NEW_ACCT_REPLAY_NONCE, NEW_ACCT_LOCATION, 201)
                .build();
    }

    private ClientAndServer setupTestCreateAccountOnlyReturnExisting() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY_1 = "{" + System.lineSeparator()  +
                "  \"5ZnL5mAsOXE\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE_1 = "4UlRsB6SRdVCGnNiN3Ll8XKbc1LBw22RAy8PyK7KWlg";

        final String NEW_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJrc2ttSXFLaXcxejFSRXpwTzBXR3B5MWtiT2xYNENIb1dHMFJib0RoSk5KVHRLR2xYcmFMN1lESnBpdFZsUmt0cWlxRDlYdExEUl9qN2llSVlkbUhuOHpkbkV0aGVEaVZ6Wk5UQVFXRGtmbXJnVlRiN1JzS01mVW9qNWR1YnY2YWFLZWVObXpTRFZDQ1hfbU15RnU5QlllV3ZxS1V4OUNXWW84YWRvOU1kQmJMUExYZWJuenhtcVlkOWJUc3JqTkxjYXBWSm50NDhENzdObjdlVURfQWNnclFTOXRyLW1FM01MRTNkeUMyZGpEbC1pY3RkTXJIXzlFdGxhQ3ViUkF6NV9tZG8xWFFlTDdMOHdFVGxqaVdQQ2NCZi03S0xRXzlkTUFpeHk4Yy1ZenplejlNWnQ1bUt0N1FIcWlFdEV5Wm1jNWdaVjNpNUdYMUZiSlY1Vmt3cVEifSwibm9uY2UiOiI0VWxSc0I2U1JkVkNHbk5pTjNMbDhYS2JjMUxCdzIyUkF5OFB5SzdLV2xnIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJtYWlsdG86YWRtaW5AZXhhbXBsZS5jb20iXX0\",\"signature\":\"bkMP9_HkVWKqvc0iA6SyJedP44L7wKbTLVJ8d2Q6E1iY0_MrqnjZooYPeFQuc4BkmMw3iqm7wB1dmPXtIvieEs4BN8aCduDkCL2KYGcHfbZbjo2x5i3EcOX2n31GYVsC1RCW_2tao6-kNk9q-qivrER2acBwY3fuDTW9Cp1H_71MipA6OJiOhvbBvziCp8ux3GdZpT2wZNJXBZrDyhw0axbaZ-E8-Gzq2HCZU1FiEb72zOoaizc5oYBMYgT5KVSwtAXzKi2oCyoisHv1H-W7iiKLUvRkdDstxuH7VjakhRzRgRwXHY9kStu4QZX9IzrTKFcnXoviSEUMfedjahDLWQ\"}";

        final String NEW_ACCT_RESPONSE_BODY_1 = "{" + System.lineSeparator()  +
                "  \"id\": 387," + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"RSA\"," + System.lineSeparator()  +
                "    \"n\": \"kskmIqKiw1z1REzpO0WGpy1kbOlX4CHoWG0RboDhJNJTtKGlXraL7YDJpitVlRktqiqD9XtLDR_j7ieIYdmHn8zdnEtheDiVzZNTAQWDkfmrgVTb7RsKMfUoj5dubv6aaKeeNmzSDVCCX_mMyFu9BYeWvqKUx9CWYo8ado9MdBbLPLXebnzxmqYd9bTsrjNLcapVJnt48D77Nn7eUD_AcgrQS9tr-mE3MLE3dyC2djDl-ictdMrH_9EtlaCubRAz5_mdo1XQeL7L8wETljiWPCcBf-7KLQ_9dMAixy8c-Yzzez9MZt5mKt7QHqiEtEyZmc5gZV3i5GX1FbJV5VkwqQ\"," + System.lineSeparator()  +
                "    \"e\": \"AQAB\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:admin@example.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2018-04-23T13:05:44.561791555-04:00\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE_1 = "wR25VhDQw1ciGDZhP88SbWjJ4hzNEh6a1PVjAbyEzO4";
        final String NEW_ACCT_LOCATION_1 = "http://localhost:4001/acme/acct/387";


        final String DIRECTORY_RESPONSE_BODY_2 = "{" + System.lineSeparator()  +
                "  \"-McmmrFKskk\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE_2 = "ixsnb6zqvuwJ0o6_tM6hXn-cGA1pTXwTe3IoO6T8sVs";

        final String NEW_ACCT_REQUEST_BODY_2 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJrc2ttSXFLaXcxejFSRXpwTzBXR3B5MWtiT2xYNENIb1dHMFJib0RoSk5KVHRLR2xYcmFMN1lESnBpdFZsUmt0cWlxRDlYdExEUl9qN2llSVlkbUhuOHpkbkV0aGVEaVZ6Wk5UQVFXRGtmbXJnVlRiN1JzS01mVW9qNWR1YnY2YWFLZWVObXpTRFZDQ1hfbU15RnU5QlllV3ZxS1V4OUNXWW84YWRvOU1kQmJMUExYZWJuenhtcVlkOWJUc3JqTkxjYXBWSm50NDhENzdObjdlVURfQWNnclFTOXRyLW1FM01MRTNkeUMyZGpEbC1pY3RkTXJIXzlFdGxhQ3ViUkF6NV9tZG8xWFFlTDdMOHdFVGxqaVdQQ2NCZi03S0xRXzlkTUFpeHk4Yy1ZenplejlNWnQ1bUt0N1FIcWlFdEV5Wm1jNWdaVjNpNUdYMUZiSlY1Vmt3cVEifSwibm9uY2UiOiJpeHNuYjZ6cXZ1d0owbzZfdE02aFhuLWNHQTFwVFh3VGUzSW9PNlQ4c1ZzIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"driFYa_o5h7nQgc9U5zngmuTIjIf_uSlxZuzmg_qrfN6dJD5z0fEA_I69dPv6APlVAz93zHWXGtkCrFDgJVJl41o6jaFu8a7Y8BAavGAR8j2rw6Z-Rn8VqFtV8U3e8WLRNN_0P7M7vLZR9EH4v7JMovPsE6oMUYPrpbCSEJhv1Cs3f0MHqffDsbKk3pC7KLby15_1H4V9nf8ZRnOvFrVf2lMjMfBeLkDUB2fbtNMTmEe5e6xVaCuNkWr1mvYisOyddxpt3lpym1OeO3wciIQclkehcee7u13QWsN650r9TuHe335aUmLatsYn6xlD16lhjAyzcmB8OEPfP8G8iUrrA\"}";

        final String NEW_ACCT_RESPONSE_BODY_2 = "";

        final String NEW_ACCT_REPLAY_NONCE_2 = "TnWjtuWLDLzjSTYL4bh_0UPGzapEi5pNl5g31OCMRbI";
        final String NEW_ACCT_LOCATION_2 = "http://localhost:4001/acme/acct/387";

        final String DIRECTORY_RESPONSE_BODY_3 = "{" + System.lineSeparator()  +
                "  \"VmW3Odu7SoU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE_3 = "Vm1A1FUMCqxZR6Z_aTxmqy9AqfwSnB3a61Tsw8yFgBE";

        final String NEW_ACCT_REQUEST_BODY_3 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJxYmFNS2hZSDdCRVNaNVRERzdicnI5UmNZdFVhWFRucHJEVVBSTmhIQXBhTDZ5UHhHTnBrcXNhYWZhdDFtVWxzb1NkQjkybHotVjJmUTJjWTJTbjRuU0h6QkFxblRkVlRDa3hNOTZZUFZMT0RWckFRcDIwYlFheG12b1JMbHFUZUVRa3EyX0NjOFBObzB6TmEzOExGUzl1Y1JQZ3hUWkdxczJvdExGWjUtSUxLQXZhSWZSY0VURGhkWHVZU1pLTEwtdXh5ZnF0T0xDd0NrUlU0X2ZRdDg1UUZKXzhHc0V6VVV5V1JnOXFKSWZ4UkRsUjdCYmk4QmNRMzd6OEh6V205SzQxbEZkei1icWdOUDQ3UTJXdWQ1b1dJNmIzRE5UVmVCc1QzOTB1NmdUNGhfbWNaRF9HQXBicElUa2hIdk1HVHN2WDUwSThKNXRhclFCN25McTU1M3cifSwibm9uY2UiOiJWbTFBMUZVTUNxeFpSNlpfYVR4bXF5OUFxZndTbkIzYTYxVHN3OHlGZ0JFIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"FKs5xndYr-LWLhzusCndaNQFhUUQZ1K-fH1-A941dWMTeQbdQSULKX2R5Vh0yoz9sNMss1oljSt8vjdSNupwT0nbGMtFpZh_ElPEzXjXgVqGrV5FzYcwZfI6w9_NkgjH035aE_-OteTv8SBRR_Z_aY9JJlDm7jRvC7Xph_Z_bkpuxN1hOM_ax6ySsE2UXp60szSykdZVvFVvOK_4goEps1GcZ-kWmvmxYEG_aDoXwZi6TwpnM_bNAXlP2FDj8TFm3VhU7DbhJxvpAv0ERVdtvfuwb-d3NBacLib_koW5S9I1g77bLxJxQRXhODoJkRlggbofwnEbm3Pa6y5tJHoGsQ\"}";

        final String NEW_ACCT_RESPONSE_BODY_3 = "{" + System.lineSeparator()  +
                "  \"type\": \"urn:ietf:params:acme:error:accountDoesNotExist\"," + System.lineSeparator()  +
                "  \"detail\": \"No account exists with the provided key\"," + System.lineSeparator()  +
                "  \"status\": 400" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE_3 = "rtJAy_mcjDFGnnzCOAbGMGM6w8P3qU0bRDMf8sjt5IU";
        final String NEW_ACCT_LOCATION_3 = "";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_1)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_1)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY_1, NEW_ACCT_RESPONSE_BODY_1, NEW_ACCT_REPLAY_NONCE_1, NEW_ACCT_LOCATION_1, 201)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_2)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_2)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY_2, NEW_ACCT_RESPONSE_BODY_2, NEW_ACCT_REPLAY_NONCE_2, NEW_ACCT_LOCATION_2, 200)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_3)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_3)
                .addNewAccountRequestAndResponse(NEW_ACCT_REQUEST_BODY_3, NEW_ACCT_RESPONSE_BODY_3, NEW_ACCT_REPLAY_NONCE_3, NEW_ACCT_LOCATION_3, 400, true)
                .build();
    }

    private ClientAndServer setupTestCreateAccountWithECPublicKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"YlEPLZkkmYU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String NEW_NONCE_RESPONSE = "7bNmFPLpdcNFpSxolQF_8evQ6xtzX3bKyEwsi24nYHA";

        final String NEW_ACCT_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"id\": 389," + System.lineSeparator()  +
                "  \"key\": {" + System.lineSeparator()  +
                "    \"kty\": \"EC\"," + System.lineSeparator()  +
                "    \"crv\": \"P-256\"," + System.lineSeparator()  +
                "    \"x\": \"hpB4Z3w5IOsY7ADpPoA-nkwOl3Rh2pCVnzO6ByUMeww\"," + System.lineSeparator()  +
                "    \"y\": \"zeaxTqrr6evY_ind3ZeVQZneL2X79nmlTxhO8aObl5A\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"contact\": [" + System.lineSeparator()  +
                "    \"mailto:admin@example.com\"" + System.lineSeparator()  +
                "  ]," + System.lineSeparator()  +
                "  \"initialIp\": \"127.0.0.1\"," + System.lineSeparator()  +
                "  \"createdAt\": \"2018-04-24T11:04:39.436869571-04:00\"," + System.lineSeparator()  +
                "  \"status\": \"valid\"" + System.lineSeparator()  +
                "}";

        final String NEW_ACCT_REPLAY_NONCE = "XCFz0nWlCpEs-49S1p7qks-S0JcXS7uw2g4gQtJwUEI";
        final String NEW_ACCT_LOCATION = "http://localhost:4001/acme/acct/389";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse("", NEW_ACCT_RESPONSE_BODY, NEW_ACCT_REPLAY_NONCE, NEW_ACCT_LOCATION, 201)
                .build();

    }

    private ClientAndServer setupTestUpdateAccount() {

        // set up a mock Let's Encrypt server
        final String ACCT_PATH = "/acme/acct/1";
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator()  +
                "  \"UlOnbFfGuy0\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}" + System.lineSeparator() ;

        final String NEW_NONCE_RESPONSE = "pWTITfHw-_6KvHfsJADIIiIrDVwroGcLId5ox444dJY";

        final String UPDATE_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSIsIm5vbmNlIjoicFdUSVRmSHctXzZLdkhmc0pBRElJaUlyRFZ3cm9HY0xJZDVveDQ0NGRKWSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSJ9\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6ZmFsc2UsImNvbnRhY3QiOlsibWFpbHRvOmNlcnRpZmljYXRlc0BleGFtcGxlcy5jb20iLCJtYWlsdG86YWRtaW5AZXhhbXBsZXMuY29tIl19\",\"signature\":\"OXZEmTDelTETz_ySHuEKjaEgaD1-ZFh51PZjvXGyNBIo5ZiEv4gAoRx0Zewz6woyb8xqi74A8HEYwlSqt4tXtOwUhAJTnXOVntVk0gbVSqQESnyTrw5Dixhvue7JRt6T6n_6KWL8geFQH4ed8y56Sc-OchwKDodDNeDYkqw1skiF0dRb-YdlVKKg-7pj-tDfSW-dSffUWnG99zH5-fdXyaDQZ0xviSzRYZpB6K6vAABa1jgBcufJcKSyeweoieCIMmEL9mJcLb0RNizK1rLWY_sd7xfVOV77_xStkYYDE3MAxrFVslGPKdqcnvqS1lPLV41532sNM9PP5gIa0dDLig\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_1 = "{" + System.lineSeparator() +
                "  \"id\": 1," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"puL-WcMYUJ2Ajdy1UsUgNzjn6ecDxiWd7NGUGq267SOLwhKjSWWMwkopfcg5VMjPJWEE38IIXyjW5nFKCqFAIf3Zlih_1SLcjgVFbibn-oMGFLZs9ggr2bjRGJsbsJQIOKmgVs2y3l5RcIyF2M-UOx4GtAUQJsYittchBLxqjs0SBjWdtpWzaX4fwTCzx48RXuZhky_mKAyKbhAYnIGdDhcVIZsff6zzEM1bpJED6OBZh6pyP-N0kOxcGmPPCHMf0MzwjnK8VrFPEaIIfQAbUC1rTauiqZX7glEnN2kYqOwl8g3nf5fbX6sUuDU15fV0cmdUthy8_GHyE2qdzjPRLw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:certificates@examples.com\"," + System.lineSeparator() +
                "    \"mailto:admin@examples.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-20T21:14:45Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}";

        final String UPDATE_ACCT_REPLAY_NONCE_1 = "qQQ5Etbc4TYQxd0tn5kPxBXgR4L7Yq7UPbNHQIoPNDA";

        final String UPDATE_ACCT_REQUEST_BODY_2 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSIsIm5vbmNlIjoicVFRNUV0YmM0VFlReGQwdG41a1B4QlhnUjRMN1lxN1VQYk5IUUlvUE5EQSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSJ9\",\"payload\":\"\",\"signature\":\"AZGMp91FTKC0Yb9eSO9F8oPTC1gZ0kJMMPGkgb3k8X4bgRTcRRslvwOIDcjc0GW0-oBukbtNIcT-IhcK-vFDtHm5n_IZJpvU-iurRGDbWXgjxKNAjX8WMdai06926E8aqmnRPmGOv8bliu1NncpL1yVGQ69JKk21hawPZ1YROYnY1dL_ul5ExyqW56lgVmYH4Tev0XYGD8ORC7yYvM7ZXRDQbL_yT2AoSaU0SyJyo6NatwXyK3m3IqcZ_QaHmD5f21oa5efdg99D4Z4FPF-WB_-nkg3GT2wZQZ7W9SupoholHMMGe9xYjyun5d740QY2GeTZtivOiwsIY-ndZS6g1w\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"id\": 1," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"puL-WcMYUJ2Ajdy1UsUgNzjn6ecDxiWd7NGUGq267SOLwhKjSWWMwkopfcg5VMjPJWEE38IIXyjW5nFKCqFAIf3Zlih_1SLcjgVFbibn-oMGFLZs9ggr2bjRGJsbsJQIOKmgVs2y3l5RcIyF2M-UOx4GtAUQJsYittchBLxqjs0SBjWdtpWzaX4fwTCzx48RXuZhky_mKAyKbhAYnIGdDhcVIZsff6zzEM1bpJED6OBZh6pyP-N0kOxcGmPPCHMf0MzwjnK8VrFPEaIIfQAbUC1rTauiqZX7glEnN2kYqOwl8g3nf5fbX6sUuDU15fV0cmdUthy8_GHyE2qdzjPRLw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:certificates@examples.com\"," + System.lineSeparator() +
                "    \"mailto:admin@examples.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-20T21:14:45Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator() ;

        final String UPDATE_ACCT_REPLAY_NONCE_2 = "TX5h0WKwHGrJ2GgievpTRzHI9vPswsIR8oAjKMEp_xA";

        final String UPDATE_ACCT_REQUEST_BODY_3 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSIsIm5vbmNlIjoiVFg1aDBXS3dIR3JKMkdnaWV2cFRSekhJOXZQc3dzSVI4b0FqS01FcF94QSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSJ9\",\"payload\":\"eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6ZmFsc2V9\",\"signature\":\"iFLiIcxjnMnzmt8iTBtawU5-ODlvixcPtSWyejHsiwnDbYpexpUmJCHP7cTBbnzLmyjaE2LMFFFxMqIkY7pWh2jFCb3onMvMbktzfO08N4QMASrTIHyPEbKsT961GFt5_JcTZVynn2Sid3jtprt0jJk15mDokrXYVwknOu-_4O_366M9HSbWFVvAu-uhOwy0GRS6gjdhm2VAdhhFv9GwdbGf832pZn6d9xPusWzeldIuWHJyvivb3uo-7jv1nKLJurwcAMc1ve0nhxwCBIYEwbBQMrvvCIeFgWJT5NFCiBnSreECv1xUOQHKd-uWoJTBXtjmq2oSjyT45r9rDzgacA\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_3 = "{" + System.lineSeparator() +
                "  \"id\": 1," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"puL-WcMYUJ2Ajdy1UsUgNzjn6ecDxiWd7NGUGq267SOLwhKjSWWMwkopfcg5VMjPJWEE38IIXyjW5nFKCqFAIf3Zlih_1SLcjgVFbibn-oMGFLZs9ggr2bjRGJsbsJQIOKmgVs2y3l5RcIyF2M-UOx4GtAUQJsYittchBLxqjs0SBjWdtpWzaX4fwTCzx48RXuZhky_mKAyKbhAYnIGdDhcVIZsff6zzEM1bpJED6OBZh6pyP-N0kOxcGmPPCHMf0MzwjnK8VrFPEaIIfQAbUC1rTauiqZX7glEnN2kYqOwl8g3nf5fbX6sUuDU15fV0cmdUthy8_GHyE2qdzjPRLw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:certificates@examples.com\"," + System.lineSeparator() +
                "    \"mailto:admin@examples.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-20T21:14:45Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator() ;

        final String UPDATE_ACCT_REPLAY_NONCE_3 = "QH2Yt2vO38y3tqfqwiuqkz3q3EdBIDH6jfym7QhqOS8";

        final String UPDATE_ACCT_REQUEST_BODY_4 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSIsIm5vbmNlIjoiUUgyWXQydk8zOHkzdHFmcXdpdXFrejNxM0VkQklESDZqZnltN1FocU9TOCIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSJ9\",\"payload\":\"\",\"signature\":\"mnFtrac5kcUQIDfMzHC1v2crf3iTteZ50hzDQUcMxgqllRpMIKIedHTPdPjtc0KsXTYy3PbdjZVc_yN_x5_Ca5B2enAzQ5K9hTI8GeEOHoqLwbmNuHO2lg1abjQ0nS4PPYY2SMf1zIYO69oLrHw2m4vlkVssMoBr-Xw4z0a7tlJBmrPZYQHg8Tn3O75rc3D4Our51D6uL6ErMrrd5VYKdAxRuP1EvDdZvYTcgNcEy8eEXw1826i7zCafjdtkgol8NgkdoOYXHezSJNmcaYmy3vFVTxJ1qCsGuOYltSowlUwOJoAqno9B3CAkrX6i6dUlRAMkpGyHI_MfnVoxajwEbg\"}";

        final String UPDATE_ACCT_RESPONSE_BODY_4 = "{" + System.lineSeparator() +
                "  \"id\": 1," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"puL-WcMYUJ2Ajdy1UsUgNzjn6ecDxiWd7NGUGq267SOLwhKjSWWMwkopfcg5VMjPJWEE38IIXyjW5nFKCqFAIf3Zlih_1SLcjgVFbibn-oMGFLZs9ggr2bjRGJsbsJQIOKmgVs2y3l5RcIyF2M-UOx4GtAUQJsYittchBLxqjs0SBjWdtpWzaX4fwTCzx48RXuZhky_mKAyKbhAYnIGdDhcVIZsff6zzEM1bpJED6OBZh6pyP-N0kOxcGmPPCHMf0MzwjnK8VrFPEaIIfQAbUC1rTauiqZX7glEnN2kYqOwl8g3nf5fbX6sUuDU15fV0cmdUthy8_GHyE2qdzjPRLw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:certificates@examples.com\"," + System.lineSeparator() +
                "    \"mailto:admin@examples.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-20T21:14:45Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator() ;

        final String UPDATE_ACCT_REPLAY_NONCE_4 = "5R1YpUP-hOkoDdJVmsDYxyRTKFePzfd9hothQ_uDzDE";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_1, UPDATE_ACCT_RESPONSE_BODY_1, UPDATE_ACCT_REPLAY_NONCE_1, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_2, UPDATE_ACCT_RESPONSE_BODY_2, UPDATE_ACCT_REPLAY_NONCE_2, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_3, UPDATE_ACCT_RESPONSE_BODY_3, UPDATE_ACCT_REPLAY_NONCE_3, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY_4, UPDATE_ACCT_RESPONSE_BODY_4, UPDATE_ACCT_REPLAY_NONCE_4, ACCT_PATH, 200)
                .build();
    }

    private ClientAndServer setupTestDeactivateAccount() {
        final String ACCT_PATH = "/acme/acct/4";

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"ZrMhBE165Rs\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "_ot8jmk3kIPA7kVzbSxr7tFZFcEX3UA2QvNUYeoe-ME";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNCIsIm5vbmNlIjoiX290OGptazNrSVBBN2tWemJTeHI3dEZaRmNFWDNVQTJRdk5VWWVvZS1NRSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNCJ9\",\"payload\":\"\",\"signature\":\"FVxUh-yhFJVXYbCFyxVyNgyKxCK_8hLJe86xymKv_kD7SvpjHLJLTwLJXO1wmoqWDe-xrXPNbn-9cMmEGZdj6wpXbZK_BWJYmkQgXnyfspbMZoztRBqmlm1eYabLL3szSi6bg2TQj0hP2NNw6YP60TD06wfzCranuxrUCj9Kqo6kOdlI20qLanJadST-xMaO3m8_wTZ0TJBb8ONYj2KQ6aWrnulzvx4Ngx3QmWai_ia3Pgr43He_8wKKE4nkJCzkT2dqhJagHgVzYtS5pYMPCfKF29CoFjSgUhmGmsXfq0dNyCzwQ6NuQ1EzO_jqFJrpTD-PpC-WeVIKtzqI_ynAOA\"}";

        final String QUERY_ACCT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"id\": 4," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"hUeAw6lgPh8RbmUW-KPexgLmvIRmW7Yf3Z60kUTK3WMIcJK3UxuLC5mSa8nSmzYTnvX9VE7JcjcoNaWn9g01qYbzTaRPMIDpryiEolmhZi4-Of7g-LREiXFRRUmEo9kdYuPOfBeGQRidbLegBP0uevJ0gmvxh-l3G4eal_ptZImDjRj0KQxA5Vv0dFrimIyGE8Cv-H_qXdysmfMtcUlMBQF2fw2kqyb-gpKZt9lsq97TolbkkEzPMR0PoKWdjL5UYlO-2PqU1L3YFjdLwU2M0Y8j9G9rTJkeUyrvi7W3QiXsXAyxJzHTZqKMyN3CAUFis0Imb2M9UIiEZ_a2EebxsQ\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@myexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-26T16:42:53Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE = "k0uKQtflzUT-teQXog32goAtH142cmkNu4Cm8xWFkis";

        final String UPDATE_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNCIsIm5vbmNlIjoiazB1S1F0Zmx6VVQtdGVRWG9nMzJnb0F0SDE0MmNta051NENtOHhXRmtpcyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNCJ9\",\"payload\":\"eyJzdGF0dXMiOiJkZWFjdGl2YXRlZCJ9\",\"signature\":\"TQZmkAUZ-yCLwbnnsUDuAX2EJhr_IudC8lQ1BqTzy5BTH_POy51yWbI_6sHsFTm9K2EKvrKuEtAbUioDx9hro5r0NkWzdB-VR9VEf07yAORN-H-2Bo-LfhxzH3qHA6POGYqTa-KWy4YJaCvqHk_9BWB3bIkzptcojf-L4OacqiND9pexJ_z-lMaF6ugiPrGuc-hg9Tme7Ij8hyz9NQRfte5x3JofPldUThJuNGvkyo0Ghne7JrI-4X6fsRp8eCwNigjphXeKoZ0Lsw_3-HqvB60OyLSH5lu6VCrxyKg7_bfsxw9-AQFLzQ9Ap3coCQofE_X0y4mAfAynQPzrVH01Wg\"}";

        final String UPDATE_ACCT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"id\": 4," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"hUeAw6lgPh8RbmUW-KPexgLmvIRmW7Yf3Z60kUTK3WMIcJK3UxuLC5mSa8nSmzYTnvX9VE7JcjcoNaWn9g01qYbzTaRPMIDpryiEolmhZi4-Of7g-LREiXFRRUmEo9kdYuPOfBeGQRidbLegBP0uevJ0gmvxh-l3G4eal_ptZImDjRj0KQxA5Vv0dFrimIyGE8Cv-H_qXdysmfMtcUlMBQF2fw2kqyb-gpKZt9lsq97TolbkkEzPMR0PoKWdjL5UYlO-2PqU1L3YFjdLwU2M0Y8j9G9rTJkeUyrvi7W3QiXsXAyxJzHTZqKMyN3CAUFis0Imb2M9UIiEZ_a2EebxsQ\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@myexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-26T16:42:53Z\"," + System.lineSeparator() +
                "  \"status\": \"deactivated\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String UPDATE_ACCT_REPLAY_NONCE = "7a63cfZZxTpf-tUO94u_PTa9T_XLs987y_SI1i0yU3M";

        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNCIsIm5vbmNlIjoiN2E2M2NmWlp4VHBmLXRVTzk0dV9QVGE5VF9YTHM5ODd5X1NJMWkweVUzTSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1vcmRlciJ9\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiMTcyLjE3LjAuMSJ9XX0\",\"signature\":\"GAZAQ3FtUVvdPJXgJ6yvsWQ64ZLUGa3R4vT7s0EyTOorh6_DfatIhS0x3Ow7-KlrAG1C1VMKPeQ8mpt0GqjCM3kiVsKMZU2ehhSvY6P7DTY2p9h9NDtH1L732Ka4UHIJ-vg-uGfFx-ChlwaR-i8g9rMiYO6l_iIZFu44jKQBjTxmg0nAO0334qfHHfk1py8XHxJSVtt0zM1pb-hdDD0NRUjmS9Kyg-RgmTjZj3P5FDTk12_e6sPWIgGoFuPyKHyCcOXP0yysUUJgm9yOs0F1m68rdcHb2L-RxBrmwEBDNEe8knLYDuC7KvILXZ9JoIbwAWuK9MGbuno7dQK2vneYdg\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"urn:ietf:params:acme:error:unauthorized\"," + System.lineSeparator() +
                "  \"detail\": \"Account is not valid, has status \\\"deactivated\\\"\"," + System.lineSeparator() +
                "  \"status\": 403" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "NjWUjJAn80Y5SfyZORhyUZ1MU15w4Zh3IiLSJdFi4jM";
        final String ORDER_LOCATION = "";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .updateAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_PATH, 200)
                .updateAccountRequestAndResponse(UPDATE_ACCT_REQUEST_BODY, UPDATE_ACCT_RESPONSE_BODY, UPDATE_ACCT_REPLAY_NONCE, ACCT_PATH, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 403, true)
                .build();
    }

    private ClientAndServer setupTestGetNonce() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"L3kiSpDcTos\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "d4o3tdwrnpzwi9xgI21EqNdDyInvLcrENqTXthWD0qg";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .build();
    }

    private ClientAndServer setupTestObtainCertificate() {
        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"hb7nxeqSiSo\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "eV3KvqTuyA_bAaCZJ9ZgdQISvgGiNB_306WG1hf6qXk";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJwdUwtV2NNWVVKMkFqZHkxVXNVZ056am42ZWNEeGlXZDdOR1VHcTI2N1NPTHdoS2pTV1dNd2tvcGZjZzVWTWpQSldFRTM4SUlYeWpXNW5GS0NxRkFJZjNabGloXzFTTGNqZ1ZGYmlibi1vTUdGTFpzOWdncjJialJHSnNic0pRSU9LbWdWczJ5M2w1UmNJeUYyTS1VT3g0R3RBVVFKc1lpdHRjaEJMeHFqczBTQmpXZHRwV3phWDRmd1RDeng0OFJYdVpoa3lfbUtBeUtiaEFZbklHZERoY1ZJWnNmZjZ6ekVNMWJwSkVENk9CWmg2cHlQLU4wa094Y0dtUFBDSE1mME16d2puSzhWckZQRWFJSWZRQWJVQzFyVGF1aXFaWDdnbEVuTjJrWXFPd2w4ZzNuZjVmYlg2c1V1RFUxNWZWMGNtZFV0aHk4X0dIeUUycWR6alBSTHcifSwibm9uY2UiOiJlVjNLdnFUdXlBX2JBYUNaSjlaZ2RRSVN2Z0dpTkJfMzA2V0cxaGY2cVhrIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"Rlkqyf_FBDoQTX5v0-JbBp2TEJL83tysY7j6O0fHldkG14MCr1nNSne-cbHoi3XrbK0i105cOstvYDtImFwGELAIr2KC4p7NVkR842tcsrcW-GarSjyZy0iydksdGlcQBJZ9597iKyn0LD6E3SMn6g-MIlmohaTgVX61WUhoJL5-JLEGQnuOPNt6UsNgXZrqvPxd_K80EDxHQqt50pqJkSef4I96mof_utLYPyovKWCRVU5t218WyjhNLPpCmAJ08s6crvrdJH-wCsAluOZ70mGIwPTC8rY4aiCUAyrXdVy9FCw0b3fZd_Q2jHJc5f5jJ9crHmNj-2F1knIQ_yyRiw\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "CuZc2AGqVfV0ukqf1zT7ZinVrzqCESVYSZEgm5GMH70";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/1";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSIsIm5vbmNlIjoiQ3VaYzJBR3FWZlYwdWtxZjF6VDdaaW5WcnpxQ0VTVllTWkVnbTVHTUg3MCIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1vcmRlciJ9\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiZmpzbGpnaGFzbGRmamdrLmNvbSJ9XX0\",\"signature\":\"W8m13WauHy74xg_xe0DvHSLSbwZTQGCZIyC-K07cDgohgcoenB1V0R9NwIcOWz8eiOosZPnVNmxt655NrXyC2V6fmxpPLlJJtfRPD9vyB_PqOm2Lg5RD1gBB1o-TWRvcGAgdDU6CCHUBuFZMmmwY6GzIBBlYIS4YuusuSTmjdVLRLV_wcs4e3FV5Qddx8iWqM7clWzI1nkCtlBT8AtddBMmr5VQYx1-FAa2xYnH7l3tpQZO7FJdOzWwplVJpiwtS2SwBMlA8C6OtrHLRR3sEMP69OIlyy5kd6WvYYGgv0cIsXmdZocsyN2kkpg7oEI8zs_pbxqXJu1Fey_vkDAms5g\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T18:18:04.480847297Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"fjsljghasldfjgk.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/1/3\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "Te8QGF7zjTU2Lncm8ieXiQi8W2aHuQVeNe4FGauokOk";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/1/3";

        final String AUTHZ_URL = "/acme/authz/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s";
        final String AUTHZ_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSIsIm5vbmNlIjoiVGU4UUdGN3pqVFUyTG5jbThpZVhpUWk4VzJhSHVRVmVOZTRGR2F1b2tPayIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2F1dGh6LzJFU2tiQ2k1Zl9CTnV1QU1XMjhUU3M2bjVHSjJxa2hycnpEejYzX0NMOHMifQ\",\"payload\":\"\",\"signature\":\"UToLcSsGlCvDTG2iDj90glUKgw-p1LC2Wc8ejbY6Osl2ZbZ3gddaEjbsKLPLJ8V8Uu7ElwT3ECRHzCMY3stFDwId4EsnHfGgnjb99LNpGTBQcNP-T7FTgZH_-hfpVTwavvc_Q3qaeGtyOYun1tEZu8lCoJEnowItBawdAMOgpa37USH6Ta4h83ET2Y4p0mDWbz3__IMhTMlYohIJ2zRi9V6a1dQF05AEkASa6OqDzz02EgzU66hLJj2qy3Si3IbVb7x2M1ZWDITSeM_ZmyGE5UumO0OcBRh__KyuQNqis95AM8dF_l1ChyOAmndKLskvhWKUOrFDtzmr-rmPPB-JrA\"}";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"fjsljghasldfjgk.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-27T21:14:45Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/5\"," + System.lineSeparator() +
                "      \"token\": \"TUucyKEqlOtB3AHYJgJXfyBDkKOlWcTpOyt_msVrXH0\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/6\"," + System.lineSeparator() +
                "      \"token\": \"EsdnMEwgN_8vim67x99uXs4PRf0pEFYPoR2zb3xpNBQ\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/7\"," + System.lineSeparator() +
                "      \"token\": \"CpKffHs2YglmLA3dcLsqqEGj54cd0QvyuYWsHDl-aFw\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/8\"," + System.lineSeparator() +
                "      \"token\": \"h1-B7k5V9rPsKmJxGIU4yEeqqaSKypCeCIWqDe1GPXQ\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String AUTHZ_REPLAY_NONCE = "H73CfbiAmBNqWm3rXPyC2RwCc5KCB6dVqsh5V5DL0Vg";

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSIsIm5vbmNlIjoiSDczQ2ZiaUFtQk5xV20zclhQeUMyUndDYzVLQ0I2ZFZxc2g1VjVETDBWZyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2NoYWxsZW5nZS8yRVNrYkNpNWZfQk51dUFNVzI4VFNzNm41R0oycWtocnJ6RHo2M19DTDhzLzgifQ\",\"payload\":\"e30\",\"signature\":\"QFiqdvYvjKDz9YcbW6okDKwfJ5la8H0EBRwmGhVYQ9Vt33U9QjD056V-X7lnKrsGxcRnxagVberF3WwjYa247g_m-luPfTcFdUpbYjawETegZzEwl7YBSKOyzb6YWuKhCKL-6G_BzCrIv3pAb5_o4EQhfcoEB0l3e5UQyxe8cLyHkkKpAKHqpm1MqV_7wKAfF5XJ_iLCv1xjooWDea7TaSb64sFA4XfN8Mci5tkaxPiGYY-KeXxGmWkn9YQwBNuWEACpkVKximFH643FurlkI1ACdf335AbOh_t4E3WdJlbrsf869LL7Xb3I6GPUXb4ymQ__-Z8GBnyDjzQOd3kzsg\"}";
        final String CHALLENGE_URL = "/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/8";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/8\"," + System.lineSeparator() +
                "  \"token\": \"h1-B7k5V9rPsKmJxGIU4yEeqqaSKypCeCIWqDe1GPXQ\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "YtR3PkcqmSPtD5evNpAD7-N41wotJYjZVP0I1D9Dg74";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/8";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/h1-B7k5V9rPsKmJxGIU4yEeqqaSKypCeCIWqDe1GPXQ";
        final String CHALLENGE_FILE_CONTENTS = "h1-B7k5V9rPsKmJxGIU4yEeqqaSKypCeCIWqDe1GPXQ.p8ESGS6nX--L-ReV0llT4mUDFkS7Bt1cyMoa0zqPDkk"; //******* FJ FIX

        final String UPDATED_AUTHZ_REPLAY_NONCE = "Fw-xaxnQWkezLY7Mn5l5q4rN6YiK88_K3ZwWsZg1RDY";
        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"fjsljghasldfjgk.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-12-23T18:31:37Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/5\"," + System.lineSeparator() +
                "      \"token\": \"TUucyKEqlOtB3AHYJgJXfyBDkKOlWcTpOyt_msVrXH0\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/6\"," + System.lineSeparator() +
                "      \"token\": \"EsdnMEwgN_8vim67x99uXs4PRf0pEFYPoR2zb3xpNBQ\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/7\"," + System.lineSeparator() +
                "      \"token\": \"CpKffHs2YglmLA3dcLsqqEGj54cd0QvyuYWsHDl-aFw\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s/8\"," + System.lineSeparator() +
                "      \"token\": \"h1-B7k5V9rPsKmJxGIU4yEeqqaSKypCeCIWqDe1GPXQ\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://172.17.0.1:5002/.well-known/acme-challenge/h1-B7k5V9rPsKmJxGIU4yEeqqaSKypCeCIWqDe1GPXQ\"," + System.lineSeparator() +
                "          \"hostname\": \"fjsljghasldfjgk.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"172.17.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"172.17.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_URL = "/acme/finalize/1/3";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T18:31:37Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"fjsljghasldfjgk.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/1/3\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff8aadf65d2fd76a59e8010a71b1aa0cfcb3\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "fpOvJkPvyGfYKIrlhFiLuQV9p5KpUnsiAE7OF4DlBHE";
        final String FINALIZE_LOCATION = "http://localhost:4001/acme/order/1/3";

        final String CHECK_ORDER_URL = "/acme/order/1/3";
        final String CHECK_ORDER_REPLAY_NONCE = "iAeto9P3tcrx_yxqayPuQ2qjIF2zPuDawOc18wyXl_g";

        final String CHECK_ORDER_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSIsIm5vbmNlIjoiZnBPdkprUHZ5R2ZZS0lybGhGaUx1UVY5cDVLcFVuc2lBRTdPRjREbEJIRSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL29yZGVyLzEvMyJ9\",\"payload\":\"\",\"signature\":\"NQtYeOF6np1sZYlNoeap7dVGJzJMuUHyOQyFk14KssttTA3R5FEst26aLW_OI0nS-DVWC545v95ws5XWtbaW7PhMP6yusWInjKL8_2Ll6Wuv-TWc67I_fO1ureaCyJx7jxI20uSKDovINtx56v6bMH0gMpmXyRXqkJ2dtVluvpP9z5xA8EnvdTJX4JavuXYJDJbP7T-fVE5xC34Jid78ShFXp86xHh37gD2ezsSTWjGO73tScpqZD8S2KBWq38VzMHto1k8ZH57rNxHsZJ70vSgfWPRyxICoUjOENmjAJHbxC56JXpagQM9Czcogfth38xK5fsJwx_gDYE5Y5OAMoA\"}";
        final String CHECK_ORDER_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T18:31:37Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"fjsljghasldfjgk.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/2ESkbCi5f_BNuuAMW28TSs6n5GJ2qkhrrzDz63_CL8s\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/1/3\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff8aadf65d2fd76a59e8010a71b1aa0cfcb3\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CERT_URL = "/acme/cert/ff8aadf65d2fd76a59e8010a71b1aa0cfcb3";
        final String CERT_REPLAY_NONCE = "FJE8Ulv3I8TflPcbCyENdFBPe3pu62V1NmwqUA0GN5E";

        final String CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMSIsIm5vbmNlIjoiaUFldG85UDN0Y3J4X3l4cWF5UHVRMnFqSUYyelB1RGF3T2MxOHd5WGxfZyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2NlcnQvZmY4YWFkZjY1ZDJmZDc2YTU5ZTgwMTBhNzFiMWFhMGNmY2IzIn0\",\"payload\":\"\",\"signature\":\"VseQTW_Log95lBnTCORmxTJpqq9UeZ2ItpFoj2wPt3bVnPz7PcLhdKaR1cFnnlZwEFMw0rPhzD-JBSusrEGnZ7a0qZ-CwFLDGhrldXZnlNfN2QMQSLVgcg8MupwYdm6W--YkMloqgWCIOPk5QMSIbCmHekZhkBeRNdL4ScNKatgnOMa3EmISFJNAMQ2eA_cVAn-8XO8qZ9S3qhhfJ86FjPV4b0b9GhI9U-tJgPNqNvzZIql3V8CyYr60MTRujXwLp1rJ-YhmKT9XnObsJo8rIRoWP-yxWrSMxcPMqXOrso-k9YJZU5PfG_met7M0NX6vS7a_MtJzyPKQmC3ZrAwN0Q\"}";
        final String CERT_RESPONSE_BODY = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIFRjCCBC6gAwIBAgITAP+KrfZdL9dqWegBCnGxqgz8szANBgkqhkiG9w0BAQsF" + System.lineSeparator() +
                "ADAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTAeFw0xODExMjMxNzMx" + System.lineSeparator() +
                "MzdaFw0xOTAyMjExNzMxMzdaMB4xHDAaBgNVBAMTE2Zqc2xqZ2hhc2xkZmpnay5j" + System.lineSeparator() +
                "b20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbeFecNuAOSBc4TiE+" + System.lineSeparator() +
                "uP6F4o6FMdKSR73ioNf+e37jUHjA2xFCU7WdAsffnVDOrE/vcaVAjee6ygLDOa5W" + System.lineSeparator() +
                "233hhlqrAjleVXb63cmKeVAqK6mWudYqvmy4KkvcMVW6wcWQSUKn7HDdQSK2NXcV" + System.lineSeparator() +
                "S5OtTnivdX/Jzyh78U/o7UkRGRlpq6GaFIejB+xKHC0r9jJAD3Rf6kE3WusZtxGt" + System.lineSeparator() +
                "KU6fmmQ2gUMkn91RVASxMEsgV3nGwPVSKFs5YM/xHs27ktiCWRe4jiEdK2LAzEe/" + System.lineSeparator() +
                "rWdJ8awRPQiosYALPb+vEfIIaGMOHbsamBo091J6RpORftB8hMMQmCaX8+YrTipw" + System.lineSeparator() +
                "Avw1AgMBAAGjggJ6MIICdjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYB" + System.lineSeparator() +
                "BQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFJpVcrQq28ZE" + System.lineSeparator() +
                "YPxS/a8CFgoEoqO8MB8GA1UdIwQYMBaAFPt4TxL5YBWDLJ8XfzQZsy426kGJMGQG" + System.lineSeparator() +
                "CCsGAQUFBwEBBFgwVjAiBggrBgEFBQcwAYYWaHR0cDovLzEyNy4wLjAuMTo0MDAy" + System.lineSeparator() +
                "LzAwBggrBgEFBQcwAoYkaHR0cDovL2JvdWxkZXI6NDQzMC9hY21lL2lzc3Vlci1j" + System.lineSeparator() +
                "ZXJ0MB4GA1UdEQQXMBWCE2Zqc2xqZ2hhc2xkZmpnay5jb20wJwYDVR0fBCAwHjAc" + System.lineSeparator() +
                "oBqgGIYWaHR0cDovL2V4YW1wbGUuY29tL2NybDBABgNVHSAEOTA3MAgGBmeBDAEC" + System.lineSeparator() +
                "ATArBgMqAwQwJDAiBggrBgEFBQcCARYWaHR0cDovL2V4YW1wbGUuY29tL2NwczCC" + System.lineSeparator() +
                "AQQGCisGAQQB1nkCBAIEgfUEgfIA8AB3AN2ZNPyl5ySAyVZofYE0mQhJskn3tWnY" + System.lineSeparator() +
                "x7yrP1zB825kAAABZ0HXcsAAAAQDAEgwRgIhANOS0vF4e5hs3GOmHPqOu9Nsf+/P" + System.lineSeparator() +
                "rBqXIlZVv/sc4/OyAiEA9ylAXlcSXCwLIrSQ3Nd13m54f9hYefgGfLr65BuSsMwA" + System.lineSeparator() +
                "dQAW6GnB0ZXq18P4lxrj8HYB94zhtp0xqFIYtoN/MagVCAAAAWdB13LAAAAEAwBG" + System.lineSeparator() +
                "MEQCIAe17g1Q0vdsK5MHs6ypajNbdbNxYCcIXCF5EjYcYjdaAiAyRZJm1T/6ozfx" + System.lineSeparator() +
                "IBxF9oC3j0Ma0q+1xzihaL3FZnWmYTANBgkqhkiG9w0BAQsFAAOCAQEATxbLjVMZ" + System.lineSeparator() +
                "LSO2nx3rok4Ybdwc1OEV4PDlDc/e4NOGCRXR6ZflZlcvp5Gv4nEpHbosuyYfKPIh" + System.lineSeparator() +
                "Ac3BPpxUxEC+r3I93p5iV8PXEhA/ajZSdp4nX1lxXR+CZtiGPJIhX9TzmR+Ba1BW" + System.lineSeparator() +
                "zdklVzU5dmodSXGXV51G1IQKTUNOdNoo26plbII50OLkAbMacgji8G55bLsgLW97" + System.lineSeparator() +
                "RxQY/XE3Phja6Pgcu3oIYPHmOGp/FPLKr7iL2uR8e1Cr/4ke53wdoCmDYctjvvrU" + System.lineSeparator() +
                "ZFts88Q9Exu92/XH2BuClpDEzPW08quHG9k6jtes5bzd8zTmJxs8E1sbE9JXUKGC" + System.lineSeparator() +
                "2kBDtvsu69hhHQ==" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator() +
                "" + System.lineSeparator() +
                "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIERTCCAy2gAwIBAgICElowDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fj" + System.lineSeparator() +
                "a2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTYwMzIyMDI0NzUyWhcN" + System.lineSeparator() +
                "MjEwMzIxMDI0NzUyWjAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTCC" + System.lineSeparator() +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5" + System.lineSeparator() +
                "Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxU" + System.lineSeparator() +
                "zpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14U" + System.lineSeparator() +
                "joaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctK" + System.lineSeparator() +
                "FUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7" + System.lineSeparator() +
                "XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsC" + System.lineSeparator() +
                "AwEAAaOCAX0wggF5MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG" + System.lineSeparator() +
                "MH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3Rp" + System.lineSeparator() +
                "ZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlk" + System.lineSeparator() +
                "ZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmk" + System.lineSeparator() +
                "P+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQB" + System.lineSeparator() +
                "gt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5j" + System.lineSeparator() +
                "cnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3Qu" + System.lineSeparator() +
                "Y29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmz" + System.lineSeparator() +
                "LjbqQYkwDQYJKoZIhvcNAQELBQADggEBAKvePfYXBaAcYca2e0WwkswwJ7lLU/i3" + System.lineSeparator() +
                "GIFM8tErKThNf3gD3KdCtDZ45XomOsgdRv8oxYTvQpBGTclYRAqLsO9t/LgGxeSB" + System.lineSeparator() +
                "jzwY7Ytdwwj8lviEGtiun06sJxRvvBU+l9uTs3DKBxWKZ/YRf4+6wq/vERrShpEC" + System.lineSeparator() +
                "KuQ5+NgMcStQY7dywrsd6x1p3bkOvowbDlaRwru7QCIXTBSb8TepKqCqRzr6YREt" + System.lineSeparator() +
                "doIw2FE8MKMCGR2p+U3slhxfLTh13MuqIOvTuA145S/qf6xCkRc9I92GpjoQk87Z" + System.lineSeparator() +
                "v1uhpkgT9uwbRw0Cs5DMdxT/LgIUSfUTKU83GNrbrQNYinkJ77i6wG0=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_REQUEST_BODY, AUTHZ_RESPONSE_BODY, AUTHZ_REPLAY_NONCE)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY, UPDATED_AUTHZ_REPLAY_NONCE)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 200)
                .addCheckOrderRequestAndResponse(CHECK_ORDER_URL, CHECK_ORDER_REQUEST_BODY, CHECK_ORDER_RESPONSE_BODY, CHECK_ORDER_REPLAY_NONCE, 200)
                .addCertificateRequestAndResponse(CERT_URL, CERT_REQUEST_BODY, CERT_RESPONSE_BODY, CERT_REPLAY_NONCE, 200)
                .build();
    }

    private ClientAndServer setupTestObtainCertificateWithKeySize() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"R0Qoi70t57s\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "as0qhFiJk4eKYeAXBE4Jr0c-cx5GphsCuRPNWF30img";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJoNWlULUY4UzZMczJLZlRMNUZpNV9hRzhpdWNZTl9yajJVXy16ck8yckpxczg2WHVHQnY1SDdMZm9vOWxqM3lsaXlxNVQ2ejdkY3RZOW1rZUZXUEIxaEk0Rjg3em16azFWR05PcnM5TV9KcDlPSVc4QVllNDFsMHBvWVpNQTllQkE0ZnV6YmZDTUdONTdXRjBfMjhRRmJuWTVXblhXR3VPa0N6QS04Uk5IQlRxX3Q1a1BWRV9jNFFVemRJcVoyZG54el9FZ05jdU1hMXVHZEs3YmNybEZIdmNrWjNxMkpsT0NEckxEdEJpYW96ZnlLR0lRUlpheGRYSlE2cl9tZVdHOWhmZUJuMTZKcG5nLTU4TFd6X0VIUVFtLTN1bl85UVl4d2pIY2RDdVBUQ1RXNEFwcFdnZ1FWdE00ZTd6U1ZzMkZYczdpaVZKVzhnMUF1dFFINU53Z1EifSwibm9uY2UiOiJhczBxaEZpSms0ZUtZZUFYQkU0SnIwYy1jeDVHcGhzQ3VSUE5XRjMwaW1nIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"ZyeduXF5oI4QUAg3ZF0zgVk8TXn4K-OdzRSOFkakYXVpbK2hwW7I7iuNh7YZIv_hUVmtMfglA9ZtISYif1lEqONDtkFWOyyZVxyom9TyjB-tdjtS77YNa-yYyELDE7O9MWBrI7m0PH6X6R2688VuNgfLtdzcjD_nWHzLbKoj8aGiIWLoArekPqq0Gg6I1hxgiCiDSaev8GvXcNDGDe9M9PhacbIyXrNGWNXxQAoOy-76Ly5ptW-2tjbLxpSYfZzJpQJP_bgK8OhndUf3TidvBS2TBI4tikGZIm6ZKsX6mwDH7kHseBf0HE--vuR7WwXnp2UKZcn-64lxGNTqIYPB0w\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "na_bjoXbpRlEFD8Bb2shGzT2Xiy6_ju4Gs6YJCPPs1E";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/2";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoibmFfYmpvWGJwUmxFRkQ4QmIyc2hHelQyWGl5Nl9qdTRHczZZSkNQUHMxRSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1vcmRlciJ9\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaW5sbmVzZXBwd2tmd2V3LmNvbSJ9XX0\",\"signature\":\"Xobxsl_guUz2T3bUMTAwA5A4MzZt4HBzcGPHlcaldvPm8nqh2HZ9BfRBh7pAqGJUxzFJkyPK4BhO8F4ekzEQsEOhhCsV42f9lelVp2lWFbxPdWJVIOIhfLrzMLgTfqkrfL2GIZqsWAT4B94VgbBw1dfB7NwAzujGv6kJo9USA86slStLYDE06q7lL7q0tWe63vKtPhzEJv5odgcLL8vBb9ANiM9ZeSlFprw6nzTGn3M7gVY3IlenkK8XHJjN_9Xw0aeYcOMqB5o14LowDpyKFlgPYeVuu-bhl1YcGMrDvUVj0lnZS-_YoW0vfMKyvWxWhZKbVf8UcH-e_eAVdx2cbA\"}";
        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:18:11.372756901Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/2/8\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "RvM3fgI2Z08HTzhbwKA-EnOrJtnGqV81tOlfErZIAK4";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/2/8";

        final String AUTHZ_URL = "/acme/authz/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk";
        final String AUTHZ_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoiUnZNM2ZnSTJaMDhIVHpoYndLQS1Fbk9ySnRuR3FWODF0T2xmRXJaSUFLNCIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2F1dGh6L1l6THF2azdHZWRMSVZmQWtyZUZnTmNydC1LY1Y1TW9LZE1XWmNPbHFKcGsifQ\",\"payload\":\"\",\"signature\":\"C5nBE_22rqq5LsqDGackn_v09Jltf09fg-aPIW_xdL9jKWu2cOlU_ktFTYGI1JEzYyVplzoLLzkXgfmOdQKlm9IrxMWB7FsY_JzfEl2bHGsacE3we-OzPXFMQjPblAyc--7Prk56_mMtVpGaJMJAYOu4Nr3ZkcdWkjTvkNyRFGj2dinKS2aFytngBG26zZbLVTgZpXXHuvSxAd8C0cgc5KxJbk8iI3E9r39k_7RcbMRQ-2_scmoiWMTyipav7kBqEj8LSPqHLNeUo7hbui0Jwh8vQ6VFc1kMURqTGioXfzGQytsm3C2A6wOYGLdPgKldVu1J9ruD_bGw2NjUmMp_kw\"}";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:18:11Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/17\"," + System.lineSeparator() +
                "      \"token\": \"vKGXiPTz4xRD23TLKdFKUflWK6DdEPIWOdChQxWBJTA\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/18\"," + System.lineSeparator() +
                "      \"token\": \"6BIn9ySZG5m9yweJX1KKkRsJa_B0alX4DrfQF1YtmJc\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/19\"," + System.lineSeparator() +
                "      \"token\": \"59uoXgFHuyYVwZDxIyXIhFe-OZkFlJhk_3iFiENmRZ4\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/20\"," + System.lineSeparator() +
                "      \"token\": \"DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String AUTHZ_REPLAY_NONCE = "KvD4oVF2ahe2w2RtqbjYP9nJH_xzVWeHJIlhDRNn-N4";

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoiS3ZENG9WRjJhaGUydzJSdHFiallQOW5KSF94elZXZUhKSWxoRFJObi1ONCIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2NoYWxsZW5nZS9Zekxxdms3R2VkTElWZkFrcmVGZ05jcnQtS2NWNU1vS2RNV1pjT2xxSnBrLzIwIn0\",\"payload\":\"e30\",\"signature\":\"FyKdGn_TlCbEg21RtgXSIZS8Js0YGMFHv5V1SJaefy1LDw_YeSx5_X1g_rEB1BLGuxUoIv96CMDeX-_GAb5PNYSVQfzc_kEIs8YLpVWrWCq_KVNbRx1NWBl5Vc4hYgwWa246wWMD2AjMBOtD46ncuYinJkueHX3sbW_CKBMEo-LG3SdupX-sNckcpuQqlRdNaEwfi1hxEZLjoHvlyzfg9kUH4m39wsoSXELQm2ZeYv8pUOqvXH3M02Ik4CjT_2_lhh0NzU6Kh_WXrHawK-2FPkSYN0xdqh4qK1i_YcUSG9_trtgxcHBVJLfn9jroqpmpy7Y4Li8M4C4J-M90nzPMXQ\"}";
        final String CHALLENGE_URL = "/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/20";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/20\"," + System.lineSeparator() +
                "  \"token\": \"DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "A-3-ge_TjcQwoYdlSJX4YtznB5fPVME627MwK-U_GkM";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/20";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/LJRH3-gjUPt5U5v8wH1Ch3eFcxu8UK-uotjutm5NB9s>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w";
        final String CHALLENGE_FILE_CONTENTS = "DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w.w2Peh-j-AQnRWPMr_Xjf-IdvQBZYnSj__5h29xxhwkk";

        final String UPDATED_AUTHZ_REPLAY_NONCE = "jBxAXwYy9_19Bue5Wcij8aiAegiC4nqGTFD_42k3HQQ";
        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-12-23T22:18:11Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/17\"," + System.lineSeparator() +
                "      \"token\": \"vKGXiPTz4xRD23TLKdFKUflWK6DdEPIWOdChQxWBJTA\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/18\"," + System.lineSeparator() +
                "      \"token\": \"6BIn9ySZG5m9yweJX1KKkRsJa_B0alX4DrfQF1YtmJc\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/19\"," + System.lineSeparator() +
                "      \"token\": \"59uoXgFHuyYVwZDxIyXIhFe-OZkFlJhk_3iFiENmRZ4\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk/20\"," + System.lineSeparator() +
                "      \"token\": \"DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://172.17.0.1:5002/.well-known/acme-challenge/DGdnia8PWJaVYXnFZOdQGOedbryAWa7AUEk9UjSxA0w\"," + System.lineSeparator() +
                "          \"hostname\": \"inlneseppwkfwew.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"172.17.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"172.17.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoiakJ4QVh3WXk5XzE5QnVlNVdjaWo4YWlBZWdpQzRucUdURkRfNDJrM0hRUSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2ZpbmFsaXplLzIvOCJ9\",\"payload\":\"eyJjc3IiOiJNSUlFc3pDQ0Fwc0NBUUF3SGpFY01Cb0dBMVVFQXd3VGFXNXNibVZ6WlhCd2QydG1kMlYzTG1OdmJUQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQUtaSU15U2NOczM0UHNPTUtXZjE5cy1ORTBMNDVaUGYxdDVVZjhGYllfYkV2UFpiSG1qbS1RalhTQ1dVZmowelVzdHo2N3h2RXZicS01d2h5Zk9tQ2VBOWw4djBrZHBacHRwdUtIdjN6T05URDBCd2N3c01adzhYTm9DQXdQWk1DTUNqMTZPNDIzYjRzbTE0RDBEUGg2bEkwanI3dXB1QVhTWXU4YkNJeUVISllJY2ZDd2pGOXNUeUctV3p6SjdwMWhwV2F1N0s5MmFNekRQTGZBandUSkFqdGNxNEhuNl9GX3NIQXNQM0RhWU5lMnp4QUxaWXRiYzBKSGFELWdreVNILUZ6TU9pWlNJR0FTNFJCV3E4S2pwUkE3YWFTaDNfWDBjNG9kbFVPVjVXYVJWbjF0eWlGaGItMlNFT2IzQW0tb19uanBqUjBTYlVrNlZlZ0xicWVyQ2V1WGdZUzNYcXF5MlU3cTZtY0FFQUF6TzktcFlpM1Fza01hQXB3XzFhUUFSUU5JWFo3NWRpcGlmN295UzdtS0hTM0RaZUtPTDRuUlY1dFRyMjY2NFc4VUxZdjlhRmJGcFp2ak5EYThlYUl4QVdGWnEwYlN1UFhISjBjVjFGOHlaMUItT2Y4bGRhZmFjWGQxTms4S0swamw3MXRoVzhraFdtekJmNTdjR1Q3bUQ0a1dmcXY3YVJ0cVVfVE1RWjM4cDdGbnp0ZFhFTUpMQTZLRVhkV04yMU5hZkxodU1uRVBqSW9Rc2d2UEVsOEJVTDdZMkwtMC1MX2JuMEc5aV9LVG4tWFdteFdDNHk4dmdZMVQ0VVV1RkptT0lYSnl3TVFmMllvWDVIZUZ1bW10S3hHRHhrMjltSURTdHotSWVQd2lUOUE4SGtlVG5hcXN5RG1CQXpyWE5KQWdNQkFBR2dVREJPQmdrcWhraUc5dzBCQ1E0eFFUQV9NQjRHQTFVZEVRUVhNQldDRTJsdWJHNWxjMlZ3Y0hkclpuZGxkeTVqYjIwd0hRWURWUjBPQkJZRUZNRmszanFiXzRQWFZnRzhPa1ZsUXMzSzZPZkRNQTBHQ1NxR1NJYjNEUUVCREFVQUE0SUNBUUFGaXpjQW5sbmYwNUxad0duR3pKZHhQTHNndGhtanp3Uy0xcWJ2dy1kNlpmNGEtSGVBdjZTakNoVXgtVUI5UklpTy1HWERranp5eVpMUFlkbE50SlAteGNCeGs0YXZDc1ZvR0x5TUdMMVE1ejItcURXOXdoakR1M210TndvVFQ5REx3Sk1UUEJLV1ROWU9Za25tQkk1WDF1alpJVkFfSjJmUHA3SzNVMlJJQXdDNE9FX01sMzVYOElJU0hsTmplMUtMOVlNN0F4a0thcm03Wl9ic1lYcFVkQmR1T2VZRGNsbkdrRU1hT0Q4WDAxVUhuS1FmRVRlLUlmb0lXYVBSZWZWNGh4SnU5MndDR3EySnUtWVY3X0k2VVRGU1B1cUZJM0JrWXBXcUVIUUdWV2Qtck1MQ194UVVSbHNxWHhfbG5KQjlPdGFmcHpYblNCU0lRRk1xdm81Z2J3VWVscENpTDA0T280ZTNfS0NfSGtLQ3c0ZTNZdXdnY2FFUVJ3YUVZS1Y0UEc5QmNsbE1Ia19McE5LVXM1SGE1NDh6V1JNQWhRc2c3d0NIZHEzb2xwZWUyWUowbUN4cjdDLUlqT2dmcFhrdUtwYWhITUs2UzlybU9zZjdLaHVLeXpWLVBHalAybXZmTXo1b2RfZVlRV3M1UHVlbDVjMEhnbkRjdlBhVGRwTDdrZ1V5TEpHRWVBUVQ3WkE5cGxscm1hSDA1aDZRREtwNHBCLUJieTBaaHVYWlFxV2hmbmZsak91dklHN0hWUzlXWXlhTl9mdlBJOFJJa1F0MTdXQ094cEZYNDJ5YmRtWC1IVUdqLWYwS3NfOExudUVsMjBhazZ3bjZFRldLOWRRZnBaOXZIcndybTVMV0xaenlhdG1zSmI4QW1KUGhjQ3lOUFVjcFJfZmg3ZyJ9\",\"signature\":\"Cs0G6_pY_ql1INkfziVjpTW2lzlNdnW7HAn1pKwlCcb2h5IFjUA-JAfCxUrWR_uMNnvlk7-KuwtTNN_AXSaocuRlc6uJd7ZsF2xpTrkGFrTDolVjfM8VxSQYZlLhN_TMKyFyH-Dxn0fAptM2Xm3PZBSkkXMuuiSuqjMUV4fGKGEik4WERuUJZsEgdiPUsZu61usfk3kyjZ1MetgU7VzMMXg0e3tTd5t490B4X6fad8sllmee1TpTFhdfNRFcf6GYDcPnkyApvRsI9sc5gB0WM_Q_zrFip5Rk2irA2QQZeVkYmdQ7E5wEucnoxbjoY-m3A4d-4y4mcBSSZ5OA1AOKHQ\"}";
        final String FINALIZE_URL = "/acme/finalize/2/8";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:18:11Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/2/8\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/fff0ba7aa54a2ce6597c0fa0dd6f7c8e87a7\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "l_OFFmSJQuq27CFQSG6N-2vbNCbyHG7E_RyF3J45wvg";
        final String FINALIZE_LOCATION = "http://localhost:4001/acme/order/2/8";

        final String CHECK_ORDER_URL = "/acme/order/2/8";
        final String CHECK_ORDER_REPLAY_NONCE = "yuXkl473reHRMcaVgTyTZ1AWO8Z_HbiHo9oj3RdoUog";

        final String CHECK_ORDER_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoibF9PRkZtU0pRdXEyN0NGUVNHNk4tMnZiTkNieUhHN0VfUnlGM0o0NXd2ZyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL29yZGVyLzIvOCJ9\",\"payload\":\"\",\"signature\":\"drMLY2890JViRe2N8BZB2gfpveieZ0hzOUYHJYz9eUPOhAzYJyS658OAs27oil7LnRVFFVdLu6iIYKmeCjS3tRWNkFQLPba8EDRSaGaJQGshaVhHtvxfv-p3M_0pJ3Mu7lJDzDwzzbZ_cYeeqI0txp1qXNqp68Ac7aT946nRrsLPaefiff0n0tGtlYvnc3TXML3hohhLtz_4xXmWnr3f_-dT17BSAZNDPrp1d7wFaoD1LVEBwTG1X-NFNOPweQ0imAEUQCg8ZPDNSbBBxxO1iLqNjQXITPxBV3hz-fmLDzh82Pgfs4KkSBtUPPkxDAX4Re6LHzkW7J-Vqu_E2NH01Q\"}";
        final String CHECK_ORDER_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:18:11Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"inlneseppwkfwew.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/YzLqvk7GedLIVfAkreFgNcrt-KcV5MoKdMWZcOlqJpk\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/2/8\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/fff0ba7aa54a2ce6597c0fa0dd6f7c8e87a7\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CERT_URL = "/acme/cert/fff0ba7aa54a2ce6597c0fa0dd6f7c8e87a7";
        final String CERT_REPLAY_NONCE = "9Ir87CU21P5mNNGfhBASf2dkD7QpJdZfB9BGMIzQW9Q";

        final String CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMiIsIm5vbmNlIjoieXVYa2w0NzNyZUhSTWNhVmdUeVRaMUFXTzhaX0hiaUhvOW9qM1Jkb1VvZyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2NlcnQvZmZmMGJhN2FhNTRhMmNlNjU5N2MwZmEwZGQ2ZjdjOGU4N2E3In0\",\"payload\":\"\",\"signature\":\"NyRAnCigeTinK1pdkEhzO1ZKwCzuG70hNBbySxzkoS00SNq-KNA_eYu9Hk5FK7SA8HPWWadgJ4UA2GNEotqaQKzMpinPPonW2hX_SrLOcUTcRAYsggpoQl6jLRCT7O4bJ4Glve_IrAW1F2GEEqWHAhEnTSQDpZul9d5qrORjUxt7qu8A_5nAbssPDErplv2uXJH4BZAyLS2v4g-MG-Yf-Iun8kN7QC4-9uFNlIZMQyclqO1nYEUbVYanZnvxTv0WysabMZlsTmCJtElsfGdraJqBMnFvstd5E5dKqcGibq5uzleJgxYd2e5sFJfKe7cew7pbVTqvjl-nk1EwqUVizw\"}";
        final String CERT_RESPONSE_BODY = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIGRjCCBS6gAwIBAgITAP/wunqlSizmWXwPoN1vfI6HpzANBgkqhkiG9w0BAQsF" + System.lineSeparator() +
                "ADAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTAeFw0xODExMjMyMTE4" + System.lineSeparator() +
                "MTJaFw0xOTAyMjEyMTE4MTJaMB4xHDAaBgNVBAMTE2lubG5lc2VwcHdrZndldy5j" + System.lineSeparator() +
                "b20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCmSDMknDbN+D7DjCln" + System.lineSeparator() +
                "9fbPjRNC+OWT39beVH/BW2P2xLz2Wx5o5vkI10gllH49M1LLc+u8bxL26vucIcnz" + System.lineSeparator() +
                "pgngPZfL9JHaWababih798zjUw9AcHMLDGcPFzaAgMD2TAjAo9ejuNt2+LJteA9A" + System.lineSeparator() +
                "z4epSNI6+7qbgF0mLvGwiMhByWCHHwsIxfbE8hvls8ye6dYaVmruyvdmjMwzy3wI" + System.lineSeparator() +
                "8EyQI7XKuB5+vxf7BwLD9w2mDXts8QC2WLW3NCR2g/oJMkh/hczDomUiBgEuEQVq" + System.lineSeparator() +
                "vCo6UQO2mkod/19HOKHZVDleVmkVZ9bcohYW/tkhDm9wJvqP546Y0dEm1JOlXoC2" + System.lineSeparator() +
                "6nqwnrl4GEt16qstlO6upnABAAMzvfqWIt0LJDGgKcP9WkAEUDSF2e+XYqYn+6Mk" + System.lineSeparator() +
                "u5ih0tw2Xiji+J0VebU69uuuFvFC2L/WhWxaWb4zQ2vHmiMQFhWatG0rj1xydHFd" + System.lineSeparator() +
                "RfMmdQfjn/JXWn2nF3dTZPCitI5e9bYVvJIVpswX+e3Bk+5g+JFn6r+2kbalP0zE" + System.lineSeparator() +
                "Gd/KexZ87XVxDCSwOihF3VjdtTWny4bjJxD4yKELILzxJfAVC+2Ni/tPi/259BvY" + System.lineSeparator() +
                "vyk5/l1psVguMvL4GNU+FFLhSZjiFycsDEH9mKF+R3hbpprSsRg8ZNvZiA0rc/iH" + System.lineSeparator() +
                "j8Ik/QPB5Hk52qrMg5gQM61zSQIDAQABo4ICejCCAnYwDgYDVR0PAQH/BAQDAgWg" + System.lineSeparator() +
                "MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0G" + System.lineSeparator() +
                "A1UdDgQWBBTBZN46m/+D11YBvDpFZULNyujnwzAfBgNVHSMEGDAWgBT7eE8S+WAV" + System.lineSeparator() +
                "gyyfF380GbMuNupBiTBkBggrBgEFBQcBAQRYMFYwIgYIKwYBBQUHMAGGFmh0dHA6" + System.lineSeparator() +
                "Ly8xMjcuMC4wLjE6NDAwMi8wMAYIKwYBBQUHMAKGJGh0dHA6Ly9ib3VsZGVyOjQ0" + System.lineSeparator() +
                "MzAvYWNtZS9pc3N1ZXItY2VydDAeBgNVHREEFzAVghNpbmxuZXNlcHB3a2Z3ZXcu" + System.lineSeparator() +
                "Y29tMCcGA1UdHwQgMB4wHKAaoBiGFmh0dHA6Ly9leGFtcGxlLmNvbS9jcmwwQAYD" + System.lineSeparator() +
                "VR0gBDkwNzAIBgZngQwBAgEwKwYDKgMEMCQwIgYIKwYBBQUHAgEWFmh0dHA6Ly9l" + System.lineSeparator() +
                "eGFtcGxlLmNvbS9jcHMwggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdgAodhoYkCf7" + System.lineSeparator() +
                "7zzQ1hoBjXawUFcpx6dBG8y99gT0XUJhUwAAAWdCpuW/AAAEAwBHMEUCIQDSlIhR" + System.lineSeparator() +
                "AaD+KnEI3cUBIigDrbXJxXDYUIwoIcYErsHF7gIgXbY/rmJ6LCbYyt8PwZkDVStn" + System.lineSeparator() +
                "2Khogm0Tk5hK4FynyxYAdgAW6GnB0ZXq18P4lxrj8HYB94zhtp0xqFIYtoN/MagV" + System.lineSeparator() +
                "CAAAAWdCpuuZAAAEAwBHMEUCIQDmVp+En4lRjkqn23HuzJk2mEkGbuDOQvLcZ+XH" + System.lineSeparator() +
                "hj4DcgIgBpfHfTG7i3mtCTYz20hP72/9qbEyKI8I/0yt/bMMjlEwDQYJKoZIhvcN" + System.lineSeparator() +
                "AQELBQADggEBAEMZGO3pbTME1J97CDjpK8SX/0HUyOa8fyLXn8et6R6Q+LfhtZuE" + System.lineSeparator() +
                "Tb+RsKtx+QcEiqwFTQF5/tIqHh3T8QoXZvSvanUmn+/wAjgmhllRHbVuNe/8QB+f" + System.lineSeparator() +
                "NE+hhbpB5IPiQjBFPNuTyHSq5HZisrPKXr9hjKc+UhqHu6VC6kgQT7JrAlQ3YXcA" + System.lineSeparator() +
                "rIUGyi325G8mOUqs+vl24Lu6ll2BP9kHTBatYJyj0b1JnuVpIiCCXSS13v3VYg+b" + System.lineSeparator() +
                "ejRaEGe9QhHNHEola5ZxYb/Ryacvd/ZGZBAIRCy8zOV4zaOmP6WXk9yajUswhymx" + System.lineSeparator() +
                "uDS1f3V/hiCjfuDZ7ljN4FQYBF2eIMZT6Ks=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator() +
                "" + System.lineSeparator() +
                "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIERTCCAy2gAwIBAgICElowDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fj" + System.lineSeparator() +
                "a2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTYwMzIyMDI0NzUyWhcN" + System.lineSeparator() +
                "MjEwMzIxMDI0NzUyWjAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTCC" + System.lineSeparator() +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5" + System.lineSeparator() +
                "Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxU" + System.lineSeparator() +
                "zpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14U" + System.lineSeparator() +
                "joaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctK" + System.lineSeparator() +
                "FUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7" + System.lineSeparator() +
                "XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsC" + System.lineSeparator() +
                "AwEAAaOCAX0wggF5MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG" + System.lineSeparator() +
                "MH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3Rp" + System.lineSeparator() +
                "ZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlk" + System.lineSeparator() +
                "ZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmk" + System.lineSeparator() +
                "P+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQB" + System.lineSeparator() +
                "gt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5j" + System.lineSeparator() +
                "cnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3Qu" + System.lineSeparator() +
                "Y29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmz" + System.lineSeparator() +
                "LjbqQYkwDQYJKoZIhvcNAQELBQADggEBAKvePfYXBaAcYca2e0WwkswwJ7lLU/i3" + System.lineSeparator() +
                "GIFM8tErKThNf3gD3KdCtDZ45XomOsgdRv8oxYTvQpBGTclYRAqLsO9t/LgGxeSB" + System.lineSeparator() +
                "jzwY7Ytdwwj8lviEGtiun06sJxRvvBU+l9uTs3DKBxWKZ/YRf4+6wq/vERrShpEC" + System.lineSeparator() +
                "KuQ5+NgMcStQY7dywrsd6x1p3bkOvowbDlaRwru7QCIXTBSb8TepKqCqRzr6YREt" + System.lineSeparator() +
                "doIw2FE8MKMCGR2p+U3slhxfLTh13MuqIOvTuA145S/qf6xCkRc9I92GpjoQk87Z" + System.lineSeparator() +
                "v1uhpkgT9uwbRw0Cs5DMdxT/LgIUSfUTKU83GNrbrQNYinkJ77i6wG0=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_REQUEST_BODY, AUTHZ_RESPONSE_BODY, AUTHZ_REPLAY_NONCE)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY, UPDATED_AUTHZ_REPLAY_NONCE)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 200)
                .addCheckOrderRequestAndResponse(CHECK_ORDER_URL, CHECK_ORDER_REQUEST_BODY, CHECK_ORDER_RESPONSE_BODY, CHECK_ORDER_REPLAY_NONCE, 200)
                .addCertificateRequestAndResponse(CERT_URL, CERT_REQUEST_BODY, CERT_RESPONSE_BODY, CERT_REPLAY_NONCE, 200)
                .build();
    }

    private ClientAndServer setupTestObtainCertificateWithECPublicKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"Xdaqm0jAr6Q\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "3oW0xyzxz_hCTdMgmDjgUb489EVl53vkM9ki9mjL-U0";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJpVk5xSnVoM3VvWW5xdkNfZGtYQzRFMDN4R292eTdLUjAwd3M4QUwwcHJWcktzajhnZFdhWjBLZkZ1Q0NUaUtMU1BhNVQ0ZnRWNFdia2l0djFMa0JWU29Wd1hqSDE0bFpIMWFHYkptR1lCX3pSOV9uVzZJTzRVb1RGc2Vqb3paN05kNW8waVFpQWpyRjBmMDhGVC1xYS1TVVZiVk16dkNnQW16SjJFVlhzOXdOQ2pzSVRnNGh3eDdZRzl5eHRhZjFoT0hkV1dKVWtwZ0hnQkVfclpZT1B5YVNlb2JyeE5mMllxVmhFNWM2ZjhrZUhYdnU2dnprODctZVNLWXlndk9hSW1YOUhFbFZhQXRVcnI0S3hFV3VvUDdNRzZCV0s2TDVpam9Db0VMQjBqM0w2UHNuXzM1VnMxQi05OFR6SFZqYU1sU1NGV20xQjdtS0NzNGZMeE1pRXcifSwibm9uY2UiOiIzb1cweHl6eHpfaENUZE1nbURqZ1ViNDg5RVZsNTN2a005a2k5bWpMLVUwIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"PN-H66GQghR3VGBTv_PBoHY3nJlKfKcbzroHfr48AZqsTcLTObf8myVdPpPdkw3vLJPG4hJupxYOhQnluI0932Dfqtc6_uY2uLOVtcVu9iyUABEOJzwr-2fWKHhhW_3O3G_5TPUgM1tCKY4Iac8hw7Qd_W78i5XNMAZ38Sd6SNur2iXdoEg2vadxVU7Onm8OutlQUhdaLdiFXAeSPSixXSpYxu2Xh-8YlnqJw1qBg6UnSxw-jCDgFrD-xL6DCRlXsl2FFpSJZK-DqPzKY07v42WWGQe8_acbpf40K0g6kw4wM0nvSugUIBuypACh8J7QdgFSns_TRZrBrGY57wjx_Q\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "GLc_xR_n3Ytx8bDjmIODHL4tuHWul6phFmFVGASUI-s";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/3";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMyIsIm5vbmNlIjoiR0xjX3hSX24zWXR4OGJEam1JT0RITDR0dUhXdWw2cGhGbUZWR0FTVUktcyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1vcmRlciJ9\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoibW5kZWxrZG5iY2lsb2hnLmNvbSJ9XX0\",\"signature\":\"REO9CCtOq19V3T0tKTuwTlZZlRwCoe1Sy_-xYitF4dHADT63cocpyzaML0OAgnuc8BrqTnbLhP3KcsLAVPx3gmFpsYY4iWPL2EsB-tVJzEWGqjHd-X2WkX9i2uO9U615zWgM2k6shzduewV7GlF6yMBl4SAB3lg7wCYtS5-cVGF1SrVqKHuBDC9istsWYLC0AkfgJwO1gdK4fweQJ4WP-0OHHi9SX7WIjwKxgRrMDlWl-UJO9bc4lqMEcIKdMQsg_q_hYwxSUgIAhM_a3a1gEidutlfOgexwvtdFQY2mMPJtHiwwkRmO9Fmre6gdvQwoVVLryLuGRJv5I-W84ZG3bg\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:43:32.370907593Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"mndelkdnbcilohg.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/3/10\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "i4xRyKelZj5ScS7U7TcTU2PxO6Ri41YpDHPamcMbfN0";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/3/10";

        final String AUTHZ_URL = "/acme/authz/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g";
        final String AUTHZ_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMyIsIm5vbmNlIjoiaTR4UnlLZWxaajVTY1M3VTdUY1RVMlB4TzZSaTQxWXBESFBhbWNNYmZOMCIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2F1dGh6L2c5bWJoaXRWS1lxMGVCWXhuaG00THgyYkNBYTJRVEtfWkJUOFhCeHlQMWcifQ\",\"payload\":\"\",\"signature\":\"YupyN8RQoenfotv3VHLvehnp2LBYtUTGJRQDcFS65kPog_bI7MojREpeIGYOcBCLrGpuLH-_LOowqdfd4aocfAv2Dk-skNg8Ma5FjLFdY51Eo2ULqPwTGXX1TY78B8cWiUpDr8se3NgFTcEDYEk6F_V-kUh8eylEwaQUsmexwTPPUL2fmT4hL-5R3CGCadWYTmsEHqB45BwqDtPvd-81CTbOQ18sTrbV1d-Xf5hQWdZfm_78FrSXjqqRl3dI-WP8K0CE7vqJ6euXJVUMa7K-Gwwkrp6CJ9yQfcOQv-eu-B9o-WIfUgQRioqjgLzOJ4z8dbojNE-gnOtId4uGn1O5xQ\"}";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"mndelkdnbcilohg.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:43:32Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/25\"," + System.lineSeparator() +
                "      \"token\": \"zjXs_VldJCiubFFW7Vvr1bctw7JAbO0PtIhjQc4Kb4U\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/26\"," + System.lineSeparator() +
                "      \"token\": \"vdUixEBpiDj0RuJKlJnplaSvpr4C_GfBOVh_zUUUulk\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/27\"," + System.lineSeparator() +
                "      \"token\": \"hGOq4xCmkDe4E7ZzqUbwT6PfjoT5VipE2PpyutL2RxQ\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/28\"," + System.lineSeparator() +
                "      \"token\": \"f-0Jro36un-NLfg-kCqPEdvsDWwPbX7-FZY1SSmZ9w8\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String AUTHZ_REPLAY_NONCE = "rqfaFFRiaabH3tAJQoW7R3J-AStDq-MmE7um5NluHSE";

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMyIsIm5vbmNlIjoicnFmYUZGUmlhYWJIM3RBSlFvVzdSM0otQVN0RHEtTW1FN3VtNU5sdUhTRSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2NoYWxsZW5nZS9nOW1iaGl0VktZcTBlQll4bmhtNEx4MmJDQWEyUVRLX1pCVDhYQnh5UDFnLzI4In0\",\"payload\":\"e30\",\"signature\":\"W777d69Y9TiV8GB2mZrkZd2AUcSvj6AJJtvCvNb7ILOIXpQuEdspA1_aFAhY5Pzilqocsd8RApJYgRyHULCmWeIwG_SOMKFfyMOXnPzUFnecUNJBRQhZzXiotrILhIUkBGU0bZBshemRmGZSdAe9bASVqcEWLqWlSaX3Idd0vJ6m31TuYqz6Po5ClUvrHWL0-1i4gjKHpNXnJ7bzqa6KRe6BCo9bVC_frMWEiSaE6Cq-YXB9pSmAXsJRkLNgbuFe8c8pRMfSFJluVkxE-yP1cTjChJGvHx5tRD6DmOKRIPXfwQ2zMEBxudjxaka8mdeKayOVpqTfXXlSp-aiS03N7w\"}";
        final String CHALLENGE_URL = "/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/28";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/28\"," + System.lineSeparator() +
                "  \"token\": \"f-0Jro36un-NLfg-kCqPEdvsDWwPbX7-FZY1SSmZ9w8\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "Luvt_xmHKnuIQuUWMpI1-HjWMsNuVMK7mSnbgciTNxw";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/28";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/f-0Jro36un-NLfg-kCqPEdvsDWwPbX7-FZY1SSmZ9w8";
        final String CHALLENGE_FILE_CONTENTS = "f-0Jro36un-NLfg-kCqPEdvsDWwPbX7-FZY1SSmZ9w8.952Xm_XyluK_IpyAn6NKkgOGuXbeWn8qoo0Bs9I8mFg";

        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"mndelkdnbcilohg.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-12-23T22:43:32Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/25\"," + System.lineSeparator() +
                "      \"token\": \"zjXs_VldJCiubFFW7Vvr1bctw7JAbO0PtIhjQc4Kb4U\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/26\"," + System.lineSeparator() +
                "      \"token\": \"vdUixEBpiDj0RuJKlJnplaSvpr4C_GfBOVh_zUUUulk\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/27\"," + System.lineSeparator() +
                "      \"token\": \"hGOq4xCmkDe4E7ZzqUbwT6PfjoT5VipE2PpyutL2RxQ\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g/28\"," + System.lineSeparator() +
                "      \"token\": \"f-0Jro36un-NLfg-kCqPEdvsDWwPbX7-FZY1SSmZ9w8\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://172.17.0.1:5002/.well-known/acme-challenge/f-0Jro36un-NLfg-kCqPEdvsDWwPbX7-FZY1SSmZ9w8\"," + System.lineSeparator() +
                "          \"hostname\": \"mndelkdnbcilohg.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"172.17.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"172.17.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String UPDATED_AUTHZ_REPLAY_NONCE = "z8JyOz3PXdq67aXf3rpXBS5LkAjSibX9xqFW4qaCvB8";

        final String FINALIZE_URL = "/acme/finalize/3/10";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:43:32Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"mndelkdnbcilohg.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/3/10\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff87f7830644eb0e60d43bf624d6d028bd89\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "9jSBsPqFmUC9D5kxAJ6g7XsN6LWGLCLp3Y6pDTWbHHM";
        final String FINALIZE_LOCATION = "http://localhost:4001/acme/order/3/10";

        final String CHECK_ORDER_URL = "/acme/order/3/10";
        final String CHECK_ORDER_REPLAY_NONCE = "WQ_v5SrNqsA_9v_xCmH3MyQgWqX2PZg59OKWG1EYIQU";

        final String CHECK_ORDER_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMyIsIm5vbmNlIjoiOWpTQnNQcUZtVUM5RDVreEFKNmc3WHNONkxXR0xDTHAzWTZwRFRXYkhITSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL29yZGVyLzMvMTAifQ\",\"payload\":\"\",\"signature\":\"HHxbg4kXThDyJrw0lp1VNfTxVi1GsKKO2AUhCUpaxNK61pgv49eRlHZq6vQiG0do5F1JGJTN8gc_NtoMoovlEQl9Rp48G-9ZHdk5_XNaTr7AEW_TDKufX3vlOpElkVDr0pRZWPhgc5RdauxzFoCQDVQQN1ZK4CbuELwp-FHTgoGvvc_vWT9gN0pOTVYPA02N7sN1yy0XF6PrJrHJgZyDvNx2urWkrIgUtemKv9-6eyjLwY315YCTQ-DygeLwkjVw1DeC2O-yMXJ_rZPOS3I3Kvephvj3xleyJ3xLoboYhdIp8_GnK3rcuPrmYHvu097XD0YfWRbfaYGzp3Zhh_0-hA\"}";
        final String CHECK_ORDER_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T22:43:32Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"mndelkdnbcilohg.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/g9mbhitVKYq0eBYxnhm4Lx2bCAa2QTK_ZBT8XBxyP1g\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/3/10\"," + System.lineSeparator() +
                "  \"certificate\": \"http://localhost:4001/acme/cert/ff87f7830644eb0e60d43bf624d6d028bd89\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CERT_URL = "/acme/cert/ff87f7830644eb0e60d43bf624d6d028bd89";
        final String CERT_REPLAY_NONCE = "by4s6iEQL4-fAf_ku09qljcbhlxL7sAftG8YdJLJfiE";

        final String CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMyIsIm5vbmNlIjoiV1FfdjVTck5xc0FfOXZfeENtSDNNeVFnV3FYMlBaZzU5T0tXRzFFWUlRVSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2NlcnQvZmY4N2Y3ODMwNjQ0ZWIwZTYwZDQzYmY2MjRkNmQwMjhiZDg5In0\",\"payload\":\"\",\"signature\":\"VfoBhgP5mnEDf2_JeomN2xcDr4AuA58b3g0Q_NgWOvGC1egoyGA4PzaqZRJQC_dg14hFnZWUF6WNUUz0hAyD7pFOiA8YEbi0s42pse4H2X-xUnnhRRGmitxcjZYS-t7BjBYaMyHirT6dhpmpcZIEiROYqUGG3WrycDQDvV3s9WsGjdjOYHCTiLA5WWnm3okB8xLugmHHdsC8XXTnUuZjuNpqYJBIJM0fg60aqmkZOZup6BCQy83T4i-Obz65hndCFVG-zHIGV7V8zPUqkPYTQ3Zzztb0Bj_fvYoB6oxZoMw687NcPV_3Q3HQ34vKfu8K2DEJleTzgwueV-7dC2BJQw\"}";
        final String CERT_RESPONSE_BODY = "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIEnzCCA4egAwIBAgITAP+H94MGROsOYNQ79iTW0Ci9iTANBgkqhkiG9w0BAQsF" + System.lineSeparator() +
                "ADAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTAeFw0xODExMjMyMTQz" + System.lineSeparator() +
                "MzJaFw0xOTAyMjEyMTQzMzJaMB4xHDAaBgNVBAMTE21uZGVsa2RuYmNpbG9oZy5j" + System.lineSeparator() +
                "b20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASkd8KOCVYYS/TzqUunlsoJX57r" + System.lineSeparator() +
                "iZbr5QuO+4vWHXpRd7kl9soPKttpDMVn6/lWgM8N/z4hyC0RxtJ9y5qJimmoo4IC" + System.lineSeparator() +
                "njCCApowDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF" + System.lineSeparator() +
                "BQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSD8y6uXfvil+pta5vpFb1pO6IF" + System.lineSeparator() +
                "nDAfBgNVHSMEGDAWgBT7eE8S+WAVgyyfF380GbMuNupBiTBmBggrBgEFBQcBAQRa" + System.lineSeparator() +
                "MFgwIgYIKwYBBQUHMAGGFmh0dHA6Ly8xMjcuMC4wLjE6NDAwMi8wMgYIKwYBBQUH" + System.lineSeparator() +
                "MAKGJmh0dHA6Ly8xMjcuMC4wLjE6NDAwMC9hY21lL2lzc3Vlci1jZXJ0MB4GA1Ud" + System.lineSeparator() +
                "EQQXMBWCE21uZGVsa2RuYmNpbG9oZy5jb20wJwYDVR0fBCAwHjAcoBqgGIYWaHR0" + System.lineSeparator() +
                "cDovL2V4YW1wbGUuY29tL2NybDBhBgNVHSAEWjBYMAgGBmeBDAECATBMBgMqAwQw" + System.lineSeparator() +
                "RTAiBggrBgEFBQcCARYWaHR0cDovL2V4YW1wbGUuY29tL2NwczAfBggrBgEFBQcC" + System.lineSeparator() +
                "AjATDBFEbyBXaGF0IFRob3UgV2lsdDCCAQUGCisGAQQB1nkCBAIEgfYEgfMA8QB2" + System.lineSeparator() +
                "ABboacHRlerXw/iXGuPwdgH3jOG2nTGoUhi2g38xqBUIAAABZ0K+FRsAAAQDAEcw" + System.lineSeparator() +
                "RQIgcDtvDgILEVlsLLOkfVFeFbOdUJdCkPaMJp1firJNv2sCIQDs5A9jhOQtsV4C" + System.lineSeparator() +
                "+v7ep/sK8kgMjiKpkmzw0xcbEgrdIgB3AN2ZNPyl5ySAyVZofYE0mQhJskn3tWnY" + System.lineSeparator() +
                "x7yrP1zB825kAAABZ0K+FR4AAAQDAEgwRgIhAMsFphjNxqMEpB5HIgZCOdujjsco" + System.lineSeparator() +
                "fVLRPntCEXoTSpXvAiEAyWf3EdceQS130qTfhboW4lrshoLyVBb5cOHCnI5UkT4w" + System.lineSeparator() +
                "DQYJKoZIhvcNAQELBQADggEBAGzFBD9ybCDO6KqcD2FCA46uS1TCTedOT2VMozJM" + System.lineSeparator() +
                "DXmGR3y/deVOc+OyTOqzPpl894EHjYz5CvlosX2Pf3LBi+VhfTM7/UgVDLyYJ+dp" + System.lineSeparator() +
                "Kh/bt4lyO9903COG/9OVDTWwychZN5vYQdUOFLNZWwd9dDbHNega11uGEoPwq4ON" + System.lineSeparator() +
                "O3IOBp+DwD1fAHJKzS2S0kroWs64yf0V0m0RJeEguHfmQ2p85UhLY4+3/vKPUuaV" + System.lineSeparator() +
                "uRAP8L3q8uR0B2RiKZHJ6DZPHC3e/KREXfDEpb6K5Dr0ChShF+YUZMoWNCi0WPn+" + System.lineSeparator() +
                "i2cGYlqkhtSCg2gFPrKhw9A0ItxKd3M/Hv/jSmX3O/el4e8=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator() +
                "" + System.lineSeparator() +
                "-----BEGIN CERTIFICATE-----" + System.lineSeparator() +
                "MIIERTCCAy2gAwIBAgICElowDQYJKoZIhvcNAQELBQAwKzEpMCcGA1UEAwwgY2Fj" + System.lineSeparator() +
                "a2xpbmcgY3J5cHRvZ3JhcGhlciBmYWtlIFJPT1QwHhcNMTYwMzIyMDI0NzUyWhcN" + System.lineSeparator() +
                "MjEwMzIxMDI0NzUyWjAfMR0wGwYDVQQDDBRoMnBweSBoMmNrZXIgZmFrZSBDQTCC" + System.lineSeparator() +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIKR3maBcUSsncXYzQT13D5" + System.lineSeparator() +
                "Nr+Z3mLxMMh3TUdt6sACmqbJ0btRlgXfMtNLM2OU1I6a3Ju+tIZSdn2v21JBwvxU" + System.lineSeparator() +
                "zpZQ4zy2cimIiMQDZCQHJwzC9GZn8HaW091iz9H0Go3A7WDXwYNmsdLNRi00o14U" + System.lineSeparator() +
                "joaVqaPsYrZWvRKaIRqaU0hHmS0AWwQSvN/93iMIXuyiwywmkwKbWnnxCQ/gsctK" + System.lineSeparator() +
                "FUtcNrwEx9Wgj6KlhwDTyI1QWSBbxVYNyUgPFzKxrSmwMO0yNff7ho+QT9x5+Y/7" + System.lineSeparator() +
                "XE59S4Mc4ZXxcXKew/gSlN9U5mvT+D2BhDtkCupdfsZNCQWp27A+b/DmrFI9NqsC" + System.lineSeparator() +
                "AwEAAaOCAX0wggF5MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGG" + System.lineSeparator() +
                "MH8GCCsGAQUFBwEBBHMwcTAyBggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3Rp" + System.lineSeparator() +
                "ZC5vY3NwLmlkZW50cnVzdC5jb20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlk" + System.lineSeparator() +
                "ZW50cnVzdC5jb20vcm9vdHMvZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFOmk" + System.lineSeparator() +
                "P+6epeby1dd5YDyTpi4kjpeqMFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQB" + System.lineSeparator() +
                "gt8TAQEBMDAwLgYIKwYBBQUHAgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5j" + System.lineSeparator() +
                "cnlwdC5vcmcwPAYDVR0fBDUwMzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3Qu" + System.lineSeparator() +
                "Y29tL0RTVFJPT1RDQVgzQ1JMLmNybDAdBgNVHQ4EFgQU+3hPEvlgFYMsnxd/NBmz" + System.lineSeparator() +
                "LjbqQYkwDQYJKoZIhvcNAQELBQADggEBAKvePfYXBaAcYca2e0WwkswwJ7lLU/i3" + System.lineSeparator() +
                "GIFM8tErKThNf3gD3KdCtDZ45XomOsgdRv8oxYTvQpBGTclYRAqLsO9t/LgGxeSB" + System.lineSeparator() +
                "jzwY7Ytdwwj8lviEGtiun06sJxRvvBU+l9uTs3DKBxWKZ/YRf4+6wq/vERrShpEC" + System.lineSeparator() +
                "KuQ5+NgMcStQY7dywrsd6x1p3bkOvowbDlaRwru7QCIXTBSb8TepKqCqRzr6YREt" + System.lineSeparator() +
                "doIw2FE8MKMCGR2p+U3slhxfLTh13MuqIOvTuA145S/qf6xCkRc9I92GpjoQk87Z" + System.lineSeparator() +
                "v1uhpkgT9uwbRw0Cs5DMdxT/LgIUSfUTKU83GNrbrQNYinkJ77i6wG0=" + System.lineSeparator() +
                "-----END CERTIFICATE-----" + System.lineSeparator();

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_REQUEST_BODY, AUTHZ_RESPONSE_BODY, AUTHZ_REPLAY_NONCE)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY, UPDATED_AUTHZ_REPLAY_NONCE)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 200)
                .addCheckOrderRequestAndResponse(CHECK_ORDER_URL, CHECK_ORDER_REQUEST_BODY, CHECK_ORDER_RESPONSE_BODY, CHECK_ORDER_REPLAY_NONCE, 200)
                .addCertificateRequestAndResponse(CERT_URL, CERT_REQUEST_BODY, CERT_RESPONSE_BODY, CERT_REPLAY_NONCE,  200)
                .build();
    }

    private ClientAndServer setupTestObtainCertificateWithUnsupportedPublicKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"faxV5ndBJsE\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "yTHivfhVul8gJCCi0zflLw0NcZm2XCq3D0f2OZKL_9Y";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJpVk5xSnVoM3VvWW5xdkNfZGtYQzRFMDN4R292eTdLUjAwd3M4QUwwcHJWcktzajhnZFdhWjBLZkZ1Q0NUaUtMU1BhNVQ0ZnRWNFdia2l0djFMa0JWU29Wd1hqSDE0bFpIMWFHYkptR1lCX3pSOV9uVzZJTzRVb1RGc2Vqb3paN05kNW8waVFpQWpyRjBmMDhGVC1xYS1TVVZiVk16dkNnQW16SjJFVlhzOXdOQ2pzSVRnNGh3eDdZRzl5eHRhZjFoT0hkV1dKVWtwZ0hnQkVfclpZT1B5YVNlb2JyeE5mMllxVmhFNWM2ZjhrZUhYdnU2dnprODctZVNLWXlndk9hSW1YOUhFbFZhQXRVcnI0S3hFV3VvUDdNRzZCV0s2TDVpam9Db0VMQjBqM0w2UHNuXzM1VnMxQi05OFR6SFZqYU1sU1NGV20xQjdtS0NzNGZMeE1pRXcifSwibm9uY2UiOiJ5VEhpdmZoVnVsOGdKQ0NpMHpmbEx3ME5jWm0yWENxM0QwZjJPWktMXzlZIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"Dd24E9F3IAg_r4-YnXk18RbLsfak0scs6xAgfrx04jqowBLT6sUVDH2Gg7K4H7GOJc7mBnMvdVMAdEsEwgvRg3zyFgTdsVvCVRV56G13dCsRszwSCPReocirhTyNeL6LFVzK2xniN6yncR_FUPulCDCytDtOryeinEmOOIl0ABR-PXV0rfGMBRmyZGsFEwix6b5VMsdhXHDxbQoc5HUfKNWW0CV0i_G_3BQFRJ7lgt3JG0a1aw3ml1X1FzCNyarnFkzBQOp3RqN7ODa3TxXSVtMZu9gXyGfJ-YBSxNq83DxcocHPWbBoUZE8tug3-IH600u3FIWulA7rSn98SnUajA\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "PTG0ESBbbcEJlcyrfjCLu8YyJwYJ9lGGgD9Af97Vo4Q";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/3";


        final String ORDER_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMyIsIm5vbmNlIjoiUFRHMEVTQmJiY0VKbGN5cmZqQ0x1OFl5SndZSjlsR0dnRDlBZjk3Vm80USIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL25ldy1vcmRlciJ9\",\"payload\":\"eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaXJhY2x6bGNxZ2F5bXJjLmNvbSJ9XX0\",\"signature\":\"OJKxVKwVDKHZF7b9kf8GVUrnfWlpjhS1m2SmHJPTJc-Zpgniv2-x6ZPnNLswYSxHIndywsSLf2BmeNBzZpDiFFJOgZU9GYeSezq6XVH-arfNCkBPa73A33PoOC3Ts_2Pd2P5fuJ2WdsLVRmpIWixPFyjedRfMuv3eVWxKmmgCc1GE-g5n6cULTrdVyEayabwfpHkr7vTOMw9X_dFYuvWvkA6F1BCnoNSxxu8Vh-UWpUS_77OhCJd9QQnL5iewjweRacY9ng2UgtsyOMnnrFILuI7B9fMv3TgaFEtwQufqmAEcP6hS29yLFBfsbUV1FcpT0UDxUlLUPiTTj1BeWjtkQ\"}";

        final String ORDER_CERT_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T23:06:59.386130633Z\"," + System.lineSeparator() +
                "  \"identifiers\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns\"," + System.lineSeparator() +
                "      \"value\": \"iraclzlcqgaymrc.com\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"authorizations\": [" + System.lineSeparator() +
                "    \"http://localhost:4001/acme/authz/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"finalize\": \"http://localhost:4001/acme/finalize/3/12\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String ORDER_CERT_REPLAY_NONCE = "Xb79RAHpMC0bOQXPPQMhLepRKc2JCrI0OXoz71P7PTQ";
        final String ORDER_LOCATION = "http://localhost:4001/acme/order/3/12";

        final String AUTHZ_REPLAY_NONCE = "3y0I9NLsV-UXaNdFRsnv4mYdIzcCDXOzJIgik85XVgg";
        final String AUTHZ_URL = "/acme/authz/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE";
        final String AUTHZ_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMyIsIm5vbmNlIjoiWGI3OVJBSHBNQzBiT1FYUFBRTWhMZXBSS2MySkNySTBPWG96NzFQN1BUUSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2F1dGh6L1gzYWJyVkZIWXhPTlNZdTAxTkdGUDhzNDlMdDJyZVNtUk9VOHRKRzcxVEUifQ\",\"payload\":\"\",\"signature\":\"LpeAtFiB2hxRdMRN0QDf016QnZwj2m81Dyb2kVdpipvz7RCMkheoc7I1vkuGbM_2LlenvBHxmHhSkSHSj3lB0IVdqmg4y5d25YgwJEgVDVZdJ0nwkJBOKp1bXDOO2HJsN8do8RT3MB2NvXJVLWyvMbHIFlKpI0ZJALaAor8U6Qo_LhXcJ7tyATsydgim4s9GvMqQbOjXoaTx0X-XIbIpYbAms6D1N7xpt1zCVv6Z7hkFaxTJsG8vmzluNDoNKYIWP8vzA_bZSoQ4yLa_t_TPVzTQ8yKBLCRDeUkJmDaB8qwd1Ykc6tRwiHGID6GE3q1z-H1fSw0na8PbXunem1uZ7g\"}";
        final String AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"iraclzlcqgaymrc.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"expires\": \"2018-11-30T23:06:59Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/33\"," + System.lineSeparator() +
                "      \"token\": \"iE2BAsOSYCgCALb-0nx1M2UDmXBkMhv07ssGmUK4kak\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/34\"," + System.lineSeparator() +
                "      \"token\": \"1rcnRMNMzxxH1AHQvEcc2tVZw9QDHRBeU3v2euASMDo\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/35\"," + System.lineSeparator() +
                "      \"token\": \"pDWP9Ja1fNgl-GPThTK7UN90ZXt5F1jwY2mG1WjK3I0\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/36\"," + System.lineSeparator() +
                "      \"token\": \"BbXZvuNCX3sbW_MQd-4vvLZzd6llkKP8tG-YNqcVBbA\"" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMyIsIm5vbmNlIjoiM3kwSTlOTHNWLVVYYU5kRlJzbnY0bVlkSXpjQ0RYT3pKSWdpazg1WFZnZyIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2NoYWxsZW5nZS9YM2FiclZGSFl4T05TWXUwMU5HRlA4czQ5THQycmVTbVJPVTh0Skc3MVRFLzM2In0\",\"payload\":\"e30\",\"signature\":\"VMZBhgSpGBVvs1rp2ZVCoga1WdbngKBJQ3DjjYak532XZvoGrVPFCIj30s-ZJeowy0gZPxHO3CT1AqhXg85jdtStmd58yveMpgOzLVeyqUtevKL9QSLY_FBj2SEUWQa_CbzNBPI2nKsAVxJQm_guZBcmFVGfadNhi3owP0w_PSagVpYzqU8F2EtJIi4EPKrG5f3o1I8lxXNY80Fc0e3JJpZ-dMxT667VI168XtH_CB47q8T9fMO1VCFBe9Kx-GXH5xc8hkX_S04ThLb52sGHpoFolWaQTvE-91BM1K-tjTXppspDnNzlC-obOi40M34BstdIYx3IOEMC56j3jVUV-A\"}";
        final String CHALLENGE_URL = "/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/36";

        final String CHALLENGE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"http-01\"," + System.lineSeparator() +
                "  \"status\": \"pending\"," + System.lineSeparator() +
                "  \"url\": \"http://localhost:4001/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/36\"," + System.lineSeparator() +
                "  \"token\": \"BbXZvuNCX3sbW_MQd-4vvLZzd6llkKP8tG-YNqcVBbA\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String CHALLENGE_REPLAY_NONCE = "mQo66pQBT1bIF2vKKEdGcgL0GecJGPk8HWNB8NduV3o";
        final String CHALLENGE_LOCATION = "http://localhost:4001/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/36";
        final String CHALLENGE_LINK = "<http://localhost:4001/acme/authz/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE>;rel=\"up\"";
        final String VERIFY_CHALLENGE_URL = "/.well-known/acme-challenge/BbXZvuNCX3sbW_MQd-4vvLZzd6llkKP8tG-YNqcVBbA";
        final String CHALLENGE_FILE_CONTENTS = "BbXZvuNCX3sbW_MQd-4vvLZzd6llkKP8tG-YNqcVBbA.952Xm_XyluK_IpyAn6NKkgOGuXbeWn8qoo0Bs9I8mFg";

        final String UPDATED_AUTHZ_REPLAY_NONCE = "uP6PqDT0I_vf0OMVncdp-T1zmxxzVhskIrg4Nz191B4";
        final String UPDATED_AUTHZ_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"identifier\": {" + System.lineSeparator() +
                "    \"type\": \"dns\"," + System.lineSeparator() +
                "    \"value\": \"iraclzlcqgaymrc.com\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"status\": \"valid\"," + System.lineSeparator() +
                "  \"expires\": \"2018-12-23T23:06:59Z\"," + System.lineSeparator() +
                "  \"challenges\": [" + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-alpn-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/33\"," + System.lineSeparator() +
                "      \"token\": \"iE2BAsOSYCgCALb-0nx1M2UDmXBkMhv07ssGmUK4kak\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"tls-sni-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/34\"," + System.lineSeparator() +
                "      \"token\": \"1rcnRMNMzxxH1AHQvEcc2tVZw9QDHRBeU3v2euASMDo\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"dns-01\"," + System.lineSeparator() +
                "      \"status\": \"pending\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/35\"," + System.lineSeparator() +
                "      \"token\": \"pDWP9Ja1fNgl-GPThTK7UN90ZXt5F1jwY2mG1WjK3I0\"" + System.lineSeparator() +
                "    }," + System.lineSeparator() +
                "    {" + System.lineSeparator() +
                "      \"type\": \"http-01\"," + System.lineSeparator() +
                "      \"status\": \"valid\"," + System.lineSeparator() +
                "      \"url\": \"http://localhost:4001/acme/challenge/X3abrVFHYxONSYu01NGFP8s49Lt2reSmROU8tJG71TE/36\"," + System.lineSeparator() +
                "      \"token\": \"BbXZvuNCX3sbW_MQd-4vvLZzd6llkKP8tG-YNqcVBbA\"," + System.lineSeparator() +
                "      \"validationRecord\": [" + System.lineSeparator() +
                "        {" + System.lineSeparator() +
                "          \"url\": \"http://172.17.0.1:5002/.well-known/acme-challenge/BbXZvuNCX3sbW_MQd-4vvLZzd6llkKP8tG-YNqcVBbA\"," + System.lineSeparator() +
                "          \"hostname\": \"iraclzlcqgaymrc.com\"," + System.lineSeparator() +
                "          \"port\": \"5002\"," + System.lineSeparator() +
                "          \"addressesResolved\": [" + System.lineSeparator() +
                "            \"172.17.0.1\"" + System.lineSeparator() +
                "          ]," + System.lineSeparator() +
                "          \"addressUsed\": \"172.17.0.1\"" + System.lineSeparator() +
                "        }" + System.lineSeparator() +
                "      ]" + System.lineSeparator() +
                "    }" + System.lineSeparator() +
                "  ]" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_URL = "/acme/finalize/3/12";

        final String FINALIZE_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"type\": \"urn:ietf:params:acme:error:malformed\"," + System.lineSeparator() +
                "  \"detail\": \"Error finalizing order :: invalid public key in CSR: unknown key type *dsa.PublicKey\"," + System.lineSeparator() +
                "  \"status\": 400" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String FINALIZE_REPLAY_NONCE = "l2LQJWlhk9_JtZNqJ2kfS6X4_9lCQY3KAwiWxIRpp94";
        final String FINALIZE_LOCATION = "";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .orderCertificateRequestAndResponse(ORDER_CERT_REQUEST_BODY, ORDER_CERT_RESPONSE_BODY, ORDER_CERT_REPLAY_NONCE, ORDER_LOCATION, 201, false)
                .addAuthorizationResponseBody(AUTHZ_URL, AUTHZ_REQUEST_BODY, AUTHZ_RESPONSE_BODY, AUTHZ_REPLAY_NONCE)
                .addChallengeRequestAndResponse(CHALLENGE_REQUEST_BODY, CHALLENGE_URL, CHALLENGE_RESPONSE_BODY, CHALLENGE_REPLAY_NONCE, CHALLENGE_LOCATION, CHALLENGE_LINK, 200, false, VERIFY_CHALLENGE_URL, CHALLENGE_FILE_CONTENTS, AUTHZ_URL, UPDATED_AUTHZ_RESPONSE_BODY, UPDATED_AUTHZ_REPLAY_NONCE)
                .addFinalizeRequestAndResponse(FINALIZE_RESPONSE_BODY, FINALIZE_REPLAY_NONCE, FINALIZE_URL, FINALIZE_LOCATION, 400, true)
                .build();
    }

    private ClientAndServer setupTestRevokeCertificate() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"," + System.lineSeparator() +
                "  \"yNEulSQUUIA\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "R_4ZVLQ2G3kNzArEuHmve0UvjR1XSxp8B2g6mOBCskE";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJwdUwtV2NNWVVKMkFqZHkxVXNVZ056am42ZWNEeGlXZDdOR1VHcTI2N1NPTHdoS2pTV1dNd2tvcGZjZzVWTWpQSldFRTM4SUlYeWpXNW5GS0NxRkFJZjNabGloXzFTTGNqZ1ZGYmlibi1vTUdGTFpzOWdncjJialJHSnNic0pRSU9LbWdWczJ5M2w1UmNJeUYyTS1VT3g0R3RBVVFKc1lpdHRjaEJMeHFqczBTQmpXZHRwV3phWDRmd1RDeng0OFJYdVpoa3lfbUtBeUtiaEFZbklHZERoY1ZJWnNmZjZ6ekVNMWJwSkVENk9CWmg2cHlQLU4wa094Y0dtUFBDSE1mME16d2puSzhWckZQRWFJSWZRQWJVQzFyVGF1aXFaWDdnbEVuTjJrWXFPd2w4ZzNuZjVmYlg2c1V1RFUxNWZWMGNtZFV0aHk4X0dIeUUycWR6alBSTHcifSwibm9uY2UiOiJSXzRaVkxRMkcza056QXJFdUhtdmUwVXZqUjFYU3hwOEIyZzZtT0JDc2tFIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"N_86Lf5tGJOHfdAcQWnmO-ha-8Ulu7yHIJWrP2CN3eSpEc2BgjRP00U-SiwJ0vNv0RftbtK-REXSAwRVvsPOULruZPG_3Dd9GUYpYvvVhklXa3d9o0-X-Bg-xJe6QfNeLmcS5KQ9CFEkO_EvOFeE9BgLnDmEpx-1VsJSKwVkyQXl2CZFqap_wsPH1UKnwbWyP6tAnCHh8p6_n8_oqoLeilal0KT3hAPmCj2qT3PF4ABRJVk3gUY-MqLtawPl0VJ9gOUvbp5PKmi31LHAzKU6105Y9O5vccPkL6AJCskbJdoos8VkV_fk_Ip4kyPcM-q9PAx2P5uq9fg-_SufSaE-8g\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "n13g7hLxpXHWocmPsq_Qx-i5nvJF1OzSqPQ7naadMZw";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/384";

        final String REVOKE_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzg0Iiwibm9uY2UiOiJuMTNnN2hMeHBYSFdvY21Qc3FfUXgtaTVudkpGMU96U3FQUTduYWFkTVp3IiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvcmV2b2tlLWNlcnQifQ\",\"payload\":\"eyJjZXJ0aWZpY2F0ZSI6Ik1JSUZaekNDQkUtZ0F3SUJBZ0lUQVAtWWVJSDJiVjRkWDZhMXVOb3JxNk5PWVRBTkJna3Foa2lHOXcwQkFRc0ZBREFmTVIwd0d3WURWUVFEREJSb01uQndlU0JvTW1OclpYSWdabUZyWlNCRFFUQWVGdzB4T0RBME16QXhPREEyTkRCYUZ3MHhPREEzTWpreE9EQTJOREJhTUI0eEhEQWFCZ05WQkFNVEUydHNhV3Q2Wld0dGJHcDFkM2hyYlM1amIyMHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDWlhuRVBXRXlYRDl0RUpyejB5T3hpNTRuNWR0RTBsOEJzRkt2OGk0bXJmdlMtYXhiaF9OUzdMb3Y0anN5Zy0tLVN6am9xQ3pJbkY4OExQVWxGanFPVlVwYkdhWjM1MWlYN1FkN216bXBsdkFSY2RhdnZXVXRrdjRXN2ZQOGF0N3VsODJaanBmc0VrS2pGcXJ1czZkZFNfQkxXeGNxblhoS3NrdUstZ3MzZ2F3SjFuTU93b01VeGJpYm5EamdpQ1JIVm9wRm5WS0NhMUttWG42MkFBTmUySnNSQTZySlJFZFE0TnE4MVRBZFpieGwyTXdjVnFUY1pYX1BBTVB5RlBCM1EtS0o0VlhPR3R2SVNTb2J1cThUaHFvWXJzeGJ6dXcwMnZYdnd4RzZPaUs3UlFobm9wOHNpdWNIZ0RsaUVlQ25BYWNkZFdRalBieTh0ajBEZzlOTTNBZ01CQUFHamdnS2JNSUlDbHpBT0JnTlZIUThCQWY4RUJBTUNCYUF3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01Bd0dBMVVkRXdFQl93UUNNQUF3SFFZRFZSME9CQllFRk5xM0VGWmk3dDhYT1Z0aUw4YjBjRGJ3a2szWU1COEdBMVVkSXdRWU1CYUFGUHQ0VHhMNVlCV0RMSjhYZnpRWnN5NDI2a0dKTUdRR0NDc0dBUVVGQndFQkJGZ3dWakFpQmdnckJnRUZCUWN3QVlZV2FIUjBjRG92THpFeU55NHdMakF1TVRvME1EQXlMekF3QmdnckJnRUZCUWN3QW9Za2FIUjBjRG92TDJKdmRXeGtaWEk2TkRRek1DOWhZMjFsTDJsemMzVmxjaTFqWlhKME1CNEdBMVVkRVFRWE1CV0NFMnRzYVd0NlpXdHRiR3AxZDNocmJTNWpiMjB3SndZRFZSMGZCQ0F3SGpBY29CcWdHSVlXYUhSMGNEb3ZMMlY0WVcxd2JHVXVZMjl0TDJOeWJEQmhCZ05WSFNBRVdqQllNQWdHQm1lQkRBRUNBVEJNQmdNcUF3UXdSVEFpQmdnckJnRUZCUWNDQVJZV2FIUjBjRG92TDJWNFlXMXdiR1V1WTI5dEwyTndjekFmQmdnckJnRUZCUWNDQWpBVERCRkVieUJYYUdGMElGUm9iM1VnVjJsc2REQ0NBUVFHQ2lzR0FRUUIxbmtDQkFJRWdmVUVnZklBOEFCM0FCYm9hY0hSbGVyWHdfaVhHdVB3ZGdIM2pPRzJuVEdvVWhpMmczOHhxQlVJQUFBQll4ZnpJLVVBQUFRREFFZ3dSZ0loQUlIMEtzUEJjdTBWSUZuSWswdHc0QVZwbW9vMl9jT2ZyRzdDLXN6OGZNMFRBaUVBa3NKbXF4cXlUWGFXZDc5dVNKQlNBTWJWNGpmdHVqbktCY2RhT1JCWFZMWUFkUURkbVRUOHBlY2tnTWxXYUgyQk5Ka0lTYkpKOTdWcDJNZThxejljd2ZOdVpBQUFBV01YOHlQbEFBQUVBd0JHTUVRQ0lGS2paSFc1YkhTZnF1ZXo4TXlWXzhsRVU4TzExQWczVWVyMEFraVVfT255QWlBSkQ2a3FsbVhfVnhOTi1MZ3o1TEJFalFvc2hReURfMFhOOXdDM2FMMFozREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBWndQMGMyTjdReTJBV3R2cDRtd25zZ2pWMmMyY3IzMFJCTTRNNkZCblM5QlEwSU13LWRMT3BhcVAxNEM0N1BYa2M4ZmVyRmZZTFVsWW9NWkFIMHlscUFUemFxd3dnZ0V4ZmF3UlhKM2s4Z1BZWHFuSXdtdDFMNkpNZ0RuZjd6MlJxci1sTlZJNUg4REFpbnFDSjJLRmdtVHh2U1JudHdkYkh2X1J6TUFJRWhTOVp2SnpQOHRRWHBjclRHeWxha0VqWndnV1lOQWs4WTdRcnhfMWhoM0E2YWpXWWNhb1FUTzJVOS1pMThaNnB2TzFwRlZSZEo0ZUozamJrVzR0UUNJVDkxeGtsWFlfT1gyZF9qc0Z3TzFBaTNEV19Eb1ViMGtPUmFaMkswZjZJZF9BczREOU5USDVXSDdEX2FrMm42T2l2V2dpTHBqZ0pxRUgzNWtPN0hWdGNnIn0\",\"signature\":\"U6822aPK85QdIwsJH6ekvg-LkmvjBlLmJmk8OViNYr79GNTbu3LBO-x9p2_R3deKotShjYE3WpcmzqcW9xpHg-FRSWgcIFczS_0EAX9d-OhI4LFzQroHyTXcEev0OruiMq_4tZrGjy1CFFfdaaXyRbpDqnP4vC_Tq2KyUHhV6LbhHhg11qaQjov3z-0jMM6eKGybmne6yDrE2lG6uKZscWzYqwGi5gkQ_iBHCb_qzYYphYs8IZLPTt6T8PAIDmRpsRCHXzgDCk0QVhj-Gl7y2H2xEn_BknKT-oPa33zSICovn5cR6utf788FRz9oh8t7tIpOAvVStwVSrb6BV6WOUQ\"}";
        final String REVOKE_CERT_REPLAY_NONCE = "poBc-xx1Oxnprg_hgWFZI_0Ji-4qgEpAnGrAdxEP6sU";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .addRevokeCertificateRequestAndResponse(REVOKE_CERT_REQUEST_BODY, REVOKE_CERT_REPLAY_NONCE, 200)
                .build();
    }

    private ClientAndServer setupTestRevokeCertificateWithReason() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"FpVd7yM-nVU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "-mlJhcox_6FFuDwNhcmL06FWD6uL7K7lam9Jel-MqqM";

        final String QUERY_ACCT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJwdUwtV2NNWVVKMkFqZHkxVXNVZ056am42ZWNEeGlXZDdOR1VHcTI2N1NPTHdoS2pTV1dNd2tvcGZjZzVWTWpQSldFRTM4SUlYeWpXNW5GS0NxRkFJZjNabGloXzFTTGNqZ1ZGYmlibi1vTUdGTFpzOWdncjJialJHSnNic0pRSU9LbWdWczJ5M2w1UmNJeUYyTS1VT3g0R3RBVVFKc1lpdHRjaEJMeHFqczBTQmpXZHRwV3phWDRmd1RDeng0OFJYdVpoa3lfbUtBeUtiaEFZbklHZERoY1ZJWnNmZjZ6ekVNMWJwSkVENk9CWmg2cHlQLU4wa094Y0dtUFBDSE1mME16d2puSzhWckZQRWFJSWZRQWJVQzFyVGF1aXFaWDdnbEVuTjJrWXFPd2w4ZzNuZjVmYlg2c1V1RFUxNWZWMGNtZFV0aHk4X0dIeUUycWR6alBSTHcifSwibm9uY2UiOiItbWxKaGNveF82RkZ1RHdOaGNtTDA2RldENnVMN0s3bGFtOUplbC1NcXFNIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"lztzTXBmbrxXGMspfEetHDGKdZ2NrpQTioysqHIa9aaL5dy8bPmKZ_Vmz68-xnUJcjK-5FMCn5vtYEKAJlJ7W3wVYzthcVuYlv-b6FNw3IYsdSSHMr5RLm0rSt9EwYd-BI4bCoT7dioYpCMHzTrd-3X8QjDS4fx1o6D-po_Hwkt4PWx5Yoo9ExlykM5cHOQlCQENPk3Pn0M4_8XkfH1QTvVTIm4A4lbo_Eko1aU9PgvWbNsqkEhRzH7rBb5FUlxFgRoSHuTJwn6uJL-H0cfYQUn-J5JyD5C-P8su3M7NoAXCj0vy_84TziHMxe1C8fI-A64M6CtlL9qGm5MwPgv8Gg\"}";

        final String QUERY_ACCT_RESPONSE_BODY= "";

        final String QUERY_ACCT_REPLAY_NONCE = "zbQR7CL_GSx0oydZ0AVoNEh7omY_XONdWFpYOfeFVQc";
        final String ACCT_LOCATION = "http://localhost:4001/acme/acct/384";

        final String REVOKE_CERT_REQUEST_BODY = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvMzg0Iiwibm9uY2UiOiJ6YlFSN0NMX0dTeDBveWRaMEFWb05FaDdvbVlfWE9OZFdGcFlPZmVGVlFjIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvcmV2b2tlLWNlcnQifQ\",\"payload\":\"eyJjZXJ0aWZpY2F0ZSI6Ik1JSUZaekNDQkUtZ0F3SUJBZ0lUQVBfNDBNVEh3LWw1M3lpOWVOMnptclFkX1RBTkJna3Foa2lHOXcwQkFRc0ZBREFmTVIwd0d3WURWUVFEREJSb01uQndlU0JvTW1OclpYSWdabUZyWlNCRFFUQWVGdzB4T0RBME16QXhPRFF4TURoYUZ3MHhPREEzTWpreE9EUXhNRGhhTUI0eEhEQWFCZ05WQkFNVEUyaHRlSFJ1ZFd0c2JHaDRlR3hpYUM1amIyMHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDWUpyX3BaQkNTeV9LZHdLd1c0TDdyNnhWYVB1R0dna1JKY3lnTE5EWUhNd2JObm9zM3FnckpEMk0tRW5HOWlrSmlIRzd5VUtfVHRGNWZrVFA3UEROUzNlallkVTl1RTFHeTM1VTcyVGVzbVpzSC1aNy11NHJsc1JxdzVXcURDUjBGeW1PR0xuUEpVa3hGN29PRlFHc1lwZ3h3T1JVV0g5TlBEUzZTT3RTWF9XbUJ0S015VGM5QW9GRjBlRHM3NlBmOWl5eXZONjh4ejF6Y3g5aENnbDB5ZVNXTFhUNHV1SUJibHIxNXZhdzdCVVFNMnBGdE9aNGFIcWRiTDUtQ05TOWVxNUk2WTRpMW1yQVBEWklkN2xMOHAxY2tQLXI0dlh0a0VVdmxEaXFNMzdiRlB3enZDMWVVeGtOanNTdnQ0OGh4TTBtMU82cHZhTVB2Qm1CWGxHOUZBZ01CQUFHamdnS2JNSUlDbHpBT0JnTlZIUThCQWY4RUJBTUNCYUF3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdFR0NDc0dBUVVGQndNQ01Bd0dBMVVkRXdFQl93UUNNQUF3SFFZRFZSME9CQllFRkl3VXBFcGpUbmhUTl9XN3JlckkwT3V2alVMck1COEdBMVVkSXdRWU1CYUFGUHQ0VHhMNVlCV0RMSjhYZnpRWnN5NDI2a0dKTUdRR0NDc0dBUVVGQndFQkJGZ3dWakFpQmdnckJnRUZCUWN3QVlZV2FIUjBjRG92THpFeU55NHdMakF1TVRvME1EQXlMekF3QmdnckJnRUZCUWN3QW9Za2FIUjBjRG92TDJKdmRXeGtaWEk2TkRRek1DOWhZMjFsTDJsemMzVmxjaTFqWlhKME1CNEdBMVVkRVFRWE1CV0NFMmh0ZUhSdWRXdHNiR2g0ZUd4aWFDNWpiMjB3SndZRFZSMGZCQ0F3SGpBY29CcWdHSVlXYUhSMGNEb3ZMMlY0WVcxd2JHVXVZMjl0TDJOeWJEQmhCZ05WSFNBRVdqQllNQWdHQm1lQkRBRUNBVEJNQmdNcUF3UXdSVEFpQmdnckJnRUZCUWNDQVJZV2FIUjBjRG92TDJWNFlXMXdiR1V1WTI5dEwyTndjekFmQmdnckJnRUZCUWNDQWpBVERCRkVieUJYYUdGMElGUm9iM1VnVjJsc2REQ0NBUVFHQ2lzR0FRUUIxbmtDQkFJRWdmVUVnZklBOEFCMUFOMlpOUHlsNXlTQXlWWm9mWUUwbVFoSnNrbjN0V25ZeDd5clAxekI4MjVrQUFBQll4Z1NzYVFBQUFRREFFWXdSQUlnTUFGb19yNFl0aWNfc1lpVmxpaE10ZGZSZDFnclNYSUl1U2pwQzNZT1NOZ0NJRzdMWTlkMGl2cVV2czJ3Y0Z1Q0tNZkFsdDFNWTNvcjR6cGJlelFsNWpvREFIY0FGdWhwd2RHVjZ0ZkQtSmNhNF9CMkFmZU00YmFkTWFoU0dMYURmekdvRlFnQUFBRmpHQkt4cFFBQUJBTUFTREJHQWlFQTRYSmZVd3JVbkxWUGxRbF9IVVFxakRUVkFRdDJIN29BdXNrWUhiT3EtYTRDSVFEcGZwa3pNbkxudlNxay02QU5ZRWRKb0p5Q0M3M1ZwdHo0WG1MVnJMNHNtekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBc1VEMUJ6M2NWQzA4NXF4a2VkYzJqd3FUSEk0UF9OaERrQVFmSGhrQ0VlaFoyVTVmRE1YWXFwZDh0UUluZUdoZU1ZTkQ4OWRFQXYyXzI5SXNGXzhKNC1uSURrLU1XQkFsQm43VUtES2xDbEdza0RDenJPajF6clJwOUtscTNLaElFSkUzT01nTGIyM3pNbERLeWRIcXA5OGtTc25hQmFoS1VlV3l1WXcxdmNwemZ3TjE0UG9xMW1jRnJWUFAxcWRBNG1NMTVFVHgyV0tZdTFWaWIySVVESmx2STNYbUg5SFR5ODZYRTRMNXFTd20xalJFbzZ5a3FDTmhSMHJMeHhHeXhDRldWVXVLNG9SaFR3YmF0VzEzR3JvSlhGdGNQeVVuRGJkSU9iRzIwLV9DME9ZMk9Rc1pWQTNWTC1IQ2c3ckt6QnZOSTNlaVkzVVNMYVBMM1I0dWhnIiwicmVhc29uIjoxMH0\",\"signature\":\"eP8PR2UEdU-HW7hM0XyeDWuPADRh_XKwmNM8QmowJzn4WLYkp-pHbnpGnID0aRTAjFQsvvPmkWIrNN9TMCgwfr5EqP7xoU1uGS3J6uNydZI4TyjGZaJ9v1I9sqb5Zw_Q5cht-vSMnxznmuEu3K_6jrDLq9x-U22sNFyA_aoqu5odPNJl_l2D2ZHaPbO19NjOfc2-mgBKR4y850oEzz8vKsFcPjtASFMoC3Ulyc2kDHuUeH9HL3W4DqvD0ygVhcbh5R9NRzwefj1h2YSD_8QJj20DprPSReJ_LxZTZzy3-oB3WWibLUaVS6xr0ZbMCPQSp_rTSRWpekWoM7vm_XwdCQ\"}";
        final String REVOKE_CERT_REPLAY_NONCE = "q4qaFhcWgftkiRaaeEZskz_fp9ue2OJGRDW3mYBGCNk";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY, QUERY_ACCT_RESPONSE_BODY, QUERY_ACCT_REPLAY_NONCE, ACCT_LOCATION, 200)
                .addRevokeCertificateRequestAndResponse(REVOKE_CERT_REQUEST_BODY, REVOKE_CERT_REPLAY_NONCE, 200)
                .build();
    }

    private ClientAndServer setupTestChangeAccountKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"DSKtJkFv-s0\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE = "jeV3SxyaRXYWQhLYAFFScyTJSO1FZGPDAnF-1r05QKc";

        final String QUERY_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJoNWlULUY4UzZMczJLZlRMNUZpNV9hRzhpdWNZTl9yajJVXy16ck8yckpxczg2WHVHQnY1SDdMZm9vOWxqM3lsaXlxNVQ2ejdkY3RZOW1rZUZXUEIxaEk0Rjg3em16azFWR05PcnM5TV9KcDlPSVc4QVllNDFsMHBvWVpNQTllQkE0ZnV6YmZDTUdONTdXRjBfMjhRRmJuWTVXblhXR3VPa0N6QS04Uk5IQlRxX3Q1a1BWRV9jNFFVemRJcVoyZG54el9FZ05jdU1hMXVHZEs3YmNybEZIdmNrWjNxMkpsT0NEckxEdEJpYW96ZnlLR0lRUlpheGRYSlE2cl9tZVdHOWhmZUJuMTZKcG5nLTU4TFd6X0VIUVFtLTN1bl85UVl4d2pIY2RDdVBUQ1RXNEFwcFdnZ1FWdE00ZTd6U1ZzMkZYczdpaVZKVzhnMUF1dFFINU53Z1EifSwibm9uY2UiOiJqZVYzU3h5YVJYWVdRaExZQUZGU2N5VEpTTzFGWkdQREFuRi0xcjA1UUtjIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"MZoKMFgb8svDNGhj89bme7AfxPjY-V95X_wtOfFCnSc3VQn07oVbFrfTS7NKOMuY_NcFejshDmqZJ-j-rpjlHShLVM5v4T0H1mkpbv_QGXf3bPKLA37KvlMMZUmnKgKJsqQLAt80wxQIvz3hJAihLFlm0KyyZ8xH8bwcdveK7S4cC875zU11UVg56dYKjjDkZAgD1boZVRgZSSn4lCYvSG0quTby3-s2MV6Pu6-PxaS_BlVbwSee-QUKvDj3Hrtvlb5vryH-rKML4hTSpz8dfS99qS8bgMtBRoBT7C6HgnwIndRkg2Dnd8XXGVsNgLUvXN0kSRlsh_EShds0Wl8Q_A\"}";

        final String QUERY_ACCT_RESPONSE_BODY_1 = "";

        final String QUERY_ACCT_REPLAY_NONCE_1 = "oHbba7Qw6BsBKUPDFp00PAP8jhHobchQPy7CAxaic9k";

        final String ACCT_PATH = "/acme/acct/2";
        final String ACCT_LOCATION = "http://localhost:4001" + ACCT_PATH;

        final String CHANGE_KEY_RESPONSE_BODY = "{" + System.lineSeparator() +
                "  \"id\": 2," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"mY95Jb8jON6IUOQns2GNRzdurkFqu3mCibXvjhY20rq9DVY45viorB4VuBS8sZ0VN1bmRC37CmuF_qLd0jQi5sMoBDj_Gzep8espmLTstvBwYqfyiPdVbyYFy1ikf-Q6A3vlRxK657pfW4cuJ9cgzCeZwj4LZpvMucHePMKlLhVG3g9uQqk5Ovq58OxTna-KyJT-5CcZ2oFoh-pWZf7jpMDgtJcmQHVdoP6zjnDxb2NIYtMsfptFOgLF5ixSXqnaZ_fZVFgEQp8Y1KYe6wrVEORlSQlvMzV-bx0kOxApUIISfMibqZsOWDSkIYIL7JfsApGJjpazjoX2et-NVZ4GRw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@myexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"agreement\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-23T22:17:00Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE = "iVwokbrHWFM6frqDaW0dtI4EcYlhvrY3TL4zIPsk_NA";

        final String QUERY_ACCT_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"id\": 2," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"mY95Jb8jON6IUOQns2GNRzdurkFqu3mCibXvjhY20rq9DVY45viorB4VuBS8sZ0VN1bmRC37CmuF_qLd0jQi5sMoBDj_Gzep8espmLTstvBwYqfyiPdVbyYFy1ikf-Q6A3vlRxK657pfW4cuJ9cgzCeZwj4LZpvMucHePMKlLhVG3g9uQqk5Ovq58OxTna-KyJT-5CcZ2oFoh-pWZf7jpMDgtJcmQHVdoP6zjnDxb2NIYtMsfptFOgLF5ixSXqnaZ_fZVFgEQp8Y1KYe6wrVEORlSQlvMzV-bx0kOxApUIISfMibqZsOWDSkIYIL7JfsApGJjpazjoX2et-NVZ4GRw\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@myexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-23T22:17:00Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE_2 = "0By1YoNhtJlVbmwH-N80RwlWVUIXpD3dS-j9Y1GnX9Y";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY)
                .addNewNonceResponse(NEW_NONCE_RESPONSE)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_1, QUERY_ACCT_RESPONSE_BODY_1, QUERY_ACCT_REPLAY_NONCE_1, ACCT_LOCATION, 200)
                .addChangeKeyRequestAndResponse("", CHANGE_KEY_RESPONSE_BODY, CHANGE_KEY_REPLAY_NONCE, 200)
                .updateAccountRequestAndResponse("", QUERY_ACCT_RESPONSE_BODY_2, QUERY_ACCT_REPLAY_NONCE_2, ACCT_PATH, 200)
                .build();
    }

    private ClientAndServer setupTestChangeAccountKeySpecifyCertificateAndPrivateKey() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY_1 = "{" + System.lineSeparator() +
                "  \"LSx0inDH8oU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE_1 = "Iq5ow6qZJI9AwCofhfDC6Ny-Z01sDpTx9-z158BTn4Q";

        final String QUERY_ACCT_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxYVFHM05QZ3RBLVdsaDdWR1hTcXh4MlZkNEFYVXdqdHprVTF6blBjcGtwMUZ3aGhVajh0dm9sSnVmdmpIUUNNWXV3eERvRFY4RWoyb0E4Tld6YlJaRzd5ZW1YbmozcVUyNmY3c2N3dWN2WFo1MDY3d0lZQVhvY3NOV0Y2RzJvVXdyc1lpc1NVVU1fWmVoUHVrX0twOHU0WmRnVVN6ZDY0eUp4Tno0ZHR3Skh6MUx2ZFpiYW1FNnZVeWhPbHNOd3hrdlR5YWdWX3lQeVdCMnJ0NVdzcTVTeXNCanNsM09fOVRySVdpeXcyeVA0UC1Od2dDVjFxRVBqZmNvQTJJbkY4SHQ0MlIyY25CakNlNVVlMHlJWkFLbTVEWU15QmUtVFBJeDlhbUVjUXppMHZrNGc4bG1STWRmNC1HLURKSVFpU1dnQ2ZraGdGS1M3amRqY3d5ZXI4cXcifSwibm9uY2UiOiJJcTVvdzZxWkpJOUF3Q29maGZEQzZOeS1aMDFzRHBUeDktejE1OEJUbjRRIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"FEO8V6ljSOsHpSCEo7t44mA-EYLj-ZzCNB0LUJzQoB6-34SodGWFrFyP9MYYJoqcdtixccnaP-_3Jgt4-fRhaZHyslvckRCqaZPY1KYYtmk890qUukQtPwvW1wUNEqr6jmXpkX_IKXSt6aY2QjfYXKmqGkex9JPMqLaqzD1seg2ZAd0KCaM-LYN5vIJYySEBtxS6RseE6e8-CkUAX4D7c7gJ2xFhVEBPbFniryBapi4s-WQRakeNSF9mzThBaVPBLWX9TXoEdJC9BswHThS4w5sYa4B0NLMNyhOpLxapN-02D5uHIKaOrrQPO2smTm9cb_YHGQVgT_YyH9LWWlST0w\"}";

        final String QUERY_ACCT_RESPONSE_BODY_1 = "";

        final String QUERY_ACCT_REPLAY_NONCE_1 = "k30WeqGdhxkrKVQOoLNl1obwrdzf_cNyFCOlsPu227Y";

        final String ACCT_PATH = "/acme/acct/5";
        final String ACCT_LOCATION = "http://localhost:4001" + ACCT_PATH;

        final String CHANGE_KEY_REQUEST_BODY_1 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNSIsIm5vbmNlIjoiazMwV2VxR2RoeGtyS1ZRT29MTmwxb2J3cmR6Zl9jTnlGQ09sc1B1MjI3WSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2tleS1jaGFuZ2UifQ\",\"payload\":\"eyJwcm90ZWN0ZWQiOiJleUpoYkdjaU9pSlNVekkxTmlJc0ltcDNheUk2ZXlKbElqb2lRVkZCUWlJc0ltdDBlU0k2SWxKVFFTSXNJbTRpT2lKdE1WVlRjSGRITkRKRGRFcEVUVk5GU2xCWVJHcFNPVU5mWDFWeVZsTk9hek00YVdGRVpXRnNVRVpYZHpOcVVHOUdNWGRJY2pBdFFUVkJlamRFYW10eFZsaFlVa2hLTW5VMk1tRnJSVVo0ZVVwUmEyTlRRakZHUjIwd05pMXRRMXBITURjNWNVRjVSbU5IYjB3NWNFMTBaV2s1UmxwcmIwbFJRVEpNUlV4WVNUSlBaVWhWVEhKdFZ5MWZNRUZPVUVZM2VIaDBZakUyV0RKa1N6VkdaMGwwYlVNNWMwbGpRMEp3VFd0aGNuRXlRMDFsU2paVWJUWmZMVXRNY2pWWWVWZGxVM0YzUjJKNFl6WlFOalpOY210M05EWmpiR1ptYW5rME5WazNUQzFSWjA1bmVWTjVkRTFITTFSNFdIUm1hMnhtTmpZNVdGcERVbVZxUjJabVUzZE1aVUkzVFd0NlNtUlZORFphZWtGb1JsUjRSbVpTY205cVYwOHlNakl4VDBOZlZXMUVUaloxZGpoTE1VRm5kbGhWT1dFNWMyVXlVRVpXTUcxZlJrRkpTR2N5U21RMFYwOVVOelppWkU5bVNXNXhkbmxtU0ZFaWZTd2lkWEpzSWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvME1EQXhMMkZqYldVdmEyVjVMV05vWVc1blpTSjkiLCJwYXlsb2FkIjoiZXlKaFkyTnZkVzUwSWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvME1EQXhMMkZqYldVdllXTmpkQzgxSWl3aWIyeGtTMlY1SWpwN0ltVWlPaUpCVVVGQ0lpd2lhM1I1SWpvaVVsTkJJaXdpYmlJNklqRmhVVWN6VGxCbmRFRXRWMnhvTjFaSFdGTnhlSGd5Vm1RMFFWaFZkMnAwZW10Vk1YcHVVR053YTNBeFJuZG9hRlZxT0hSMmIyeEtkV1oyYWtoUlEwMVpkWGQ0Ukc5RVZqaEZhakp2UVRoT1YzcGlVbHBITjNsbGJWaHVhak54VlRJMlpqZHpZM2QxWTNaWVdqVXdOamQzU1ZsQldHOWpjMDVYUmpaSE1tOVZkM0p6V1dselUxVlZUVjlhWldoUWRXdGZTM0E0ZFRSYVpHZFZVM3BrTmpSNVNuaE9lalJrZEhkS1NIb3hUSFprV21KaGJVVTJkbFY1YUU5c2MwNTNlR3QyVkhsaFoxWmZlVkI1VjBJeWNuUTFWM054TlZONWMwSnFjMnd6VDE4NVZISkpWMmw1ZHpKNVVEUlFMVTUzWjBOV01YRkZVR3BtWTI5Qk1rbHVSamhJZERReVVqSmpia0pxUTJVMVZXVXdlVWxhUVV0dE5VUlpUWGxDWlMxVVVFbDRPV0Z0UldOUmVta3dkbXMwWnpoc2JWSk5aR1kwTFVjdFJFcEpVV2xUVjJkRFptdG9aMFpMVXpkcVpHcGpkM2xsY2poeGR5SjlmUSIsInNpZ25hdHVyZSI6IlFuS0RONWJsY2k1OGNESXYyaENkSVlUSHpSNWdZWHRIbXN2LTVnVHd5YXQ1cGJZUHhicVgwZDRUeUNOcWVjYVpsb3djZDRqNlRTSTNTODdZRVN4N2VvN3BkbjVLazktZFRXQVhPS0NuX1BNWmQzNE5uV2ZfamFVZ2tKUFlib044RWd2bURZbDlPaTk0cXliZUkzNTNDR210aHZKbnVSbUV6M3pnVzFVVHJsX0g2RWF3bno3Y1ZRajkxZVdKV3Y2VW9FaTRqTUdBV19OeHpuN2lTT1FSZnJvVHVWR3hNc0lMZ1BFdV9YUnNZZ29NU2Q0S21IZTd2SFhmR2FNekNJbVhka2NKeGVjbmlCbFBBNnNEeHFUOGhKQlZzc1Y5LXh6Q3lYVzNUUWdnbkFaREhYN0hab0tNVEQyYmNJWEYySWhXTEk1S0pxcVNjSmh3a2NTQzdvS3puZyJ9\",\"signature\":\"zd3ZZFH5z-QB7pKLiYzz5rs05WVt2PE3heb7Zo_ok9vCGd9zKS1WccC9DTkl_OmCdSVHibGfBIGvLSwObEZiy361b5oPBus_O_CMxIpywBjdptFkCzizeji8KXuvpD1jMg0IzxPuyXrco2nphQAk_kvGTFDtlKrvc4roBOv5IApDC3KO4yL0odRShQqWVTq-QSdZDH1K9VmVWRnsYTqh2YDrJtl7nDowu10QtIpIEwnvlwg4q4cTTBt5yz7GuKohC3HMUqlCO_UU7KDc6NKyQ708mFgLbYRXC9-gr5qPaal7ebfwiLLHIzlknFGBF6yhKgfXnKiBJ_77is7AE-LSAw\"}";
        final String CHANGE_KEY_RESPONSE_BODY_1 = "{" + System.lineSeparator() +
                "  \"id\": 5," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"m1USpwG42CtJDMSEJPXDjR9C__UrVSNk38iaDealPFWw3jPoF1wHr0-A5Az7DjkqVXXRHJ2u62akEFxyJQkcSB1FGm06-mCZG079qAyFcGoL9pMtei9FZkoIQA2LELXI2OeHULrmW-_0ANPF7xxtb16X2dK5FgItmC9sIcCBpMkarq2CMeJ6Tm6_-KLr5XyWeSqwGbxc6P66Mrkw46clffjy45Y7L-QgNgySytMG3TxXtfklf669XZCRejGffSwLeB7MkzJdU46ZzAhFTxFfRrojWO2221OC_UmDN6uv8K1AgvXU9a9se2PFV0m_FAIHg2Jd4WOT76bdOfInqvyfHQ\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@myexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"agreement\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-26T18:21:53Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE_1 = "GgZctTaTHY3weRky_SYuaUKINDcV8o-28xfbCB7vkyI";

        final String QUERY_ACCT_REQUEST_BODY_2 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNSIsIm5vbmNlIjoiR2daY3RUYVRIWTN3ZVJreV9TWXVhVUtJTkRjVjhvLTI4eGZiQ0I3dmt5SSIsInVybCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMS9hY21lL2FjY3QvNSJ9\",\"payload\":\"\",\"signature\":\"AayOyEhXNLUT0rHnUf3XoCQ4y1UwpgTyjbpZ2DD7C4XvMFMr-Qc8s6akitwVwy54x0mACYxLcwhjT3_cyC16n5wreI8mm30z1vNnuhPLXUVUZxUFJY1KAjucGTe322iLS6YG7aTCXuu84ExzkcE-OFjnYzVjpoGEwLkh1qVerXVQZuhz5sMfPbuYP8hutEzT9RdhN58M9yDrOSLGfYmcid22mWLdOoI-_Oe-KrmCw2-68eqdYLPKsjnWd6inv97enNF741YDTnwZofE3h1MJLC_9Xux9m_XHpu7mhVm0w2tNoEjo8DQ7jA4JFdMxg9gLN63f0cQ-Cz9cdJz8CHhSMA\"}";
        final String QUERY_ACCT_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"id\": 5," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"RSA\"," + System.lineSeparator() +
                "    \"n\": \"m1USpwG42CtJDMSEJPXDjR9C__UrVSNk38iaDealPFWw3jPoF1wHr0-A5Az7DjkqVXXRHJ2u62akEFxyJQkcSB1FGm06-mCZG079qAyFcGoL9pMtei9FZkoIQA2LELXI2OeHULrmW-_0ANPF7xxtb16X2dK5FgItmC9sIcCBpMkarq2CMeJ6Tm6_-KLr5XyWeSqwGbxc6P66Mrkw46clffjy45Y7L-QgNgySytMG3TxXtfklf669XZCRejGffSwLeB7MkzJdU46ZzAhFTxFfRrojWO2221OC_UmDN6uv8K1AgvXU9a9se2PFV0m_FAIHg2Jd4WOT76bdOfInqvyfHQ\"," + System.lineSeparator() +
                "    \"e\": \"AQAB\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@myexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-26T18:21:53Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE_2 = "FcI1Il9OFY6CiO6Dc74UXx4K8s_J9yYjOb8WdjIUxv0";

        final String CHANGE_KEY_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"id\": 5," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"EC\"," + System.lineSeparator() +
                "    \"crv\": \"P-256\"," + System.lineSeparator() +
                "    \"x\": \"tQ5PThpaP5fm5fW3x3yL4nXkXWxzOc2Hffzt7kHQ-R8\"," + System.lineSeparator() +
                "    \"y\": \"KQNlYw-4nn6S3ssFOpMpTWNmg97QFVGb2Ibtef2ojjw\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@myexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"agreement\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-26T18:21:53Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE_2 = "Z6p2-PomrN5uKZ3vghnse18Kopd9H3xIN7GAIapsyqE";

        final String QUERY_ACCT_RESPONSE_BODY_3 = "{" + System.lineSeparator() +
                "  \"id\": 5," + System.lineSeparator() +
                "  \"key\": {" + System.lineSeparator() +
                "    \"kty\": \"EC\"," + System.lineSeparator() +
                "    \"crv\": \"P-256\"," + System.lineSeparator() +
                "    \"x\": \"tQ5PThpaP5fm5fW3x3yL4nXkXWxzOc2Hffzt7kHQ-R8\"," + System.lineSeparator() +
                "    \"y\": \"KQNlYw-4nn6S3ssFOpMpTWNmg97QFVGb2Ibtef2ojjw\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"contact\": [" + System.lineSeparator() +
                "    \"mailto:admin@myexample.com\"" + System.lineSeparator() +
                "  ]," + System.lineSeparator() +
                "  \"initialIp\": \"10.77.77.1\"," + System.lineSeparator() +
                "  \"createdAt\": \"2018-11-26T18:21:53Z\"," + System.lineSeparator() +
                "  \"status\": \"valid\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String QUERY_ACCT_REPLAY_NONCE_3 = "MM5G1fR094N5KCWic_bu6HWT5SJbBbOf_TDxGtzW5G8";


        final String DIRECTORY_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"jJpTfXFmKDw\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"caaIdentities\": [" + System.lineSeparator() +
                "      \"happy-hacker-ca.invalid\"" + System.lineSeparator() +
                "    ]," + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator() +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String NEW_NONCE_RESPONSE_2 = "UkzxjeLrOYrYiuFn9SoYov7f_So0g9TA_oOFh32S_5I";

        final String QUERY_ACCT_REQUEST_BODY_4 = "{\"protected\":\"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiJ6azltdDczT2tSVG5wTXBXeEJJNTZaZl85dEdidkpIclZFazlDZlJNTHVZTnVEZjVTbHhMbnVGNE84NG50T19KV1R6bGR1bkdHVkJfWUtvMWxEV3N0ZUtkWmhseE9Da1JKV3JtTnlla3paanpGZGJDeXNKMXZEb3hxTlA2Si1lUXc0UlYzS0hISVhXUThjblliWkprR2JNNWVlV016cTNsMUd3dnY0UXhZNHRvSEE5cTBENGpsTVBFOEVrXzRSTzVxdFhKWnlZTThuQWVCM3pkM0JwZkhSemxhWWxnb1JtQ3VRXzdWdFFHYm10YkNqcHFUTmVydjY2ZDE2WTFNQlU2dk9jdnFrTERFbFgxa1JVdy1fRWMydVc0emk5bDBvaGdxQWNxMExaY3pydHAzblg0UGZiMzhwSzFJVVppMlQtVzROM1JxbUtCTUE0YjRLRkdFT2xJencifSwibm9uY2UiOiJVa3p4amVMck9ZcllpdUZuOVNvWW92N2ZfU28wZzlUQV9vT0ZoMzJTXzVJIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAxL2FjbWUvbmV3LWFjY3QifQ\",\"payload\":\"eyJvbmx5UmV0dXJuRXhpc3RpbmciOnRydWV9\",\"signature\":\"XBLjskGqczOHxcq1dfhQHzMPlk-TmwnXEdXcV_Pbdv-KYOASSTT6e-NYStN2S2lTmzpUPZSLSNulnKexx8tGj4CKZTOrDP-0at9ErjS6LEdTZhOQKo3Gwx2mvw_Ki0O6ZyIV-2_j5M5gejRAS9-IaCrGzeS1wT5pPcmffyYPQTynqT1cuBK8poM7Xc4DIiM3skYZupnBEIcl6G7TIG3UHY9CPBFLt6kFgQldox1LigNtrPnKUSkJZgcK8Gi1PDQwzUnuXvcDDtueEaKBGl9OeMUVHpaLrHfnMAT-unFTudpMPFrvWd9tU30XdqLCwmAiiXqy_PyHRNUtMbh8ekYyCQ\"}";

        final String QUERY_ACCT_RESPONSE_BODY_4 = "";

        final String QUERY_ACCT_REPLAY_NONCE_4 = "rB3tEJTZGzo0KQqA_2fb2hxX9H14N7puc6CRAD2-mz0";

        final String ACCT_PATH_2 = "/acme/acct/413";
        final String ACCT_LOCATION_2 = "http://localhost:4001" + ACCT_PATH_2;

        final String CHANGE_KEY_RESPONSE_BODY_3 = "{" + System.lineSeparator() +
                "  \"type\": \"urn:ietf:params:acme:error:malformed\"," + System.lineSeparator() +
                "  \"detail\": \"New key is already in use for a different account\"," + System.lineSeparator() +
                "  \"status\": 409" + System.lineSeparator() +
                "}" + System.lineSeparator();
        final String CHANGE_KEY_REPLAY_NONCE_3 = "rB3tEJTZGzo0KQqA_2fb2hxX9H14N7puc6CRAD2-mz0";

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_1)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_1)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_1, QUERY_ACCT_RESPONSE_BODY_1, QUERY_ACCT_REPLAY_NONCE_1, ACCT_LOCATION, 200)
                .addChangeKeyRequestAndResponse(CHANGE_KEY_REQUEST_BODY_1, CHANGE_KEY_RESPONSE_BODY_1, CHANGE_KEY_REPLAY_NONCE_1, 200)
                .updateAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_2, QUERY_ACCT_RESPONSE_BODY_2, QUERY_ACCT_REPLAY_NONCE_2, ACCT_PATH, 200)
                .addChangeKeyRequestAndResponse("", CHANGE_KEY_RESPONSE_BODY_2, CHANGE_KEY_REPLAY_NONCE_2, 200)
                .updateAccountRequestAndResponse("", QUERY_ACCT_RESPONSE_BODY_3, QUERY_ACCT_REPLAY_NONCE_3, ACCT_PATH, 200)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_2)
                .addNewNonceResponse(NEW_NONCE_RESPONSE_2)
                .addNewAccountRequestAndResponse(QUERY_ACCT_REQUEST_BODY_4, QUERY_ACCT_RESPONSE_BODY_4, QUERY_ACCT_REPLAY_NONCE_4, ACCT_LOCATION_2, 200)
                .addChangeKeyRequestAndResponse("", CHANGE_KEY_RESPONSE_BODY_3, CHANGE_KEY_REPLAY_NONCE_3, 409)
                .build();
    }

    private ClientAndServer setupTestGetMetadata() {

        // set up a mock Let's Encrypt server
        final String DIRECTORY_RESPONSE_BODY_1 = "{" + System.lineSeparator()  +
                "  \"TrOIFke5bdM\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator()  +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator()  +
                "  \"meta\": {" + System.lineSeparator()  +
                "    \"caaIdentities\": [" + System.lineSeparator()  +
                "      \"happy-hacker-ca.invalid\"," + System.lineSeparator()  +
                "      \"happy-hacker2-ca.invalid\"" + System.lineSeparator()  +
                "    ]," + System.lineSeparator()  +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"," + System.lineSeparator()  +
                "    \"website\": \"https://github.com/letsencrypt/boulder\"," + System.lineSeparator()  +
                "    \"externalAccountRequired\": true" + System.lineSeparator()  +
                "  }," + System.lineSeparator()  +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator()  +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator()  +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator()  +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator()  +
                "}";

        final String DIRECTORY_RESPONSE_BODY_2 = "{" + System.lineSeparator() +
                "  \"iXia3_B0CrU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"meta\": {" + System.lineSeparator() +
                "    \"termsOfService\": \"https://boulder:4431/terms/v7\"" + System.lineSeparator() +
                "  }," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        final String DIRECTORY_RESPONSE_BODY_3 = "{" + System.lineSeparator() +
                "  \"iXia3_B0CrU\": \"https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417\"," + System.lineSeparator() +
                "  \"keyChange\": \"http://localhost:4001/acme/key-change\"," + System.lineSeparator() +
                "  \"newAccount\": \"http://localhost:4001/acme/new-acct\"," + System.lineSeparator() +
                "  \"newNonce\": \"http://localhost:4001/acme/new-nonce\"," + System.lineSeparator() +
                "  \"newOrder\": \"http://localhost:4001/acme/new-order\"," + System.lineSeparator() +
                "  \"revokeCert\": \"http://localhost:4001/acme/revoke-cert\"" + System.lineSeparator() +
                "}" + System.lineSeparator();

        return new AcmeMockServerBuilder(server)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_1)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_2)
                .addDirectoryResponseBody(DIRECTORY_RESPONSE_BODY_3)
                .build();
    }

    private AcmeAccount populateBasicAccount(String alias) throws Exception{
        AcmeAccount account = populateBasicBuilder()
                .setKey(aliasToCertificateMap.get(alias), aliasToPrivateKeyMap.get(alias))
                .build();
        return account;
    }

    private AcmeAccount populateAccount(String alias) throws Exception{
        AcmeAccount account = populateBuilder()
                .setKey(aliasToCertificateMap.get(alias), aliasToPrivateKeyMap.get(alias))
                .build();
        return account;
    }
}
