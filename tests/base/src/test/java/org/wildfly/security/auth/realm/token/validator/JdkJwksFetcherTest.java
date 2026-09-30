/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.auth.realm.token.validator;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.jose.jwks.JwksException;
import org.wildfly.security.ssl.SSLContextBuilder;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;

/**
 * Unit tests for {@link JdkJwksFetcher} — HTTP status-code checking and the response-size cap
 * (ELY-3066 consolidation).
 *
 * @author <a href="mailto:rojeda@redhat.com">Raul Ojeda Robles</a>
 */
public class JdkJwksFetcherTest {

    private static final MockWebServer server = new MockWebServer();
    private static char[] PASSWORD = "password".toCharArray();
    private static SSLContext serverSslContext;
    private static SSLContext clientSslContext;

    @BeforeClass
    public static void setup() throws GeneralSecurityException, IOException {
        SelfSignedX509CertificateAndSigningKey selfSigned = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal("CN=localhost"))
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA256withRSA")
                .build();
        X509Certificate certificate = selfSigned.getSelfSignedCertificate();

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", selfSigned.getSigningKey(), PASSWORD, new X509Certificate[]{certificate});

        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", certificate);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, PASSWORD);
        X509ExtendedKeyManager keyManager = null;
        for (KeyManager km : kmf.getKeyManagers()) {
            if (km instanceof X509ExtendedKeyManager) {
                keyManager = (X509ExtendedKeyManager) km;
                break;
            }
        }
        serverSslContext = new SSLContextBuilder().setKeyManager(keyManager).build().create();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        X509TrustManager trustManager = null;
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                trustManager = (X509TrustManager) tm;
                break;
            }
        }
        clientSslContext = new SSLContextBuilder()
                .setTrustManager(trustManager)
                .setClientMode(true)
                .setSessionTimeout(10)
                .build()
                .create();

        server.useHttps(serverSslContext.getSocketFactory(), false);
        server.start();
    }

    @AfterClass
    public static void cleanup() throws IOException {
        server.shutdown();
    }

    private URL serverUrl(String path) throws Exception {
        return new URL("https://localhost:" + server.getPort() + path);
    }

    @Test
    public void testSuccessfulResponseReturnsBody() throws Exception {
        byte[] body = "hello world".getBytes();
        server.enqueue(new MockResponse().setBody(new String(body)));
        JdkJwksFetcher fetcher = new JdkJwksFetcher(clientSslContext, (a, b) -> true, 2000, 2000);

        byte[] result = fetcher.fetch(serverUrl("/"));
        assertArrayEquals(body, result);
    }

    @Test
    public void testNon200StatusThrowsJwksException() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(404));
        JdkJwksFetcher fetcher = new JdkJwksFetcher(clientSslContext, (a, b) -> true, 2000, 2000);

        JwksException e = assertThrows(JwksException.class, () -> fetcher.fetch(serverUrl("/")));
        assertTrue("expected the status code in the message: " + e.getMessage(), e.getMessage().contains("404"));
    }

    @Test
    public void testNon200StatusDoesNotLeakConnection() throws Exception {
        // exercised implicitly: a second request on the same fetcher/server must still succeed,
        // proving the connection from the failed request above was properly closed/disconnected
        server.enqueue(new MockResponse().setResponseCode(500));
        JdkJwksFetcher fetcher = new JdkJwksFetcher(clientSslContext, (a, b) -> true, 2000, 2000);
        assertThrows(JwksException.class, () -> fetcher.fetch(serverUrl("/")));

        server.enqueue(new MockResponse().setBody("ok"));
        byte[] result = fetcher.fetch(serverUrl("/"));
        assertArrayEquals("ok".getBytes(), result);
    }

    @Test
    public void testResponseAtCapSucceeds() throws Exception {
        byte[] body = new byte[100];
        server.enqueue(new MockResponse().setBody(new String(body)));
        JdkJwksFetcher fetcher = new JdkJwksFetcher(clientSslContext, (a, b) -> true, 2000, 2000, 100);

        byte[] result = fetcher.fetch(serverUrl("/"));
        assertNotNull(result);
    }

    @Test
    public void testResponseExceedingCapThrowsJwksException() throws Exception {
        byte[] body = new byte[101];
        server.enqueue(new MockResponse().setBody(new String(body)));
        JdkJwksFetcher fetcher = new JdkJwksFetcher(clientSslContext, (a, b) -> true, 2000, 2000, 100);

        JwksException e = assertThrows(JwksException.class, () -> fetcher.fetch(serverUrl("/")));
        assertTrue("expected a size-related message: " + e.getMessage(), e.getMessage().contains("100"));
    }

    @Test
    public void testDefaultMaxResponseSizeIs256Kb() {
        org.junit.Assert.assertEquals(262_144L, JdkJwksFetcher.DEFAULT_MAX_RESPONSE_SIZE_BYTES);
    }

    @Test
    public void testNonHttpsUrlRejected() throws Exception {
        JdkJwksFetcher fetcher = new JdkJwksFetcher(clientSslContext, (a, b) -> true, 2000, 2000);

        JwksException e = assertThrows(JwksException.class, () -> fetcher.fetch(new URL("http://localhost:1/never-connects")));
        assertTrue(e.getMessage().contains("HTTPS"));
    }
}
