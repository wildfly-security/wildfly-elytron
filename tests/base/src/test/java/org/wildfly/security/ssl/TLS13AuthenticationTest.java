/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.ssl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.ssl.test.util.CAGenerationTool;
import org.wildfly.security.ssl.test.util.CAGenerationTool.Identity;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;

/**
 * Simple test case to test two-way SSL using TLSv1.3.
 *
 * @author <a href="mailto:fjuma@redhat">Farah Juma</a>
 */
public class TLS13AuthenticationTest {

    private static final String CLIENT_CONFIG = "tls13-authentication-config.xml";
    private static final char[] PASSWORD = "Elytron".toCharArray();
    private static final String CA_JKS_LOCATION = "./target/test-classes/jks";

    private static CAGenerationTool caGenerationTool = null;
    private static SecurityDomain securityDomain = null;

    @BeforeClass
    public static void setUp() throws Exception{

        caGenerationTool = CAGenerationTool.builder()
                .setBaseDir(CA_JKS_LOCATION)
                .setRequestIdentities(Identity.LADYBIRD, Identity.SCARAB)
                .build();

        SecurityRealm securityRealm = new KeyStoreBackedSecurityRealm(loadKeyStore("/jks/beetles.keystore"));
        securityDomain = SecurityDomain.builder()
                .addRealm("KeystoreRealm", securityRealm)
                .build()
                .setDefaultRealmName("KeystoreRealm")
                .setPrincipalDecoder(new X500AttributePrincipalDecoder("2.5.4.3", 1))
                .setPreRealmRewriter((String s) -> s.toLowerCase(Locale.ENGLISH))
                .setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.ALL)
                .build();

    }

    @AfterClass
    public static void cleanUp() throws IOException {
        caGenerationTool.close();
    }

    @Test
    public void testTwoWayTLS13() throws Exception {
        final String CIPHER_SUITE = "TLS_AES_128_GCM_SHA256";

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setCipherSuiteSelector(CipherSuiteSelector.fromNamesString(CIPHER_SUITE))
                .setKeyManager(getKeyManager("/jks/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .build().create();

        SecurityIdentity identity = performConnectionTest(serverContext, "protocol://test-two-way-tls13.org", CLIENT_CONFIG, CIPHER_SUITE, true);
        assertNotNull(identity);
        assertEquals("Principal Name", "ladybird", identity.getPrincipal().getName());
    }

    @Test
    public void testDifferentPreferredTLS13Suites() throws Exception {
        final String REQUIRED_CIPHER_SUITE = "TLS_AES_128_GCM_SHA256";
        final String PREFERRED_CIPHER_SUITE = "TLS_AES_256_GCM_SHA384";
        final String SERVER_CIPHER_SUITE = String.format("%s:%s", PREFERRED_CIPHER_SUITE, REQUIRED_CIPHER_SUITE);

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setCipherSuiteSelector(CipherSuiteSelector.fromNamesString(SERVER_CIPHER_SUITE))
                .setKeyManager(getKeyManager("/jks/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .build().create();

        SecurityIdentity identity = performConnectionTest(serverContext, "protocol://test-different-preferred-tls13-suites.org", CLIENT_CONFIG, REQUIRED_CIPHER_SUITE, true);
        assertNotNull(identity);
        assertEquals("Principal Name", "ladybird", identity.getPrincipal().getName());
    }

    @Test
    public void testClientTLS12Only() throws Exception {
        final String TLS13_CIPHER_SUITE = "TLS_AES_128_GCM_SHA256";
        final String TLS12_CIPHER_SUITE = "TLS_RSA_WITH_AES_128_CBC_SHA256"; // TLS v1.2

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setCipherSuiteSelector(CipherSuiteSelector.aggregate(
                                CipherSuiteSelector.fromNamesString(TLS13_CIPHER_SUITE),
                                CipherSuiteSelector.fromString(TLS12_CIPHER_SUITE)
                ))
                .setKeyManager(getKeyManager("/jks/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .build().create();

        SecurityIdentity identity = performConnectionTest(serverContext, "protocol://test-client-tls12-only.org", CLIENT_CONFIG, TLS12_CIPHER_SUITE, false);
        assertNotNull(identity);
        assertEquals("Principal Name", "ladybird", identity.getPrincipal().getName());
    }

    @Test
    public void testServerTLS12Only() throws Exception {
        final String SERVER_CIPHER_SUITE = "TLS_RSA_WITH_AES_128_CBC_SHA256"; // TLS v1.2

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setCipherSuiteSelector(CipherSuiteSelector.fromString(SERVER_CIPHER_SUITE))
                .setKeyManager(getKeyManager("/jks/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .build().create();

        SecurityIdentity identity = performConnectionTest(serverContext, "protocol://test-server-tls12-only.org", CLIENT_CONFIG, SERVER_CIPHER_SUITE, false);
        assertNotNull(identity);
        assertEquals("Principal Name", "ladybird", identity.getPrincipal().getName());
    }

    @Test
    public void testOneWayTLS13() throws Exception {
        final String CIPHER_SUITE = "TLS_AES_128_GCM_SHA256";

        SSLContext serverContext = new SSLContextBuilder()
                .setCipherSuiteSelector(CipherSuiteSelector.fromNamesString(CIPHER_SUITE))
                .setKeyManager(getKeyManager("/jks/scarab.keystore"))
                .build().create();

        SecurityIdentity identity = performConnectionTest(serverContext, "protocol://test-one-way-tls13.org", CLIENT_CONFIG, CIPHER_SUITE, true);
        assertNull(identity);
    }

    private SecurityIdentity performConnectionTest(SSLContext serverContext, String clientUri, String clientConfigFileName, String expectedCipherSuite, boolean expectTLS13) throws Exception {
        System.setProperty("wildfly.config.url", SSLAuthenticationTest.class.getResource(clientConfigFileName).toExternalForm());
        AccessController.doPrivileged((PrivilegedAction<Integer>) () -> Security.insertProviderAt(new WildFlyElytronProvider(), 1));

        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        SSLContext clientContext = contextConfigurationClient.getSSLContext(URI.create(clientUri), context);

        SSLServerSocketFactory sslServerSocketFactory = serverContext.getServerSocketFactory();

        SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(1111, 10, InetAddress.getLoopbackAddress());

        ExecutorService executorService = Executors.newSingleThreadExecutor();
        Future<SSLSocket> socketFuture = executorService.submit(() -> {
            try {
                System.out.println("About to connect client");
                SSLSocket sslSocket = (SSLSocket) clientContext.getSocketFactory().createSocket(InetAddress.getLoopbackAddress(), 1111);
                sslSocket.getSession();

                return sslSocket;
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                System.out.println("Client connected");
            }
        });

        SSLSocket serverSocket = (SSLSocket) sslServerSocket.accept();
        SSLSession serverSession = serverSocket.getSession();
        SSLSocket clientSocket = socketFuture.get();
        SSLSession clientSession = clientSocket.getSession();

        try {
            if (expectedCipherSuite != null) {
                if(expectTLS13) {
                    assertEquals("TLSv1.3", serverSession.getProtocol());
                    assertEquals("TLSv1.3", clientSession.getProtocol());
                } else {
                    assertEquals("TLSv1.2", serverSession.getProtocol());
                    assertEquals("TLSv1.2", clientSession.getProtocol());
                }

                assertEquals(expectedCipherSuite, serverSession.getCipherSuite());
                assertEquals(expectedCipherSuite, clientSession.getCipherSuite());
            }
            return (SecurityIdentity) serverSession.getValue(SSLUtils.SSL_SESSION_IDENTITY_KEY);
        } finally {
            safeClose(serverSocket);
            safeClose(clientSocket);
            safeClose(sslServerSocket);
        }
    }

    /**
     * Get the key manager backed by the specified key store.
     *
     * @param keystorePath the path to the keystore with X509 private key
     * @return the initialised key manager.
     */
    private static X509ExtendedKeyManager getKeyManager(final String keystorePath) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(loadKeyStore(keystorePath), PASSWORD);

        for (KeyManager current : keyManagerFactory.getKeyManagers()) {
            if (current instanceof X509ExtendedKeyManager) {
                return (X509ExtendedKeyManager) current;
            }
        }

        throw new IllegalStateException("Unable to obtain X509ExtendedKeyManager.");
    }

    /**
     * Get the trust manager that trusts all certificates signed by the certificate authority.
     *
     * @return the trust manager that trusts all certificates signed by the certificate authority.
     * @throws KeyStoreException
     */
    private static X509TrustManager getCATrustManager() throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(loadKeyStore("/jks/ca.truststore"));

        for (TrustManager current : trustManagerFactory.getTrustManagers()) {
            if (current instanceof X509TrustManager) {
                return (X509TrustManager) current;
            }
        }

        throw new IllegalStateException("Unable to obtain X509TrustManager.");
    }

    private static KeyStore loadKeyStore(final String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        try (InputStream caTrustStoreFile = SSLAuthenticationTest.class.getResourceAsStream(path)) {
            keyStore.load(caTrustStoreFile, PASSWORD);
        }

        return keyStore;
    }

    private void safeClose(Closeable closeable) {
        try {
            closeable.close();
        } catch (Exception ignored) {}
    }
}
