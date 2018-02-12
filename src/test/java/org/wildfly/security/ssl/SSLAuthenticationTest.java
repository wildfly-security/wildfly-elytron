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
package org.wildfly.security.ssl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.Closeable;
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

import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.x500.X500AttributePrincipalDecoder;

/**
 * Simple test case to test authentication occurring during the establishment of an {@link SSLSession}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SSLAuthenticationTest {

    private static final boolean IS_IBM = System.getProperty("java.vendor").contains("IBM");

    /**
     * Get the key manager backed by the specified key store.
     *
     * @param keystorePath the path to the keystore with X509 private key
     * @return the initialised key manager.
     */
    private static X509ExtendedKeyManager getKeyManager(final String keystorePath) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(IS_IBM ? "IbmX509" : "SunX509");
        keyManagerFactory.init(loadKeyStore(keystorePath), "Elytron".toCharArray());

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
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(IS_IBM ? "IbmX509" : "SunX509");
        trustManagerFactory.init(loadKeyStore("/ca/jks/ca.truststore"));

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
            keyStore.load(caTrustStoreFile, "Elytron".toCharArray());
        }

        return keyStore;
    }

    @Test
    public void testOneWay() throws Exception {
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(getKeyManager("/ca/jks/firefly.keystore"))
                .build().create();

        SecurityIdentity identity = performConnectionTest(serverContext, "protocol://test-one-way.org", true);
        assertNull(identity);
    }

    @Test
    public void testCrlBlank() throws Exception {
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(getKeyManager("/ca/jks/firefly.keystore"))
                .build().create();

        SecurityIdentity identity = performConnectionTest(serverContext, "protocol://test-one-way-crl.org", true);
        assertNull(identity);
    }

    @Test
    public void testServerRevoked() throws Exception {
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(getKeyManager("/ca/jks/firefly.keystore"))
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-firefly-revoked.org", false);
    }

    @Test
    public void testServerIcaRevoked() throws Exception {
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(getKeyManager("/ica/jks/rove.keystore"))
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-ica-revoked.org", false);
    }

    @Test
    public void testTwoWay() throws Exception {
        SecurityRealm securityRealm = new KeyStoreBackedSecurityRealm(loadKeyStore("/ca/jks/beetles.keystore"));

        SecurityDomain securityDomain = SecurityDomain.builder()
                .addRealm("KeystoreRealm", securityRealm)
                .build()
                .setDefaultRealmName("KeystoreRealm")
                .setPrincipalDecoder(new X500AttributePrincipalDecoder("2.5.4.3", 1))
                .setPreRealmRewriter((String s) -> s.toLowerCase(Locale.ENGLISH))
                .setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.ALL)
                .build();

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setKeyManager(getKeyManager("/ca/jks/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .build().create();

        SecurityIdentity identity = performConnectionTest(serverContext, "protocol://test-two-way.org", true);
        assertNotNull(identity);
        assertEquals("Principal Name", "ladybird", identity.getPrincipal().getName());
    }

    @Test
    public void testTwoWayIca() throws Exception {
        SecurityRealm securityRealm = new KeyStoreBackedSecurityRealm(loadKeyStore("/ica/jks/shortwinged.keystore"));

        SecurityDomain securityDomain = SecurityDomain.builder()
                .addRealm("KeystoreRealm", securityRealm)
                .build()
                .setDefaultRealmName("KeystoreRealm")
                .setPrincipalDecoder(new X500AttributePrincipalDecoder("2.5.4.3", 1))
                .setPreRealmRewriter((String s) -> s.toLowerCase(Locale.ENGLISH))
                .setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.ALL)
                .build();

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setKeyManager(getKeyManager("/ca/jks/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .build().create();

        SecurityIdentity identity = performConnectionTest(serverContext, "protocol://test-two-way-ica.org", true);
        assertNotNull(identity);
        assertEquals("Principal Name", "rove", identity.getPrincipal().getName());
    }

    private SecurityIdentity performConnectionTest(SSLContext serverContext, String clientUri, boolean expectValid) throws Exception {
        System.setProperty("wildfly.config.url", SSLAuthenticationTest.class.getResource("wildfly-ssl-test-config.xml").toExternalForm());
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
            if (expectValid) {
                assertTrue("Client SSL Session should be Valid", clientSession.isValid());
                assertTrue("Server SSL Session should be Valid", serverSession.isValid());
                return (SecurityIdentity) serverSession.getValue(SSLUtils.SSL_SESSION_IDENTITY_KEY);
            } else {
                assertFalse("Client SSL Session should be Invalid", clientSession.isValid());
                assertFalse("Server SSL Session should be Invalid", serverSession.isValid());
                return null;
            }
        } finally {
            safeClose(serverSocket);
            safeClose(clientSocket);
            safeClose(sslServerSocket);
        }
    }

    private void safeClose(Closeable closeable) {
        try {
            closeable.close();
        } catch (Exception ignored) {}
    }
}
