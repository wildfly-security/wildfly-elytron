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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.Closeable;
import java.io.InputStream;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
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

import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.provider.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.x500.X500AttributePrincipalDecoder;

/**
 * Simple test case to test authentication occurring during the establishment of an {@link SSLSession}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SSLAuthenticationTest {

    private static SSLContext clientContext;
    private static SSLContext serverContext;

    @BeforeClass
    public static void setupServer() throws Exception {
        SecurityRealm securityRealm = new KeyStoreBackedSecurityRealm(loadKeyStore("/ca/jks/beetles.keystore"));

        SecurityDomain securityDomain = SecurityDomain.builder()
                .addRealm("KeystoreRealm", securityRealm)
                    .build()
                .setDefaultRealmName("KeystoreRealm")
                .setPrincipalDecoder(new X500AttributePrincipalDecoder("2.5.4.3", 1))
                .setPreRealmRewriter(s -> s.toLowerCase())
                .build();

        serverContext = new ServerSSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setKeyManager(getKeyManager("/ca/jks/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setRequireClientAuth(true)
                .build().create();
    }

    @BeforeClass
    public static void setupClient() throws Exception {
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(new KeyManager[] { getKeyManager("/ca/jks/ladybird.keystore") },
                new TrustManager[] { getCATrustManager() }, null);

        SSLAuthenticationTest.clientContext = clientContext;
    }

    /**
     * Get the key manager backed by the specified key store.
     *
     * @param keystoreName the name of the key store to load.
     * @return the initialised key manager.
     */
    private static X509ExtendedKeyManager getKeyManager(final String keystorePath) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
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
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
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

    /**
     * @throws ExecutionException
     * @throws InterruptedException
     *
     */
    @Test
    public void performConnectionTest() throws Exception {
        SSLServerSocketFactory sslServerSocketFactory = serverContext.getServerSocketFactory();

        SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(1111, 10, InetAddress.getLoopbackAddress());

        ExecutorService executorService = Executors.newSingleThreadExecutor();
        Future<SSLSocket> socketFuture = executorService.submit((Callable<SSLSocket>) () -> {
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

        assertTrue("Server SSL Session Valid", serverSession.isValid());
        SecurityIdentity identity =  (SecurityIdentity) serverSession.getValue(SSLUtils.SSL_SESSION_IDENTITY_KEY);
        assertNotNull(identity);
        assertEquals("Principa Name", "ladybird", identity.getPrincipal().getName());

        SSLSocket clientSocket = socketFuture.get();
        SSLSession clientSession = clientSocket.getSession();
        assertTrue("Client SSL Session Valid", clientSession.isValid());

        safeClose(serverSocket);
        safeClose(clientSocket);
    }

    private void safeClose(Closeable closeable) {
        try {
            closeable.close();
        } catch (Exception ignored) {}
    }
}
