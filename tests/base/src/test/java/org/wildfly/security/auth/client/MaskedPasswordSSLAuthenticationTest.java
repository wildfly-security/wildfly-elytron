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

package org.wildfly.security.auth.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.PrivilegedAction;
import java.security.Security;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.ssl.builder.SSLContextBuilder;
import org.wildfly.security.ssl.builder.SSLUtils;
import org.wildfly.security.ssl.test.util.CAGenerationTool;
import org.wildfly.security.ssl.test.util.CAGenerationTool.Identity;
import org.wildfly.security.ssl.test.util.DefinedCAIdentity;
import org.wildfly.security.ssl.test.util.DefinedIdentity;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;

/**
 * Tests a successful SSL authentication with key store masked password in client xml configuration
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */

public class MaskedPasswordSSLAuthenticationTest {

    private static final String JKS_LOCATION = "./target/test-classes/jks";

    private static CAGenerationTool caGenerationTool;

    private static SecurityDomain getKeyStoreBackedSecurityDomain(KeyStore keyStore) throws Exception {
        SecurityRealm securityRealm = new KeyStoreBackedSecurityRealm(keyStore);

        return SecurityDomain.builder()
                .addRealm("KeystoreRealm", securityRealm)
                .build()
                .setDefaultRealmName("KeystoreRealm")
                .setPrincipalDecoder(new X500AttributePrincipalDecoder("2.5.4.3", 1))
                .setPreRealmRewriter((String s) -> s.toLowerCase(Locale.ENGLISH))
                .setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.ALL)
                .build();
    }

    @BeforeClass
    public static void beforeTest() throws Exception {
        caGenerationTool = CAGenerationTool.builder()
                .setBaseDir(JKS_LOCATION)
                .setRequestIdentities(Identity.CA, Identity.LADYBIRD, Identity.SCARAB)
                .build();
    }

    @AfterClass
    public static void afterTest() throws IOException {
        caGenerationTool.close();
    }

    @Test
    public void testTwoWay() throws Exception {
        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore()))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(ca.createTrustManager())
                .setNeedClientAuth(true)
                .build().create();

        SecurityIdentity identity = performConnectionTest(serverContext, "protocol://test-two-way.org", true);
        assertNotNull(identity);
        assertEquals("Principal Name", "ladybird", identity.getPrincipal().getName());
    }

    private SecurityIdentity performConnectionTest(SSLContext serverContext, String clientUri, boolean expectValid) throws Exception {
        System.setProperty("wildfly.config.url", MaskedPasswordSSLAuthenticationTest.class.getResource("wildfly-masked-password-ssl-config-v1_4.xml").toExternalForm());
        AccessController.doPrivileged((PrivilegedAction<Integer>) () -> Security.insertProviderAt(WildFlyElytronPasswordProvider.getInstance(), 1));

        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        SSLContext clientContext = contextConfigurationClient.getSSLContext(URI.create(clientUri), context);

        return performConnectionTest(serverContext, clientContext, expectValid);
    }

    private SecurityIdentity performConnectionTest(SSLContext serverContext, SSLContext clientContext, boolean expectValid) throws Exception {
        SSLServerSocketFactory sslServerSocketFactory = serverContext.getServerSocketFactory();

        SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(1111, 10, InetAddress.getLoopbackAddress());

        ExecutorService executorService = Executors.newSingleThreadExecutor();
        Future<SSLSocket> socketFuture = executorService.submit(() -> {
            try {
                System.out.println("About to connect client");
                SSLSocket sslSocket = (SSLSocket) clientContext.getSocketFactory().createSocket(InetAddress.getLoopbackAddress(), 1111);
                sslSocket.getSession();

                System.out.println("Client connected");
                return sslSocket;
            } catch (Exception e) {
                System.out.println("Client Connection Failed");
                throw new RuntimeException(e);
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
