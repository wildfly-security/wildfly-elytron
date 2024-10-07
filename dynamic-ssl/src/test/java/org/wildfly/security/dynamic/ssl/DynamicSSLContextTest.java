/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.dynamic.ssl;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.auth.client.ElytronXmlParser;
import org.wildfly.security.auth.client.InvalidAuthenticationConfigurationException;
import org.wildfly.security.auth.client.MatchRule;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.cert.CertificateException;

import static java.security.AccessController.doPrivileged;
import static org.wildfly.security.dynamic.ssl.SSLServerSocketTestInstance.ServerThread.STATUS_OK;

/**
 * Functional tests of DynamicSSLContext.
 *
 * @author <a href="mailto:dvilkola@redhat.com">Diana Krepinska (Vilkolakova)</a>
 */
public class DynamicSSLContextTest {
    static final String RESOURCES = "./target/keystores/";
    private static org.wildfly.security.dynamic.ssl.SSLServerSocketTestInstance sslServerSocketTestInstancePort10001;
    private static org.wildfly.security.dynamic.ssl.SSLServerSocketTestInstance sslServerSocketTestInstancePort10002;
    private static org.wildfly.security.dynamic.ssl.SSLServerSocketTestInstance sslServerSocketTestInstancePort10003;
    private static org.wildfly.security.dynamic.ssl.SSLServerSocketTestInstance sslServerSocketTestInstancePort10000Default;

    @BeforeClass
    public static void before() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        DynamicSSLTestUtils.createKeystores();
        sslServerSocketTestInstancePort10001 = new SSLServerSocketTestInstance(RESOURCES + "server1.keystore.jks", RESOURCES + "server1.truststore.jks", 10001);
        sslServerSocketTestInstancePort10002 = new SSLServerSocketTestInstance(RESOURCES + "server2.keystore.jks", RESOURCES + "server2.truststore.jks", 10002);
        sslServerSocketTestInstancePort10003 = new SSLServerSocketTestInstance(RESOURCES + "server3.keystore.jks", RESOURCES + "server3.truststore.jks", 10003);
        sslServerSocketTestInstancePort10000Default = new SSLServerSocketTestInstance(RESOURCES + "default-server.keystore.jks", RESOURCES + "default-server.truststore.jks", 10000);

        sslServerSocketTestInstancePort10001.run();
        sslServerSocketTestInstancePort10002.run();
        sslServerSocketTestInstancePort10003.run();
        sslServerSocketTestInstancePort10000Default.run();
    }

    @AfterClass
    public static void after() {
        sslServerSocketTestInstancePort10001.stop();
        sslServerSocketTestInstancePort10002.stop();
        sslServerSocketTestInstancePort10003.stop();
        sslServerSocketTestInstancePort10000Default.stop();
        org.wildfly.security.dynamic.ssl.DynamicSSLTestUtils.deleteKeystores();
    }

    @Test
    public void smokeTestWith4Servers() throws NoSuchAlgorithmException {
        SSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLSocketFactory dynamicSSLContextSocketFactory = dynamicSSLContext.getSocketFactory();
        getAuthenticationContext("wildfly-config-dynamic-ssl-test.xml").run(() -> {
            try {
                SSLSocket clientSslSocket1 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 10001);
                clientSslSocket1.setUseClientMode(true);
                clientSslSocket1.setReuseAddress(true);
                checkOutputIsOK(clientSslSocket1);
                clientSslSocket1.close();

                SSLSocket clientSslSocket2 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 10002);
                clientSslSocket2.setReuseAddress(true);
                checkOutputIsOK(clientSslSocket2);
                clientSslSocket2.close();

                SSLSocket clientSslSocket3 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 10003);
                clientSslSocket3.setReuseAddress(true);
                checkOutputIsOK(clientSslSocket3);
                clientSslSocket3.close();

                SSLSocket clientSslSocket4 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 10000);
                clientSslSocket4.setReuseAddress(true);
                checkOutputIsOK(clientSslSocket4);
                clientSslSocket4.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });
    }

    @Test
    public void smokeTestAuthenticationContextPassedExplicitly() throws DynamicSSLContextException, GeneralSecurityException {
        SSLContext dynamicSSLContext = new DynamicSSLContext(new DynamicSSLContextImpl(getAuthenticationContext("wildfly-config-dynamic-ssl-test.xml")));
        SSLSocketFactory dynamicSSLContextSocketFactory = dynamicSSLContext.getSocketFactory();
        try {
            SSLSocket clientSslSocket1 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 10001);
            clientSslSocket1.setUseClientMode(true);
            clientSslSocket1.setReuseAddress(true);
            checkOutputIsOK(clientSslSocket1);
            clientSslSocket1.close();

            SSLSocket clientSslSocket2 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 10002);
            clientSslSocket2.setReuseAddress(true);
            checkOutputIsOK(clientSslSocket2);
            clientSslSocket2.close();

            SSLSocket clientSslSocket3 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 10003);
            clientSslSocket3.setReuseAddress(true);
            checkOutputIsOK(clientSslSocket3);
            clientSslSocket3.close();

            SSLSocket clientSslSocket4 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 10000);
            clientSslSocket4.setReuseAddress(true);
            checkOutputIsOK(clientSslSocket4);
            clientSslSocket4.close();
        } catch (Exception e) {
            Assert.assertEquals("fine", e.getMessage());
        }
    }

    @Test(expected = SocketException.class)
    public void smokeTestWithoutElytronClientContextWillFail() throws NoSuchAlgorithmException, IOException {
        SSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLSocketFactory dynamicSSLContextSocketFactory = dynamicSSLContext.getSocketFactory();
        SSLSocket clientSslSocket1 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 10002);
        clientSslSocket1.setUseClientMode(true);
        clientSslSocket1.setReuseAddress(true);
        checkOutputIsOK(clientSslSocket1);
        clientSslSocket1.close();
    }

    @Test
    public void testCreateSocketByInetAddressPort() throws NoSuchAlgorithmException {
        SSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLSocketFactory dynamicSSLContextSocketFactory = dynamicSSLContext.getSocketFactory();
        getAuthenticationContext("wildfly-config-dynamic-ssl-test.xml").run(() -> {
            try {
                SSLSocket clientSslSocket = (SSLSocket) dynamicSSLContextSocketFactory.createSocket(InetAddress.getByName("localhost"), 10002);
                clientSslSocket.setReuseAddress(true);
                checkOutputIsOK(clientSslSocket);
                clientSslSocket.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });
    }

    @Test
    public void testCreateSocketByHostPortLocalAddressLocalPort() throws NoSuchAlgorithmException {
        SSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLSocketFactory dynamicSSLContextSocketFactory = dynamicSSLContext.getSocketFactory();
        getAuthenticationContext("wildfly-config-dynamic-ssl-test.xml").run(() -> {
            try {
                SSLSocket clientSslSocket = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 10001, InetAddress.getByName("localhost"), 0);
                clientSslSocket.setReuseAddress(true);
                checkOutputIsOK(clientSslSocket);
                clientSslSocket.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });
    }

    @Test
    public void testCreateSocketByAddressPortLocalAddressLocalPort() throws NoSuchAlgorithmException {
        SSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLSocketFactory dynamicSSLContextSocketFactory = dynamicSSLContext.getSocketFactory();
        getAuthenticationContext("wildfly-config-dynamic-ssl-test.xml").run(() -> {
            try {
                SSLSocket clientSslSocket = (SSLSocket) dynamicSSLContextSocketFactory.createSocket(InetAddress.getByName("localhost"), 10001, InetAddress.getByName("localhost"), 12555);
                clientSslSocket.setReuseAddress(true);
                checkOutputIsOK(clientSslSocket);
                clientSslSocket.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });
    }

    @Test
    public void testCreateSocketBySocketHostPortAutoCloseTrue() throws NoSuchAlgorithmException {
        SSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLSocketFactory dynamicSSLContextSocketFactory = dynamicSSLContext.getSocketFactory();
        getAuthenticationContext("wildfly-config-dynamic-ssl-test.xml").run(() -> {
            try {
                Socket plainSocket = new Socket();
                plainSocket.connect(new InetSocketAddress("localhost", 10001));
                SSLSocket clientSslSocket = (SSLSocket) dynamicSSLContextSocketFactory.createSocket(plainSocket, "localhost", 10001, true);
                clientSslSocket.setReuseAddress(true);
                checkOutputIsOK(clientSslSocket);
                clientSslSocket.close();
                plainSocket.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });
    }

    @Test
    public void testCreateSocketsBySocketHostPortAutoCloseFalse() throws NoSuchAlgorithmException {
        SSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLSocketFactory dynamicSSLContextSocketFactory = dynamicSSLContext.getSocketFactory();
        getAuthenticationContext("wildfly-config-dynamic-ssl-test.xml").run(() -> {
            try {
                Socket plainSocket = new Socket();
                plainSocket.connect(new InetSocketAddress("localhost", 10001));
                SSLSocket clientSslSocket = (SSLSocket) dynamicSSLContextSocketFactory.createSocket(plainSocket, "localhost", 10001, false);
                clientSslSocket.setReuseAddress(true);
                checkOutputIsOK(clientSslSocket);
                clientSslSocket.close();
                plainSocket.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });
    }

    @Test
    public void testCreateSocketbyHostAndPortAndConfiguredSSLParams2() throws NoSuchAlgorithmException {
        DynamicSSLContext dynamicSSLContext = new DynamicSSLContext();
        AuthenticationContext context = getAuthenticationContext("wildfly-config-dynamic-ssl-test.xml");
        context.run(() -> {
            try {
                DynamicSSLSocketFactory dynamicSSLContextSocketFactory = (DynamicSSLSocketFactory) dynamicSSLContext.getSocketFactory();
                dynamicSSLContext.getDefaultSSLParameters().setCipherSuites(new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA256"});
                SSLSocket clientSslSocket = (SSLSocket) dynamicSSLContextSocketFactory.createSocket();
                SSLParameters sslParameters = clientSslSocket.getSSLParameters();
                sslParameters.setCipherSuites(new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA256"});
                clientSslSocket.setSSLParameters(sslParameters);
                dynamicSSLContext.getDefaultSSLParameters().setCipherSuites(new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA256"});
                clientSslSocket.connect(new InetSocketAddress("localhost", 10000));
                clientSslSocket.startHandshake();
                Assert.assertEquals("TLS_RSA_WITH_AES_128_CBC_SHA256", clientSslSocket.getSession().getCipherSuite());
                checkOutputIsOK(clientSslSocket);
                clientSslSocket.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });
    }

    @Test(expected = UnsupportedOperationException.class)
    public void checkExceptionThrownClientSessionContext() throws Exception {
        SSLContext sslContext = new DynamicSSLContext();
        sslContext.getClientSessionContext();
    }

    @Test(expected = UnsupportedOperationException.class)
    public void checkExceptionThrownServerSessionContext() throws Exception {
        SSLContext sslContext = new DynamicSSLContext();
        sslContext.getServerSessionContext();
    }

    // thorough testing of sslEngine would need a lot of code with socket implementation that is pretty low level
    // it is reasonable to assume that it is being tested anyway since sockets created by SSLSocketFactory seem to always use this SSLEngine
    // here I at least test that the SSLEngine was created with correct host and port
    @Test
    public void smokeTestCorrectSSLEngineIsUsed() throws NoSuchAlgorithmException {
        DynamicSSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLEngine sslEngine = dynamicSSLContext.createSSLEngine("localhost", 10000);
        Assert.assertEquals("localhost", sslEngine.getPeerHost());
        Assert.assertEquals(10000, sslEngine.getPeerPort());

        SSLEngine sslEngine2 = dynamicSSLContext.createSSLEngine();
        Assert.assertNull(sslEngine2.getPeerHost());
        Assert.assertEquals(-1, sslEngine2.getPeerPort());
    }

    @Test
    public void smokeTestIntersectionOfCipherSuites() throws NoSuchAlgorithmException {
        DynamicSSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLServerSocketTestInstance testSSLServerSingleCipherSuite =
                new SSLServerSocketTestInstance(RESOURCES + "default-server.keystore.jks", RESOURCES + "default-server.truststore.jks", 10004);
        testSSLServerSingleCipherSuite.setConfiguredEnabledCipherSuites(new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_256_CBC_SHA256"});
        testSSLServerSingleCipherSuite.run();
        AuthenticationContext context = getAuthenticationContext("wildfly-config-dynamic-ssl-test.xml");
        context.run(() -> {
            try {
                SSLSocket clientSslSocket = (SSLSocket) dynamicSSLContext.getSocketFactory().createSocket();
                SSLParameters sslParameters = clientSslSocket.getSSLParameters();
                sslParameters.setCipherSuites(new String[]{"TLS_RSA_WITH_AES_256_CBC_SHA256"});
                clientSslSocket.setSSLParameters(sslParameters);
                clientSslSocket.connect(new InetSocketAddress("localhost", 10000));
                clientSslSocket.startHandshake();
                Assert.assertEquals("TLS_RSA_WITH_AES_256_CBC_SHA256", clientSslSocket.getSession().getCipherSuite());
                checkOutputIsOK(clientSslSocket);
                clientSslSocket.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });
    }

    @Test
    public void testChangingAuthenticationContextsTest() throws NoSuchAlgorithmException {
        DynamicSSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLSocketFactory socketFactory = dynamicSSLContext.getSocketFactory();

        AuthenticationContext.empty().withSsl(MatchRule.ALL.matchPort(10001), () -> DynamicSSLTestUtils
                .createSSLContext(RESOURCES + "client1.keystore.jks", RESOURCES + "client1.truststore.jks", "Elytron")).run(() -> {
            try {
                Socket clientSslSocket = socketFactory.createSocket("localhost", 10001);
                checkOutputIsOK((SSLSocket) clientSslSocket);
                clientSslSocket.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });

        AuthenticationContext.empty().withSsl(MatchRule.ALL.matchPort(10002), () -> DynamicSSLTestUtils
                .createSSLContext(RESOURCES + "client2.keystore.jks", RESOURCES + "client2.truststore.jks", "Elytron")).run(() -> {
            try {
                Socket clientSslSocket = socketFactory.createSocket("localhost", 10002);
                checkOutputIsOK((SSLSocket) clientSslSocket);
                clientSslSocket.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });

        AuthenticationContext.empty().withSsl(MatchRule.ALL.matchPort(10003), () -> DynamicSSLTestUtils
                .createSSLContext(RESOURCES + "client3.keystore.jks", RESOURCES + "client3.truststore.jks", "Elytron")).run(() -> {
            try {
                Socket clientSslSocket = socketFactory.createSocket("localhost", 10003);
                checkOutputIsOK((SSLSocket) clientSslSocket);
                clientSslSocket.close();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
            }
        });
    }

    @Test(expected = IllegalStateException.class)
    public void testThrowAnExceptionWhenLoop() throws NoSuchAlgorithmException {

        DynamicSSLContext dynamicSSLContext = new DynamicSSLContext();
        SSLSocketFactory socketFactory = dynamicSSLContext.getSocketFactory();
        SSLContext previousDefaultSSLContext = SSLContext.getDefault();
        SSLContext.setDefault(dynamicSSLContext);
        AuthenticationContext.empty().withSsl(MatchRule.ALL.matchPort(10000), () -> DynamicSSLTestUtils
                .createSSLContext(RESOURCES + "client1.keystore.jks", RESOURCES + "client1.truststore.jks", "Elytron")).run(() -> {
            try {
                Socket clientSslSocket = socketFactory.createSocket("localhost", 12345);
                checkOutputIsOK((SSLSocket) clientSslSocket);
                clientSslSocket.close();
            } catch (IOException e) {
                Assert.assertEquals("fine", e.getMessage());
            } finally {
                SSLContext.setDefault(previousDefaultSSLContext);
            }
        });
    }


    @Test
    public void testPreconfiguredDefault() throws NoSuchAlgorithmException {
        DynamicSSLContext dynamicSSLContext = new DynamicSSLContext();
        final AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT =
                AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
        try {

            AuthenticationContext contextWithConfiguredDefault = getAuthenticationContext("wildfly-config-dynamic-ssl-test.xml");
            AuthenticationContext contextWithoutConfiguredDefault = getAuthenticationContext("wildfly-config-dynamic-ssl-test-without-default-sslcontext.xml");

            SSLContext preconfiguredDefault = AUTH_CONTEXT_CLIENT.getDefaultSSLContext(contextWithConfiguredDefault);
            SSLContext jvmDefault = AUTH_CONTEXT_CLIENT.getDefaultSSLContext(contextWithoutConfiguredDefault);

            Assert.assertEquals(jvmDefault, SSLContext.getDefault());

            // AuthenticationContextConfigurationClient always creates new instances. So we can check that preconfigured SSLContext was received
            // correctly by successful connection to the host and port that requires that ssl context.

            // We first test configured default by using createSocket(host, port) with port not specified in any match rules.
            // Second we use empty createSocket method that will later connect to the same host and port successfully.

            contextWithConfiguredDefault.run(() -> {
                        try {
                            SSLSocket clientSslSocket1 = (SSLSocket) preconfiguredDefault.getSocketFactory().createSocket("localhost", 10000);
                            clientSslSocket1.setReuseAddress(true);
                            checkOutputIsOK(clientSslSocket1);
                            clientSslSocket1.close();
                            //preconfigured default will be used to create socket since no host and port was provided
                            SSLSocket clientSocketWithDynamicDefaultSSLContext = (SSLSocket) dynamicSSLContext.getSocketFactory().createSocket();
                            clientSocketWithDynamicDefaultSSLContext.setUseClientMode(true);
                            // configured default is the one which passes for this host and port
                            clientSocketWithDynamicDefaultSSLContext.connect(new InetSocketAddress("localhost", 10000));
                            checkOutputIsOK(clientSocketWithDynamicDefaultSSLContext);
                            clientSocketWithDynamicDefaultSSLContext.close();
                        } catch (Exception e) {
                            Assert.assertEquals("fine", e.getMessage());
                        }
                    }
            );

        } catch (Exception e) {
            Assert.assertEquals("fine", e.getMessage());
        }
    }

    private void checkOutputIsOK(SSLSocket clientSslSocket) throws IOException {
        PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(clientSslSocket.getOutputStream()));
        printWriter.println("Client Hello");
        printWriter.flush();
        InputStream inputStream = clientSslSocket.getInputStream();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        String line = bufferedReader.readLine().trim();
        Assert.assertEquals(STATUS_OK, line);
    }

    private AuthenticationContext getAuthenticationContext(String path) {
        return doPrivileged((PrivilegedAction<AuthenticationContext>) () -> {
            URL config = getClass().getResource(path);
            try {
                return ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI()).create();
            } catch (Exception e) {
                Assert.assertEquals("fine", e.getMessage());
                throw new InvalidAuthenticationConfigurationException(e);
            }
        });
    }
}
