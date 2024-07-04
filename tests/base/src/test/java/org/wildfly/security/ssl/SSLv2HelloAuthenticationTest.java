/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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
import static org.junit.Assert.assertTrue;

import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
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
import javax.security.auth.x500.X500Principal;

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
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

/**
 * Simple test cases to test two-way and one-way SSL using SSLv2Hello.
 *
 * @author <a href="mailto:szaldana@redhat">Sonia Zaldana</a>
 */
public class SSLv2HelloAuthenticationTest {

    private static final char[] PASSWORD = "Elytron".toCharArray();
    private static final String CA_JKS_LOCATION = "./target/test-classes/ca/pkcs12";
    private static File ladybirdFile = null;
    private static File scarabFile = null;
    private static File beetlesFile = null;
    private static File trustFile = null;
    private static File workingDirCA = null;
    private static SecurityRealm securityRealm = null;
    private static SecurityDomain securityDomain = null;
    public static String disabledAlgorithms;

    @BeforeClass
    public static void setUp() throws Exception{
        disabledAlgorithms = Security.getProperty("jdk.tls.disabledAlgorithms");
        if (disabledAlgorithms != null && (disabledAlgorithms.contains("TLSv1") || disabledAlgorithms.contains("TLSv1.1"))) {
            // reset the disabled algorithms to make sure that the protocols required in this test are available
            Security.setProperty("jdk.tls.disabledAlgorithms", "");
        }

        workingDirCA = new File(CA_JKS_LOCATION);
        if (!workingDirCA.exists()) {
            workingDirCA.mkdirs();
        }

        ladybirdFile = new File(workingDirCA,"ladybird.keystore");
        scarabFile = new File(workingDirCA,"scarab.keystore");
        beetlesFile = new File(workingDirCA,"beetles.keystore");
        trustFile = new File(workingDirCA,"ca.truststore");

        createKeyStores(ladybirdFile, scarabFile, beetlesFile, trustFile);

        securityRealm = new KeyStoreBackedSecurityRealm(loadKeyStore("/ca/pkcs12/beetles.keystore"));

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
    public static void cleanUp(){
        ladybirdFile.delete();
        ladybirdFile = null;
        scarabFile.delete();
        scarabFile = null;
        beetlesFile.delete();
        beetlesFile = null;
        trustFile.delete();
        trustFile = null;
        workingDirCA.delete();
        workingDirCA = null;

        if (disabledAlgorithms != null) {
            Security.setProperty("jdk.tls.disabledAlgorithms", disabledAlgorithms);
        }
    }

    /**
     * Test one way authentication when both the client and the server have
     * SSLv2Hello enabled.
     */
    @Test
    public void testOneWaySSLv2HelloProtocolMatch() throws Exception {
        ArrayList<Protocol> list = new ArrayList<>();
        list.add(Protocol.forName("SSLv2Hello"));
        list.add(Protocol.forName("TLSv1"));

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setKeyManager(getKeyManager("/ca/pkcs12/scarab.keystore"))
                .setProtocolSelector(ProtocolSelector.empty().add(EnumSet.copyOf(list)))
                .build().create();

        String[] enabledProtocols = new String[]{"SSLv2Hello", "TLSv1"};

        SecurityIdentity identity = performConnectionTest(serverContext,
                "protocol://one-way-sslv2hello.org",
                "wildfly-ssl-test-config-v1_6.xml",
                enabledProtocols, // We expect client and server socket to only have SSLv2Hello and TLSv1 enabled
                "TLSv1"); // We expect the negotiated protocol to be TLSv1, as SSLv2Hello is a pseudo-protocol
    }

    /**
     * Test two way authentication when both the client and the server have
     * SSLv2Hello enabled.
     */
    @Test
    public void testTwoWaySSLv2HelloProtocolMatch() throws Exception {
        List<Protocol> list = new ArrayList<>();
        list.add(Protocol.forName("SSLv2Hello"));
        list.add(Protocol.forName("TLSv1"));

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setKeyManager(getKeyManager("/ca/pkcs12/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .setProtocolSelector(ProtocolSelector.empty().add(EnumSet.copyOf(list)))
                .build().create();

        String[] enabledProtocols = new String[]{"SSLv2Hello", "TLSv1"};

        SecurityIdentity identity = performConnectionTest(serverContext,
                "protocol://test-two-way-sslv2hello.org",
                "wildfly-ssl-test-config-v1_6.xml",
                enabledProtocols, // We expect client and server socket to only have SSLv2Hello and TLSv1 enabled
                "TLSv1"); // We expect the negotiated protocol to be TLSv1, as SSLv2Hello is a pseudo-protocol


        assertNotNull(identity);
        assertEquals("Principal Name", "ladybird", identity.getPrincipal().getName());
    }

    /**
     * Verify SSLv2Hello is not enabled in client or server if not explicitly configured.
     * This tests uses the default protocols enabled in Elytron.
     */
    @Test
    public void testTwoWaySSLv2HelloNotEnabled() throws Exception {
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setKeyManager(getKeyManager("/ca/pkcs12/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .build().create();

        String[] enabledProtocols = new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"};

        SecurityIdentity identity = performConnectionTest(serverContext,
                "protocol://two-way-no-sslv2hello.org",
                "wildfly-ssl-test-config-v1_6.xml",
                enabledProtocols, // We expect the default protocols to be enabled i.e. SSLv2Hello should only be enabled if explicitly configured
                "TLSv1.2"); // We expect the negotiated protocol to be the highest version protocol in common

        assertNotNull(identity);
        assertEquals("Principal Name", "ladybird", identity.getPrincipal().getName());
    }

    /**
     * Test two way authentication when the client does not support SSLv2Hello,
     * but the server has SSLv2Hello support enabled.
     */
    @Test
    public void testTwoWaySSLv2HelloNoClientSupport() throws Exception {
        List<Protocol> list = new ArrayList<>();
        list.add(Protocol.forName("SSLv2Hello"));
        list.add(Protocol.forName("TLSv1"));

        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(securityDomain)
                .setKeyManager(getKeyManager("/ca/pkcs12/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .setProtocolSelector(ProtocolSelector.empty().add(EnumSet.copyOf(list)))
                .build().create();

        String[] enabledServerProtocols = new String[]{"SSLv2Hello", "TLSv1"};
        String[] enabledClientProtocols = new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}; // default protocols enabled

        SecurityIdentity identity = performConnectionTest(serverContext,
                "protocol://two-way-no-sslv2hello.org",
                "wildfly-ssl-test-config-v1_6.xml",
                enabledClientProtocols,
                enabledServerProtocols,
                "TLSv1"); // We expect the negotiated protocol to be the highest version protocol in common
        assertNotNull(identity);
        assertEquals("Principal Name", "ladybird", identity.getPrincipal().getName());
    }

    /**
     * Test two way authentication where the client supports SSLv2Hello but the server does not.
     * Handshake should fail.
     */
    @Test
    public void testTwoWaySSlv2HelloNoServerSupport() throws Exception {
            List<Protocol> list = new ArrayList<>();
            list.add(Protocol.forName("TLSv1.1"));

            SSLContext serverContext = new SSLContextBuilder()
                    .setSecurityDomain(securityDomain)
                    .setKeyManager(getKeyManager("/ca/pkcs12/scarab.keystore"))
                    .setTrustManager(getCATrustManager())
                    .setNeedClientAuth(true)
                    .setProtocolSelector(ProtocolSelector.empty().add(EnumSet.copyOf(list)))
                    .build().create();

            String[] serverEnabledProtocols = new String[]{"TLSv1.1"};
            String[] clientEnabledProtocols = new String[]{ "SSLv2Hello", "TLSv1"};

            SecurityIdentity identity = performConnectionTest(serverContext,
                    "protocol://test-two-way-sslv2hello.org",
                    "wildfly-ssl-test-config-v1_6.xml",
                    clientEnabledProtocols,
                    serverEnabledProtocols,
                    "NONE"); // handshake is expected to fail, which in turn returns an empty SSLSession

        assertNull(identity);
    }

    private SecurityIdentity performConnectionTest(SSLContext serverContext, String clientUri, String clientConfigFileName, String[] enabledProtocols, String negotiatedProtocol) throws Exception {
        return performConnectionTest(serverContext, clientUri, clientConfigFileName, enabledProtocols, enabledProtocols, negotiatedProtocol);
    }

    private SecurityIdentity performConnectionTest(SSLContext serverContext, String clientUri, String clientConfigFileName, String[] enabledClientProtocols, String[] enabledServerProtocols,  String negotiatedProtocol) throws Exception {
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
            // Ensure the enabled protocols are the only ones that were configured
            Set<String> serverProtocols = new HashSet<>(Arrays.asList(serverSocket.getEnabledProtocols()));
            Set<String> clientProtocols = new HashSet<>(Arrays.asList(clientSocket.getEnabledProtocols()));
            Set<String> enabledServer = new HashSet<>(Arrays.asList(enabledServerProtocols));
            Set<String> enabledClient = new HashSet<>(Arrays.asList(enabledClientProtocols));

            assertTrue(enabledServer.equals(serverProtocols));
            assertTrue(enabledClient.equals(clientProtocols));

            // Check the negotiated protocol is equal to what we expected
            assertEquals(negotiatedProtocol, serverSession.getProtocol());
            assertEquals(negotiatedProtocol, clientSession.getProtocol());
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
        trustManagerFactory.init(loadKeyStore("/ca/pkcs12/ca.truststore"));

        for (TrustManager current : trustManagerFactory.getTrustManagers()) {
            if (current instanceof X509TrustManager) {
                return (X509TrustManager) current;
            }
        }

        throw new IllegalStateException("Unable to obtain X509TrustManager.");
    }

    private static KeyStore loadKeyStore() throws Exception{
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null,null);
        return ks;
    }

    private static KeyStore loadKeyStore(final String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream caTrustStoreFile = SSLAuthenticationTest.class.getResourceAsStream(path)) {
            keyStore.load(caTrustStoreFile, PASSWORD);
        }

        return keyStore;
    }

    private static void createTemporaryKeyStoreFile(KeyStore keyStore, File outputFile, char[] password) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(outputFile)){
            keyStore.store(fos, password);
        }
    }

    private static void createKeyStores(File ladybirdFile, File scarabFile, File beetlesFile, File trustFile) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        X500Principal issuerDN = new X500Principal("CN=Elytron CA, ST=Elytron, C=UK, EMAILADDRESS=elytron@wildfly.org, O=Root Certificate Authority");
        X500Principal intermediateIssuerDN = new X500Principal("CN=Elytron ICA, ST=Elytron, C=UK, O=Intermediate Certificate Authority");
        X500Principal ladybirdDN = new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Ladybird");
        X500Principal scarabDN = new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Scarab");

        KeyStore ladybirdKeyStore = loadKeyStore();
        KeyStore scarabKeyStore = loadKeyStore();
        KeyStore beetlesKeyStore = loadKeyStore();
        KeyStore trustStore = loadKeyStore();

        // Generates the issuer certificate and adds it to the keystores
        SelfSignedX509CertificateAndSigningKey issuerSelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(issuerDN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA256withRSA")
                .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
                .build();
        X509Certificate issuerCertificate = issuerSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        ladybirdKeyStore.setCertificateEntry("ca", issuerCertificate);
        scarabKeyStore.setCertificateEntry("ca", issuerCertificate);
        trustStore.setCertificateEntry("mykey",issuerCertificate);

        // Generates the intermediate issuer certificate
        KeyPair intermediateIssuerKeys = keyPairGenerator.generateKeyPair();
        PrivateKey intermediateIssuerSigningKey = intermediateIssuerKeys.getPrivate();
        PublicKey intermediateIssuerPublicKey = intermediateIssuerKeys.getPublic();

        X509Certificate intermediateIssuerCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(intermediateIssuerDN)
                .setSignatureAlgorithmName("SHA256withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(intermediateIssuerPublicKey)
                .setSerialNumber(new BigInteger("6"))
                .addExtension(new BasicConstraintsExtension(false, true, 0))
                .build();

        // Generates certificate and keystore for Ladybird
        KeyPair ladybirdKeys = keyPairGenerator.generateKeyPair();
        PrivateKey ladybirdSigningKey = ladybirdKeys.getPrivate();
        PublicKey ladybirdPublicKey = ladybirdKeys.getPublic();

        X509Certificate ladybirdCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(ladybirdDN)
                .setSignatureAlgorithmName("SHA256withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(ladybirdPublicKey)
                .setSerialNumber(new BigInteger("3"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .build();
        ladybirdKeyStore.setKeyEntry("ladybird", ladybirdSigningKey, PASSWORD, new X509Certificate[]{ladybirdCertificate,issuerCertificate});

        // Generates certificate and keystore for Scarab
        KeyPair scarabKeys = keyPairGenerator.generateKeyPair();
        PrivateKey scarabSigningKey = scarabKeys.getPrivate();
        PublicKey scarabPublicKey = scarabKeys.getPublic();

        X509Certificate scarabCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(scarabDN)
                .setSignatureAlgorithmName("SHA256withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(scarabPublicKey)
                .setSerialNumber(new BigInteger("4"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .build();
        scarabKeyStore.setKeyEntry("scarab", scarabSigningKey, PASSWORD, new X509Certificate[]{scarabCertificate,issuerCertificate});

        // Adds trusted certs for beetles
        beetlesKeyStore.setCertificateEntry("ladybird", ladybirdCertificate);
        beetlesKeyStore.setCertificateEntry("scarab", scarabCertificate);

        // Create the temporary files
        createTemporaryKeyStoreFile(ladybirdKeyStore, ladybirdFile, PASSWORD);
        createTemporaryKeyStoreFile(scarabKeyStore, scarabFile, PASSWORD);
        createTemporaryKeyStoreFile(beetlesKeyStore, beetlesFile, PASSWORD);
        createTemporaryKeyStoreFile(trustStore, trustFile, PASSWORD);
    }

    private void safeClose(Closeable closeable) {
        try {
            closeable.close();
        } catch (Exception ignored) {}
    }
}
