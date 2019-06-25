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
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.security.AccessController;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
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
import javax.security.auth.x500.X500Principal;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.permission.PermissionVerifier;
import org.wildfly.security.ssl.SSLContextBuilder;
import org.wildfly.security.ssl.SSLUtils;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;

/**
 * Tests a successful SSL authentication with key store masked password in client xml configuration
 *
 * @author <a href="mailto:aabdelsa@redhat.com">Ashley Abdel-Sayed</a>
 */

public class MaskedPasswordSSLAuthenticationTest {
    private static final boolean IS_IBM = System.getProperty("java.vendor").contains("IBM");
    private static final char[] PASSWORD = "Elytron".toCharArray();
    private static final String CA_JKS_LOCATION = "./target/test-classes/ca/jks";
    private static final File WORKING_DIR_CA = new File(CA_JKS_LOCATION);
    private static final File LADYBIRD_FILE = new File(WORKING_DIR_CA,"ladybird.keystore");
    private static final File SCARAB_FILE = new File(WORKING_DIR_CA,"scarab.keystore");
    private static final File BEETLES_FILE = new File(WORKING_DIR_CA,"beetles.keystore");
    private static final File TRUST_FILE = new File(WORKING_DIR_CA,"ca.truststore");

    /**
     * Get the key manager backed by the specified key store.
     *
     * @param keystorePath the path to the keystore with X509 private key
     * @return the initialised key manager.
     */
    private static X509ExtendedKeyManager getKeyManager(final String keystorePath) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(IS_IBM ? "IbmX509" : "SunX509");
        keyManagerFactory.init(createKeyStore(keystorePath), PASSWORD);

        for (KeyManager current : keyManagerFactory.getKeyManagers()) {
            if (current instanceof X509ExtendedKeyManager) {
                return (X509ExtendedKeyManager) current;
            }
        }

        throw new IllegalStateException("Unable to obtain X509ExtendedKeyManager.");
    }

    private static TrustManagerFactory getTrustManagerFactory() throws Exception {
        return TrustManagerFactory.getInstance("PKIX");
    }

    /**
     * Get the trust manager that trusts all certificates signed by the certificate authority.
     *
     * @return the trust manager that trusts all certificates signed by the certificate authority.
     * @throws KeyStoreException
     */
    private static X509TrustManager getCATrustManager() throws Exception {
        TrustManagerFactory trustManagerFactory = getTrustManagerFactory();
        trustManagerFactory.init(createKeyStore("/ca/jks/ca.truststore"));

        for (TrustManager current : trustManagerFactory.getTrustManagers()) {
            if (current instanceof X509TrustManager) {
                return (X509TrustManager) current;
            }
        }

        throw new IllegalStateException("Unable to obtain X509TrustManager.");
    }

    private static KeyStore createKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null,null);
        return ks;
    }

    private static KeyStore createKeyStore(final String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        try (InputStream caTrustStoreFile = MaskedPasswordSSLAuthenticationTest.class.getResourceAsStream(path)) {
            keyStore.load(caTrustStoreFile, PASSWORD);
        }

        return keyStore;
    }

    private static void createTemporaryKeyStoreFile(KeyStore keyStore, File outputFile, char[] password) throws Exception {
        if (!outputFile.exists()) {
            outputFile.createNewFile();
        }
        try (FileOutputStream fos = new FileOutputStream(outputFile)){
            keyStore.store(fos, password);
        }
    }

    private static SecurityDomain getKeyStoreBackedSecurityDomain(String keyStorePath) throws Exception {
        SecurityRealm securityRealm = new KeyStoreBackedSecurityRealm(createKeyStore(keyStorePath));

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
        WORKING_DIR_CA.mkdirs();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        X500Principal issuerDN = new X500Principal("CN=Elytron CA, ST=Elytron, C=UK, EMAILADDRESS=elytron@wildfly.org, O=Root Certificate Authority");

        KeyStore ladybirdKeyStore = createKeyStore();
        KeyStore scarabKeyStore = createKeyStore();
        KeyStore beetlesKeyStore = createKeyStore();
        KeyStore trustStore = createKeyStore();

        // Generates the issuer certificate and adds it to the keystores
        SelfSignedX509CertificateAndSigningKey issuerSelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(issuerDN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA1withRSA")
                .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
                .build();
        X509Certificate issuerCertificate = issuerSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        ladybirdKeyStore.setCertificateEntry("ca", issuerCertificate);
        scarabKeyStore.setCertificateEntry("ca", issuerCertificate);
        trustStore.setCertificateEntry("mykey",issuerCertificate);

        // Generates certificate and keystore for Ladybird
        KeyPair ladybirdKeys = keyPairGenerator.generateKeyPair();
        PrivateKey ladybirdSigningKey = ladybirdKeys.getPrivate();
        PublicKey ladybirdPublicKey = ladybirdKeys.getPublic();

        X509Certificate ladybirdCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Ladybird"))
                .setSignatureAlgorithmName("SHA1withRSA")
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
                .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Scarab"))
                .setSignatureAlgorithmName("SHA1withRSA")
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
        createTemporaryKeyStoreFile(ladybirdKeyStore, LADYBIRD_FILE, PASSWORD);
        createTemporaryKeyStoreFile(scarabKeyStore, SCARAB_FILE, PASSWORD);
        createTemporaryKeyStoreFile(beetlesKeyStore, BEETLES_FILE, PASSWORD);
        createTemporaryKeyStoreFile(trustStore, TRUST_FILE, PASSWORD);

    }

    @AfterClass
    public static void afterTest() {
        LADYBIRD_FILE.delete();
        SCARAB_FILE.delete();
        BEETLES_FILE.delete();
        TRUST_FILE.delete();
        WORKING_DIR_CA.delete();
    }

    @Test
    public void testTwoWay() throws Exception {
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain("/ca/jks/beetles.keystore"))
                .setKeyManager(getKeyManager("/ca/jks/scarab.keystore"))
                .setTrustManager(getCATrustManager())
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
