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
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
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

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemWriter;
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
import org.wildfly.security.x500.X500AttributePrincipalDecoder;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

/**
 * Simple test case to test authentication occurring during the establishment of an {@link SSLSession}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SSLAuthenticationTest {

    private static final boolean IS_IBM = System.getProperty("java.vendor").contains("IBM");
    private static final char[] PASSWORD = "Elytron".toCharArray();
    private static final String CA_JKS_LOCATION = "./target/test-classes/ca/jks";
    private static final String ICA_JKS_LOCATION = "./target/test-classes/ica/jks";
    private static final String CA_CRL_LOCATION = "./target/test-classes/ca/crl";
    private static final String ICA_CRL_LOCATION = "./target/test-classes/ica/crl";
    private static File ladybirdFile = null;
    private static File scarabFile = null;
    private static File dungFile = null;
    private static File fireflyFile = null;
    private static File beetlesFile = null;
    private static File trustFile = null;
    private static File shortwingedFile = null;
    private static File roveFile = null;
    private static File caBlankPemCrl = null;
    private static File icaBlankPemCrl = null;
    private static File blankBlankPemCrl = null;
    private static File fireflyRevokedPemCrl = null;
    private static File icaRevokedPemCrl = null;
    private static File workingDirCA = null;
    private static File workingDirICA = null;
    private static File workingDirCACRL = null;
    private static File workingDirICACRL = null;

    /**
     * Get the key manager backed by the specified key store.
     *
     * @param keystorePath the path to the keystore with X509 private key
     * @return the initialised key manager.
     */
    private static X509ExtendedKeyManager getKeyManager(final String keystorePath) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(IS_IBM ? "IbmX509" : "SunX509");
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
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(IS_IBM ? "IbmX509" : "SunX509");
        trustManagerFactory.init(loadKeyStore("/ca/jks/ca.truststore"));

        for (TrustManager current : trustManagerFactory.getTrustManagers()) {
            if (current instanceof X509TrustManager) {
                return (X509TrustManager) current;
            }
        }

        throw new IllegalStateException("Unable to obtain X509TrustManager.");
    }

    private static KeyStore loadKeyStore() throws Exception{
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null,null);
        return ks;
    }

    private static KeyStore loadKeyStore(final String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
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

    private static void createKeyStores(File ladybirdFile, File scarabFile, File dungFile, File fireflyFile, File beetlesFile, File trustFile, File shortwingedFile, File roveFile, File caBlankPemCrl, File icaBlankPemCrl, File blankBlankPemCrl, File fireflyRevokedPemCrl, File icaRevokedPemCrl) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        X500Principal issuerDN = new X500Principal("CN=Elytron CA, ST=Elytron, C=UK, EMAILADDRESS=elytron@wildfly.org, O=Root Certificate Authority");
        X500Principal intermediateIssuerDN = new X500Principal("CN=Elytron ICA, ST=Elytron, C=UK, O=Intermediate Certificate Authority");
        X500Principal ladybirdDN = new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Ladybird");
        X500Principal scarabDN = new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Scarab");
        X500Principal dungDN = new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Dung");
        X500Principal fireflyDN = new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly");
        X500Principal roveDN = new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Rove");

        KeyStore ladybirdKeyStore = loadKeyStore();
        KeyStore scarabKeyStore = loadKeyStore();
        KeyStore dungKeyStore = loadKeyStore();
        KeyStore fireflyKeyStore = loadKeyStore();
        KeyStore beetlesKeyStore = loadKeyStore();
        KeyStore trustStore = loadKeyStore();
        KeyStore shortwingedKeyStore = loadKeyStore();
        KeyStore roveKeyStore = loadKeyStore();

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
        dungKeyStore.setCertificateEntry("ca", issuerCertificate);
        fireflyKeyStore.setCertificateEntry("ca", issuerCertificate);
        trustStore.setCertificateEntry("mykey",issuerCertificate);

        // Generates the intermediate issuer certificate
        KeyPair intermediateIssuerKeys = keyPairGenerator.generateKeyPair();
        PrivateKey intermediateIssuerSigningKey = intermediateIssuerKeys.getPrivate();
        PublicKey intermediateIssuerPublicKey = intermediateIssuerKeys.getPublic();

        X509Certificate intermediateIssuerCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(intermediateIssuerDN)
                .setSignatureAlgorithmName("SHA1withRSA")
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
                .setSubjectDn(scarabDN)
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(scarabPublicKey)
                .setSerialNumber(new BigInteger("4"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .build();
        scarabKeyStore.setKeyEntry("scarab", scarabSigningKey, PASSWORD, new X509Certificate[]{scarabCertificate,issuerCertificate});

        // Generates certificate and keystore for Dung
        KeyPair dungKeys = keyPairGenerator.generateKeyPair();
        PrivateKey dungSigningKey = dungKeys.getPrivate();
        PublicKey dungPublicKey = dungKeys.getPublic();

        X509Certificate dungCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(dungDN)
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(dungPublicKey)
                .setSerialNumber(new BigInteger("2"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .build();
        dungKeyStore.setKeyEntry("dung", dungSigningKey, PASSWORD, new X509Certificate[]{dungCertificate,issuerCertificate});

        // Generates certificate and keystore for Firefly
        KeyPair fireflyKeys = keyPairGenerator.generateKeyPair();
        PrivateKey fireflySigningKey = fireflyKeys.getPrivate();
        PublicKey fireflyPublicKey = fireflyKeys.getPublic();

        X509Certificate fireflyCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(fireflyDN)
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(fireflyPublicKey)
                .setSerialNumber(new BigInteger("1"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .build();
        fireflyKeyStore.setKeyEntry("firefly", fireflySigningKey, PASSWORD, new X509Certificate[]{fireflyCertificate,issuerCertificate});

        // Generates certificate and keystore for Rove
        KeyPair roveKeys = keyPairGenerator.generateKeyPair();
        PrivateKey roveSigningKey = roveKeys.getPrivate();
        PublicKey rovePublicKey = roveKeys.getPublic();

        X509Certificate roveCertificate = new X509CertificateBuilder()
                .setIssuerDn(intermediateIssuerDN)
                .setSubjectDn(roveDN)
                .setSignatureAlgorithmName("SHA256withRSA")
                .setSigningKey(intermediateIssuerSigningKey)
                .setPublicKey(rovePublicKey)
                .setSerialNumber(new BigInteger("100"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .build();
        roveKeyStore.setKeyEntry("rove", roveSigningKey, PASSWORD, new X509Certificate[]{roveCertificate,intermediateIssuerCertificate,issuerCertificate});

        // Adds trusted certs for beetles
        beetlesKeyStore.setCertificateEntry("ladybird", ladybirdCertificate);
        beetlesKeyStore.setCertificateEntry("scarab", scarabCertificate);
        beetlesKeyStore.setCertificateEntry("dung", dungCertificate);
        beetlesKeyStore.setCertificateEntry("firefly", fireflyCertificate);

        // Adds trusted cert for shortwinged
        shortwingedKeyStore.setCertificateEntry("rove", roveCertificate);

        // Used for all CRLs
        Calendar calendar = Calendar.getInstance();
        Date currentDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date nextYear = calendar.getTime();
        calendar.add(Calendar.YEAR, -1);
        calendar.add(Calendar.SECOND, -30);
        Date revokeDate = calendar.getTime();

        // Creates the CRL for ca/crl/blank.pem
        X509v2CRLBuilder caBlankCrlBuilder = new X509v2CRLBuilder(
                convertSunStyleToBCStyle(intermediateIssuerCertificate.getIssuerDN()),
                currentDate
        );
        X509CRLHolder caBlankCrlHolder = caBlankCrlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder("SHA1withRSA")
                        .setProvider("BC")
                        .build(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
        );

        // Creates the CRL for ica/crl/blank.pem
        X509v2CRLBuilder icaBlankCrlBuilder = new X509v2CRLBuilder(
                convertSunStyleToBCStyle(intermediateIssuerDN),
                currentDate
        );
        X509CRLHolder icaBlankCrlHolder = icaBlankCrlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder("SHA256withRSA")
                        .setProvider("BC")
                        .build(intermediateIssuerSigningKey)
        );

        // Creates the CRL for firefly-revoked.pem
        X509v2CRLBuilder fireflyRevokedCrlBuilder = new X509v2CRLBuilder(
                convertSunStyleToBCStyle(issuerCertificate.getSubjectDN()),
                currentDate
        );
        fireflyRevokedCrlBuilder.addCRLEntry(
                new BigInteger("1"),
                revokeDate,
                CRLReason.unspecified
        );
        X509CRLHolder fireflyRevokedCrlHolder = fireflyRevokedCrlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder("SHA1withRSA")
                        .setProvider("BC")
                        .build(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
        );

        // Creates the CRL for ica-revoked.pem
        X509v2CRLBuilder icaRevokedCrlBuilder = new X509v2CRLBuilder(
                convertSunStyleToBCStyle(issuerCertificate.getSubjectDN()),
                currentDate
        );
        icaRevokedCrlBuilder.addCRLEntry(
                new BigInteger("6"),
                revokeDate,
                CRLReason.unspecified
        );
        X509CRLHolder icaRevokedCrlHolder = icaRevokedCrlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder("SHA1withRSA")
                        .setProvider("BC")
                        .build(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
        );

        // Create the temporary files
        createTemporaryKeyStoreFile(ladybirdKeyStore, ladybirdFile, PASSWORD);
        createTemporaryKeyStoreFile(scarabKeyStore, scarabFile, PASSWORD);
        createTemporaryKeyStoreFile(dungKeyStore, dungFile, PASSWORD);
        createTemporaryKeyStoreFile(fireflyKeyStore, fireflyFile, PASSWORD);
        createTemporaryKeyStoreFile(beetlesKeyStore, beetlesFile, PASSWORD);
        createTemporaryKeyStoreFile(trustStore, trustFile, PASSWORD);
        createTemporaryKeyStoreFile(shortwingedKeyStore, shortwingedFile, PASSWORD);
        createTemporaryKeyStoreFile(roveKeyStore, roveFile, PASSWORD);

        PemWriter caBlankCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(caBlankPemCrl)));
        PemWriter icaBlankCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(icaBlankPemCrl)));
        PemWriter blankBlankCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(blankBlankPemCrl)));
        PemWriter fireflyRevokedCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(fireflyRevokedPemCrl)));
        PemWriter icaRevokedCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(icaRevokedPemCrl)));

        caBlankCrlOutput.writeObject(new MiscPEMGenerator(caBlankCrlHolder));
        icaBlankCrlOutput.writeObject(new MiscPEMGenerator(icaBlankCrlHolder));
        blankBlankCrlOutput.writeObject(new MiscPEMGenerator(icaBlankCrlHolder));
        blankBlankCrlOutput.writeObject(new MiscPEMGenerator(caBlankCrlHolder));
        fireflyRevokedCrlOutput.writeObject(new MiscPEMGenerator(fireflyRevokedCrlHolder));
        icaRevokedCrlOutput.writeObject(new MiscPEMGenerator(icaRevokedCrlHolder));

        caBlankCrlOutput.close();
        icaBlankCrlOutput.close();
        blankBlankCrlOutput.close();
        fireflyRevokedCrlOutput.close();
        icaRevokedCrlOutput.close();
    }

    private static org.bouncycastle.asn1.x500.X500Name convertSunStyleToBCStyle(Principal dn){
        String dnName = dn.getName();
        String[] dnComponents = dnName.split(", ");
        StringBuilder dnBuffer = new StringBuilder(dnName.length());

        dnBuffer.append(dnComponents[dnComponents.length-1]);
        for(int i = dnComponents.length-2; i >= 0; i--){
            dnBuffer.append(',');
            dnBuffer.append(dnComponents[i]);
        }

        return new X500Name(dnBuffer.toString());
    }

    @BeforeClass
    public static void beforeTest() throws Exception{
        workingDirCA = new File(CA_JKS_LOCATION);
        if (workingDirCA.exists() == false) {
            workingDirCA.mkdirs();
        }
        workingDirICA = new File(ICA_JKS_LOCATION);
        if (workingDirICA.exists() == false) {
            workingDirICA.mkdirs();
        }
        workingDirCACRL = new File(CA_CRL_LOCATION);
        if (workingDirCACRL.exists() == false) {
            workingDirCACRL.mkdirs();
        }
        workingDirICACRL = new File(ICA_CRL_LOCATION);
        if (workingDirICACRL.exists() == false) {
            workingDirICACRL.mkdirs();
        }

        ladybirdFile = new File(workingDirCA,"ladybird.keystore");
        scarabFile = new File(workingDirCA,"scarab.keystore");
        dungFile = new File(workingDirCA,"dung.keystore");
        fireflyFile = new File(workingDirCA,"firefly.keystore");
        beetlesFile = new File(workingDirCA,"beetles.keystore");
        trustFile = new File(workingDirCA,"ca.truststore");
        shortwingedFile = new File(workingDirICA, "shortwinged.keystore");
        roveFile = new File(workingDirICA, "rove.keystore");
        caBlankPemCrl = new File(workingDirCACRL, "blank.pem");
        icaBlankPemCrl = new File(workingDirICACRL, "blank.pem");
        blankBlankPemCrl = new File(workingDirICACRL, "blank-blank.pem");
        fireflyRevokedPemCrl = new File(workingDirCACRL, "firefly-revoked.pem");
        icaRevokedPemCrl = new File(workingDirCACRL, "ica-revoked.pem");

        createKeyStores(ladybirdFile, scarabFile, dungFile, fireflyFile, beetlesFile, trustFile, shortwingedFile, roveFile, caBlankPemCrl, icaBlankPemCrl, blankBlankPemCrl, fireflyRevokedPemCrl, icaRevokedPemCrl);
    }


    @AfterClass
    public static void afterTest(){
        ladybirdFile.delete();
        ladybirdFile = null;
        scarabFile.delete();
        scarabFile = null;
        dungFile.delete();
        dungFile = null;
        fireflyFile.delete();
        fireflyFile = null;
        beetlesFile.delete();
        beetlesFile = null;
        trustFile.delete();
        trustFile = null;
        shortwingedFile.delete();
        shortwingedFile = null;
        roveFile.delete();
        roveFile = null;
        workingDirCA.delete();
        workingDirCA = null;
        workingDirICA.delete();
        workingDirICA = null;
        caBlankPemCrl.delete();
        caBlankPemCrl = null;
        icaBlankPemCrl.delete();
        icaBlankPemCrl = null;
        blankBlankPemCrl.delete();
        blankBlankPemCrl = null;
        fireflyRevokedPemCrl.delete();
        fireflyRevokedPemCrl = null;
        icaRevokedPemCrl.delete();
        icaRevokedPemCrl = null;
        workingDirCACRL.delete();
        workingDirCACRL = null;
        workingDirICACRL.delete();
        workingDirICACRL = null;
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
        System.setProperty("wildfly.config.url", SSLAuthenticationTest.class.getResource("wildfly-ssl-test-config-v1_1.xml").toExternalForm());
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
