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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.wildfly.security.x500.X500.OID_AD_OCSP;
import static org.wildfly.security.x500.X500.OID_KP_OCSP_SIGNING;

import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketException;
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
import java.util.Collections;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
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
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.auth.realm.KeyStoreBackedSecurityRealm;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.permission.PermissionVerifier;

import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;
import org.wildfly.security.x500.cert.AccessDescription;
import org.wildfly.security.x500.cert.AuthorityInformationAccessExtension;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.ExtendedKeyUsageExtension;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

/**
 * Simple test case to test authentication occurring during the establishment of an {@link SSLSession}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
// has dependency on wildfly-elytron-client, wildfly-elytron-x500-cert, wildfly-elytron-realm, wildly-elytron-x500-deprecated
public class SSLAuthenticationTest {

    private static final boolean IS_IBM = System.getProperty("java.vendor").contains("IBM");
    private static final int OCSP_PORT = 4854;
    private final int TESTING_PORT = 18201;
    private static final char[] PASSWORD = "Elytron".toCharArray();
    private static final String CA_JKS_LOCATION = "./target/test-classes/ca/jks";
    private static final String ICA_JKS_LOCATION = "./target/test-classes/ica/jks";
    private static final String CA_CRL_LOCATION = "./target/test-classes/ca/crl";
    private static final String ICA_CRL_LOCATION = "./target/test-classes/ica/crl";
    private static final File WORKING_DIR_CA = new File(CA_JKS_LOCATION);
    private static final File WORKING_DIR_ICA =  new File(ICA_JKS_LOCATION);
    private static final File WORKING_DIR_CACRL = new File(CA_CRL_LOCATION);
    private static final File WORKING_DIR_ICACRL = new File(ICA_CRL_LOCATION);
    private static final File LADYBIRD_FILE = new File(WORKING_DIR_CA,"ladybird.keystore");
    private static final File SCARAB_FILE = new File(WORKING_DIR_CA,"scarab.keystore");
    private static final File DUNG_FILE = new File(WORKING_DIR_CA,"dung.keystore");
    private static final File FIREFLY_FILE = new File(WORKING_DIR_CA,"firefly.keystore");
    private static final File OCSP_RESPONDER_FILE = new File(WORKING_DIR_CA,"ocsp-responder.keystore");
    private static final File OCSP_CHECKED_GOOD_FILE = new File(WORKING_DIR_CA,"ocsp-checked-good.keystore");
    private static final File OCSP_CHECKED_REVOKED_FILE = new File(WORKING_DIR_CA,"ocsp-checked-revoked.keystore");
    private static final File OCSP_CHECKED_UNKNOWN_FILE = new File(WORKING_DIR_CA,"ocsp-checked-unknown.keystore");
    private static final File BEETLES_FILE = new File(WORKING_DIR_CA,"beetles.keystore");
    private static final File TRUST_FILE = new File(WORKING_DIR_CA,"ca.truststore");
    private static final File SHORTWINGED_FILE = new File(WORKING_DIR_ICA, "shortwinged.keystore");
    private static final File ROVE_FILE = new File(WORKING_DIR_ICA, "rove.keystore");
    private static final File CA_BLANK_PEM_CRL = new File(WORKING_DIR_CACRL, "blank.pem");
    private static final File ICA_BLANK_PEM_CRL = new File(WORKING_DIR_ICACRL, "blank.pem");
    private static final File BLANK_BLANK_PEM_CRL = new File(WORKING_DIR_ICACRL, "blank-blank.pem");
    private static final File FIREFLY_REVOKED_PEM_CRL = new File(WORKING_DIR_CACRL, "firefly-revoked.pem");
    private static final File ICA_REVOKED_PEM_CRL = new File(WORKING_DIR_CACRL, "ica-revoked.pem");
    private static TestingOcspServer ocspServer = null;
    private static X509Certificate ocspResponderCertificate;

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
        try (InputStream caTrustStoreFile = SSLAuthenticationTest.class.getResourceAsStream(path)) {
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
        WORKING_DIR_CACRL.mkdirs();
        WORKING_DIR_ICA.mkdirs();
        WORKING_DIR_ICACRL.mkdirs();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        X500Principal issuerDN = new X500Principal("CN=Elytron CA, ST=Elytron, C=UK, EMAILADDRESS=elytron@wildfly.org, O=Root Certificate Authority");
        X500Principal intermediateIssuerDN = new X500Principal("CN=Elytron ICA, ST=Elytron, C=UK, O=Intermediate Certificate Authority");

        KeyStore ladybirdKeyStore = createKeyStore();
        KeyStore scarabKeyStore = createKeyStore();
        KeyStore dungKeyStore = createKeyStore();
        KeyStore fireflyKeyStore = createKeyStore();
        KeyStore beetlesKeyStore = createKeyStore();
        KeyStore trustStore = createKeyStore();
        KeyStore shortwingedKeyStore = createKeyStore();
        KeyStore roveKeyStore = createKeyStore();

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
                .addExtension(new BasicConstraintsExtension(false, true, -1))
                .addExtension(new AuthorityInformationAccessExtension(Collections.singletonList(
                        new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_PORT + "/ocsp"))
                )))
                .build();

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

        // Generates certificate and keystore for Dung
        KeyPair dungKeys = keyPairGenerator.generateKeyPair();
        PrivateKey dungSigningKey = dungKeys.getPrivate();
        PublicKey dungPublicKey = dungKeys.getPublic();

        X509Certificate dungCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Dung"))
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
                .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly"))
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
                .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Rove"))
                .setSignatureAlgorithmName("SHA256withRSA")
                .setSigningKey(intermediateIssuerSigningKey)
                .setPublicKey(rovePublicKey)
                .setSerialNumber(new BigInteger("100"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .build();
        roveKeyStore.setKeyEntry("rove", roveSigningKey, PASSWORD, new X509Certificate[]{roveCertificate,intermediateIssuerCertificate,issuerCertificate});

        // Generates certificate and keystore for OCSP responder
        KeyPair ocspResponderKeys = keyPairGenerator.generateKeyPair();
        PrivateKey ocspResponderSigningKey = ocspResponderKeys.getPrivate();
        PublicKey ocspResponderPublicKey = ocspResponderKeys.getPublic();

        ocspResponderCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=OcspResponder"))
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(ocspResponderPublicKey)
                .setSerialNumber(new BigInteger("15"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .addExtension(new ExtendedKeyUsageExtension(false, Collections.singletonList(OID_KP_OCSP_SIGNING)))
                .build();
        KeyStore ocspResponderKeyStore = createKeyStore();
        ocspResponderKeyStore.setCertificateEntry("ca", issuerCertificate);
        ocspResponderKeyStore.setKeyEntry("ocspResponder", ocspResponderSigningKey, PASSWORD, new X509Certificate[]{ocspResponderCertificate, issuerCertificate});
        createTemporaryKeyStoreFile(ocspResponderKeyStore, OCSP_RESPONDER_FILE, PASSWORD);

        // Generates GOOD certificate referencing the OCSP responder
        KeyPair ocspCheckedGoodKeys = keyPairGenerator.generateKeyPair();
        PrivateKey ocspCheckedGoodSigningKey = ocspCheckedGoodKeys.getPrivate();
        PublicKey ocspCheckedGoodPublicKey = ocspCheckedGoodKeys.getPublic();

        X509Certificate ocspCheckedGoodCertificate = new X509CertificateBuilder()
                .setIssuerDn(intermediateIssuerDN)
                .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=ocspCheckedGood"))
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(intermediateIssuerSigningKey)
                .setPublicKey(ocspCheckedGoodPublicKey)
                .setSerialNumber(new BigInteger("20"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .addExtension(new AuthorityInformationAccessExtension(Collections.singletonList(
                        new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_PORT + "/ocsp"))
                )))
                .build();
        KeyStore ocspCheckedGoodKeyStore = createKeyStore();
        ocspCheckedGoodKeyStore.setCertificateEntry("ca", issuerCertificate);
        ocspCheckedGoodKeyStore.setCertificateEntry("ca2", intermediateIssuerCertificate);
        ocspCheckedGoodKeyStore.setKeyEntry("checked", ocspCheckedGoodSigningKey, PASSWORD, new X509Certificate[]{ocspCheckedGoodCertificate, intermediateIssuerCertificate, issuerCertificate});
        createTemporaryKeyStoreFile(ocspCheckedGoodKeyStore, OCSP_CHECKED_GOOD_FILE, PASSWORD);

        // Generates REVOKED certificate referencing the OCSP responder
        KeyPair ocspCheckedRevokedKeys = keyPairGenerator.generateKeyPair();
        PrivateKey ocspCheckedRevokedSigningKey = ocspCheckedRevokedKeys.getPrivate();
        PublicKey ocspCheckedRevokedPublicKey = ocspCheckedRevokedKeys.getPublic();

        X509Certificate ocspCheckedRevokedCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=ocspCheckedRevoked"))
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(ocspCheckedRevokedPublicKey)
                .setSerialNumber(new BigInteger("17"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .addExtension(new AuthorityInformationAccessExtension(Collections.singletonList(
                        new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_PORT + "/ocsp"))
                )))
                .build();
        KeyStore ocspCheckedRevokedKeyStore = createKeyStore();
        ocspCheckedRevokedKeyStore.setCertificateEntry("ca", issuerCertificate);
        ocspCheckedRevokedKeyStore.setKeyEntry("checked", ocspCheckedRevokedSigningKey, PASSWORD, new X509Certificate[]{ocspCheckedRevokedCertificate,issuerCertificate});
        createTemporaryKeyStoreFile(ocspCheckedRevokedKeyStore, OCSP_CHECKED_REVOKED_FILE, PASSWORD);

        // Generates UNKNOWN certificate referencing the OCSP responder
        KeyPair ocspCheckedUnknownKeys = keyPairGenerator.generateKeyPair();
        PrivateKey ocspCheckedUnknownSigningKey = ocspCheckedUnknownKeys.getPrivate();
        PublicKey ocspCheckedUnknownPublicKey = ocspCheckedUnknownKeys.getPublic();

        X509Certificate ocspCheckedUnknownCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=ocspCheckedUnknown"))
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(ocspCheckedUnknownPublicKey)
                .setSerialNumber(new BigInteger("18"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .addExtension(new AuthorityInformationAccessExtension(Collections.singletonList(
                        new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_PORT + "/ocsp"))
                )))
                .build();
        KeyStore ocspCheckedUnknownKeyStore = createKeyStore();
        ocspCheckedUnknownKeyStore.setCertificateEntry("ca", issuerCertificate);
        ocspCheckedUnknownKeyStore.setKeyEntry("checked", ocspCheckedUnknownSigningKey, PASSWORD, new X509Certificate[]{ocspCheckedUnknownCertificate,issuerCertificate});
        createTemporaryKeyStoreFile(ocspCheckedUnknownKeyStore, OCSP_CHECKED_UNKNOWN_FILE, PASSWORD);


        // Adds trusted certs for beetles
        beetlesKeyStore.setCertificateEntry("ladybird", ladybirdCertificate);
        beetlesKeyStore.setCertificateEntry("scarab", scarabCertificate);
        beetlesKeyStore.setCertificateEntry("dung", dungCertificate);
        beetlesKeyStore.setCertificateEntry("firefly", fireflyCertificate);
        beetlesKeyStore.setCertificateEntry("ocspResponder", ocspResponderCertificate);
        beetlesKeyStore.setCertificateEntry("ocspCheckedGood", ocspCheckedGoodCertificate);
        beetlesKeyStore.setCertificateEntry("ocspCheckedRevoked", ocspCheckedRevokedCertificate);
        beetlesKeyStore.setCertificateEntry("ocspCheckedUnknown", ocspCheckedUnknownCertificate);

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
        createTemporaryKeyStoreFile(ladybirdKeyStore, LADYBIRD_FILE, PASSWORD);
        createTemporaryKeyStoreFile(scarabKeyStore, SCARAB_FILE, PASSWORD);
        createTemporaryKeyStoreFile(dungKeyStore, DUNG_FILE, PASSWORD);
        createTemporaryKeyStoreFile(fireflyKeyStore, FIREFLY_FILE, PASSWORD);
        createTemporaryKeyStoreFile(beetlesKeyStore, BEETLES_FILE, PASSWORD);
        createTemporaryKeyStoreFile(trustStore, TRUST_FILE, PASSWORD);
        createTemporaryKeyStoreFile(shortwingedKeyStore, SHORTWINGED_FILE, PASSWORD);
        createTemporaryKeyStoreFile(roveKeyStore, ROVE_FILE, PASSWORD);

        PemWriter caBlankCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(CA_BLANK_PEM_CRL)));
        PemWriter icaBlankCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(ICA_BLANK_PEM_CRL)));
        PemWriter blankBlankCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(BLANK_BLANK_PEM_CRL)));
        PemWriter fireflyRevokedCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(FIREFLY_REVOKED_PEM_CRL)));
        PemWriter icaRevokedCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(ICA_REVOKED_PEM_CRL)));

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

        ocspServer = new TestingOcspServer(OCSP_PORT);
        ocspServer.createIssuer(1, issuerCertificate);
        ocspServer.createIssuer(2, intermediateIssuerCertificate);
        ocspServer.createCertificate(1, 1, intermediateIssuerCertificate);
        ocspServer.createCertificate(2, 2, ocspCheckedGoodCertificate);
        ocspServer.createCertificate(3, 1, ocspCheckedRevokedCertificate);
        ocspServer.revokeCertificate(3, 4);
        ocspServer.start();

    }

    private static org.bouncycastle.asn1.x500.X500Name convertSunStyleToBCStyle(Principal dn) {
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

    @AfterClass
    public static void afterTest() throws Exception {
        if (ocspServer != null) {
            ocspServer.stop();
        }
        LADYBIRD_FILE.delete();
        SCARAB_FILE.delete();
        DUNG_FILE.delete();
        FIREFLY_FILE.delete();
        OCSP_RESPONDER_FILE.delete();
        OCSP_CHECKED_GOOD_FILE.delete();
        OCSP_CHECKED_REVOKED_FILE.delete();
        OCSP_CHECKED_UNKNOWN_FILE.delete();
        BEETLES_FILE.delete();
        TRUST_FILE.delete();
        SHORTWINGED_FILE.delete();
        ROVE_FILE.delete();
        CA_BLANK_PEM_CRL.delete();
        ICA_BLANK_PEM_CRL.delete();
        BLANK_BLANK_PEM_CRL.delete();
        FIREFLY_REVOKED_PEM_CRL.delete();
        ICA_REVOKED_PEM_CRL.delete();
        WORKING_DIR_CA.delete();
        WORKING_DIR_ICA.delete();
        WORKING_DIR_CACRL.delete();
        WORKING_DIR_ICACRL.delete();
    }

    @Test
    public void testOneWay() throws Throwable {
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(getKeyManager("/ca/jks/firefly.keystore"))
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Firefly", null, true);
    }

    @Test
    public void testCrlBlank() throws Throwable {
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(getKeyManager("/ca/jks/firefly.keystore"))
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-crl.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Firefly", null, true);
    }

    @Test
    public void testServerRevoked() throws Throwable {
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(getKeyManager("/ca/jks/firefly.keystore"))
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-firefly-revoked.org", false, null, null, true);
    }

    @Test
    public void testServerIcaRevoked() throws Throwable {
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(getKeyManager("/ica/jks/rove.keystore"))
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-ica-revoked.org", false, null, null, true);
    }

    @Test
    public void testTwoWay() throws Throwable {
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain("/ca/jks/beetles.keystore"))
                .setKeyManager(getKeyManager("/ca/jks/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Ladybird", false);
    }

    @Test
    public void testTwoWayIca() throws Throwable {
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain("/ica/jks/shortwinged.keystore"))
                .setKeyManager(getKeyManager("/ca/jks/scarab.keystore"))
                .setTrustManager(getCATrustManager())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way-ica.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Rove", false);
    }

    @Test
    public void testOcspGood() throws Throwable {
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain("/ca/jks/beetles.keystore"))
                .setKeyManager(getKeyManager("/ca/jks/scarab.keystore"))
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(createKeyStore("/ca/jks/ca.truststore"))
                        .setOcspResponderCert(ocspResponderCertificate)
                        .build())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way-ocsp-good.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=ocspCheckedGood", false);
    }

    @Test
    public void testOcspMaxCertPathNeg1() throws Throwable {
        ocspMaxCertPathCommon(-1, false);
    }

    @Test
    public void testOcspMaxCertPath0() throws Throwable {
        ocspMaxCertPathCommon(0, false);
    }

    @Test
    public void testOcspMaxCertPathTooLong() throws Throwable {
        ocspMaxCertPathCommon(1, false);
    }

    @Test
    public void testOcspMaxCertPathOkay() throws Throwable {
        ocspMaxCertPathCommon(2, true);
    }

    private void ocspMaxCertPathCommon(int maxCertPath, boolean expectValid) throws Throwable {
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain("/ca/jks/beetles.keystore"))
                .setKeyManager(getKeyManager("/ca/jks/scarab.keystore"))
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(createKeyStore("/ca/jks/ca.truststore"))
                        .setOcspResponderCert(ocspResponderCertificate)
                        .setMaxCertPath(maxCertPath)
                        .build())
                .setNeedClientAuth(true)
                .build().create();
        performConnectionTest(serverContext, "protocol://test-two-way-ocsp-good.org", expectValid, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=ocspCheckedGood", false);
    }

    @Test
    public void testClientSideOcsp() throws Throwable {
        SSLContext serverContextGood = new SSLContextBuilder()
                .setKeyManager(getKeyManager("/ca/jks/ocsp-checked-good.keystore"))
                .build().create();

        SSLContext serverContextRevoked = new SSLContextBuilder()
                .setKeyManager(getKeyManager("/ca/jks/ocsp-checked-revoked.keystore"))
                .build().create();

        SSLContext clientContext = new SSLContextBuilder()
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(createKeyStore("/ca/jks/ca.truststore"))
                        .setOcspResponderCert(ocspResponderCertificate)
                        .build())
                .setClientMode(true)
                .build().create();


        testCommunication(serverContextGood, clientContext, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=ocspCheckedGood", null, true);
        try {
            testCommunication(serverContextRevoked, clientContext, null, null, true);
            fail("Expected SSLHandshakeException not thrown");
        } catch (SSLHandshakeException expected) {
            //expected
        }
    }

    private void performConnectionTest(SSLContext serverContext, String clientUri, boolean expectValid, String expectedServerPrincipal, String expectedClientPrincipal, boolean oneWay) throws Throwable {
        System.setProperty("wildfly.config.url", SSLAuthenticationTest.class.getResource("wildfly-ssl-test-config-v1_1.xml").toExternalForm());
        AccessController.doPrivileged((PrivilegedAction<Integer>) () -> Security.insertProviderAt(WildFlyElytronPasswordProvider.getInstance(), 1));

        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        SSLContext clientContext = contextConfigurationClient.getSSLContext(URI.create(clientUri), context);

        try {
            testCommunication(serverContext, clientContext, expectedServerPrincipal, expectedClientPrincipal, oneWay);
            if (!expectValid) fail("Expected SSLHandshakeException not thrown");
        } catch (SSLHandshakeException expected) {
            if (expectValid) throw new IllegalStateException("Unexpected SSLHandshakeException", expected);
        } catch (SSLException expected) {
            if (expectValid) {
                throw new IllegalStateException("Unexpected SSLException", expected);
            } else if (expected.getCause() instanceof SocketException){
                //expected
            }
        }
    }

    private void testCommunication(SSLContext serverContext, SSLContext clientContext, String expectedServerPrincipal, String expectedClientPrincipal, boolean oneWay) throws Throwable {
        ServerSocket listeningSocket = serverContext.getServerSocketFactory().createServerSocket();
        listeningSocket.bind(new InetSocketAddress("localhost", TESTING_PORT));
        SSLSocket clientSocket = (SSLSocket) clientContext.getSocketFactory().createSocket("localhost", TESTING_PORT);
        SSLSocket serverSocket = (SSLSocket) listeningSocket.accept();

        ExecutorService serverExecutorService = Executors.newSingleThreadExecutor();
        Future<byte[]> serverFuture = serverExecutorService.submit(() -> {
            try {
                byte[] received = new byte[2];
                serverSocket.getInputStream().read(received);
                serverSocket.getOutputStream().write(new byte[]{0x56, 0x78});

                if (expectedClientPrincipal != null) {
                    assertEquals(expectedClientPrincipal, serverSocket.getSession().getPeerPrincipal().getName());
                }

                SecurityIdentity identity = (SecurityIdentity) serverSocket.getSession().getValue(SSLUtils.SSL_SESSION_IDENTITY_KEY);
                if (oneWay) {
                    assertNull(identity);
                } else {
                    assertNotNull(identity);
                }

                return received;
            } catch (Exception e) {
                throw new RuntimeException("Server exception", e);
            }
        });

        ExecutorService clientExecutorService = Executors.newSingleThreadExecutor();
        Future<byte[]> clientFuture = clientExecutorService.submit(() -> {
            try {
                byte[] received = new byte[2];
                clientSocket.getOutputStream().write(new byte[]{0x12, 0x34});
                clientSocket.getInputStream().read(received);

                if (expectedServerPrincipal != null) {
                    assertEquals(expectedServerPrincipal, clientSocket.getSession().getPeerPrincipal().getName());
                }

                if (oneWay) {
                    assertFalse(clientSocket.getSession().getProtocol().equals("TLSv1.3")); // since TLS 1.3 is not enabled by default (ELY-1917)
                } else {
                    assertFalse(serverSocket.getSession().getProtocol().equals("TLSv1.3")); // since TLS 1.3 is not enabled by default
                    assertFalse(clientSocket.getSession().getProtocol().equals("TLSv1.3")); // since TLS 1.3 is not enabled by default
                }
                return received;
            } catch (Exception e) {
                throw new RuntimeException("Client exception", e);
            }
        });

        try {
            assertArrayEquals(new byte[]{0x12, 0x34}, serverFuture.get());
            assertArrayEquals(new byte[]{0x56, 0x78}, clientFuture.get());
        } catch (ExecutionException e) {
            if (e.getCause() != null && e.getCause() instanceof RuntimeException && e.getCause().getCause() != null) {
                throw e.getCause().getCause(); // unpack
            } else {
                throw e;
            }
        } finally {
            safeClose(serverSocket);
            safeClose(clientSocket);
            safeClose(listeningSocket);
        }
    }

    private void safeClose(Closeable closeable) {
        try {
            closeable.close();
        } catch (Exception ignored) {}
    }
}
