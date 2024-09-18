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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.wildfly.security.ssl.test.util.CAGenerationTool.SIGNATURE_ALGORTHM;
import static org.wildfly.security.x500.X500.OID_AD_OCSP;
import static org.wildfly.security.x500.X500.OID_KP_OCSP_SIGNING;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.URI;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
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
import org.wildfly.common.Assert;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
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
import org.wildfly.security.ssl.test.util.CustomIdentity;
import org.wildfly.security.ssl.test.util.DefinedCAIdentity;
import org.wildfly.security.ssl.test.util.DefinedIdentity;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.cert.AccessDescription;
import org.wildfly.security.x500.cert.AuthorityInformationAccessExtension;
import org.wildfly.security.x500.cert.ExtendedKeyUsageExtension;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;

/**
 * Simple test case to test authentication occurring during the establishment of an {@link SSLSession}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
// has dependency on wildfly-elytron-client, wildfly-elytron-x500-cert, wildfly-elytron-realm, wildly-elytron-x500-deprecated
public class SSLAuthenticationTest {

    private static final int OCSP_PORT = 4854;
    private final int TESTING_PORT = 18201;
    private static final char[] PASSWORD = "Elytron".toCharArray();

    private static final String JKS_LOCATION = "./target/test-classes/pkcs12";
    private static final String CA_CRL_LOCATION = "./target/test-classes/ca/crl";
    private static final String ICA_CRL_LOCATION = "./target/test-classes/ica/crl";
    private static final File WORKING_DIR_CACRL = new File(CA_CRL_LOCATION);
    private static final File WORKING_DIR_ICACRL = new File(ICA_CRL_LOCATION);
    private static final File SHORTWINGED_FILE = new File(JKS_LOCATION, "shortwinged.keystore");
    private static final File CA_BLANK_PEM_CRL = new File(WORKING_DIR_CACRL, "blank.pem");
    private static final File ICA_BLANK_PEM_CRL = new File(WORKING_DIR_ICACRL, "blank.pem");
    private static final File BLANK_BLANK_PEM_CRL = new File(WORKING_DIR_ICACRL, "blank-blank.pem");
    private static final File FIREFLY_REVOKED_PEM_CRL = new File(WORKING_DIR_CACRL, "firefly-revoked.pem");
    private static final File ICA_REVOKED_PEM_CRL = new File(WORKING_DIR_CACRL, "ica-revoked.pem");
    private static final File ROVE_REVOKED_PEM_CRL = new File(WORKING_DIR_ICACRL, "rove-revoked.pem");
    private static CAGenerationTool caGenerationTool = null;
    private static final File LADYBUG_REVOKED_PEM_CRL = new File(WORKING_DIR_CACRL, "ladybug-revoked.pem");
    private static TestingOcspServer ocspServer = null;
    private static X509Certificate ocspResponderCertificate;
    private static KeyStore shortWingedKeyStore;
    private static CustomIdentity goodIdentity;
    private static CustomIdentity revokedIdentity;

    private static TrustManagerFactory getTrustManagerFactory() throws Exception {
        return TrustManagerFactory.getInstance("PKIX");
    }

    private static KeyStore createKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        return ks;
    }

    private static void createTemporaryKeyStoreFile(KeyStore keyStore, File outputFile, char[] password) throws Exception {
        if (!outputFile.exists()) {
            outputFile.createNewFile();
        }
        try (FileOutputStream fos = new FileOutputStream(outputFile)){
            keyStore.store(fos, password);
        }
    }

    private static SecurityDomain getKeyStoreBackedSecurityDomain(KeyStore keyStore) throws Exception {
        return getKeyStoreBackedSecurityDomain(keyStore, true);
    }

    private static SecurityDomain getKeyStoreBackedSecurityDomain(KeyStore keyStore, boolean decoder) throws Exception {
        SecurityRealm securityRealm = new KeyStoreBackedSecurityRealm(keyStore);

        SecurityDomain.Builder builder = SecurityDomain.builder()
                .addRealm("KeystoreRealm", securityRealm)
                .build()
                .setDefaultRealmName("KeystoreRealm")
                .setPreRealmRewriter((String s) -> s.toLowerCase(Locale.ENGLISH))
                .setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.ALL);
        if (decoder) {
            builder.setPrincipalDecoder(new X500AttributePrincipalDecoder("2.5.4.3", 1));
        }
        return builder.build();
    }

    @BeforeClass
    public static void beforeTest() throws Exception {
        WORKING_DIR_CACRL.mkdirs();
        WORKING_DIR_ICACRL.mkdirs();

        caGenerationTool = CAGenerationTool.builder()
                .setBaseDir(JKS_LOCATION)
                .setRequestIdentities(Identity.values()) // Create all identities.
                .build();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Generates certificate and keystore for OCSP responder
        DefinedCAIdentity caIdentity = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedCAIdentity intermediateCAIdentity = caGenerationTool.getDefinedCAIdentity(Identity.INTERMEDIATE);
        CustomIdentity responderIdentity = caIdentity.createIdentity("ocspResponder",
        new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=OcspResponder"),
        "ocsp-responder.keystore", new ExtendedKeyUsageExtension(false, Collections.singletonList(OID_KP_OCSP_SIGNING)));
        ocspResponderCertificate = responderIdentity.getCertificate();

        // Generates GOOD certificate referencing the OCSP responder
        goodIdentity = intermediateCAIdentity.createIdentity("checked",
        new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=ocspCheckedGood"),
        "ocsp-checked-good.keystore", new AuthorityInformationAccessExtension(Collections.singletonList(
                new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_PORT + "/ocsp"))
        )));
        X509Certificate ocspCheckedGoodCertificate = goodIdentity.getCertificate();

        // Generates REVOKED certificate referencing the OCSP responder
        revokedIdentity = caIdentity.createIdentity("checked",
        new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=ocspCheckedRevoked"),
        "ocsp-checked-revoked.keystore", (new AuthorityInformationAccessExtension(Collections.singletonList(
                new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_PORT + "/ocsp"))
        ))));
        X509Certificate ocspCheckedRevokedCertificate = revokedIdentity.getCertificate();

        // Generates UNKNOWN certificate referencing the OCSP responder
        CustomIdentity unknownIdentity = caIdentity.createIdentity("checked",
        new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=ocspCheckedUnknown"),
        "ocsp-checked-unknown.keystore", new AuthorityInformationAccessExtension(Collections.singletonList(
                new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_PORT + "/ocsp"))
        )));
        X509Certificate ocspCheckedUnknownCertificate = unknownIdentity.getCertificate();

        X509Certificate greenJuneCertificate = caGenerationTool
                                                .getDefinedIdentity(Identity.GREENJUNE)
                                                .getCertificate();

        KeyStore beetlesKeyStore = caGenerationTool.getBeetlesKeyStore();
        beetlesKeyStore.setCertificateEntry("ocspResponder", ocspResponderCertificate);
        beetlesKeyStore.setCertificateEntry("ocspCheckedGood", ocspCheckedGoodCertificate);
        beetlesKeyStore.setCertificateEntry("ocspCheckedRevoked", ocspCheckedRevokedCertificate);
        beetlesKeyStore.setCertificateEntry("ocspCheckedUnknown", ocspCheckedUnknownCertificate);
        beetlesKeyStore.setCertificateEntry("green june", greenJuneCertificate);
        createTemporaryKeyStoreFile(beetlesKeyStore, new File(JKS_LOCATION, "beetles.keystore"), PASSWORD);

        // Adds trusted cert for shortwinged
        shortWingedKeyStore = createKeyStore();
        shortWingedKeyStore.setCertificateEntry("rove", caGenerationTool.getDefinedIdentity(Identity.ROVE).getCertificate());
        //createTemporaryKeyStoreFile(shortwingedKeyStore, SHORTWINGED_FILE, PASSWORD);

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
                convertSunStyleToBCStyle(caIdentity.getCertificate().getSubjectDN()),
                currentDate
        );
        X509CRLHolder caBlankCrlHolder = caBlankCrlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder(SIGNATURE_ALGORTHM)
                        .setProvider("BC")
                        .build(caIdentity.getPrivateKey())
        );

        // Creates the CRL for ica/crl/blank.pem
        X509v2CRLBuilder icaBlankCrlBuilder = new X509v2CRLBuilder(
                convertSunStyleToBCStyle(intermediateCAIdentity.getCertificate().getSubjectDN()),
                currentDate
        );
        X509CRLHolder icaBlankCrlHolder = icaBlankCrlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder(SIGNATURE_ALGORTHM)
                        .setProvider("BC")
                        .build(intermediateCAIdentity.getPrivateKey())
        );

        // Creates the CRL for firefly-revoked.pem
        X509v2CRLBuilder fireflyRevokedCrlBuilder = new X509v2CRLBuilder(
                convertSunStyleToBCStyle(caIdentity.getCertificate().getSubjectDN()),
                currentDate
        );

        fireflyRevokedCrlBuilder.addCRLEntry(
                caGenerationTool.getDefinedIdentity(Identity.FIREFLY).getCertificate().getSerialNumber(),
                revokeDate,
                CRLReason.unspecified
        );
        X509CRLHolder fireflyRevokedCrlHolder = fireflyRevokedCrlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder(SIGNATURE_ALGORTHM)
                        .setProvider("BC")
                        .build(caIdentity.getPrivateKey())
        );

        DefinedCAIdentity secondCAIdentity = caGenerationTool.getDefinedCAIdentity(Identity.SECOND_CA);
        // Creates the CRL for ladybug-revoked.pem
        X509v2CRLBuilder ladybugRevokedCrlBuilder = new X509v2CRLBuilder(
                convertSunStyleToBCStyle(secondCAIdentity.getCertificate().getSubjectDN()),
                currentDate
        );

        // revokes the certificate with serial number #2
        ladybugRevokedCrlBuilder.addCRLEntry(
                caGenerationTool.getDefinedIdentity(Identity.LADYBUG).getCertificate().getSerialNumber(),
                revokeDate,
                CRLReason.unspecified
        );

        X509CRLHolder ladybugRevokedCrlHolder = ladybugRevokedCrlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder(SIGNATURE_ALGORTHM)
                .setProvider("BC")
                .build(secondCAIdentity.getPrivateKey())
        );

        // Creates the CRL for ica-revoked.pem
        X509v2CRLBuilder icaRevokedCrlBuilder = new X509v2CRLBuilder(
                convertSunStyleToBCStyle(caIdentity.getCertificate().getSubjectDN()),
                currentDate
        );
        icaRevokedCrlBuilder.addCRLEntry(
                intermediateCAIdentity.getCertificate().getSerialNumber(),
                revokeDate,
                CRLReason.unspecified
        );
        X509CRLHolder icaRevokedCrlHolder = icaRevokedCrlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder(SIGNATURE_ALGORTHM)
                        .setProvider("BC")
                        .build(caIdentity.getPrivateKey())
        );

        // Creates the CRL for rove-revoked.pem
        X509v2CRLBuilder roveRevokedCrlBuilder = new X509v2CRLBuilder(
                convertSunStyleToBCStyle(intermediateCAIdentity.getCertificate().getSubjectDN()),
                currentDate
        );

        X509CRLHolder roveRevokedCrlHolder = roveRevokedCrlBuilder.setNextUpdate(nextYear).build(
                new JcaContentSignerBuilder(SIGNATURE_ALGORTHM)
                .setProvider("BC")
                .build(intermediateCAIdentity.getPrivateKey())
        );

        PemWriter caBlankCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(CA_BLANK_PEM_CRL)));
        PemWriter icaBlankCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(ICA_BLANK_PEM_CRL)));
        PemWriter blankBlankCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(BLANK_BLANK_PEM_CRL)));
        PemWriter fireflyRevokedCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(FIREFLY_REVOKED_PEM_CRL)));
        PemWriter icaRevokedCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(ICA_REVOKED_PEM_CRL)));
        PemWriter ladybugRevokedCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(LADYBUG_REVOKED_PEM_CRL)));
        PemWriter roveRevokedCrlOutput = new PemWriter(new OutputStreamWriter(new FileOutputStream(ROVE_REVOKED_PEM_CRL)));

        caBlankCrlOutput.writeObject(new MiscPEMGenerator(caBlankCrlHolder));
        icaBlankCrlOutput.writeObject(new MiscPEMGenerator(icaBlankCrlHolder));
        blankBlankCrlOutput.writeObject(new MiscPEMGenerator(icaBlankCrlHolder));
        blankBlankCrlOutput.writeObject(new MiscPEMGenerator(caBlankCrlHolder));
        fireflyRevokedCrlOutput.writeObject(new MiscPEMGenerator(fireflyRevokedCrlHolder));
        icaRevokedCrlOutput.writeObject(new MiscPEMGenerator(icaRevokedCrlHolder));
        roveRevokedCrlOutput.writeObject(new MiscPEMGenerator(roveRevokedCrlHolder));
        roveRevokedCrlOutput.writeObject(new MiscPEMGenerator(icaBlankCrlHolder));
        roveRevokedCrlOutput.writeObject(new MiscPEMGenerator(caBlankCrlHolder));
        ladybugRevokedCrlOutput.writeObject(new MiscPEMGenerator(ladybugRevokedCrlHolder));

        caBlankCrlOutput.close();
        icaBlankCrlOutput.close();
        blankBlankCrlOutput.close();
        fireflyRevokedCrlOutput.close();
        icaRevokedCrlOutput.close();
        ladybugRevokedCrlOutput.close();
        roveRevokedCrlOutput.close();

        ocspServer = new TestingOcspServer(OCSP_PORT);
        ocspServer.createIssuer(1, caIdentity.getCertificate());
        ocspServer.createIssuer(2, intermediateCAIdentity.getCertificate());
        ocspServer.createCertificate(1, 1, intermediateCAIdentity.getCertificate());
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

        SHORTWINGED_FILE.delete();
        CA_BLANK_PEM_CRL.delete();
        ICA_BLANK_PEM_CRL.delete();
        BLANK_BLANK_PEM_CRL.delete();
        FIREFLY_REVOKED_PEM_CRL.delete();
        ICA_REVOKED_PEM_CRL.delete();
        LADYBUG_REVOKED_PEM_CRL.delete();
        ROVE_REVOKED_PEM_CRL.delete();
        WORKING_DIR_CACRL.delete();
        WORKING_DIR_ICACRL.delete();

        caGenerationTool.close();

        Security.removeProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider().getName());
    }

    @Test
    public void testOneWay() throws Throwable {
        DefinedIdentity firefly = caGenerationTool.getDefinedIdentity(Identity.FIREFLY);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(firefly.createKeyManager())
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Firefly", null, true);
    }

    @Test
    public void testCrlBlank() throws Throwable {
        DefinedIdentity firefly = caGenerationTool.getDefinedIdentity(Identity.FIREFLY);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(firefly.createKeyManager())
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-crl.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Firefly", null, true);
    }

    @Test
    public void testServerRevoked() throws Throwable {
        DefinedIdentity firefly = caGenerationTool.getDefinedIdentity(Identity.FIREFLY);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(firefly.createKeyManager())
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-firefly-revoked.org", false, null, null, true);
    }

    @Test
    public void testServerIcaRevoked() throws Throwable {
        DefinedIdentity rove = caGenerationTool.getDefinedIdentity(Identity.ROVE);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(rove.createKeyManager())
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-ica-revoked.org", false, null, null, true);
    }

    /**
     * One way SSL test where a client configures a single CRL under the certificate-revocation-lists
     * attribute. A server is configured to send a certificate which is present in the CRL configured
     * by the client. The communication is expected to fail.
     */
    @Test
    public void testOneWayServerRejectedWithSingleCRL() throws Throwable {
        DefinedIdentity firefly = caGenerationTool.getDefinedIdentity(Identity.FIREFLY);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(firefly.createKeyManager())
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-one-crl.org", false, null, null, true);
    }

    /**
     * One way SSL test where a client configures multiple CRLs under the certificate-revocation-lists
     * attribute. A server is configured to send a certificate which is present in one of the CRLs
     * configured by the client. Communication is expected to fail.
     */
    @Test
    public void testOneWayServerRejectedWithMultipleCRL() throws Throwable {
        DefinedIdentity firefly = caGenerationTool.getDefinedIdentity(Identity.FIREFLY);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(firefly.createKeyManager())
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-multiple-crls-failure.org", false,
                null, null, true);
    }

    /**
     * One way SSL test where a client configures multiple CRLs under the certificate-revocation-lists
     * attribute. A server is configured to send a certificate *not* present in any of the CRLs
     * configured by the client. Communication is expected to succeed.
     */
    @Test
    public void testOneWayServerAcceptedWithMultipleCRL() throws Throwable {
        DefinedIdentity greenJune = caGenerationTool.getDefinedIdentity(Identity.GREENJUNE);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(greenJune.createKeyManager())
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-multiple-crls-success.org", true,
                "OU=Wildfly,O=Wildfly,C=CA,ST=Wildfly,CN=Green June", null, true);
    }

    /**
     * This test verifies communication succeds when the certification path length does not exceed
     * the default value 5. The length of this Rove's certification path is 2.
     */
    @Test
    public void testCRLMaxCertPathSucceeds() throws Throwable {
        DefinedIdentity rove = caGenerationTool.getDefinedIdentity(Identity.ROVE);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(rove.createKeyManager())
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-max-cert-path.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Rove", null, true);
    }

    /**
     * This test verifies communication fails when the certification path length exceeds the
     * maximum certificate path length. The length of this Rove's certification path is 2,
     * and the maximum length specified is 1.
     */
    @Test
    public void testCRLMaxCertPathFails() throws Throwable {
        DefinedIdentity rove = caGenerationTool.getDefinedIdentity(Identity.ROVE);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(rove.createKeyManager())
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way-max-cert-path-failure.org", false, null, null, true);
    }

    @Test
    public void testTwoWay() throws Throwable {
        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore()))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(ca.createTrustManager())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Ladybird", false);
    }

    @Test
    public void testTwoWayNoDecoder() throws Throwable {
        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore(), false))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(ca.createTrustManager())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Ladybird", false);
    }

    @Test
    public void testTwoWayIca() throws Throwable {
        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(shortWingedKeyStore))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(ca.createTrustManager())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way-ica.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Rove", false);
    }

    /**
     * Verifies ELY-2057 (No acceptedIssuers sent when CRLs are configured) is resolved.
     * Test verifies a X509RevocationTrustManager configures accepted issuers.
     */
    @Test
    public void testAcceptedIssuersConfiguredWithCRL() throws Throwable {
        InputStream crl = new FileInputStream("./target/test-classes/ica/crl/blank-blank.pem");

        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        X509RevocationTrustManager trustManager = X509RevocationTrustManager.builder()
                .setTrustManagerFactory(getTrustManagerFactory())
                .setTrustStore(ca.loadKeyStore())
                .setCrlStream(crl)
                .setPreferCrls(true)
                .setNoFallback(true)
                .build();

        Assert.assertTrue(trustManager.getAcceptedIssuers().length > 0);
    }

    /**
     * Two way SSL test where a server configures a list of CRLs containing a single CRL.
     * The client configures no CRLs, but it sends
     * a certificate present in the CRL configured by the server. Communication is expected to fail.
     */
    @Test
    public void testTwoWayClientRejectedWithSingleCRL() throws Throwable {

        List<InputStream> crlStreams = new ArrayList<>();
        // this CRL contains the certificate with the alias "ladybug" which is being sent by the client
        crlStreams.add(new FileInputStream("target/test-classes/ca/crl/ladybug-revoked.pem"));

        DefinedCAIdentity secondCA = caGenerationTool.getDefinedCAIdentity(Identity.SECOND_CA);
        DefinedIdentity firefly = caGenerationTool.getDefinedIdentity(Identity.FIREFLY);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(firefly.createKeyManager())
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(secondCA.loadKeyStore())
                        .setCrlStreams(crlStreams)
                        .setPreferCrls(true)
                        .setNoFallback(true)
                        .build())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way-no-crl-failure.org", false,
                null, null, false);
    }

    /**
     * Two way SSL test where a server configures a list of CRLs containing a single CRL.
     * The client configures no CRLs, and it sends
     * a certificate *not* present in the CRL configured by the server. Communication is expected to succeed.
     */
    @Test
    public void testTwoWayClientAcceptedWithSingleCRL() throws Throwable {
        List<InputStream> crlStreams = new ArrayList<>();
        // CRL contains "ladybug" certificate but client sends "green june" certificate
        crlStreams.add(new FileInputStream("target/test-classes/ca/crl/ladybug-revoked.pem"));

        DefinedCAIdentity secondCA = caGenerationTool.getDefinedCAIdentity(Identity.SECOND_CA);
        DefinedIdentity firefly = caGenerationTool.getDefinedIdentity(Identity.FIREFLY);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore()))
                .setKeyManager(firefly.createKeyManager())
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(secondCA.loadKeyStore())
                        .setCrlStreams(crlStreams)
                        .setPreferCrls(true)
                        .setNoFallback(true)
                        .build())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way-no-crl-success.org", true,
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Firefly",
                "OU=Wildfly,O=Wildfly,C=CA,ST=Wildfly,CN=Green June", false);
    }

    /**
     * Two way SSL test where a server configures a list of CRLs containing two CRLs.
     * The client configures no CRLs, but it sends a certificate present in one of the CRLs configured by the server.
     * Communication is expected to fail.
     */
    @Test
    public void testTwoWayClientRejectedWithMultipleCRL() throws Throwable {

        List<InputStream> crlStreams = new ArrayList<>();
        // CRLs contain the "ladybug" and "firefly" certificates. The client sends "ladybug".
        crlStreams.add(new FileInputStream("target/test-classes/ca/crl/ladybug-revoked.pem"));
        crlStreams.add(new FileInputStream("target/test-classes/ca/crl/firefly-revoked.pem"));

        DefinedCAIdentity secondCA = caGenerationTool.getDefinedCAIdentity(Identity.SECOND_CA);
        DefinedIdentity firefly = caGenerationTool.getDefinedIdentity(Identity.FIREFLY);
        SSLContext serverContext = new SSLContextBuilder()
                .setKeyManager(firefly.createKeyManager())
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(secondCA.loadKeyStore())
                        .setCrlStreams(crlStreams)
                        .setPreferCrls(true)
                        .setNoFallback(true)
                        .build())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way-no-crl-failure.org", false,
                null, null, false);
    }

    /**
     * Two way SSL test where a server configures a list of CRLs containing two CRLs.
     * The client configures no CRLs, and it sends a certificate *not* present in any of the CRLs configured by the server.
     * Communication is expected to succeed.
     */
    @Test
    public void testTwoWayClientAcceptedWithMultipleCRL() throws Throwable {
        List<InputStream> crlStreams = new ArrayList<>();
        // CRLs contain the "ladybug" and "firefly" certificates, but the client sends "green june"
        crlStreams.add(new FileInputStream("target/test-classes/ca/crl/ladybug-revoked.pem"));
        crlStreams.add(new FileInputStream("target/test-classes/ca/crl/firefly-revoked.pem"));

        DefinedCAIdentity secondCA = caGenerationTool.getDefinedCAIdentity(Identity.SECOND_CA);
        DefinedIdentity firefly = caGenerationTool.getDefinedIdentity(Identity.FIREFLY);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore()))
                .setKeyManager(firefly.createKeyManager())
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(secondCA.loadKeyStore())
                        .setCrlStreams(crlStreams)
                        .setPreferCrls(true)
                        .setNoFallback(true)
                        .build())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way-no-crl-success.org", true,
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Firefly",
                "OU=Wildfly,O=Wildfly,C=CA,ST=Wildfly,CN=Green June", false);
    }

    @Test
    public void testOcspGood() throws Throwable {
        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore()))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(ca.loadKeyStore())
                        .setOcspResponderCert(ocspResponderCertificate)
                        .build())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way-ocsp-good.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=ocspCheckedGood", false);
    }

    @Test
    public void testOcspRevoked() throws Throwable {
        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore()))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(ca.loadKeyStore())
                        .setOcspResponderCert(ocspResponderCertificate)
                        .build())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way-ocsp-revoked.org", false, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=ocspCheckedRevoked", false);
    }

    @Test
    public void testOcspUnknown() throws Throwable {
        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore()))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(ca.loadKeyStore())
                        .setOcspResponderCert(ocspResponderCertificate)
                        .build())
                .setNeedClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way-ocsp-unknown.org", false, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=ocspCheckedUnknown", false);
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
        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore()))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(ca.loadKeyStore())
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
                .setKeyManager(goodIdentity.createKeyManager())
                .build().create();

        SSLContext serverContextRevoked = new SSLContextBuilder()
                .setKeyManager(revokedIdentity.createKeyManager())
                .build().create();

        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        SSLContext clientContext = new SSLContextBuilder()
                .setTrustManager(X509RevocationTrustManager.builder()
                        .setTrustManagerFactory(getTrustManagerFactory())
                        .setTrustStore(ca.loadKeyStore())
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

    @Test
    public void testWantClientAuthWithCorrectCertificate() throws Throwable {
        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore()))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(ca.createTrustManager())
                .setWantClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-two-way.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Ladybird", false);
    }

    @Test
    public void testWantClientAuthWithIncorrectCertificate() throws Throwable {
        DefinedCAIdentity ca = caGenerationTool.getDefinedCAIdentity(Identity.CA);
        DefinedIdentity scarab = caGenerationTool.getDefinedIdentity(Identity.SCARAB);
        SSLContext serverContext = new SSLContextBuilder()
                .setSecurityDomain(getKeyStoreBackedSecurityDomain(caGenerationTool.getBeetlesKeyStore()))
                .setKeyManager(scarab.createKeyManager())
                .setTrustManager(ca.createTrustManager())
                .setWantClientAuth(true)
                .build().create();

        performConnectionTest(serverContext, "protocol://test-one-way.org", true, "OU=Elytron,O=Elytron,C=UK,ST=Elytron,CN=Scarab",
                null, true);
    }

    private void performConnectionTest(SSLContext serverContext, String clientUri, boolean expectValid, String expectedServerPrincipal, String expectedClientPrincipal, boolean oneWay) throws Throwable {
        System.setProperty("wildfly.config.url", SSLAuthenticationTest.class.getResource("ssl-authentication-config.xml").toExternalForm());
        AccessController.doPrivileged((PrivilegedAction<Integer>) () -> Security.insertProviderAt(WildFlyElytronPasswordProvider.getInstance(), 1));

        AuthenticationContext context = AuthenticationContext.getContextManager().get();
        AuthenticationContextConfigurationClient contextConfigurationClient = AccessController.doPrivileged(AuthenticationContextConfigurationClient.ACTION);
        SSLContext clientContext = contextConfigurationClient.getSSLContext(URI.create(clientUri), context);

        try {
            testCommunication(serverContext, clientContext, expectedServerPrincipal, expectedClientPrincipal, oneWay);
            if (!expectValid) fail("Expected SSLHandshakeException not thrown");
        } catch (SSLHandshakeException|SocketException expected) {
            if (expectValid) {
                throw new IllegalStateException("Unexpected SSLHandshakeException", expected);
            }
        } catch (SSLException expected) {
            if (expectValid) {
                throw new IllegalStateException("Unexpected SSLException", expected);
            } else if (expected.getCause() instanceof SocketException) {
                //expected
            }
        } finally {
            System.clearProperty("wildfly.config.url");
            Security.removeProvider(WildFlyElytronPasswordProvider.getInstance().getName());
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
                    assertNotEquals("TLSv1.3", clientSocket.getSession().getProtocol());// since TLS 1.3 is not enabled by default (ELY-1917)
                } else {
                    assertNotEquals("TLSv1.3", serverSocket.getSession().getProtocol()); // since TLS 1.3 is not enabled by default
                    assertNotEquals("TLSv1.3", clientSocket.getSession().getProtocol()); // since TLS 1.3 is not enabled by default
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
