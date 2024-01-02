package org.wildfly.security.auth.client;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class EncryptedExpressionXMLParserTest {

    private static final File CREDSTORE_DIR = new File("./target/credstore");
    private static final String CLIENT_CREDSTORE_FILENAME = "/mycredstore.cs";
    private static final char[] PASSWORD = "password".toCharArray();

    @Test
    public void testEncryptedExpressionConfig() throws Exception {
        URL config = getClass().getResource("test-encrypted-expression-v1_0.xml");
        SecurityFactory<EncryptedExpressionContext> clientConfiguration = EncryptedExpressionsXmlParser.parseEncryptedExpressionClientConfiguration(config.toURI());
        Assert.assertNotNull(clientConfiguration);
    }

    @BeforeClass
    public static void prepareCredStores() throws Exception {
        if (!CREDSTORE_DIR.exists()) {
            CREDSTORE_DIR.mkdirs();
        }

        KeyStore credentialStore = KeyStore.getInstance("JCEKS");
        credentialStore.load(null, null);

        createCredentialStore(credentialStore);

        File clientFile = new File(CREDSTORE_DIR, CLIENT_CREDSTORE_FILENAME);

        try (FileOutputStream clientStream = new FileOutputStream(clientFile)) {
            credentialStore.store(clientStream, PASSWORD);
        }
    }


    @AfterClass
    public static void removeProvider() {
        Assert.assertTrue("Credential Store deleted", new File(CREDSTORE_DIR, CLIENT_CREDSTORE_FILENAME).delete());
        Assert.assertTrue("Credential store directory deleted", CREDSTORE_DIR.delete());
    }

    private static void createCredentialStore(KeyStore credentialStore) throws Exception {
        // Generate testclient2.example.com self signed certificate
        X500Principal testClient2DN = new X500Principal("CN=testclient2.example.com, OU=JBoss, O=Red Hat, L=Raleigh, ST=North Carolina, C=US");
        SelfSignedX509CertificateAndSigningKey testClient2SelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setKeyAlgorithmName("DSA")
                .setSignatureAlgorithmName("SHA1withDSA")
                .setDn(testClient2DN)
                .setKeySize(1024)
                .build();
        X509Certificate testClient2Certificate = testClient2SelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        credentialStore.setKeyEntry("dnsincnclient", testClient2SelfSignedX509CertificateAndSigningKey.getSigningKey(), PASSWORD, new X509Certificate[]{testClient2Certificate});


        // Generate Test Authority self signed certificate
        X500Principal testAuthorityDN = new X500Principal("CN=Test Authority, OU=JBoss, O=Red Hat, L=Raleigh, ST=North Carolina, C=US");
        SelfSignedX509CertificateAndSigningKey testAuthoritySelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(testAuthorityDN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA1withRSA")
                .build();
        X509Certificate testAuthorityCertificate = testAuthoritySelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        credentialStore.setKeyEntry("testauthority", testAuthoritySelfSignedX509CertificateAndSigningKey.getSigningKey(), PASSWORD, new X509Certificate[]{testAuthorityCertificate});


        // Generate Test Client 1 self signed certificate
        X500Principal testClient1DN = new X500Principal("CN=Test Client 1, OU=JBoss, O=Red Hat, L=Raleigh, ST=North Carolina, C=US");
        SelfSignedX509CertificateAndSigningKey testClient1SelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(testClient1DN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA1withRSA")
                .addExtension(false, "SubjectAlternativeName", "DNS:testclient1.example.com")
                .build();
        X509Certificate testClient1Certificate = testClient1SelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        credentialStore.setKeyEntry("testclient1", testClient1SelfSignedX509CertificateAndSigningKey.getSigningKey(), PASSWORD, new X509Certificate[]{testClient1Certificate});


        // Generate Signed Test Client certificate signed by Test Authority
        X500Principal signedTestClientDN = new X500Principal("CN=Signed Test Client, OU=JBoss, O=Red Hat, ST=North Carolina, C=US");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair signedTestClientGeneratedKeys = keyPairGenerator.generateKeyPair();
        PrivateKey signedTestClientSigningKey = signedTestClientGeneratedKeys.getPrivate();
        PublicKey signedTestClientPublicKey = signedTestClientGeneratedKeys.getPublic();

        X509Certificate signedTestClientCertificate = new X509CertificateBuilder()
                .setIssuerDn(testAuthorityDN)
                .setSubjectDn(signedTestClientDN)
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(testAuthoritySelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(signedTestClientPublicKey)
                .build();
        credentialStore.setKeyEntry("testclientsignedbyca", signedTestClientSigningKey, PASSWORD, new X509Certificate[]{signedTestClientCertificate, testAuthorityCertificate});
    }
}