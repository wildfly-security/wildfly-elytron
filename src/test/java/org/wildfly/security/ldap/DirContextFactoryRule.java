/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.ldap;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.apacheds.LdapService;
import org.wildfly.security.auth.realm.ldap.DirContextFactory;
import org.wildfly.security.auth.realm.ldap.SimpleDirContextFactoryBuilder;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DirContextFactoryRule implements TestRule {

    static final String SERVER_DN = "uid=server,dc=elytron,dc=wildfly,dc=org";
    static final String SERVER_CREDENTIAL = "serverPassword";
    static final int LDAP_PORT = 11390;

    private static final Provider provider = new WildFlyElytronProvider();
    private static final char[] PASSWORD = "Elytron".toCharArray();
    private static final String LDAP_DIRECTORY_LOCATION = "./target/test-classes/ldap";
    private static final String LDIF_LOCATION = "/elytron-x509-verification.ldif";
    private static final String CA_JKS_LOCATION = "./target/test-classes/ca/jks";

    private static void createStoreFiles(File localhostFile, KeyStore localhostKeyStore, File scarabFile, KeyStore scarabKeyStore, File trustFile, KeyStore trustStore) throws Exception{
        try (OutputStream ladybirdStream = new FileOutputStream(localhostFile)){
            localhostKeyStore.store(ladybirdStream, PASSWORD);
        }
        try (OutputStream scarabStream = new FileOutputStream(scarabFile)){
            scarabKeyStore.store(scarabStream, PASSWORD);
        }
        try (OutputStream trustStream = new FileOutputStream(trustFile)){
            trustStore.store(trustStream, PASSWORD);
        }
    }

    private static void createStores(KeyStore localhostKeyStore, KeyStore scarabKeyStore, KeyStore trustStore) throws Exception{
        X500Principal issuerDN = new X500Principal("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA");
        X500Principal localhostDN = new X500Principal("OU=Elytron, O=Elytron, C=CZ, ST=Elytron, CN=localhost");
        X500Principal scarabDN = new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Scarab");

        SelfSignedX509CertificateAndSigningKey issuerSelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(issuerDN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA1withRSA")
                .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
                .build();
        X509Certificate issuerCertificate = issuerSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        localhostKeyStore.setCertificateEntry("ca", issuerCertificate);
        trustStore.setCertificateEntry("mykey", issuerCertificate);

        // Generates certificate and keystore for Localhost
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair localhostKeys = keyPairGenerator.generateKeyPair();
        PrivateKey localhostSigningKey = localhostKeys.getPrivate();
        PublicKey localhostPublicKey = localhostKeys.getPublic();

        X509Certificate localhostCertificate = new X509CertificateBuilder()
                .setIssuerDn(issuerDN)
                .setSubjectDn(localhostDN)
                .setSignatureAlgorithmName("SHA1withRSA")
                .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
                .setPublicKey(localhostPublicKey)
                .setSerialNumber(new BigInteger("3"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .build();
        localhostKeyStore.setKeyEntry("localhost", localhostSigningKey, PASSWORD, new X509Certificate[]{localhostCertificate,issuerCertificate});

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

        // Modify the ldif
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        String digest = ByteIterator.ofBytes(md.digest(scarabCertificate.getEncoded())).hexEncode(true).drainToString();

        File workingDirLDIF = new File(LDAP_DIRECTORY_LOCATION);
        if (workingDirLDIF.exists() == false) {
            workingDirLDIF.mkdirs();
        }

        CodePointIterator certificateBytes = ByteIterator.ofBytes(scarabCertificate.getEncoded()).base64Encode();
        String certificateBaseString = "usercertificate:: " + certificateBytes.drainToString();
        String certificateString = "";
        int counter = 0;
        for (int i = 0; i < certificateBaseString.length(); i++){
            if(i == 78 || i == (78+77*counter)){
                certificateString = certificateString + System.getProperty("line.separator");
                certificateString = certificateString + " ";
                counter += 1;
            }
            certificateString = certificateString + certificateBaseString.charAt(i);
        }

        FileWriter ldif = new FileWriter(workingDirLDIF.toString() + LDIF_LOCATION, true);
        ldif.write("x509digest: " + digest + System.getProperty("line.separator"));
        ldif.write(certificateString);
        ldif.close();
    }

    private static void setUp() throws Exception{
        File workingDirCA = new File(CA_JKS_LOCATION);
        if (workingDirCA.exists() == false) {
            workingDirCA.mkdirs();
        }

        KeyStore localhostKeyStore = KeyStore.getInstance("JKS");
        localhostKeyStore.load(null, null);
        KeyStore scarabKeyStore = KeyStore.getInstance("JKS");
        scarabKeyStore.load(null, null);
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);

        File localhostFile = new File(workingDirCA, "localhost.keystore");
        File scarabFile = new File(workingDirCA, "scarab.keystore");
        File trustFile = new File(workingDirCA, "ca.truststore");

        createStores(localhostKeyStore, scarabKeyStore, trustStore);
        createStoreFiles(localhostFile, localhostKeyStore, scarabFile, scarabKeyStore, trustFile, trustStore);
    }

    @Override
    public Statement apply(Statement current, Description description) {
        return new Statement() {

            @Override
            public void evaluate() throws Throwable {
                setUp();
                Security.addProvider(provider);
                LdapService embeddedServer = startEmbeddedServer();

                try {
                    current.evaluate();
                } catch (Exception e) {
                    throw e;
                } finally {
                    if (embeddedServer != null) {
                        embeddedServer.close();
                    }

                    Security.removeProvider(provider.getName());
                }
            }
        };
    }

    public ExceptionSupplier<DirContext, NamingException> create() {
        SocketFactory socketFactory;
        try {
            File workingDirCA = new File(CA_JKS_LOCATION);
            File trustFile = new File(workingDirCA, "ca.truststore");
            if (trustFile.exists() == false) {
                setUp();
            }

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(new FileInputStream(getClass().getResource("/ca/jks/ca.truststore").getFile()), PASSWORD);
            TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustFactory.init(keyStore);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustFactory.getTrustManagers(), null);
            socketFactory = context.getSocketFactory();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        return () -> SimpleDirContextFactoryBuilder.builder()
                        .setProviderUrl(String.format("ldap://localhost:%d/", LDAP_PORT))
                        .setSecurityPrincipal(SERVER_DN)
                        .setSecurityCredential(SERVER_CREDENTIAL)
                        .setSocketFactory(socketFactory)
                        .build().obtainDirContext(DirContextFactory.ReferralMode.IGNORE);
    }

    private LdapService startEmbeddedServer() {
        try {
            return LdapService.builder()
                    .setWorkingDir(new File("./target/apache-ds/working"))
                    .createDirectoryService("Test Service")
                    .addPartition("Elytron", "dc=elytron,dc=wildfly,dc=org", 5, "uid")
                    .importLdif(PasswordSupportSuiteChild.class.getResourceAsStream("/ldap/elytron-credential-tests.ldif"))
                    .importLdif(PasswordSupportSuiteChild.class.getResourceAsStream("/ldap/memberOf-schema.ldif"))
                    .importLdif(PasswordSupportSuiteChild.class.getResourceAsStream("/ldap/elytron-attribute-tests.ldif"))
                    .importLdif(PasswordSupportSuiteChild.class.getResourceAsStream("/ldap/elytron-role-mapping-tests.ldif"))
                    .importLdif(PasswordSupportSuiteChild.class.getResourceAsStream("/ldap/elytron-group-mapping-tests.ldif"))
                    .importLdif(PasswordSupportSuiteChild.class.getResourceAsStream("/ldap/elytron-otp-tests.ldif"))
                    .importLdif(PasswordSupportSuiteChild.class.getResourceAsStream("/ldap/elytron-keystore-tests.ldif"))
                    .importLdif(PasswordSupportSuiteChild.class.getResourceAsStream("/ldap/elytron-x509-verification.ldif"))
                    .addTcpServer("Default TCP", "localhost", LDAP_PORT, "/ca/jks/localhost.keystore", "Elytron")
                    .start();
        } catch (Exception e) {
            throw new RuntimeException("Could not start LDAP embedded server.", e);
        }
    }
}
