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

import java.io.File;
import java.io.FileOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.security.auth.x500.X500Principal;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

/**
 * @author Tomas Hofman (thofman@redhat.com)
 */
public class ElytronXmlParserTest {

    private static File KEYSTORE_DIR = new File("./target/keystore");
    private static final String CLIENT_KEYSTORE_FILENAME = "/client.keystore";
    private static final char[] PASSWORD = "password".toCharArray();
    private static final Provider provider = new WildFlyElytronProvider();


    /**
     * ELY-1428
     */
    private static void createClientKeyStore(KeyStore clientKeyStore) throws Exception {
        // Generate testclient2.example.com self signed certificate
        X500Principal testClient2DN = new X500Principal("CN=testclient2.example.com, OU=JBoss, O=Red Hat, L=Raleigh, ST=North Carolina, C=US");
        SelfSignedX509CertificateAndSigningKey testClient2SelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setKeyAlgorithmName("DSA")
                .setSignatureAlgorithmName("SHA1withDSA")
                .setDn(testClient2DN)
                .setKeySize(1024)
                .build();
        X509Certificate testClient2Certificate = testClient2SelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        clientKeyStore.setKeyEntry("dnsincnclient", testClient2SelfSignedX509CertificateAndSigningKey.getSigningKey(), PASSWORD, new X509Certificate[]{testClient2Certificate});


        // Generate Test Authority self signed certificate
        X500Principal testAuthorityDN = new X500Principal("CN=Test Authority, OU=JBoss, O=Red Hat, L=Raleigh, ST=North Carolina, C=US");
        SelfSignedX509CertificateAndSigningKey testAuthoritySelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(testAuthorityDN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA1withRSA")
                .build();
        X509Certificate testAuthorityCertificate = testAuthoritySelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        clientKeyStore.setKeyEntry("testauthority", testAuthoritySelfSignedX509CertificateAndSigningKey.getSigningKey(), PASSWORD, new X509Certificate[]{testAuthorityCertificate});


        // Generate Test Client 1 self signed certificate
        X500Principal testClient1DN = new X500Principal("CN=Test Client 1, OU=JBoss, O=Red Hat, L=Raleigh, ST=North Carolina, C=US");
        SelfSignedX509CertificateAndSigningKey testClient1SelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(testClient1DN)
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA1withRSA")
                .addExtension(false, "SubjectAlternativeName", "DNS:testclient1.example.com")
                .build();
        X509Certificate testClient1Certificate = testClient1SelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        clientKeyStore.setKeyEntry("testclient1", testClient1SelfSignedX509CertificateAndSigningKey.getSigningKey(), PASSWORD, new X509Certificate[]{testClient1Certificate});


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
        clientKeyStore.setKeyEntry("testclientsignedbyca", signedTestClientSigningKey, PASSWORD, new X509Certificate[]{signedTestClientCertificate, testAuthorityCertificate});
    }

    @Test
    public void testKeyStoreClearPassword() throws ConfigXMLParseException, URISyntaxException {
        URL config = getClass().getResource("test-wildfly-config-v1_4.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
    }

    @Test
    public void testKeyStoreMaskedPassword() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-v1_4.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<SecurityFactory<SSLContext>> node = authContext.create().sslRuleMatching(new URI("http://masked/"), null, null);
        Assert.assertNotNull(node);
        Assert.assertNotNull(node.getConfiguration().create());
    }

    @Test
    public void testClearCredential() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-v1_4.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("http://clear/"), null, null);
        Assert.assertNotNull(node);
        Password password = node.getConfiguration().getCredentialSource().getCredential(PasswordCredential.class).getPassword();
        Assert.assertTrue(password instanceof ClearPassword);
        Assert.assertEquals(new String(PASSWORD), new String(((ClearPassword)password).getPassword()));
    }

    @Test
    public void testMaskedCredential() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-v1_4.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("http://masked/"), null, null);
        Assert.assertNotNull(node);
        Password password = node.getConfiguration().getCredentialSource().getCredential(PasswordCredential.class).getPassword();
        Assert.assertEquals(new String(PASSWORD), new String(((ClearPassword)password).getPassword()));
    }

    @Test
    public void testWebservices() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-v1_5.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("http://webservices/"), null, null);
        Assert.assertNotNull(node);
        String wsHttpMechanism  = node.getConfiguration().getWsHttpMechanism();
        String wsSecurityType = node.getConfiguration().getWsSecurityType();
        Assert.assertEquals(wsHttpMechanism, "BASIC");
        Assert.assertEquals(wsSecurityType, "UsernameToken");
    }

    @Test
    public void testEmptyWebServices() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-v1_5.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        RuleNode<AuthenticationConfiguration> node = authContext.create().authRuleMatching(new URI("http://webservices-empty/"), null, null);
        Assert.assertNotNull(node);
        String wsSecurityType = node.getConfiguration().getWsSecurityType();
        String wsHttpMechanism  = node.getConfiguration().getWsHttpMechanism();
        Assert.assertNull(wsHttpMechanism);
        Assert.assertNull(wsSecurityType);
    }

    @Test
    public void testCipherSuites() throws Exception {
        URL config = getClass().getResource("test-wildfly-config-v1_5.xml");
        SecurityFactory<AuthenticationContext> authContext = ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI());
        Assert.assertNotNull(authContext);
        checkSSLContext(authContext, "http://both.org");
        checkSSLContext(authContext, "http://selector-only.org");
        checkSSLContext(authContext, "http://names-only.org");
    }

    private void checkSSLContext(SecurityFactory<AuthenticationContext> authContext, String uri) throws Exception {
        RuleNode<SecurityFactory<SSLContext>> node = authContext.create().sslRuleMatching(new URI(uri), null, null);
        Assert.assertNotNull(node);
        Assert.assertNotNull(node.getConfiguration().create());
    }

    @BeforeClass
    public static void prepareKeyStores() throws Exception {
        Security.addProvider(provider);

        if (KEYSTORE_DIR.exists() == false) {
            KEYSTORE_DIR.mkdirs();
        }

        KeyStore clientKeyStore = KeyStore.getInstance("JKS");
        clientKeyStore.load(null, null);

        createClientKeyStore(clientKeyStore);

        File clientFile = new File(KEYSTORE_DIR, CLIENT_KEYSTORE_FILENAME);

        try (FileOutputStream clientStream = new FileOutputStream(clientFile)){
            clientKeyStore.store(clientStream, PASSWORD);
        }
    }

    @AfterClass
    public static void removeProvider() {
        Security.removeProvider(provider.getName());
    }
}
