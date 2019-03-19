/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.keystore;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.asn1.ASN1Encodable;
import org.wildfly.security.x500.X500;
import org.wildfly.security.x500.X500AttributeTypeAndValue;
import org.wildfly.security.x500.X500PrincipalBuilder;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

import javax.security.auth.x500.X500Principal;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;

/**
 * Tests for KeyStoreUtil.
 *
 * @author <a href="mailto:mmazanek@redhat.com">Martin Mazanek</a>
 */
public class KeyStoreUtilTest {

    private final Supplier<Provider[]> providerSupplier = () -> Security.getProviders();

    private static final Provider elytronProvider = new WildFlyElytronProvider();
    private static final Provider bcProvider = new BouncyCastleProvider();
    private File workingDir = null;
    private List<File> files = new LinkedList<>();
    private KeyPairGenerator keyGen = null;

    @BeforeClass
    public static void setup() {
        Security.addProvider(elytronProvider);
        Security.addProvider(bcProvider);
    }

    @AfterClass
    public static void cleanup() {
        Security.removeProvider(elytronProvider.getName());
        Security.removeProvider(bcProvider.getName());
    }

    @Before
    public void beforeTest() throws NoSuchAlgorithmException {
        keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        workingDir = getWorkingDir();
    }

    @After
    public void afterTest() {
        files.forEach(file -> file.delete());
    }


    @Test
    public void testJKS() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        System.out.println("Testing JKS...");
        Certificate jkscert = generateCertificate();
        String filename = "testks.jks";
        String alias = "alias";
        char[] password = "password".toCharArray();

        generateKeyStoreWithKey(filename, "jks", alias, password, jkscert);

        KeyStore loadedStore = KeyStoreUtil.loadKeyStore(providerSupplier, null, new FileInputStream(new File(workingDir, filename)), filename, password);
        Assert.assertNotNull(loadedStore);
        Certificate loadedCert = loadedStore.getCertificate(alias);

        Assert.assertEquals(jkscert, loadedCert);
    }

    @Test
    public void testJCEKS() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        System.out.println("Testing JCEKS...");
        Certificate jkscert = generateCertificate();
        String filename = "testks.pkcs12";
        String alias = "alias";
        char[] password = "password".toCharArray();

        generateKeyStoreWithKey(filename, "jceks", alias, password, jkscert);

        KeyStore loadedStore = KeyStoreUtil.loadKeyStore(providerSupplier, null, new FileInputStream(new File(workingDir, filename)), filename, password);
        Assert.assertNotNull(loadedStore);
        Certificate loadedCert = loadedStore.getCertificate(alias);

        Assert.assertEquals(jkscert, loadedCert);
    }

    @Test
    public void testPKCS12() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        System.out.println("Testing PKCS12...");
        Certificate jkscert = generateCertificate();
        String filename = "testks.asdf";
        String alias = "alias";
        char[] password = "password".toCharArray();

        generateKeyStoreWithKey(filename, "pkcs12", alias, password, jkscert);

        KeyStore loadedStore = KeyStoreUtil.loadKeyStore(providerSupplier, null, new FileInputStream(new File(workingDir, filename)), filename, password);
        Assert.assertNotNull(loadedStore);
        Certificate loadedCert = loadedStore.getCertificate(alias);

        Assert.assertEquals(jkscert, loadedCert);
    }

    @Test
    public void testBKS() throws CertificateException, KeyStoreException, IOException {
        System.out.println("Testing BKS...");
        Certificate jkscert = generateCertificate();
        String filename = "testks.bks";
        String alias = "alias";
        char[] password = "password".toCharArray();
        boolean bcfailed = false;
        try {
            generateKeyStoreWithKey(filename, "bks", alias, password, jkscert);
        } catch (Exception e) {
            bcfailed = true;
        }

        Assume.assumeFalse("BC elytronProvider not found, skipping BC keystore recognition", bcfailed);

        KeyStore loadedStore = KeyStoreUtil.loadKeyStore(providerSupplier, null, new FileInputStream(new File(workingDir, filename)), filename, password);
        Assert.assertNotNull(loadedStore);
        Certificate loadedCert = loadedStore.getCertificate(alias);

        Assert.assertEquals(jkscert, loadedCert);
    }

    @Test
    public void testUBER() throws CertificateException, KeyStoreException, IOException {
        System.out.println("Testing UBER...");
        Certificate jkscert = generateCertificate();
        String filename = "testks.ubr";
        String alias = "alias";
        char[] password = "password".toCharArray();
        boolean bcfailed = false;
        try {
            generateKeyStoreWithKey(filename, "uber", alias, password, jkscert);
        } catch (Exception e) {
            bcfailed = true;
        }

        Assume.assumeFalse("BC elytronProvider not found, skipping BC keystore recognition", bcfailed);

        KeyStore loadedStore = KeyStoreUtil.loadKeyStore(providerSupplier, null, new FileInputStream(new File(workingDir, filename)), filename, password);
        Assert.assertNotNull(loadedStore);
        Certificate loadedCert = loadedStore.getCertificate(alias);

        Assert.assertEquals(jkscert, loadedCert);
    }

    @Test
    public void testBCFKS() throws CertificateException, KeyStoreException, IOException {
        System.out.println("Testing BCFKS...");
        Certificate jkscert = generateCertificate();
        String filename = "testks.bcfks";
        String alias = "alias";
        char[] password = "password".toCharArray();
        boolean bcfailed = false;
        try {
            generateKeyStoreWithKey(filename, "bcfks", alias, password, jkscert);
        } catch (Exception e) {
            bcfailed = true;
        }

        Assume.assumeFalse("BC elytronProvider not found, skipping BC keystore recognition", bcfailed);

        KeyStore loadedStore = KeyStoreUtil.loadKeyStore(providerSupplier, null, new FileInputStream(new File(workingDir, filename)), filename, password);
        Assert.assertNotNull(loadedStore);
        Certificate loadedCert = loadedStore.getCertificate(alias);

        Assert.assertEquals(jkscert, loadedCert);
    }

    @Test
    public void testNoKeystore() throws IOException, KeyStoreException{
        String filename = "notakeystore.txt";
        File f = new File(workingDir, filename);
        files.add(f);
        FileWriter fw = new FileWriter(f);
        fw.write("joejoejoe");
        fw.flush();
        fw.close();
        try {
            KeyStore loadedStore = KeyStoreUtil.loadKeyStore(providerSupplier, null, new FileInputStream(f), filename, "whatever".toCharArray());
        } catch (Exception e) {
            return;
        }
        Assert.fail("Key store detection should fail.");
    }


    private void generateKeyStoreWithKey(String filename, String type, String alias, char[] password, Certificate cert) throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException {
        File keyStoreFile = new File(workingDir, filename);
        files.add(keyStoreFile);
        KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(null, null);
        keyStore.setCertificateEntry(alias, cert);
        keyStore.store(new FileOutputStream(keyStoreFile), password);
    }

    private X509Certificate generateCertificate() throws CertificateException {
        X509CertificateBuilder builder = new X509CertificateBuilder();
        X500PrincipalBuilder principalBuilder = new X500PrincipalBuilder();
        KeyPair kp = keyGen.generateKeyPair();
        principalBuilder.addItem(X500AttributeTypeAndValue.create(X500.OID_AT_COMMON_NAME, ASN1Encodable.ofUtf8String("jane")));
        final X500Principal dn = principalBuilder.build();
        builder.setIssuerDn(dn);
        builder.setSubjectDn(dn);
        builder.setSignatureAlgorithmName("SHA256withRSA");
        builder.setSigningKey(kp.getPrivate());
        builder.setPublicKey(kp.getPublic());
        return builder.build();
    }

    private static File getWorkingDir() {
        File workingDir = new File("./target/keystore");
        if (workingDir.exists() == false) {
            workingDir.mkdirs();
        }
        return workingDir;
    }
}
