/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.http.client.utils;

import org.junit.Assert;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.SubjectAlternativeNamesExtension;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * @author Diana Krepinska
 * */
public class ClientCertSSLTestUtils {

    private static final String CLIENT_ALIAS = "client";
    private static final String LOCALHOST_ALIAS = "localhost";
    private static final String KEYSTORE_TYPE = "JKS";
    private static final String SHA_1_WITH_RSA = "SHA1withRSA";
    private static final String TLS_PROTOCOL_VERSION = "TLSv1.2";
    public static final String KEY_MANAGER_FACTORY_ALGORITHM = "SunX509";
    private static char[] PASSWORD = "secret".toCharArray();
    private static File KEYSTORES_DIR = new File("./target/keystores");

    private static String CLIENT1_KEYSTORE_FILENAME = "client1.keystore.jks";
    private static String CLIENT1_TRUSTSTORE_FILENAME = "client1.truststore.jks";
    private static String SERVER1_KEYSTORE_FILENAME = "server1.keystore.jks";
    private static String SERVER1_TRUSTSTORE_FILENAME = "server1.truststore.jks";

    public static SSLContext createSSLContext(String keystorePath, String truststorePath, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(new FileInputStream(keystorePath), password.toCharArray());

            // Create key manager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KEY_MANAGER_FACTORY_ALGORITHM);
            keyManagerFactory.init(keyStore, password.toCharArray());
            KeyManager[] km = keyManagerFactory.getKeyManagers();

            KeyStore trustStore = KeyStore.getInstance(KEYSTORE_TYPE);
            trustStore.load(new FileInputStream(truststorePath), password.toCharArray());
            // Create trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KEY_MANAGER_FACTORY_ALGORITHM);
            trustManagerFactory.init(trustStore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();

            // Initialize SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_PROTOCOL_VERSION);
            sslContext.init(km, tm, null);

            return sslContext;
        } catch (Exception ex) {
            Assert.fail();
        }
        return null;
    }

    private static void generateTwoWaySSLKeystoresAndTruststores(String clientKeystoreFilename, String serverKeystoreFilename,
                                                                 String clientTruststoreFilename, String serverTruststoreFilename) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        // Generates client certificate and keystore
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyStore clientKeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        clientKeyStore.load(null, null);

        KeyPair clientKeyPair = keyPairGenerator.generateKeyPair();
        PrivateKey signingKey = clientKeyPair.getPrivate();
        PublicKey publicKey = clientKeyPair.getPublic();

        X500Principal testClient10DN = new X500Principal("CN=" + CLIENT_ALIAS);
        X509Certificate clientCertificate = new X509CertificateBuilder()
                .setIssuerDn(testClient10DN)
                .setSubjectDn(new X500Principal("OU=Elytron"))
                .setSignatureAlgorithmName(SHA_1_WITH_RSA)
                .setSigningKey(signingKey)
                .setPublicKey(publicKey)
                .setSerialNumber(new BigInteger("3"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .build();
        clientKeyStore.setKeyEntry(CLIENT_ALIAS, signingKey, PASSWORD, new X509Certificate[]{clientCertificate});


        // Generates server certificate and keystore
        KeyStore serverKeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        serverKeyStore.load(null, null);

        KeyPair serverKeyPair = keyPairGenerator.generateKeyPair();
        PrivateKey serverSigningKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        X500Principal testServer10DN = new X500Principal("CN=" + LOCALHOST_ALIAS);
        X509Certificate serverCertificate = new X509CertificateBuilder()
                .setIssuerDn(testServer10DN)
                .setSubjectDn(new X500Principal("OU=Elytron"))
                .setSignatureAlgorithmName(SHA_1_WITH_RSA)
                .setSigningKey(serverSigningKey)
                .setPublicKey(serverPublicKey)
                .setSerialNumber(new BigInteger("4"))
                .addExtension(new BasicConstraintsExtension(false, false, -1))
                .addExtension(new SubjectAlternativeNamesExtension(
                        true,
                        Arrays.asList(new GeneralName.DNSName(LOCALHOST_ALIAS))))
                .build();
        serverKeyStore.setKeyEntry(LOCALHOST_ALIAS, serverSigningKey, PASSWORD, new X509Certificate[]{serverCertificate});

        File clientKeystoreFile = new File(KEYSTORES_DIR, clientKeystoreFilename);
        try (FileOutputStream clientStream = new FileOutputStream(clientKeystoreFile)) {
            clientKeyStore.store(clientStream, PASSWORD);
        }

        File serverKeystoreFile = new File(KEYSTORES_DIR, serverKeystoreFilename);
        try (FileOutputStream serverStream = new FileOutputStream(serverKeystoreFile)) {
            serverKeyStore.store(serverStream, PASSWORD);
        }

        // create truststores
        KeyStore clientTrustStore = KeyStore.getInstance(KEYSTORE_TYPE);
        clientTrustStore.load(null, null);

        KeyStore serverTrustStore = KeyStore.getInstance(KEYSTORE_TYPE);
        serverTrustStore.load(null, null);
        clientTrustStore.setCertificateEntry(LOCALHOST_ALIAS, serverKeyStore.getCertificate(LOCALHOST_ALIAS));
        serverTrustStore.setCertificateEntry(CLIENT_ALIAS, clientKeyStore.getCertificate(CLIENT_ALIAS));

        File clientTrustFile = new File(KEYSTORES_DIR, clientTruststoreFilename);
        try (FileOutputStream clientStream = new FileOutputStream(clientTrustFile)) {
            clientTrustStore.store(clientStream, PASSWORD);
        }

        File serverTrustFile = new File(KEYSTORES_DIR, serverTruststoreFilename);
        try (FileOutputStream serverStream = new FileOutputStream(serverTrustFile)) {
            serverTrustStore.store(serverStream, PASSWORD);
        }
    }

    public static void createKeystores() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        if (!KEYSTORES_DIR.exists()) {
            KEYSTORES_DIR.mkdirs();
        }
        generateTwoWaySSLKeystoresAndTruststores(CLIENT1_KEYSTORE_FILENAME, SERVER1_KEYSTORE_FILENAME, CLIENT1_TRUSTSTORE_FILENAME, SERVER1_TRUSTSTORE_FILENAME);
    }

    public static void deleteKeystores() {
        new File(KEYSTORES_DIR, CLIENT1_KEYSTORE_FILENAME).delete();
        new File(KEYSTORES_DIR, CLIENT1_TRUSTSTORE_FILENAME).delete();
        new File(KEYSTORES_DIR, SERVER1_KEYSTORE_FILENAME).delete();
        new File(KEYSTORES_DIR, SERVER1_TRUSTSTORE_FILENAME).delete();
        KEYSTORES_DIR.delete();
    }
}
