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

package org.wildfly.security.auth.server;

import mockit.Mock;
import mockit.MockUp;
import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.callback.SSLCallback;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.FileSystemSecurityRealm;
import org.wildfly.security.sasl.external.ExternalSaslServerFactory;
import org.wildfly.security.sasl.util.SetMechanismInformationSaslServerFactory;
import org.wildfly.security.ssl.SSLConnection;
import org.wildfly.security.x500.X500;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.X509CertificateBuilder;
import org.wildfly.security.x500.principal.X500AttributePrincipalDecoder;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.x500.X500Principal;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SaslExternalServerAuthenticationCallbackTest {

    static Path rootPath;
    static SecurityDomain securityDomain;
    static SetMechanismInformationSaslServerFactory factory;

    @BeforeClass
    public static void setup() throws Exception {
        mockClientsCertificateEvidence();

        // create a test user
        FileSystemSecurityRealm securityRealm = new FileSystemSecurityRealm(getRootPath(), 3);
        ModifiableRealmIdentity identity = securityRealm.getRealmIdentityForUpdate(new NamePrincipal("externalSaslUser"));
        identity.create();
        identity.dispose();
        assertTrue(identity.exists());

        // create security domain with CN principal decoder
        securityDomain = SecurityDomain.builder().setDefaultRealmName("default").addRealm("default", securityRealm).build()
                .setPermissionMapper((permissionMappable, roles) -> LoginPermission.getInstance())
                .setPrincipalDecoder(new X500AttributePrincipalDecoder("2.5.4.3"))
                .build();

        // create external sasl server factory for tests
        SaslServerFactory externalSaslServerFactory = new ExternalSaslServerFactory();
        factory = new SetMechanismInformationSaslServerFactory(externalSaslServerFactory);
        assertNotNull("SaslServerFactory not registered", factory);
    }

    @Test
    public void testWithSkipCertificateVerificationProp() throws GeneralSecurityException, IOException, UnsupportedCallbackException {
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        CallbackHandler callbackHandler = sac.createCallbackHandler();
        SSLConnection sslConnection = SSLConnection.forSession(new DummySessionContainingPeerCertificates(), true);
        callbackHandler.handle(new SSLCallback[]{new SSLCallback(sslConnection)});

        SaslServer saslServerWithSkipCertificateProp = factory.createSaslServer("EXTERNAL", "test", "localhost", setProp("org.wildfly.security.sasl.skip-certificate-verification", "true"), callbackHandler);
        try {
            byte[] response = saslServerWithSkipCertificateProp.evaluateResponse("externalSaslUser".getBytes());
            Assert.assertNull(response);
        } catch (SaslException e) {
            fail("SASL EXTERNAL authentication with org.wildfly.sasl.skip-certificate-verification property failed");
        }
    }

    @Test
    public void testWithSkipCertificateVerificationPropFalse() throws GeneralSecurityException, IOException, UnsupportedCallbackException {
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        CallbackHandler callbackHandler = sac.createCallbackHandler();
        SSLConnection sslConnection = SSLConnection.forSession(new DummySessionContainingPeerCertificates(), true);
        callbackHandler.handle(new SSLCallback[]{new SSLCallback(sslConnection)});

        SaslServer saslServerWithSkipCertificateProp = factory.createSaslServer("EXTERNAL", "test", "localhost", setProp("org.wildfly.security.sasl.skip-certificate-verification", "false"), callbackHandler);
        try {
            byte[] response = saslServerWithSkipCertificateProp.evaluateResponse("externalSaslUser".getBytes());
            Assert.fail();
        } catch (SaslException expected) {
            // ignore
        }
    }

    @Test
    public void testWithNullProperties() throws IOException, UnsupportedCallbackException {
        ServerAuthenticationContext sac = securityDomain.createNewAuthenticationContext();
        CallbackHandler callbackHandler = sac.createCallbackHandler();
        SSLConnection sslConnection = SSLConnection.forSession(new DummySessionContainingPeerCertificates(), true);
        callbackHandler.handle(new SSLCallback[]{new SSLCallback(sslConnection)});

        SaslServer withoutSkipCertificateProp = factory.createSaslServer("EXTERNAL", "test", "localhost", null, callbackHandler);
        try {
            withoutSkipCertificateProp.evaluateResponse("externalSaslUser".getBytes());
            Assert.fail();
        } catch (SaslException expected) {
            // ignore
        }
    }

    @AfterClass
    public static void deleteTestFilesystemRealm() throws IOException {
        FileUtils.cleanDirectory(rootPath.toFile());
    }

    private Map<String, ?> setProp(String key, String value) {
        return Stream.of(key).collect(Collectors.toMap(Function.identity(), s -> value));
    }

    private static Path getRootPath() throws Exception {
        rootPath = Paths.get(SaslExternalServerAuthenticationCallbackTest.class.getResource(File.separator).toURI())
                .resolve("filesystem-realm");

        return Files.walkFileTree(Files.createDirectories(rootPath), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
    }

    protected static void mockClientsCertificateEvidence() {

        new MockUp<ServerAuthenticationContext.InactiveState>() {
            @Mock
            public boolean canVerifyEvidence() {
                return true;
            }
        };

        new MockUp<X500>() {
            @Mock
            public X509Certificate[] asX509CertificateArray(Object[] certificates) throws ArrayStoreException {
                X509Certificate clientCertificate = generateX509CertificateWithExternalSaslUserCN();
                return new X509Certificate[]{clientCertificate};
            }
        };
    }

    private static X509Certificate generateX509CertificateWithExternalSaslUserCN() {
        X509Certificate clientCertificate = null;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            KeyPair clientKeyPair = keyPairGenerator.generateKeyPair();
            PrivateKey signingKey = clientKeyPair.getPrivate();
            PublicKey publicKey = clientKeyPair.getPublic();
            X500Principal testClient10DN = new X500Principal("CN=" + "issuer");
            clientCertificate = new X509CertificateBuilder()
                    .setIssuerDn(testClient10DN)
                    .setSubjectDn(new X500Principal("CN=externalSaslUser"))
                    .setSignatureAlgorithmName("SHA1withRSA")
                    .setSigningKey(signingKey)
                    .setPublicKey(publicKey)
                    .setSerialNumber(new BigInteger("3"))
                    .addExtension(new BasicConstraintsExtension(false, false, -1))
                    .build();
        } catch (CertificateException | NoSuchAlgorithmException e) {
            fail();
        }
        return clientCertificate;
    }

    static class DummySessionContainingPeerCertificates implements SSLSession {

        @Override
        public byte[] getId() {
            return new byte[0];
        }

        @Override
        public SSLSessionContext getSessionContext() {
            return null;
        }

        @Override
        public long getCreationTime() {
            return 0;
        }

        @Override
        public long getLastAccessedTime() {
            return 0;
        }

        @Override
        public void invalidate() {

        }

        @Override
        public boolean isValid() {
            return false;
        }

        @Override
        public void putValue(String s, Object o) {

        }

        @Override
        public Object getValue(String s) {
            return null;
        }

        @Override
        public void removeValue(String s) {

        }

        @Override
        public String[] getValueNames() {
            return new String[0];
        }

        @Override
        public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
            return new Certificate[0];
        }

        @Override
        public Certificate[] getLocalCertificates() {
            return new Certificate[0];
        }

        @Override
        public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
            return new javax.security.cert.X509Certificate[0];
        }

        @Override
        public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            return null;
        }

        @Override
        public Principal getLocalPrincipal() {
            return null;
        }

        @Override
        public String getCipherSuite() {
            return null;
        }

        @Override
        public String getProtocol() {
            return null;
        }

        @Override
        public String getPeerHost() {
            return null;
        }

        @Override
        public int getPeerPort() {
            return 0;
        }

        @Override
        public int getPacketBufferSize() {
            return 0;
        }

        @Override
        public int getApplicationBufferSize() {
            return 0;
        }
    }
}
