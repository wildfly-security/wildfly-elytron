/*
 * Copyright 2020 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.ssl.test.util;

import static org.wildfly.security.x500.X500.OID_AD_OCSP;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import javax.security.auth.x500.X500Principal;

import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.cert.AccessDescription;
import org.wildfly.security.x500.cert.AuthorityInformationAccessExtension;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;
import org.wildfly.security.x500.cert.X509CertificateExtension;

/**
 * A tool for generating a complete set of certificates backed by a generated certificate authority.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class CAGenerationTool implements Closeable {

    public static final String SIGNATURE_ALGORTHM = "SHA256withRSA";

    private static final String BEETLES_STORE = "beetles.keystore";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String KEYSTORE_TYPE = "JKS"; // TODO Switch to PKCS#12
    private static final int OCSP_PORT = 4854;
    private static final char[] PASSWORD = "Elytron".toCharArray();

    private static final Set<Identity> BEETLES = Collections
            .unmodifiableSet(new HashSet<>(Arrays.asList(Identity.LADYBIRD, Identity.SCARAB, Identity.DUNG, Identity.FIREFLY)));
    private static final Predicate<Identity> INCLUDE_IN_BEETLES = BEETLES::contains;

    private final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    private final Map<Identity, CAState> caMap = new HashMap<>();
    private final Map<Identity, X509Certificate> certificateMap = new HashMap<>();

    private final File workingDir;

    protected CAGenerationTool(Builder builder) throws Exception {
        // Ensure we have the directory created to hold the resulting KeyStores
        workingDir = new File(builder.baseDir);
        workingDir.mkdirs();

        KeyStore beetlesStore = createEmptyKeyStore();

        for (Identity currentIdentity : builder.requestedIdentities) {
            if (currentIdentity.isCertificateAuthority()) {
                caMap.computeIfAbsent(currentIdentity, this::createCA);
            } else {
                X509Certificate certificate = createIdentity(currentIdentity);
                certificateMap.put(currentIdentity, certificate);
                if (INCLUDE_IN_BEETLES.test(currentIdentity)) {
                    beetlesStore.setCertificateEntry(currentIdentity.toString(), certificate);
                }
            }
        }

        try {
            File keyStoreFile = new File(workingDir, BEETLES_STORE);
            try (OutputStream out = new FileOutputStream(keyStoreFile)) {
                beetlesStore.store(out, PASSWORD);
            }
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public X509Certificate getCertificate(final Identity identity) {
        return certificateMap.get(identity);
    }

    public PrivateKey getPrivateKey(final Identity identity) {
        if (!identity.isCertificateAuthority()) {
            throw new IllegalStateException(String.format("Identity %s if not a CertificateAuthority", identity.toString()));
        }

        return caMap.computeIfAbsent(identity, this::createCA).signingKey;
    }

    private CAState createCA(final Identity identity) {
        CAState caState = new CAState();

        Identity signedBy = identity.getSignedBy();
        if (signedBy == null) {
            // As a root CA it will require a self signed certificate.
            SelfSignedX509CertificateAndSigningKey issuerSelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
                    .setDn(identity.getPrincipal())
                    .setKeyAlgorithmName(KEY_ALGORITHM)
                    .setSignatureAlgorithmName(SIGNATURE_ALGORTHM)
                    .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
                    .build();
            caState.issuerCertificate = issuerSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
            caState.signingKey = issuerSelfSignedX509CertificateAndSigningKey.getSigningKey();
        } else {
            try {
                CAState signerState = caMap.computeIfAbsent(signedBy, this::createCA);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                X509Certificate intermediateIssuerCertificate = new X509CertificateBuilder()
                        .setIssuerDn(signedBy.getPrincipal())
                        .setSubjectDn(identity.getPrincipal())
                        .setSignatureAlgorithmName(SIGNATURE_ALGORTHM)
                        .setSigningKey(signerState.signingKey)
                        .setPublicKey(keyPair.getPublic())
                        .setSerialNumber(BigInteger.valueOf(signerState.serialNumber++))
                        .addExtension(new BasicConstraintsExtension(false, true, -1))
                        .addExtension(new AuthorityInformationAccessExtension(Collections.singletonList(
                                new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_PORT + "/ocsp"))
                        )))
                        .build();

                caState.issuerCertificate = intermediateIssuerCertificate;
                caState.signingKey = keyPair.getPrivate();
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            }
        }

        if (identity.getKeyStoreName() != null) {
            try {
                File keyStoreFile = new File(workingDir, identity.getKeyStoreName());
                final KeyStore keyStore = keyStoreFile.exists() ? loadKeyStore(keyStoreFile) : createEmptyKeyStore();
                keyStore.setCertificateEntry(identity.toString(), caState.issuerCertificate);
                try (OutputStream out = new FileOutputStream(keyStoreFile)) {
                    keyStore.store(out, PASSWORD);
                }
            } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        certificateMap.put(identity, caState.issuerCertificate);
        return caState;
    }

    public X509Certificate createIdentity(final String alias, final X500Principal principal, final String keyStoreName,
            final Identity ca, final X509CertificateExtension... extensions) {
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        CAState caState = caMap.computeIfAbsent(ca, this::createCA);

        try {
            X509CertificateBuilder certificateBuilder = new X509CertificateBuilder()
                    .setIssuerDn(ca.getPrincipal())
                    .setSubjectDn(principal)
                    .setSignatureAlgorithmName(SIGNATURE_ALGORTHM)
                    .setSigningKey(caState.signingKey)
                    .setPublicKey(keyPair.getPublic())
                    .setSerialNumber(BigInteger.valueOf(caState.serialNumber++))
                    .addExtension(new BasicConstraintsExtension(false, false, -1));
            for (X509CertificateExtension currentExtension : extensions) {
                certificateBuilder.addExtension(currentExtension);
            }
            X509Certificate builtCertificate = certificateBuilder.build();

            File keyStoreFile = new File(workingDir, keyStoreName);
            KeyStore keyStore = createEmptyKeyStore();

            List<X509Certificate> certificates = new ArrayList<>();
            certificates.add(builtCertificate);

            Identity caIdentity = ca;
            do {
                caState = caMap.get(caIdentity); // We just created a signed cert above, the complete chain must be present.
                keyStore.setCertificateEntry(caIdentity.toString(), caState.issuerCertificate); // This could be removed as the cert chain is added to the Entry.
                certificates.add(caState.issuerCertificate);
                caIdentity = caIdentity.getSignedBy();
            } while (caIdentity != null);

            keyStore.setKeyEntry(alias, keyPair.getPrivate(), PASSWORD,
                    certificates.toArray(new X509Certificate[certificates.size()]));
            try (OutputStream out = new FileOutputStream(keyStoreFile)) {
                keyStore.store(out, PASSWORD);
            }

            return builtCertificate;
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public X509Certificate createSelfSignedIdentity(final String alias, final X500Principal principal, final String keyStoreName) {
        SelfSignedX509CertificateAndSigningKey selfSignedIdentity = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(principal)
                .setKeyAlgorithmName(KEY_ALGORITHM)
                .setSignatureAlgorithmName(SIGNATURE_ALGORTHM)
                .build();

        X509Certificate selfSignedCertificate = selfSignedIdentity.getSelfSignedCertificate();
        File keyStoreFile = new File(workingDir, keyStoreName);
        KeyStore keyStore = createEmptyKeyStore();
        try {
            keyStore.setKeyEntry(alias, selfSignedIdentity.getSigningKey(), PASSWORD,
                    new X509Certificate[] { selfSignedIdentity.getSelfSignedCertificate() });
            try (OutputStream out = new FileOutputStream(keyStoreFile)) {
                keyStore.store(out, PASSWORD);
            }
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return selfSignedCertificate;
    }

    private X509Certificate createIdentity(final Identity identity) {
        Identity caIdentity = identity.getSignedBy();
        if (caIdentity == null) {
            // This should not happen but better than a NPE.
            throw new IllegalStateException(String.format("Identity %s does not have a CA.", identity.toString()));
        }

        return createIdentity(identity.toString(), identity.getPrincipal(), identity.getKeyStoreName(), caIdentity);
    }

    private static KeyStore createEmptyKeyStore() {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
            ks.load(null,null);

            return ks;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyStore loadKeyStore(final File location) {
        try (InputStream caTrustStoreFile = new FileInputStream(location)) {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(caTrustStoreFile, PASSWORD);

            return keyStore;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void close() throws IOException {
        workingDir.delete();
    }

    public static Builder builder() {
        return new Builder();
    }

    static class CAState {
        PrivateKey signingKey;
        X509Certificate issuerCertificate;
        int serialNumber = 1;
    }

    public enum Identity {

        CA("CN=Elytron CA, ST=Elytron, C=UK, EMAILADDRESS=elytron@wildfly.org, O=Root Certificate Authority",
                null, true, "ca.truststore"),
        LADYBIRD("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Ladybird",
                CA, false, "ladybird.keystore"),
        SCARAB("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Scarab",
                CA, false, "scarab.keystore"),
        DUNG("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Dung",
                CA, false, "dung.keystore"),
        FIREFLY("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Firefly",
                CA, false, "firefly.keystore"),
        INTERMEDIATE("CN=Elytron ICA, ST=Elytron, C=UK, O=Intermediate Certificate Authority",
                CA, true, null),
        ROVE("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=Rove",
                INTERMEDIATE, false, "rove.keystore");

        private final X500Principal principal;
        private final Identity signedBy;
        private final boolean ca;
        private final String keyStoreName;

        private Identity(final String distinguishedName, final Identity signedBy, final boolean ca, final String keyStoreName) {
            this.principal =  new X500Principal(distinguishedName);
            this.signedBy = signedBy;
            this.ca = ca;
            this.keyStoreName = keyStoreName;
        }

        public X500Principal getPrincipal() {
            return principal;
        }

        public Identity getSignedBy() {
            return signedBy;
        }

        public boolean isCertificateAuthority() {
            return ca;
        }

        public String getKeyStoreName() {
            return keyStoreName;
        }

        public String toString() {
            return this.name().toLowerCase();
        }
    }

    public static class Builder {

        private String baseDir = ".";
        private Identity[] requestedIdentities = {};

        public Builder setBaseDir(final String baseDir) {
            this.baseDir = baseDir;

            return this;
        }

        public Builder setRequestIdentities(Identity... requestedIdentities) {
            this.requestedIdentities = requestedIdentities;

            return this;
        }

        public CAGenerationTool build() throws Exception {
            return new CAGenerationTool(this);
        }

    }

}
