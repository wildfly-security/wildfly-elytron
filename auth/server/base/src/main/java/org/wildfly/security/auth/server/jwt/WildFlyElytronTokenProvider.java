/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2021 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.auth.server.jwt;

import static org.wildfly.security.auth.server._private.ElytronMessages.log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.lang.JoseException;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server._private.ElytronMessages;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import io.smallrye.jwt.algorithm.KeyEncryptionAlgorithm;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import io.smallrye.jwt.util.KeyUtils;

/**
 * A token provider which holds information regarding dynamic token issuance
 * including encryption and signing keys. This configuration is mapped to a {@link SecurityDomain}
 * to use for all tokens generated during the authentication process associated with this Security Domain.
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class WildFlyElytronTokenProvider implements TokenProvider {

    private KeyStore keyStore;
    private String issuer = "WildFly Elytron";
    private long accessTokenExpiryTime = 300;
    private long refreshTokenExpiryTime = 1209600; // 14 days
    private List<String> audience = Arrays.asList("JWT");
    private String keyStorePassword = "secret";
    private String signingAlias = "serverSigning";
    private String encryptionAlias = "serverEncryption";
    private Path keyStorePath = Paths.get("tokenKeystore.jks");
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
    private KeyEncryptionAlgorithm keyEncryptionAlgorithm = KeyEncryptionAlgorithm.RSA_OAEP_256;
    private int keySize = 2048;
    private PublicKey encryptionKey;
    private PrivateKey decryptionKey;
    private PublicKey verificationKey;
    private PrivateKey signingKey;
    private SecretKey secretKey;
    private boolean built;

    private final String SIGNING_DN = "cn=WildFly Elytron Signing";
    private final String ENCRYPTION_DN = "cn=WildFly Elytron Encryption";


    public WildFlyElytronTokenProvider(Builder builder) throws Exception {
        if (builder.issuer != null) {
            this.issuer = builder.issuer;
        }
        if (builder.accessTokenExpiryTime != 0) {
            this.accessTokenExpiryTime = builder.accessTokenExpiryTime;
        }
        if (builder.refreshTokenExpiryTime != 0) {
            this.refreshTokenExpiryTime = builder.refreshTokenExpiryTime;
        }
        if (builder.audience != null) {
            this.audience = builder.audience;
        }
        if (builder.keyStorePassword != null) {
            this.keyStorePassword = builder.keyStorePassword;
        }
        if (builder.keyEncryptionAlgorithm != null) {
            this.keyEncryptionAlgorithm = builder.keyEncryptionAlgorithm;
        }
        if (builder.signatureAlgorithm != null) {
            this.signatureAlgorithm = builder.signatureAlgorithm;
        }
        if (builder.keySize != 0) {
            this.keySize = builder.keySize;
        }

        // User provided keystore, store its path and respective aliases
        if (builder.keyStorePath != null) {
            if (builder.keyStorePassword == null || (builder.encryptionAlias == null && builder.signingAlias == null) ||
                    (builder.encryptionAlias != null && builder.signingAlias == null)) {
                throw log.missingInformationForUserKeyStore();
            }
            this.keyStorePath = builder.keyStorePath;
            this.keyStorePassword = builder.keyStorePassword;
            this.encryptionAlias = builder.encryptionAlias;
            this.signingAlias = builder.signingAlias;
        }

        if (builder.secret != null) {
            // If using symmetric encryption and algorithm not specified, we want to use another default
            if (builder.keyEncryptionAlgorithm == null) {
                this.keyEncryptionAlgorithm = KeyEncryptionAlgorithm.A256KW;
            }
            this.secretKey = KeyUtils.createSecretKeyFromSecret(builder.secret);
        }

        // Store keystore along with encryption and signing key pairs.
        this.keyStore = loadKeyStore(this.keyStorePath, this.keyStorePassword);

        try {
            if (this.encryptionAlias != null) {
                this.encryptionKey = loadPublicKey(this.keyStore, this.encryptionAlias);
                this.decryptionKey = loadPrivateKey(this.keyStore, this.encryptionAlias, this.keyStorePassword);
            }
            this.signingKey = loadPrivateKey(this.keyStore, this.signingAlias, this.keyStorePassword);
            this.verificationKey = loadPublicKey(this.keyStore, this.signingAlias);
        } catch (Exception e) {
            throw log.failedToLoadKey(e);
        }

        this.built = true;

    }

    public String getSigningAlias() {
        return this.signingAlias;
    }

    public String getEncryptionAlias() {
        return this.encryptionAlias;
    }

    public Path getKeyStorePath() {
        return this.keyStorePath;
    }

    public String getKeyStorePassword() {
        return this.keyStorePassword;
    }

    public String getIssuer() {
        return this.issuer;
    }

    public List<String> getAudience() {
        return this.audience;
    }

    public long getAccessTokenExpiryTime() {
        return this.accessTokenExpiryTime;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public KeyEncryptionAlgorithm getKeyEncryptionAlgorithm() {
        return this.keyEncryptionAlgorithm;
    }

    public PublicKey getEncryptionKey() {
        return this.encryptionKey;
    }

    public PrivateKey getDecryptionKey() {
        return this.decryptionKey;
    }

    public PublicKey getVerificationKey() {
        return this.verificationKey;
    }

    public PrivateKey getSigningKey() {
        return this.signingKey;
    }

    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    private KeyStore loadKeyStore(Path keyStorePath, String password) throws Exception {
        File file = keyStorePath.toFile();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        if (file.exists()) {
            // if exists, load
            try {
                keyStore.load(new FileInputStream(file), password.toCharArray());
            } catch (Exception e) {
                throw log.keystoreFileDoesNotExist(e);
            }
        } else {
            // Create Signing KeyPair
            SelfSignedX509CertificateAndSigningKey certificateSigning =
                    generateCertificate(SIGNING_DN);

            // Create Encryption Keypair
            SelfSignedX509CertificateAndSigningKey certificateEncryption =
                    generateCertificate(ENCRYPTION_DN);

            X509Certificate[] certificateChainSigning = {certificateSigning.getSelfSignedCertificate()};
            X509Certificate[] certificateChainEncryption = {certificateEncryption.getSelfSignedCertificate()};

            // Set keystore entries
            try {
                keyStore.load(null, null);
                keyStore.setKeyEntry(this.signingAlias, certificateSigning.getSigningKey(), password.toCharArray(), certificateChainSigning);
                keyStore.setKeyEntry(this.encryptionAlias, certificateEncryption.getSigningKey(), password.toCharArray(), certificateChainEncryption);
                keyStore.store(new FileOutputStream(file), password.toCharArray());
            } catch (NoSuchAlgorithmException e) {
                throw log.noSuchAlgorithmToCheckKeyStoreIntegrity(e);
            } catch (CertificateException e) {
                throw log.couldNotStoreCertificate(e);
            }

        }
        return keyStore;
    }

    private SelfSignedX509CertificateAndSigningKey generateCertificate(String dn) {
        return SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal(dn))
                .setKeySize(this.keySize)
                .setKeyAlgorithmName("RSA")
                .build();
    }

    private PrivateKey loadPrivateKey(KeyStore keyStore, String alias, String password) throws Exception {
        return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    }

    private PublicKey loadPublicKey(KeyStore keyStore, String alias) throws Exception {
        return keyStore.getCertificate(alias).getPublicKey();
    }

    public static Builder builder() {
        return new Builder();
    }

    void assertBuilt() {
        if (! built) {
            throw log.tokenProviderNotBuilt();
        }
    }

    @Override
    public String issueAccessToken(SecurityIdentity securityIdentity) throws JwtException {
        try {
            Assert.assertNotNull(securityIdentity);
            assertBuilt();

            Roles roles = securityIdentity.getRoles();
            HashSet<String> groups = new HashSet<>();
            roles.spliterator().forEachRemaining(role -> groups.add(role));

            JwtClaimsBuilder builder = Jwt.claims();
            builder.groups(groups)
                    .issuer(this.issuer)
                    .subject(securityIdentity.getPrincipal().getName())
                    .audience(new HashSet<>(this.audience))
                    .expiresIn(this.accessTokenExpiryTime);

            return signAndEncryptClaims(builder);
        } catch (Exception e) {
            throw ElytronMessages.log.failedToIssueJwt();
        }
    }

    @Override
    public String issueRefreshToken(SecurityIdentity securityIdentity) throws JwtException {
        try {
            Assert.assertNotNull(securityIdentity);
            assertBuilt();

            JwtClaimsBuilder builder = Jwt.claims();
            builder.issuer(this.issuer)
                    .subject(securityIdentity.getPrincipal().getName())
                    .expiresIn(this.refreshTokenExpiryTime);

            return signAndEncryptClaims(builder);
        } catch (Exception e) {
            throw ElytronMessages.log.failedToIssueJwt();

        }
    }

    private String signAndEncryptClaims(JwtClaimsBuilder builder) throws JwtException {
        if (this.signingKey != null && this.signatureAlgorithm != null) {

            // Inner sign and symmetric key encryption
            if (this.secretKey != null) {
                return builder.jws().algorithm(this.signatureAlgorithm)
                        .innerSign(this.signingKey)
                        .keyAlgorithm(this.keyEncryptionAlgorithm)
                        .encrypt(this.secretKey);
            }

            // Inner sign and asymmetric key encryption
            if (this.encryptionKey != null && this.keyEncryptionAlgorithm != null) {
                return builder.jws().algorithm(this.signatureAlgorithm)
                        .innerSign(this.signingKey)
                        .keyAlgorithm(this.keyEncryptionAlgorithm)
                        .encrypt(this.encryptionKey);
            }
            return builder.jws().algorithm(this.signatureAlgorithm)
                    .sign(this.signingKey);

        }
        throw ElytronMessages.log.invalidSigningAndEncryptionConfiguration();
    }

    @Override
    public JsonWebToken parseAndVerifyAccessToken(String token) throws JwtException {
        return parseAndVerifyToken(token, true);
    }

    @Override
    public JsonWebToken parseAndVerifyRefreshToken(String token) throws JwtException {
        return parseAndVerifyToken(token, false);
    }

    private JsonWebToken parseAndVerifyToken(String token, boolean isAccessToken) throws JwtException {
        try {
            Assert.assertNotNull(token);
            assertBuilt();

            String tokenSequence = token;
            if (this.secretKey != null) {
                tokenSequence = decryptSignedToken(token, true);
            } else if (this.decryptionKey != null && this.keyEncryptionAlgorithm != null) {
                tokenSequence = decryptSignedToken(token, false);
            }

            JwtContext jwtContext = parseClaims(tokenSequence, isAccessToken);
            return new DynamicJsonWebToken(jwtContext.getJwtClaims());
        } catch (ParseException e) {
            throw ElytronMessages.log.errorParsingJwt(e);
        } catch (Exception e) {
            throw ElytronMessages.log.failedToIssueJwt();
        }
    }

    private JwtContext parseClaims(String token, boolean isAccessToken) throws ParseException {
        JwtConsumerBuilder builder = new JwtConsumerBuilder();
        builder.setVerificationKey(this.verificationKey);
        builder.setJwsAlgorithmConstraints(
                new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                        this.signatureAlgorithm.getAlgorithm()));
        builder.setRequireExpirationTime();
        builder.setRequireIssuedAt();
        builder.setExpectedIssuer(this.issuer);
        builder.setEvaluationTime(NumericDate.fromSeconds(0));

        if (isAccessToken) {
            List<String> audience = this.audience;
            builder.setExpectedAudience(audience.toArray(new String[audience.size()]));
        }

        JwtConsumer jwtConsumer = builder.build();

        try {
            //  Validate the JWT and process it to the Claims
            JwtContext jwtContext = jwtConsumer.process(token);
            JwtClaims claimsSet = jwtContext.getJwtClaims();
            verifyIatAndExpAndTimeToLive(claimsSet);
            return jwtContext;
        } catch (InvalidJwtException e) {
            throw log.failedToVerifyToken(e);
        }
    }

    private void verifyIatAndExpAndTimeToLive(JwtClaims claimsSet) throws ParseException {
        NumericDate iat;
        NumericDate exp;

        try {
            iat = claimsSet.getIssuedAt();
            exp = claimsSet.getExpirationTime();
        } catch (Exception ex) {
            throw log.invalidIatExp();
        }
        if (iat.getValue() > exp.getValue()) {
            throw log.failedToVerifyIatExp(exp, iat);
        }
        final long maxTimeToLiveSecs = this.accessTokenExpiryTime;

        if (exp.getValue() - iat.getValue() > maxTimeToLiveSecs) {
            throw log.expExceeded(exp, maxTimeToLiveSecs, iat);
        }
    }

    private String decryptSignedToken(String token, boolean isSymmetric) throws ParseException {
        try {
            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setAlgorithmConstraints(
                    new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                            this.keyEncryptionAlgorithm.getAlgorithm()));
            if (isSymmetric) {
                jwe.setKey(this.secretKey);
            } else {
                jwe.setKey(this.decryptionKey);
            }
            jwe.setCompactSerialization(token);
            return jwe.getPlaintextString();
        } catch (JoseException e) {
            throw log.encryptedTokenSequenceInvalid(e);
        }
    }

    public static final class Builder {
        private String signingAlias;
        private String encryptionAlias;
        private Path keyStorePath;
        private String keyStorePassword;
        private String issuer;
        private List<String> audience;
        private long accessTokenExpiryTime;
        private long refreshTokenExpiryTime;
        private SignatureAlgorithm signatureAlgorithm;
        private KeyEncryptionAlgorithm keyEncryptionAlgorithm;
        private int keySize;
        private String secret;


        Builder() {

        }

        /**
         * Set the alias associated with the signing keypair entry in the keystore
         * @param signingAlias the alias for the signing keypair
         * @return this builder
         */
        public Builder setSigningAlias(String signingAlias) {
            Assert.assertNotNull(signingAlias);
            this.signingAlias = signingAlias;
            return this;
        }

        /**
         * Set the alias associated with the encryption keypair entry in the keystore
         * @param encryptionAlias the alias for the encryption keypair
         * @return this builder
         */
        public Builder setEncryptionAlias(String encryptionAlias) {
            Assert.assertNotNull(encryptionAlias);
            this.encryptionAlias = encryptionAlias;
            return this;
        }

        /**
         * Set the path where the is stored
         * @param path the path to the keystore
         * @return this builder
         */
        public Builder setKeyStorePath(Path path) {
            Assert.assertNotNull(path);
            this.keyStorePath = path;
            return this;
        }

        /**
         * Set the clear text password to use with the keystore
         * @param password the password
         * @return this builder
         */
        // TODO look into whether this should be a different type. Maybe ClearPassword?
        public Builder setKeyStorePassword(String password) {
            Assert.assertNotNull(password);
            this.keyStorePassword = password;
            return this;
        }

        /**
         * Set the value for the issuer claim
         * @param issuer the issuer
         * @return this builder
         */
        public Builder setIssuer(String issuer) {
            Assert.assertNotNull(issuer);
            this.issuer = issuer;
            return this;
        }

        /**
         * Set the value for the audience claim
         * @param audience the intended audience
         * @return this builder
         */
        public Builder setAudience(String audience) {
            Assert.assertNotNull(audience);
            this.audience = Arrays.asList(audience);
            return this;
        }

        public Builder setAudience(Set<String> audience) {
            Assert.assertNotNull(audience);
            this.audience = new ArrayList<>(audience);
            return this;
        }

        /**
         * Set the access token's expiry time in seconds
         * @param accessTokenExpiryTime the access token's expiry time
         * @return this builder
         */
        public Builder setAccessTokenExpiryTime(long accessTokenExpiryTime) {
            Assert.assertNotNull(accessTokenExpiryTime);
            this.accessTokenExpiryTime = accessTokenExpiryTime;
            return this;
        }

        /**
         * Set the refresh token's expiry time in seconds
         * @param refreshTokenExpiryTime the refresh token's expiry time
         * @return this builder
         */
        public Builder setRefreshTokenExpiryTime(long refreshTokenExpiryTime) {
            Assert.assertNotNull(refreshTokenExpiryTime);
            this.refreshTokenExpiryTime = refreshTokenExpiryTime;
            return this;
        }

        /**
         * Set the signature algorithm to use during the token issuance
         * @param signatureAlgorithm the signature algorithm
         * @return this builder
         */
        public Builder setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
            Assert.assertNotNull(signatureAlgorithm);
            this.signatureAlgorithm = signatureAlgorithm;
            return this;
        }

        /**
         * Set the encryption algorithm to use during the token issuance
         * @param keyEncryptionAlgorithm the encryption algorithm
         * @return this builder
         */
        public Builder setKeyEncryptionAlgorithm(KeyEncryptionAlgorithm keyEncryptionAlgorithm) {
            Assert.assertNotNull(keyEncryptionAlgorithm);
            this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
            return this;
        }

        /**
         * Set the key size for the automatically generated keys
         * @param keySize the key size
         * @return this builder
         */
        public Builder setKeySize(int keySize) {
            Assert.assertNotNull(keySize);
            this.keySize = keySize;
            return this;
        }

        /**
         * Set a secret if symmetric encryption is desired
         * @return this builder
         * @param secret
         */
        public Builder setSecret(String secret) {
            this.secret = secret;
            return this;
        }

        public WildFlyElytronTokenProvider build() throws Exception {
            return new WildFlyElytronTokenProvider(this);
        }
    }
}
