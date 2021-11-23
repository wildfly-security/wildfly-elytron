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
 * including encryption and signing keys. This provider is mapped to a {@link SecurityDomain}
 * to use for all tokens generated during the authentication process associated with this Security Domain.
 *
 * The token provider only signs tokens by default but it can encrypt them if an encryption alias is specified.
 *
 * @author <a href="mailto:szaldana@redhat.com">Sonia Zaldana</a>
 */
public class WildFlyElytronTokenProvider implements TokenProvider {

    private static final String ISSUER = "WildFly Elytron";
    private static final long ACCESS_TOKEN_EXPIRY_TIME = 300;
    private static final long REFRESH_TOKEN_EXPIRY_TIME = 1209600; // 14 days
    private static final List<String> AUDIENCE = Arrays.asList("JWT");
    private static final String KEYSTORE_PASSWORD = "secret";
    private static final String SIGNING_ALIAS = "serverSigning";
    private static final Path KEYSTORE_PATH = Paths.get("tokenKeystore.jks");
    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.RS256;
    private static final KeyEncryptionAlgorithm KEY_ENCRYPTION_ALGORITHM = KeyEncryptionAlgorithm.RSA_OAEP_256;
    private static final int KEY_SIZE = 2048;
    private static final String SIGNING_DN = "cn=WildFly Elytron Signing";
    private static final String ENCRYPTION_DN = "cn=WildFly Elytron Encryption";

    private KeyStore keyStore;
    private String issuer;
    private long accessTokenExpiryTime;
    private long refreshTokenExpiryTime;
    private List<String> audience;
    private String keyStorePassword;
    private String signingAlias;
    private String encryptionAlias;
    private Path keyStorePath;
    private SignatureAlgorithm signatureAlgorithm;
    private KeyEncryptionAlgorithm keyEncryptionAlgorithm;
    private int keySize;
    private PublicKey encryptionKey;
    private PrivateKey decryptionKey;
    private PublicKey verificationKey;
    private PrivateKey signingKey;
    private SecretKey secretKey;
    private boolean built;


    public WildFlyElytronTokenProvider(Builder builder) throws Exception {
        this.issuer = builder.issuer != null ? builder.issuer : ISSUER;
        this.accessTokenExpiryTime = builder.accessTokenExpiryTime != 0 ? builder.accessTokenExpiryTime : ACCESS_TOKEN_EXPIRY_TIME;
        this.refreshTokenExpiryTime = builder.refreshTokenExpiryTime != 0 ? builder.refreshTokenExpiryTime : REFRESH_TOKEN_EXPIRY_TIME;
        this.audience = builder.audience != null ? builder.audience : AUDIENCE;
        this.keyEncryptionAlgorithm = builder.keyEncryptionAlgorithm != null ? builder.keyEncryptionAlgorithm : KEY_ENCRYPTION_ALGORITHM;
        this.signatureAlgorithm = builder.signatureAlgorithm != null ? builder.signatureAlgorithm : SIGNATURE_ALGORITHM;
        this.keySize = builder.keySize != 0 ? builder.keySize : KEY_SIZE;


        // Do checks for necessary information with user provided keystore
        if (builder.keyStorePath != null) {
            if (builder.keyStorePassword == null ) {
                throw log.missingKeystorePassword();
            }
            if (builder.encryptionAlias != null && builder.signingAlias == null) {
                throw log.missingSigningAlias();
            }
            if (builder.encryptionAlias == null && builder.signingAlias == null) {
                throw log.missingEncryptionAndSigningAlias();
            }
        }

        this.keyStorePath = builder.keyStorePath != null ? builder.keyStorePath : KEYSTORE_PATH;
        this.keyStorePassword = builder.keyStorePassword != null ? builder.keyStorePassword : KEYSTORE_PASSWORD;
        this.signingAlias = builder.signingAlias != null ? builder.signingAlias : SIGNING_ALIAS;
        this.encryptionAlias = builder.encryptionAlias; // This one can be set to null if we don't want encryption

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
                if (this.encryptionAlias != null) {
                    keyStore.setKeyEntry(this.encryptionAlias, certificateEncryption.getSigningKey(), password.toCharArray(), certificateChainEncryption);
                }
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
         * Set the alias associated with the encryption keypair entry in the keystore.
         * This is necessary for encryption, otherwise the token only gets signed by default.
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
