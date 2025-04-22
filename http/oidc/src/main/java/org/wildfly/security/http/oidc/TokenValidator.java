/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.IDToken.AT_HASH;
import static org.wildfly.security.http.oidc.Oidc.DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME;
import static org.wildfly.security.http.oidc.Oidc.INVALID_AT_HASH_CLAIM;
import static org.wildfly.security.http.oidc.Oidc.INVALID_ISSUED_FOR_CLAIM;
import static org.wildfly.security.http.oidc.Oidc.INVALID_SESSION_RANDOM_VALUE;
import static org.wildfly.security.http.oidc.Oidc.INVALID_TYPE_CLAIM;
import static org.wildfly.security.http.oidc.Oidc.getJavaAlgorithmForHash;
import static org.wildfly.security.jose.jwk.JWKUtil.BASE64_URL;

import java.nio.charset.StandardCharsets;
import java.security.AccessController;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.ErrorCodeValidator;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.wildfly.common.Assert;
import org.wildfly.common.iteration.ByteIterator;

/**
 * Validator for an ID token or bearer token, as per <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * and <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523</a></a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class TokenValidator {

    static final boolean DISABLE_TYP_CLAIM_VALIDATION_PROPERTY;

    static {
        DISABLE_TYP_CLAIM_VALIDATION_PROPERTY = AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            @Override
            public Boolean run() {
                return Boolean.parseBoolean(System.getProperty(DISABLE_TYP_CLAIM_VALIDATION_PROPERTY_NAME, "false"));
            }
        });
    }

    private static final int HEADER_INDEX = 0;
    private JwtConsumerBuilder jwtConsumerBuilder;
    private OidcClientConfiguration clientConfiguration;

    private TokenValidator(Builder builder) {
        this.jwtConsumerBuilder = builder.jwtConsumerBuilder;
        this.clientConfiguration = builder.clientConfiguration;
    }

    public VerifiedTokens parseAndVerifyToken(final String idToken, final String accessToken) throws OidcException {
        return parseAndVerifyToken(idToken, accessToken, null, false);
    }

    /**
     * Parse and verify the given ID token.
     *
     * @param idToken the ID token
     * @return the {@code VerifiedTokens} if the ID token was valid
     * @throws OidcException if the ID token is invalid
     */
    public VerifiedTokens parseAndVerifyToken(final String idToken, final String accessToken,
                                              OidcHttpFacade.Cookie cookie, boolean isValidateNonce) throws OidcException {
        try {
            JwtContext idJwtContext = setVerificationKey(idToken, jwtConsumerBuilder);
            jwtConsumerBuilder.setExpectedAudience(clientConfiguration.getResourceName());
            jwtConsumerBuilder.registerValidator(new AzpValidator(clientConfiguration.getResourceName()));
            jwtConsumerBuilder.registerValidator(new AtHashValidator(accessToken, clientConfiguration.getTokenSignatureAlgorithm()));
            if (isValidateNonce) {
                jwtConsumerBuilder.registerValidator(new NonceValidator(cookie));
            }

            // second pass to validate
            jwtConsumerBuilder.build().processContext(idJwtContext);
            JwtClaims idJwtClaims = idJwtContext.getJwtClaims();
            if (idJwtClaims == null) {
                throw log.invalidIDTokenClaims();
            }
            JwtClaims jwtClaims = new JwtConsumerBuilder().setSkipSignatureVerification().setSkipAllValidators().build().processToClaims(accessToken);
            return new VerifiedTokens(new IDToken(idJwtClaims), new AccessToken(jwtClaims));
        } catch (InvalidJwtException e) {
            log.tracef("Problem parsing ID token: " + idToken, e);
            throw log.invalidIDToken(e);
        }
    }

    /**
     * Parse and verify the given bearer token.
     *
     * @param bearerToken the bearer token
     * @return the {@code AccessToken} if the bearer token was valid
     * @throws OidcException if the bearer token is invalid
     */
    public AccessToken parseAndVerifyToken(final String bearerToken) throws OidcException {
        try {
            JwtContext jwtContext = setVerificationKey(bearerToken, jwtConsumerBuilder);
            jwtConsumerBuilder.setRequireSubject();
            if (! DISABLE_TYP_CLAIM_VALIDATION_PROPERTY) {
                jwtConsumerBuilder.registerValidator(new TypeValidator("Bearer"));
            }
            if (clientConfiguration.isVerifyTokenAudience()) {
                jwtConsumerBuilder.setExpectedAudience(clientConfiguration.getResourceName());
            } else {
                jwtConsumerBuilder.setSkipDefaultAudienceValidation();
            }
            // second pass to validate
            jwtConsumerBuilder.build().processContext(jwtContext);
            JwtClaims jwtClaims = jwtContext.getJwtClaims();
            if (jwtClaims == null) {
                throw log.invalidBearerTokenClaims();
            }
            return new AccessToken(jwtClaims);
        } catch (InvalidJwtException e) {
            log.tracef("Problem parsing bearer token: " + bearerToken, e);
            throw log.invalidBearerToken(e);
        }
    }

    private JwtContext setVerificationKey(final String token, final JwtConsumerBuilder jwtConsumerBuilder) throws InvalidJwtException {
        // first pass to determine the kid, if present
        JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();
        JwtContext jwtContext = firstPassJwtConsumer.process(token);
        String kid =  jwtContext.getJoseObjects().get(HEADER_INDEX).getKeyIdHeaderValue();
        if (kid != null && clientConfiguration.getPublicKeyLocator() != null) {
            jwtConsumerBuilder.setVerificationKey(clientConfiguration.getPublicKeyLocator().getPublicKey(kid, clientConfiguration));
        } else {
            // secret key
            ClientSecretCredentialsProvider clientSecretCredentialsProvider = (ClientSecretCredentialsProvider) clientConfiguration.getClientAuthenticator();
            jwtConsumerBuilder.setVerificationKey(clientSecretCredentialsProvider.getClientSecret());
        }
        return jwtContext;
    }

    /**
     * Construct a new builder instance.
     *
     * @param clientConfiguration the OIDC client configuration
     * @return the new builder instance
     */
    public static Builder builder(OidcClientConfiguration clientConfiguration) {
        return new Builder(clientConfiguration);
    }

    public static class Builder {
        private OidcClientConfiguration clientConfiguration;
        private String expectedIssuer;
        private String clientId;
        private String expectedJwsAlgorithm;
        private PublicKeyLocator publicKeyLocator;
        private SecretKey clientSecretKey;
        private JwtConsumerBuilder jwtConsumerBuilder;

        /**
         * Construct a new uninitialized instance.
         *
         * @param clientConfiguration the OIDC client configuration
         */
        Builder(OidcClientConfiguration clientConfiguration) {
            Assert.checkNotNullParam("clientConfiguration", clientConfiguration);
            this.clientConfiguration = clientConfiguration;
        }

        /**
         * Create an ID token or bearer token validator.
         *
         * @return the newly created token validator
         * @throws IllegalArgumentException if a required builder parameter is missing or invalid
         */
        public TokenValidator build() throws IllegalArgumentException {
            expectedIssuer = clientConfiguration.getIssuerUrl();
            if (expectedIssuer == null || expectedIssuer.length() == 0) {
                throw log.noExpectedIssuerGiven();
            }
            clientId = clientConfiguration.getResourceName();
            if (clientId == null || clientId.length() == 0) {
                throw log.noClientIDGiven();
            }
            expectedJwsAlgorithm = clientConfiguration.getTokenSignatureAlgorithm();
            if (expectedJwsAlgorithm == null || expectedJwsAlgorithm.length() == 0) {
                throw log.noExpectedJwsAlgorithmGiven();
            }
            publicKeyLocator = clientConfiguration.getPublicKeyLocator();
            if (clientConfiguration.getClientAuthenticator() instanceof ClientSecretCredentialsProvider) {
                ClientSecretCredentialsProvider clientSecretCredentialsProvider = (ClientSecretCredentialsProvider) clientConfiguration.getClientAuthenticator();
                clientSecretKey = clientSecretCredentialsProvider.getClientSecret();
            }
            if (publicKeyLocator == null && clientSecretKey == null) {
                throw log.noJwksPublicKeyOrClientSecretKeyGiven();
            }

            jwtConsumerBuilder = new JwtConsumerBuilder()
                    .setExpectedIssuer(expectedIssuer)
                    .setJwsAlgorithmConstraints(
                            new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT, expectedJwsAlgorithm))
                    .setRequireExpirationTime();

            return new TokenValidator(this);
        }
    }

    private static class AzpValidator implements ErrorCodeValidator {
        public static final String AZP = "azp";
        private final String issuedFor;

        public AzpValidator(String issuedFor) {
            this.issuedFor = issuedFor;
        }

        public ErrorCodeValidator.Error validate(JwtContext jwtContext) throws MalformedClaimException {
            JwtClaims jwtClaims = jwtContext.getJwtClaims();
            boolean valid = false;
            if (jwtClaims.getAudience().size() > 1) {
                // if the ID token contains multiple audiences, then verify that an azp claim is present
                if (jwtClaims.hasClaim(AZP)) {
                    String azpValue = jwtClaims.getStringClaimValue(AZP);
                    valid = azpValue != null && jwtClaims.getClaimValueAsString(AZP).equals(issuedFor);
                }
            } else {
                valid = true; // one audience
            }
            if (! valid) {
                return new ErrorCodeValidator.Error(INVALID_ISSUED_FOR_CLAIM, log.unexpectedValueForIssuedForClaim());
            }
            return null;
        }
    }

    private static class AtHashValidator implements ErrorCodeValidator {
        private final String accessTokenString;
        private final String jwsAlgorithm;

        public AtHashValidator(String accessTokenString, String jwsAlgorithm) {
            this.accessTokenString = accessTokenString;
            this.jwsAlgorithm = jwsAlgorithm;
        }

        public ErrorCodeValidator.Error validate(JwtContext jwtContext) throws MalformedClaimException {
            JwtClaims jwtClaims = jwtContext.getJwtClaims();
            boolean valid = true;
            if (jwtClaims.hasClaim(AT_HASH)) {
                String atHash = jwtClaims.getStringClaimValue(AT_HASH);
                String actualHash;
                try {
                    actualHash = getAccessTokenHash(accessTokenString, jwsAlgorithm);
                    valid = atHash.equals(actualHash);
                } catch (Exception e) {
                    valid = false;
                }
            }
            if (! valid) {
                return new ErrorCodeValidator.Error(INVALID_AT_HASH_CLAIM, log.unexpectedValueForAtHashClaim());
            }
            return null;
        }

        private static String getAccessTokenHash(String accessTokenString, String jwsAlgorithm) throws NoSuchAlgorithmException {
            byte[] inputBytes = accessTokenString.getBytes(StandardCharsets.UTF_8);
            String javaAlgName = getJavaAlgorithmForHash(jwsAlgorithm);
            MessageDigest md = MessageDigest.getInstance(javaAlgName);
            md.update(inputBytes);
            byte[] hash = md.digest();
            int hashLength = hash.length / 2;
            byte[] hashInput = Arrays.copyOf(hash, hashLength); // leftmost half of the hash
            return ByteIterator.ofBytes(hashInput).base64Encode(BASE64_URL, false).drainToString();
        }

    }


    private static class NonceValidator implements ErrorCodeValidator {
        private OidcHttpFacade.Cookie cookie;

        public NonceValidator(OidcHttpFacade.Cookie cookie) {
            this.cookie = cookie;
        }

        public ErrorCodeValidator.Error validate(JwtContext jwtContext) throws MalformedClaimException {
            JwtClaims idJwtClaims = jwtContext.getJwtClaims();
            IDToken idToken = new IDToken(idJwtClaims);

            if (cookie != null) {
                String sessionRandomValue = Oidc.getCryptographicValue(cookie.getValue());
                String nonceValue = idToken.getNonce();
                if (!sessionRandomValue.equals(nonceValue)) {
                    return new ErrorCodeValidator.Error(INVALID_SESSION_RANDOM_VALUE,
                            log.invalidNonceValue(nonceValue));
                }
            } else {
                return new ErrorCodeValidator.Error(INVALID_SESSION_RANDOM_VALUE,
                        log.nonceCookieDoesNotExist());
            }
            return null;
        }
    }

    private static class TypeValidator implements ErrorCodeValidator {
        public static final String TYPE = "typ";
        private final String expectedType;

        public TypeValidator(String expectedType) {
            this.expectedType = expectedType;
        }

        public ErrorCodeValidator.Error validate(JwtContext jwtContext) throws MalformedClaimException {
            JwtClaims jwtClaims = jwtContext.getJwtClaims();
            boolean valid = false;
            if (jwtClaims.hasClaim(TYPE)) {
                valid = jwtClaims.getStringClaimValue(TYPE).equals(expectedType);
            }
            if (! valid) {
                return new ErrorCodeValidator.Error(INVALID_TYPE_CLAIM, log.unexpectedValueForTypeClaim());
            }
            return null;
        }
    }

    public static class VerifiedTokens {

        private final AccessToken accessToken;
        private final IDToken idToken;

        public VerifiedTokens(final IDToken idToken, final AccessToken accessToken) {
            this.idToken = idToken;
            this.accessToken = accessToken;
        }

        public AccessToken getAccessToken() {
            return accessToken;
        }

        public IDToken getIdToken() {
            return idToken;
        }
    }
}


