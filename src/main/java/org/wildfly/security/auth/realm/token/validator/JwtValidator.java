/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.realm.token.validator;

import org.wildfly.security.auth.realm.token.TokenValidator;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.pem.PemEntry;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import static java.util.Arrays.asList;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.util.JsonUtil.toAttributes;

/**
 * A {@link TokenValidator} capable of validating and parsing JWT. Most of the validations performed by this validator are
 * based on RFC-7523 (JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants).
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JwtValidator implements TokenValidator {

    /**
     * Returns a {@link Builder} instance that can be used to configure and create a {@link JwtValidator}.
     *
     * @return a {@link Builder} instance
     */
    public static Builder builder() {
        return new Builder();
    }

    private final Set<String> issuers;
    private final Set<String> audiences;

    private final byte[] publicKey;

    JwtValidator(Builder configuration) {
        this.issuers = checkNotNullParam("issuers", configuration.issuers);
        this.audiences = checkNotNullParam("audience", configuration.audience);
        this.publicKey = checkNotNullParam("publicKey", configuration.publicKey);
    }

    @Override
    public Attributes validate(BearerTokenEvidence evidence) throws RealmUnavailableException {
        checkNotNullParam("evidence", evidence);
        String jwt = evidence.getToken();
        String[] parts = jwt.split("\\.");

        if (parts.length < 3) {
            throw log.tokenRealmJwtInvalidFormat();
        }

        String encodedHeader = parts[0];
        String encodedClaims = parts[1];
        String encodedSignature = parts[2];

        JsonObject claims = extractClaims(encodedClaims);

        if (verifySignature(encodedHeader, encodedClaims, encodedSignature)
                && hasValidIssuer(claims)
                && hasValidAudience(claims)
                && verifyTimeConstraints(claims)) {
            return toAttributes(claims);
        }

        return null;
    }

    private boolean verifyTimeConstraints(JsonObject claims) {
        int currentTime = currentTimeInSeconds();
        boolean expired = currentTime > claims.getInt("exp", -1);

        if (expired) {
            log.debug("Token expired");
            return false;
        }

        if (claims.containsKey("nbf")) {
            boolean notBefore = currentTime >= claims.getInt("nbf");

            if (!notBefore) {
                log.debugf("Token is before [%s]", notBefore);
                return false;
            }
        }

        return true;
    }

    private JsonObject extractClaims(String encodedClaims) throws RealmUnavailableException {
        try {
            Base64.Decoder urlDecoder = Base64.getUrlDecoder();
            CodePointIterator decodedClaims = CodePointIterator.ofUtf8Bytes(urlDecoder.decode(encodedClaims));

            return Json.createReader(decodedClaims.asUtf8().asInputStream()).readObject();
        } catch (Exception cause) {
            throw log.tokenRealmJwtParseFailed(cause);
        }
    }

    private boolean verifySignature(String encodedHeader, String encodedClaims, String encodedSignature) throws RealmUnavailableException {
        try {
            Base64.Decoder urlDecoder = Base64.getUrlDecoder();
            byte[] decodedSignature = urlDecoder.decode(encodedSignature);

            boolean verify = ByteIterator.ofBytes(decodedSignature).verify(createSignature(encodedHeader, encodedClaims));

            if (!verify) {
                log.debug("Signature verification failed");
            }

            return verify;
        } catch (Exception cause) {
            throw log.tokenRealmJwtSignatureCheckFailed(cause);
        }
    }

    private boolean hasValidAudience(JsonObject claims) throws RealmUnavailableException {
        JsonValue audience = claims.get("aud");

        if (audience == null) {
            log.debug("Token does not contain an audience claim");
            return false;
        }

        JsonArray audClaimArray;

        if (JsonValue.ValueType.STRING.equals(audience.getValueType())) {
            audClaimArray = Json.createArrayBuilder().add(audience).build();
        } else {
            audClaimArray = (JsonArray) audience;
        }

        boolean valid = audClaimArray.stream()
                .map(jsonValue -> (JsonString) jsonValue)
                .anyMatch(audience1 -> audiences.contains(audience1.getString()));

        if (!valid) {
            log.debugf("Audience check failed. Provided [%s] but was expected [%s].", audClaimArray.toArray(), this.audiences);
        }

        return valid;
    }

    private boolean hasValidIssuer(JsonObject claims) throws RealmUnavailableException {
        String issuer = claims.getString("iss", null);

        if (issuer == null) {
            return false;
        }

        boolean valid = this.issuers.contains(issuer);

        if (!valid) {
            log.debugf("Issuer check failed. Provided [%s] but was expected [%s].", issuer, this.issuers);
        }

        return valid;
    }

    private Signature createSignature(String encodedHeader, String encodedClaims) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, RealmUnavailableException {
        Signature signature = Signature.getInstance(resolveAlgorithm(encodedHeader));
        Iterator<PemEntry<?>> pemEntryIterator = Pem.parsePemContent(CodePointIterator.ofUtf8Bytes(this.publicKey));
        PublicKey publicKey = (PublicKey) pemEntryIterator.next().getEntry();

        signature.initVerify(publicKey);
        signature.update((encodedHeader + "." + encodedClaims).getBytes());

        return signature;
    }

    private String resolveAlgorithm(String part) throws RealmUnavailableException {
        byte[] headerDecoded = Base64.getUrlDecoder().decode(part);
        JsonObject headers = Json.createReader(ByteIterator.ofBytes(headerDecoded).asInputStream()).readObject();
        JsonString algClaim = (JsonString) headers.get("alg");

        if (algClaim == null) {
            throw log.tokenRealmJwtSignatureInvalidAlgorithm("not_provided");
        }

        String algorithm = algClaim.getString();

        log.debugf("Token is using algorithm [%s]", algorithm);

        switch (algorithm) {
            case "RS256":
                return "SHA256withRSA";
            case "RS384":
                return "SHA384withRSA";
            case "RS512":
                return "SHA512withRSA";
            default:
                throw log.tokenRealmJwtSignatureInvalidAlgorithm(algorithm);
        }
    }

    private int currentTimeInSeconds() {
        return ((int) (System.currentTimeMillis() / 1000));
    }

    public static class Builder {

        private Set<String> issuers = new LinkedHashSet<>();
        private Set<String> audience = new LinkedHashSet<>();
        private byte[] publicKey;

        private Builder() {
        }

        /**
         * Defines one or more string values representing an unique identifier for the entities that are allowed as issuers of a given JWT. During validation
         * JWT tokens must have a <code>iss</code> claim that contains one of the values defined here.
         *
         * @param issuer one or more string values representing the issuers (must not be {@code null})
         * @return this instance
         */
        public Builder issuer(String... issuer) {
            this.issuers.addAll(asList(issuer));
            return this;
        }

        /**
         * Defines one or more string values representing the audiences supported by this configuration. During validation JWT tokens
         * must have an <code>aud</code> claim that contains one of the values defined here.
         *
         * @param audience one or more string values representing the audience (must not be {@code null})
         * @return this instance
         */
        public Builder audience(String... audience) {
            this.audience.addAll(asList(audience));
            return this;
        }

        /**
         * A public key in its PEM format used to validate the signature.
         *
         * @param publicKey the public key in its PEM format (must not be {@code null})
         * @return this instance
         */
        public Builder publicKey(byte[] publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        /**
         * A {@link PublicKey} format used to validate the signature.
         *
         * @param publicKey the public key in its PEM format (must not be {@code null})
         * @return this instance
         */
        public Builder publicKey(PublicKey publicKey) {
            ByteStringBuilder builder = new ByteStringBuilder();

            Pem.generatePemPublicKey(builder, publicKey);

            return publicKey(builder.toArray());
        }

        /**
         * Returns a {@link JwtValidator} instance based on all the configuration provided with this builder.
         *
         * @return a new {@link JwtValidator} instance with all the given configuration
         */
        public JwtValidator build() {
            return new JwtValidator(this);
        }
    }
}
