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

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.realm.token.TokenValidator;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.pem.PemEntry;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static java.util.Arrays.asList;
import static org.wildfly.common.Assert.checkNotNullParam;
import static org.wildfly.security.auth.realm.token._private.ElytronMessages.log;
import static org.wildfly.security.json.util.JsonUtil.toAttributes;

/**
 * <p>A {@link TokenValidator} capable of validating and parsing JWT. Most of the validations performed by this validator are
 * based on RFC-7523 (JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants).
 *
 * <p>This validator can also be used as a JWT parser only. In this case, for security reasons, you need to make sure that
 * JWT validations such as issuer, audience and signature checks are performed before obtaining identities from this realm.
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
    private final Set<String> allowedJkuValues;
    private final JwkManager jwkManager;
    private final Map<String, PublicKey> namedKeys;

    private final PublicKey defaultPublicKey;

    JwtValidator(Builder configuration) {
        this.issuers = checkNotNullParam("issuers", configuration.issuers);
        this.audiences = checkNotNullParam("audience", configuration.audience);
        this.allowedJkuValues = checkNotNullParam("allowedJkuValues", configuration.allowedJkuValues);
        this.defaultPublicKey = configuration.publicKey;
        this.namedKeys = configuration.namedKeys;
        if (configuration.sslContext != null) {
            this.jwkManager = new JwkManager(configuration.sslContext,
                                            configuration.hostnameVerifier != null ? configuration.hostnameVerifier : HttpsURLConnection.getDefaultHostnameVerifier(),
                                            configuration.updateTimeout, configuration.connectionTimeout, configuration.readTimeout, configuration.minTimeBetweenRequests, configuration.allowedJkuValues);
        }
        else {
            log.tokenRealmJwtNoSSLIgnoringJku();
            this.jwkManager = null;
        }
        if (defaultPublicKey == null && jwkManager == null && namedKeys.isEmpty()) {
            log.tokenRealmJwtWarnNoPublicKeyIgnoringSignatureCheck();
        }

        if (issuers.isEmpty()) {
            log.tokenRealmJwtWarnNoIssuerIgnoringIssuerCheck();
        }
        if (audiences.isEmpty()) {
            log.tokenRealmJwtWarnNoAudienceIgnoringAudienceCheck();
        }
        if (allowedJkuValues.isEmpty()) {
            log.allowedJkuValuesNotConfigured();
        }

    }

    @Override
    public Attributes validate(BearerTokenEvidence evidence) throws RealmUnavailableException {
        checkNotNullParam("evidence", evidence);
        String jwt = evidence.getToken();
        String[] parts = jwt.split("\\.", -1);

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
        long currentTime = currentTimeInSeconds();
        if (claims.containsKey("exp")) {
            boolean expired = currentTime > claims.getJsonNumber("exp").longValue();

            if (expired) {
                log.debug("Token expired");
                return false;
            }
        }
        if (claims.containsKey("nbf")) {
            boolean notBefore = currentTime >= claims.getJsonNumber("nbf").longValue();

            if (!notBefore) {
                log.debugf("Token is before [%s]", notBefore);
                return false;
            }
        }

        return true;
    }

    private JsonObject extractClaims(String encodedClaims) throws RealmUnavailableException {
        JsonObject retValue = null;
        JsonReader jsonReader = null;
        try {
            Base64.Decoder urlDecoder = Base64.getUrlDecoder();
            CodePointIterator decodedClaims = CodePointIterator.ofUtf8Bytes(urlDecoder.decode(encodedClaims));
            jsonReader = Json.createReader(decodedClaims.asUtf8().asInputStream());
            retValue = jsonReader.readObject();
        } catch (Exception cause) {
            throw log.tokenRealmJwtParseFailed(cause);
        } finally {
            if (jsonReader != null) {
                jsonReader.close();
            }
        }
        return retValue;
    }

    private boolean verifySignature(String encodedHeader, String encodedClaims, String encodedSignature) throws RealmUnavailableException {
        if (defaultPublicKey == null && jwkManager == null && namedKeys.isEmpty()) {
            return true;
        }

        try {
            Base64.Decoder urlDecoder = Base64.getUrlDecoder();
            byte[] decodedSignature = urlDecoder.decode(encodedSignature);

            Signature signature = createSignature(encodedHeader, encodedClaims);
            boolean verify = signature != null ? ByteIterator.ofBytes(decodedSignature).verify(signature) : false;

            if (!verify) {
                log.debug("Signature verification failed");
            }

            return verify;
        } catch (Exception cause) {
            throw log.tokenRealmJwtSignatureCheckFailed(cause);
        }
    }

    private boolean hasValidAudience(JsonObject claims) throws RealmUnavailableException {
        if (this.audiences.isEmpty()) return true;

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
        if (this.issuers.isEmpty()) return true;

        String issuer = claims.getString("iss", null);

        if (issuer == null) {
            log.debug("Token does not contain an issuer claim");
            return false;
        }

        boolean valid = this.issuers.contains(issuer);

        if (!valid) {
            log.debugf("Issuer check failed. Provided [%s] but was expected [%s].", issuer, this.issuers);
        }

        return valid;
    }

    private Signature createSignature(String encodedHeader, String encodedClaims) throws NoSuchAlgorithmException, SignatureException, RealmUnavailableException {

        byte[] headerDecoded = Base64.getUrlDecoder().decode(encodedHeader);
        JsonObject headers = null;
        try (final JsonReader jsonReader = Json.createReader(ByteIterator.ofBytes(headerDecoded).asInputStream())) {
            headers = jsonReader.readObject();
        }

        String headerAlg = resolveAlgorithm(headers);
        Signature signature = Signature.getInstance(headerAlg);
        try {
            PublicKey publicKey = resolvePublicKey(headers);
            if (publicKey == null) {
                log.debug("Public key could not be resolved.");
                return null;
            }
            signature.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }

        signature.update((encodedHeader + "." + encodedClaims).getBytes());

        return signature;
    }

    private String resolveAlgorithm(JsonObject headers) {
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

    private PublicKey resolvePublicKey(JsonObject headers) {
        JsonString kid = headers.getJsonString("kid");
        JsonString jku = headers.getJsonString("jku");

        if (kid == null) {
            if (defaultPublicKey == null) {
                log.debug("Default public key not configured. Cannot validate token without kid claim.");
                return null;
            }
            return defaultPublicKey;
        }
        if (jku != null) {
            if (jwkManager == null) {
                log.debugf("Cannot validate token with jku [%s]. SSL is not configured and jku claim is not supported.", jku);
                return null;
            }
            if (! allowedJkuValues.contains(jku.getString())) {
                log.debug("Cannot validate token, jku value is not allowed");
                return null;
            }
            try {
                return jwkManager.getPublicKey(kid.getString(), new URL(jku.getString()));
            } catch (MalformedURLException e) {
                log.debug("Invalid jku URL.");
                return null;
            }
        } else {
            if (namedKeys.isEmpty()) {
                log.debug("Cannot validate token with kid claim.");
                return null;
            }
            PublicKey res = namedKeys.get(kid.getString());
            if (res == null) {
                log.debug("Unknown kid.");
            }
            return res;
        }
    }

    private static long currentTimeInSeconds() {
        return System.currentTimeMillis() / 1000;
    }

    public static class Builder {
        private static final int CONNECTION_TIMEOUT = 2000;//2s
        private static final int MIN_TIME_BETWEEN_REQUESTS = 10000; // 10s

        private Set<String> issuers = new LinkedHashSet<>();
        private Set<String> audience = new LinkedHashSet<>();
        private Set<String> allowedJkuValues = new LinkedHashSet<>();
        private PublicKey publicKey;
        private Map<String, PublicKey> namedKeys = new LinkedHashMap<>();
        private HostnameVerifier hostnameVerifier;
        private SSLContext sslContext;
        private long updateTimeout = 120000;
        private int connectionTimeout = CONNECTION_TIMEOUT;
        private int readTimeout = CONNECTION_TIMEOUT;
        private int minTimeBetweenRequests = MIN_TIME_BETWEEN_REQUESTS;

        private Builder() {
        }

        /**
         * <p>Defines one or more string values representing an unique identifier for the entities that are allowed as issuers of a given JWT. During validation
         * JWT tokens must have a <code>iss</code> claim that contains one of the values defined here.
         *
         * <p>If not provided, the validator will not perform validations based on the issuer claim.
         *
         * @param issuer one or more string values representing the valid issuers
         * @return this instance
         */
        public Builder issuer(String... issuer) {
            this.issuers.addAll(asList(issuer));
            return this;
        }

        /**
         * <p>Defines one or more string values representing the audiences supported by this configuration. During validation JWT tokens
         * must have an <code>aud</code> claim that contains one of the values defined here.
         *
         * <p>If not provided, the validator will not perform validations based on the audience claim.
         *
         * @param audience one or more string values representing the valid audiences
         * @return this instance
         */
        public Builder audience(String... audience) {
            this.audience.addAll(asList(audience));
            return this;
        }

        /**
         * <p>A default public key in its PEM format used to validate the signature of tokens without <code>kid</code> header parameter.
         *
         * <p>If not provided, the validator will not validate signatures.
         *
         * @param publicKeyPem the public key in its PEM format
         * @return this instance
         */
        public Builder publicKey(byte[] publicKeyPem) {
            Iterator<PemEntry<?>> pemEntryIterator = Pem.parsePemContent(CodePointIterator.ofUtf8Bytes(publicKeyPem));
            PublicKey publicKey = pemEntryIterator.next().tryCast(PublicKey.class);

            if (publicKey == null) {
                throw log.tokenRealmJwtInvalidPublicKeyPem();
            }

            this.publicKey = publicKey;

            return this;
        }

        /**
         * <p>A default {@link PublicKey} format used to validate the signature of tokens without <code>kid</code> header parameter.
         *
         * <p>If not provided, the validator will not validate signatures.
         *
         * @param publicKey the public key in its PEM format
         * @return this instance
         */
        public Builder publicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        /**
         * <p>A {@link PublicKey} map, which is used for validating tokens with <code>kid</code> and without <code>jku</code> header parameter.
         *
         * @param namedKeys map of public keys for toen verification, where the maps key stand for kid
         * @return this instance
         */
        public Builder publicKeys(Map<String, PublicKey> namedKeys) {
            this.namedKeys.putAll(namedKeys);
            return this;
        }

        /**
         * <p>A predefined {@link SSLContext} that will be used to connect to the jku endpoint when retrieving remote keys. This configuration is mandatory
         * if using jku claims.
         *
         * @param sslContext the SSL context
         * @return this instance
         */
        public Builder useSslContext(SSLContext sslContext) {
            this.sslContext = sslContext;
            return this;
        }

        /**
         * <p>A {@link HostnameVerifier} that will be used to validate the hostname when using SSL/TLS. This configuration is mandatory
         * if using jku claims.
         *
         * @param hostnameVerifier the hostname verifier
         * @return this instance
         */
        public Builder useSslHostnameVerifier(HostnameVerifier hostnameVerifier) {
            this.hostnameVerifier = hostnameVerifier;
            return this;
        }

        /**
         * <p>A timeout for cached jwks when using jku claim. After this timeout, the keys of need to be re-cached before use.
         * Default value is 2 minutes.
         *
         * @param timeout timeout in ms before keys needs to be re-cached
         * @return this instance
         */
        public Builder setJkuTimeout(long timeout) {
            this.updateTimeout = timeout;
            return this;
        }

        /**
         * Sets the connection timeout to a specified timeout, in milliseconds. A non-zero value specifies the timeout when connecting
         * to a resource. A timeout of zero is interpreted as an infinite timeout.
         * @param connectionTimeout the connection timeout
         * @return this instance
         */
        public Builder connectionTimeout(int connectionTimeout) {
            this.connectionTimeout = connectionTimeout;
            return this;
        }

        /**
         * Sets the read timeout to a specified timeout, in milliseconds. A non-zero value specifies the timeout when reading
         * from Input stream when a connection is established to a resource. A timeout of zero is interpreted as an infinite timeout.
         * @param readTimeout the read timeout
         * @return this instance
         */
        public Builder readTimeout(int readTimeout) {
            this.readTimeout = readTimeout;
            return this;
        }

        /**
         * <p>The time in which there will be no more requests to retrieve
         * the keys from the jkws URL.</p>
         *
         * @param minTimeBetweenRequests The time in millis
         * @return this instance
         */
        public Builder setJkuMinTimeBetweenRequests(int minTimeBetweenRequests) {
            this.minTimeBetweenRequests = minTimeBetweenRequests;
            return this;
        }

        /**
         * One or more string values representing the jku values that are supported by this configuration.
         * During JWT validation, if the jku header parameter is present in a token, it must exactly match
         * one of the strings defined here or token validation will fail.
         *
         * @param allowedJkuValues the allowed values for the jku header parameter
         * @return this instance
         */
        public Builder setAllowedJkuValues(String... allowedJkuValues) {
            this.allowedJkuValues.addAll(asList(allowedJkuValues));
            return this;
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
