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

package org.wildfly.security.x500.cert.acme;

import static org.wildfly.security.x500.cert.acme.ElytronMessages.acme;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.json.Json;
import javax.json.JsonObject;

import org.wildfly.common.codec.Base64Alphabet;
import org.wildfly.common.iteration.ByteIterator;

/**
 * Useful constants and utilities related to the <a href="https://www.ietf.org/id/draft-ietf-acme-acme-14.txt">Automatic Certificate
 * Management Environment (ACME)</a> protocol.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.5.0
 */
public final class Acme {

    public static final String ACCOUNT = "account";
    public static final String ALG = "alg";
    public static final String AUTHORIZATIONS = "authorizations";
    public static final String CAA_IDENTITIES = "caaIdentities";
    public static final String CERTIFICATE = "certificate";
    public static final String CHALLENGES = "challenges";
    public static final String CONTACT = "contact";
    public static final String CURVE = "crv";
    public static final String CSR = "csr";
    public static final String DEACTIVATED = "deactivated";
    public static final String DETAIL = "detail";
    public static final String DNS = "dns";
    public static final String EXPONENT = "e";
    public static final String EXTERNAL_ACCOUNT_REQUIRED = "externalAccountRequired";
    public static final String FINALIZE = "finalize";
    public static final String IDENTIFIER = "identifier";
    public static final String IDENTIFIERS = "identifiers";
    public static final String INSTANCE = "instance";
    public static final String INVALID = "invalid";
    public static final String JWK = "jwk";
    public static final String KEY_TYPE = "kty";
    public static final String KID = "kid";
    public static final String META = "meta";
    public static final String MODULUS = "n";
    public static final String NEW_KEY = "newKey";
    public static final String NONCE = "nonce";
    public static final String OLD_KEY = "oldKey";
    public static final String ONLY_RETURN_EXISTING = "onlyReturnExisting";
    public static final String PAYLOAD = "payload";
    public static final String PENDING = "pending";
    public static final String PROTECTED = "protected";
    public static final String REASON = "reason";
    public static final String SIGNATURE = "signature";
    public static final String STATUS = "status";
    public static final String SUBPROBLEMS = "subproblems";
    public static final String TERMS_OF_SERVICE = "termsOfService";
    public static final String TERMS_OF_SERVICE_AGREED = "termsOfServiceAgreed";
    public static final String TOKEN = "token";
    public static final String TITLE = "title";
    public static final String TYPE = "type";
    public static final String URL = "url";
    public static final String VALID = "valid";
    public static final String VALUE = "value";
    public static final String WEBSITE = "website";
    public static final String X_COORDINATE = "x";
    public static final String Y_COORDINATE = "y";

    public static final String GET = "GET";
    public static final String HEAD = "HEAD";
    public static final String POST = "POST";
    public static final String ACCEPT_LANGUAGE = "Accept-Language";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String LOCATION = "Location";
    public static final String REPLAY_NONCE = "Replay-Nonce";
    public static final String RETRY_AFTER = "Retry-After";
    public static final String JSON_CONTENT_TYPE = "application/json";
    public static final String PROBLEM_JSON_CONTENT_TYPE = "application/problem+json";
    public static final String JOSE_JSON_CONTENT_TYPE = "application/jose+json";
    public static final String PEM_CERTIFICATE_CHAIN_CONTENT_TYPE = "application/pem-certificate-chain";
    public static final String USER_AGENT = "User-Agent";

    public static final String ERROR_TYPE_PREFIX = "urn:ietf:params:acme:error:";
    public static final String BAD_NONCE = ERROR_TYPE_PREFIX + "badNonce";
    public static final String USER_ACTION_REQUIRED = ERROR_TYPE_PREFIX + "userActionRequired";
    public static final String RATE_LIMITED = ERROR_TYPE_PREFIX + "rateLimited";

    /**
     * Get the JWS "alg" header parameter value that corresponds to the given signature algorithm.
     *
     * @param signatureAlgorithm the signature algorithm
     * @return the JWS "alg" header parameter value that corresponds to the given signature algorithm
     * @throws IllegalArgumentException if the given signature algorithm is not supported
     */
    static String getAlgHeaderFromSignatureAlgorithm(String signatureAlgorithm) {
        switch (signatureAlgorithm) {
            case "SHA256withRSA":
                return "RS256";
            case "SHA384withRSA":
                return "RS384";
            case "SHA512withRSA":
                return "RS512";
            case "SHA256withECDSA":
                return "ES256";
            case "SHA384withECDSA":
                return "ES384";
            case "SHA512withECDSA":
                return "ES512";
            default:
                throw acme.unsupportedAcmeAccountSignatureAlgorithm(signatureAlgorithm);
        }
    }

    static JsonObject getJwk(PublicKey publicKey, String algHeader) {
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            return Json.createObjectBuilder()
                    .add(EXPONENT, base64UrlEncode(rsaPublicKey.getPublicExponent().toByteArray()))
                    .add(KEY_TYPE, "RSA")
                    .add(MODULUS, base64UrlEncode(modulusToByteArray(rsaPublicKey.getModulus())))
                    .build();
        } else if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            int fieldSize = ecPublicKey.getParams().getCurve().getField().getFieldSize();
            return Json.createObjectBuilder()
                    .add(CURVE, getCurveParameterFromAlgHeader(algHeader))
                    .add(KEY_TYPE, "EC")
                    .add(X_COORDINATE, base64UrlEncode(coordinateToByteArray(fieldSize, ecPublicKey.getW().getAffineX())))
                    .add(Y_COORDINATE, base64UrlEncode(coordinateToByteArray(fieldSize, ecPublicKey.getW().getAffineY())))
                    .build();
        } else {
            throw acme.unsupportedAcmeAccountPublicKeyType(publicKey.getAlgorithm());
        }
    }

    private static byte[] modulusToByteArray(BigInteger modulus) {
        // As specified in https://tools.ietf.org/html/rfc7518#section-6.3.1, the extra zero-valued octet
        // needs to be omitted if present
        byte[] modulusByteArray = modulus.toByteArray();
        if ((modulus.bitLength() % 8 == 0) && (modulusByteArray[0] == 0) && modulusByteArray.length > 1) {
            return ByteIterator.ofBytes(modulusByteArray, 1, modulusByteArray.length - 1).drain();
        } else {
            return modulusByteArray;
        }
    }

    private static byte[] coordinateToByteArray(int fieldSize, BigInteger coordinate) {
        byte[] coordinateByteArray = modulusToByteArray(coordinate);
        int fullSize = (int) Math.ceil(fieldSize / 8d);

        if (fullSize > coordinateByteArray.length) {
            final byte[] fullSizeCoordinateByteArray = new byte[fullSize];
            System.arraycopy(coordinateByteArray, 0, fullSizeCoordinateByteArray, fullSize - coordinateByteArray.length, coordinateByteArray.length);
            return fullSizeCoordinateByteArray;
        } else {
            return coordinateByteArray;
        }

    }

    private static String getCurveParameterFromAlgHeader(String algHeader) {
        switch (algHeader) {
            case "ES256":
                return "P-256";
            case "ES384":
                return "P-384";
            case "ES512":
                return "P-521";
            default:
                throw acme.unableToDetermineCurveParameterFromAlgHeader(algHeader);
        }
    }



    static String base64UrlEncode(byte[] data) {
        return ByteIterator.ofBytes(data).base64Encode(BASE64_URL, false).drainToString();
    }

    /**
     * The <a href="http://tools.ietf.org/html/rfc4648">RFC 4648</a> base64url alphabet.
     */
    static final Base64Alphabet BASE64_URL = new Base64Alphabet(false) {
        public int encode(final int val) {
            if (val <= 25) {
                return 'A' + val;
            } else if (val <= 51) {
                return 'a' + val - 26;
            } else if (val <= 61) {
                return '0' + val - 52;
            } else if (val == 62) {
                return '-';
            } else {
                assert val == 63;
                return '_';
            }
        }

        public int decode(final int codePoint) throws IllegalArgumentException {
            if ('A' <= codePoint && codePoint <= 'Z') {
                return codePoint - 'A';
            } else if ('a' <= codePoint && codePoint <= 'z') {
                return codePoint - 'a' + 26;
            } else if ('0' <= codePoint && codePoint <= '9') {
                return codePoint - '0' + 52;
            } else if (codePoint == '-') {
                return 62;
            } else if (codePoint == '_') {
                return 63;
            } else {
                return -1;
            }
        }
    };

}

