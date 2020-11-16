/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.jose.jwk;


import static org.wildfly.security.pem.Pem.extractDerContent;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.wildfly.common.Assert;
import org.wildfly.common.codec.Base64Alphabet;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;

/**
 * Utility methods for use with JSON Web Keys.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.14.0
 */
public class JWKUtil {

    public static String base64UrlEncode(byte[] data) {
        return ByteIterator.ofBytes(data).base64Encode(BASE64_URL, false).drainToString();
    }

    public static byte[] base64UrlDecode(String data) {
        return CodePointIterator.ofString(data).base64Decode(BASE64_URL, false).drain();
    }

    /**
     * The <a href="http://tools.ietf.org/html/rfc4648">RFC 4648</a> base64url alphabet.
     */
    public static final Base64Alphabet BASE64_URL = new Base64Alphabet(false) {
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

    /**
     * Generate the thumbprint for the first certificate in the given certificate chain.
     *
     * @param certChain the certificate chain in PEM format
     * @param algorithm the algorithm to use
     * @return the generated thumbprint for the first certificate in the given certificate chain in base64url format
     * @throws NoSuchAlgorithmException if the given algorithm cannot be used
     */
    public static String generateThumbprint(String[] certChain, String algorithm) throws NoSuchAlgorithmException {
        Assert.checkNotNullParam("certChain", certChain);
        Assert.checkNotNullParam("algorithm", algorithm);
        return ByteIterator.ofBytes(generateThumbprintBytes(certChain, algorithm)).base64Encode(BASE64_URL, false).drainToString();
    }

    static byte[] generateThumbprintBytes(String[] certChain, String algorithm) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(algorithm).digest(extractDerContent(CodePointIterator.ofString(certChain[0])));
    }

}
