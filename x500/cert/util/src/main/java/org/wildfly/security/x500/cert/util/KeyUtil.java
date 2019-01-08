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

package org.wildfly.security.x500.cert.util;

import static org.wildfly.security.x500.cert.util.ElytronMessages.log;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECParameterSpec;

import org.wildfly.security.asn1.DERDecoder;

/**
 * Key utility methods.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.5.0
 */
public final class KeyUtil {


    /**
     * Get the default compatible signature algorithm name for the given private key.
     *
     * @param privateKey the private key
     * @return the default compatible signature algorithm name for the given private key or {@code null}
     * if the default compatible signature algorithm name cannot not be determined
     * @throws IllegalArgumentException if the key size cannot be determined from the given private key
     */
    public static String getDefaultCompatibleSignatureAlgorithmName(final PrivateKey privateKey) throws IllegalArgumentException {
        final int keySize = getKeySize(privateKey);
        if (keySize == -1) {
            throw log.unableToDetermineKeySize();
        }
        return getDefaultCompatibleSignatureAlgorithmName(privateKey.getAlgorithm(), keySize);
    }

    /**
     * Get the default compatible signature algorithm name for the given key algorithm name and key size.
     *
     * @param keyAlgorithmName the key algorithm name
     * @param keySize the key size
     * @return the default compatible signature algorithm name for the given key algorithm name and key size
     * or {@code null} if the default compatible signature algorithm name cannot not be determined
     */
    public static String getDefaultCompatibleSignatureAlgorithmName(final String keyAlgorithmName, final int keySize) {
        final String messageDigestAlgorithmName = getDefaultMessageDigestAlgorithmName(keyAlgorithmName, keySize);
        if (messageDigestAlgorithmName == null) {
            return null;
        }
        switch (keyAlgorithmName) {
            case "DSA": {
                return messageDigestAlgorithmName + "withDSA";
            }
            case "RSA": {
                return messageDigestAlgorithmName + "withRSA";
            }
            case "EC": {
                return messageDigestAlgorithmName + "withECDSA";
            }
            default: {
                return null;
            }
        }
    }

    /**
     * Get the default message digest algorithm name for the given key algorithm name and key size.
     *
     * @param keyAlgorithmName the key algorithm name
     * @param keySize the key size
     * @return the default message digest algorithm name or {@code null} if the default message algorithm name cannot be determined
     */
    private static String getDefaultMessageDigestAlgorithmName(final String keyAlgorithmName, final int keySize) {
        // These defaults are based on Tables 2 and 3 in NIST SP 800-57 Part 1 Revision 4
        // (see https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-4/final)
        switch (keyAlgorithmName) {
            case "DSA": {
                return "SHA256";
            }
            case "RSA": {
                if (keySize <= 3072) {
                    return "SHA256";
                } else if (keySize <= 7680) {
                    return "SHA384";
                } else {
                    return "SHA512";
                }
            }
            case "EC": {
                if (keySize <= 383) {
                    return "SHA256";
                } else if (keySize <= 511) {
                    return "SHA384";
                } else {
                    return "SHA512";
                }
            }
            default: {
                return null;
            }
        }
    }

    /**
     * Get the key size for the given {@code Key}.
     *
     * @param key the key
     * @return the key size or -1 if the key size cannot be determined
     */
    public static int getKeySize(final Key key) {
        if (key instanceof ECKey) {
            ECParameterSpec params = ((ECKey) key).getParams();
            if (params != null) {
                return params.getOrder().bitLength();
            }
        } else if (key instanceof DSAKey) {
            DSAParams params = ((DSAKey) key).getParams();
            if (params != null) {
                return params.getP().bitLength();
            }
        } else if (key instanceof RSAKey) {
            return ((RSAKey) key).getModulus().bitLength();
        }
        return -1;
    }

    /**
     * Get the key identifier, which is composed of the 160-bit SHA-1 hash of the value of the BIT STRING
     * {@code subjectPublicKey} (excluding the tag, length, and number of unused bits), as per
     * <a href="https://tools.ietf.org/html/rfc3280">RFC 3280</a>.
     *
     * @param publicKey the public key
     * @return the key identifier
     */
    public static byte[] getKeyIdentifier(final PublicKey publicKey) {
        DERDecoder decoder = new DERDecoder(publicKey.getEncoded());
        decoder.startSequence();
        decoder.skipElement(); // skip the algorithm
        byte[] subjectPublicKey = decoder.decodeBitString();
        decoder.endSequence();

        final MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.update(subjectPublicKey);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
