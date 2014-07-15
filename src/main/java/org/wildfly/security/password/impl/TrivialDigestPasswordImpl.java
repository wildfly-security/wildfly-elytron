/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.password.impl;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.wildfly.security.password.interfaces.TrivialDigestPassword;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.TrivialDigestPasswordSpec;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class TrivialDigestPasswordImpl extends AbstractPasswordImpl implements TrivialDigestPassword {

    private static final long serialVersionUID = -5673285507422174313L;

    private final String algorithm;
    private final byte[] digest;

    TrivialDigestPasswordImpl(final String algorithm, final byte[] digest) {
        this.algorithm = algorithm;
        this.digest = digest;
    }

    TrivialDigestPasswordImpl(final TrivialDigestPasswordSpec spec) {
        this(spec.getAlgorithm(), spec.getDigest().clone());
    }

    TrivialDigestPasswordImpl(final TrivialDigestPassword password) {
        this(password.getAlgorithm(), password.getDigest().clone());
    }

    TrivialDigestPasswordImpl(final String algorithm, final EncryptablePasswordSpec spec) throws InvalidKeySpecException {
        this(algorithm, spec.getPassword());
    }

    private TrivialDigestPasswordImpl(final String algorithm, final char[] chars) throws InvalidKeySpecException {
        this(algorithm, getDigestOfKS(algorithm, chars));
    }

    <S extends KeySpec> S getKeySpec(final Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType == TrivialDigestPasswordSpec.class) {
            return keySpecType.cast(new TrivialDigestPasswordSpec(algorithm, digest.clone()));
        }
        throw new InvalidKeySpecException();
    }

    static byte[] getDigestOfKS(String algorithm, char[] chars) throws InvalidKeySpecException {
        try {
            return getDigestOf(algorithm, chars);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeySpecException("No such MessageDigest algorithm for " + algorithm);
        }
    }

    static byte[] getDigestOf(String algorithm, char[] chars) throws NoSuchAlgorithmException {
        final MessageDigest md = getMessageDigest(algorithm);
        md.update(new String(chars).getBytes(StandardCharsets.UTF_8));
        return md.digest();
    }

    static MessageDigest getMessageDigest(String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case ALGORITHM_DIGEST_MD2:     return MessageDigest.getInstance("MD2");
            case ALGORITHM_DIGEST_MD5:     return MessageDigest.getInstance("MD5");
            case ALGORITHM_DIGEST_SHA_1:   return MessageDigest.getInstance("SHA-1");
            case ALGORITHM_DIGEST_SHA_256: return MessageDigest.getInstance("SHA-256");
            case ALGORITHM_DIGEST_SHA_384: return MessageDigest.getInstance("SHA-384");
            case ALGORITHM_DIGEST_SHA_512: return MessageDigest.getInstance("SHA-512");
            default: throw new NoSuchAlgorithmException();
        }
    }

    boolean verify(final char[] guess) throws InvalidKeyException {
        try {
            return Arrays.equals(digest, getDigestOf(algorithm, guess));
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException("No such MessageDigest algorithm for " + algorithm);
        }
    }

    <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType) {
        return keySpecType == TrivialDigestPasswordSpec.class;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getFormat() {
        return null;
    }

    public byte[] getEncoded() {
        return new byte[0];
    }

    public byte[] getDigest() {
        return digest.clone();
    }
}
