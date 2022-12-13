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

import static org.wildfly.common.math.HashMath.multiHashOrdered;
import static org.wildfly.security.password.impl.ElytronMessages.log;

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.HashPasswordSpec;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SimpleDigestPasswordImpl extends AbstractPasswordImpl implements SimpleDigestPassword {

    private static final long serialVersionUID = -5673285507422174313L;

    private final String algorithm;
    private final byte[] digest;

    SimpleDigestPasswordImpl(final String algorithm, final byte[] digest) {
        this.algorithm = algorithm;
        this.digest = digest;
    }

    SimpleDigestPasswordImpl(final String algorithm, final HashPasswordSpec spec) {
        this(algorithm, spec.getDigest().clone());
    }

    SimpleDigestPasswordImpl(final SimpleDigestPassword password) {
        this(password.getAlgorithm(), password.getDigest().clone());
    }

    SimpleDigestPasswordImpl(final String algorithm, final ClearPasswordSpec spec) throws InvalidKeySpecException {
        this(algorithm, spec.getEncodedPassword(), StandardCharsets.UTF_8);
    }

    SimpleDigestPasswordImpl(final String algorithm, final char[] chars, final Charset hashCharset) throws InvalidKeySpecException {
        this.algorithm = algorithm;
        this.digest = getDigestOfKS(algorithm, chars, hashCharset);
    }

    <S extends KeySpec> S getKeySpec(final Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(HashPasswordSpec.class)) {
            return keySpecType.cast(new HashPasswordSpec(digest.clone()));
        }
        throw new InvalidKeySpecException();
    }

    static byte[] getDigestOfKS(String algorithm, char[] chars, Charset hashCharset) throws InvalidKeySpecException {
        try {
            return getDigestOf(algorithm, chars, hashCharset);
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeySpecNoSuchMessageDigestAlgorithm(algorithm);
        }
    }

    static byte[] getDigestOf(String algorithm, char[] chars, Charset hashCharset) throws NoSuchAlgorithmException {
        final MessageDigest md = getMessageDigest(algorithm);
        md.update(new String(chars).getBytes(hashCharset));
        return md.digest();
    }

    static MessageDigest getMessageDigest(String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case ALGORITHM_SIMPLE_DIGEST_MD2:     return MessageDigest.getInstance("MD2");
            case ALGORITHM_SIMPLE_DIGEST_MD5:     return MessageDigest.getInstance("MD5");
            case ALGORITHM_SIMPLE_DIGEST_SHA_1:   return MessageDigest.getInstance("SHA-1");
            case ALGORITHM_SIMPLE_DIGEST_SHA_256: return MessageDigest.getInstance("SHA-256");
            case ALGORITHM_SIMPLE_DIGEST_SHA_384: return MessageDigest.getInstance("SHA-384");
            case ALGORITHM_SIMPLE_DIGEST_SHA_512: return MessageDigest.getInstance("SHA-512");
            default: throw log.noSuchAlgorithmInvalidAlgorithm(algorithm);
        }
    }

    boolean verify(final char[] guess) throws InvalidKeyException {
        return verify(guess, StandardCharsets.UTF_8);
    }

    @Override
    boolean verify(char[] guess, Charset hashCharset) throws InvalidKeyException {
        try {
            return Arrays.equals(digest, getDigestOf(algorithm, guess, hashCharset));
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeyNoSuchMessageDigestAlgorithm(algorithm);
        }
    }

    <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(HashPasswordSpec.class);
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public byte[] getDigest() {
        return digest.clone();
    }

    public int hashCode() {
        return multiHashOrdered(Arrays.hashCode(digest), algorithm.hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof SimpleDigestPasswordImpl)) {
            return false;
        }
        SimpleDigestPasswordImpl other = (SimpleDigestPasswordImpl) obj;
        return algorithm.equals(other.algorithm) && MessageDigest.isEqual(digest, other.digest);
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }

    Object writeReplace() {
        return SimpleDigestPassword.createRaw(algorithm, digest);
    }

    public SimpleDigestPasswordImpl clone() {
        return this;
    }
}
