/*
 * JBoss, Home of Professional Open Source
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
import static org.wildfly.security.password.impl.DigestUtil.userRealmPasswordDigest;

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;

/**
 * Pre-digested (DigestMD5) credential type implementation.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class DigestPasswordImpl extends AbstractPasswordImpl implements DigestPassword {

    private static final long serialVersionUID = - 8454721263222529136L;

    private final String algorithm;
    private final String username;
    private final String realm;
    private final byte[] digest;

    DigestPasswordImpl(final String algorithm, final String username, final String realm, final byte[] digest) {
        this.algorithm = algorithm;
        this.username = username;
        this.realm = realm;
        this.digest = digest;
    }

    DigestPasswordImpl(final String algorithm, final DigestPasswordSpec spec) {
        this(algorithm, spec.getUsername(), spec.getRealm(),  spec.getDigest().clone());
    }

    DigestPasswordImpl(final DigestPassword password) {
        this(password.getAlgorithm(), password.getUsername(), password.getRealm(), password.getDigest().clone());
    }

    // We can not support conversion from ClearPasswordSpec as we require additional
    // information we can not generate ourselves.

    DigestPasswordImpl(final String algorithm, final EncryptablePasswordSpec spec) throws InvalidKeySpecException {
        this(algorithm, spec.getPassword(), (DigestPasswordAlgorithmSpec) spec.getAlgorithmParameterSpec(), spec.getHashCharset());
    }

    DigestPasswordImpl(final String algorithm, final char[] password, final DigestPasswordAlgorithmSpec spec, final Charset hashCharset) throws InvalidKeySpecException {
        this.algorithm = algorithm;
        this.username = spec.getUsername();
        this.realm = spec.getRealm();
        try {
            this.digest = userRealmPasswordDigest(getMessageDigest(algorithm), spec.getUsername(), spec.getRealm(), password, hashCharset);
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeySpecNoSuchMessageDigestAlgorithm(algorithm);
        }
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getRealm() {
        return realm;
    }

    @Override
    public byte[] getDigest() {
        return digest.clone();
    }

    @Override
    <S extends KeySpec> S getKeySpec(Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(DigestPasswordSpec.class)) {
            return keySpecType.cast(new DigestPasswordSpec(username, realm, digest.clone()));
        }
        throw new InvalidKeySpecException();
    }

    @Override
    boolean verify(char[] guess) throws InvalidKeyException {
        try {
            byte[] guessDigest = userRealmPasswordDigest(getMessageDigest(algorithm), username, realm, guess);
            return MessageDigest.isEqual(digest, guessDigest);
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeyNoSuchMessageDigestAlgorithm(algorithm);
        }
    }

    @Override
    boolean verify(char[] guess, Charset hashCharset) throws InvalidKeyException {
        try {
            byte[] guessDigest = userRealmPasswordDigest(getMessageDigest(algorithm), username, realm, guess, hashCharset);
            // compare guessDigest equals the digest calculated by server
            return Arrays.equals(digest, guessDigest);
        } catch (NoSuchAlgorithmException e) {
            throw log.invalidKeyNoSuchMessageDigestAlgorithm(algorithm);
        }
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(DigestPasswordSpec.class);
    }

    private static MessageDigest getMessageDigest(final String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case ALGORITHM_DIGEST_MD5:
                return MessageDigest.getInstance("MD5");
            case ALGORITHM_DIGEST_SHA:
                return MessageDigest.getInstance("SHA-1");
            case ALGORITHM_DIGEST_SHA_256:
                return MessageDigest.getInstance("SHA-256");
            case ALGORITHM_DIGEST_SHA_384:
                return MessageDigest.getInstance("SHA-384");
            case ALGORITHM_DIGEST_SHA_512:
                return MessageDigest.getInstance("SHA-512");
            case ALGORITHM_DIGEST_SHA_512_256:
                return MessageDigest.getInstance("SHA-512-256");
            default:
                throw log.noSuchAlgorithmInvalidAlgorithm(algorithm);
        }
    }

    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(multiHashOrdered(Arrays.hashCode(digest), username.hashCode()), realm.hashCode()), algorithm.hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof DigestPasswordImpl)) {
            return false;
        }
        DigestPasswordImpl other = (DigestPasswordImpl) obj;
        return MessageDigest.isEqual(digest, other.digest) && username.equals(other.username) && realm.equals(other.realm) && algorithm.equals(other.algorithm);
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }

    Object writeReplace() {
        return DigestPassword.createRaw(algorithm, username, realm, digest);
    }

    public DigestPasswordImpl clone() {
        return this;
    }

}
