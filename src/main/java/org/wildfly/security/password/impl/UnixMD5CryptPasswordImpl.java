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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;
import org.wildfly.security.password.spec.UnixMD5CryptPasswordSpec;

/**
 * Implementation of the Unix MD5 Crypt password.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class UnixMD5CryptPasswordImpl extends AbstractPasswordImpl implements UnixMD5CryptPassword {

    private static final long serialVersionUID = 8315521712238708363L;

    private final byte[] hash;
    private final byte[] salt;

    UnixMD5CryptPasswordImpl(final byte[] hash, final byte[] salt) {
        this.hash = hash;
        this.salt = salt;
    }

    UnixMD5CryptPasswordImpl(UnixMD5CryptPassword unixMD5CryptPassword) {
        this.hash = unixMD5CryptPassword.getHash().clone();
        this.salt = unixMD5CryptPassword.getSalt().clone();
    }

    @Override
    public String getAlgorithm() {
        return UnixMD5CryptUtil.ALGORITHM_MD5_CRYPT;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    @Override
    public byte[] getHash() {
        return hash.clone();
    }

    @Override
    public byte[] getSalt() {
        return salt.clone();
    }

    @Override
    <S extends KeySpec> S getKeySpec(final Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType == UnixMD5CryptPasswordSpec.class) {
            return keySpecType.cast(new UnixMD5CryptPasswordSpec(getEncoded(), getSalt()));
        }
        throw new InvalidKeySpecException();
    }

    @Override
    boolean verify(final char[] guess) throws InvalidKeyException {
        ByteBuffer guessAsBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(guess));
        byte[] guessAsBytes = new byte[guessAsBuffer.remaining()];
        guessAsBuffer.get(guessAsBytes);

        byte[] test;
        try {
            test = UnixMD5CryptUtil.encode(guessAsBytes, getSalt());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Cannot verify password", e);
        }
        return Arrays.equals(getHash(), test);
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType) {
        return keySpecType == UnixMD5CryptPasswordSpec.class;
    }
}
