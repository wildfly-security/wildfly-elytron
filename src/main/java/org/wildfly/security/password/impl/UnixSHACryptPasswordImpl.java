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

import org.wildfly.security.password.interfaces.UnixSHACryptPassword;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import org.wildfly.security.password.spec.UnixSHACryptPasswordSpec;

/**
 * @author <a href="mailto:juraci.javadoc@kroehling.de">Juraci Paixão Kröhling</a>
 */
final class UnixSHACryptPasswordImpl extends AbstractPasswordImpl implements UnixSHACryptPassword {

    private String algorithm;
    private byte[] salt;
    private int iterationCount;
    private byte[] hash;

    public UnixSHACryptPasswordImpl(UnixSHACryptPassword password) {
        this(password.getSalt(), password.getIterationCount(), password.getAlgorithm(), password.getHash());
    }

    public UnixSHACryptPasswordImpl(byte[] salt, int iterationCount, String algorithm) {
        this(salt, iterationCount, algorithm, null);
    }

    public UnixSHACryptPasswordImpl(byte[] salt, int iterationCount, String algorithm, byte[] hash) {
        if (!ALGORITHM_SHA256CRYPT.equals(algorithm) && !ALGORITHM_SHA512CRYPT.equals(algorithm)) {
            throw new IllegalArgumentException("The ID for this Unix SHA crypt password was neither 5 nor 6.");
        }

        this.salt = salt;
        this.iterationCount = iterationCount;
        this.algorithm = algorithm;
        this.hash = hash;
    }

    @Override
    public byte[] getSalt() {
        return salt.clone();
    }

    @Override
    public int getIterationCount() {
        return iterationCount;
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
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    <S extends KeySpec> S getKeySpec(Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType == UnixSHACryptPasswordSpec.class) {
            return keySpecType.cast(new UnixSHACryptPasswordSpec(this.getAlgorithm(), this.getEncoded(), this.getSalt(), this.getIterationCount()));
        } else {
            throw new InvalidKeySpecException("Expected to get a UnixSHACryptPasswordSpec as spec, got " + keySpecType.getName());
        }
    }

    @Override
    boolean verify(char[] guess) throws InvalidKeyException {
        try {
            return UnixSHACryptPasswordUtil.verify(this, guess);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Cannot verify password", e);
        }
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(Class<T> keySpecType) {
        return keySpecType == UnixSHACryptPasswordSpec.class;
    }
}
