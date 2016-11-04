/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.OneTimePasswordSpec;

/**
 * A {@code Password} implementation for {@link OneTimePassword}.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class OneTimePasswordImpl extends AbstractPasswordImpl implements OneTimePassword {

    private static final long serialVersionUID = 5524179164918986449L;

    private final String algorithm;
    private final byte[] hash;
    private final byte[] seed;
    private final int sequenceNumber;

    OneTimePasswordImpl(final String algorithm, final byte[] hash, final byte[] seed, final int sequenceNumber) {
        this.algorithm = algorithm;
        this.hash = hash;
        this.seed = seed;
        this.sequenceNumber = sequenceNumber;
    }

    OneTimePasswordImpl(final OneTimePassword password) {
        this(password.getAlgorithm(), password.getHash().clone(), password.getSeed().clone(), password.getSequenceNumber());
    }

    OneTimePasswordImpl(final String algorithm, final OneTimePasswordSpec spec) {
        this(algorithm, spec.getHash().clone(), spec.getSeed().clone(), spec.getSequenceNumber());
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    @Override
    public byte[] getHash() {
        return hash.clone();
    }

    @Override
    public byte[] getSeed() {
        return seed.clone();
    }

    @Override
    public int getSequenceNumber() {
        return sequenceNumber;
    }

    @Override
    <S extends KeySpec> S getKeySpec(Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(OneTimePasswordSpec.class)) {
            return keySpecType.cast(new OneTimePasswordSpec(hash.clone(), seed.clone(), sequenceNumber));
        }
        throw new InvalidKeySpecException();
    }

    @Override
    boolean verify(char[] guess) throws InvalidKeyException {
        // The OTP SASL mechanism handles this (this involves updating the stored password)
        throw new InvalidKeyException();
    }

    @Override
    <T extends KeySpec> boolean convertibleTo(Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(OneTimePasswordSpec.class);
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }

    Object writeReplace() {
        return OneTimePassword.createRaw(algorithm, hash, seed, sequenceNumber);
    }

    public OneTimePasswordImpl clone() {
        return this;
    }

}
