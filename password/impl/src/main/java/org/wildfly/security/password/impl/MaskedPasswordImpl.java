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

package org.wildfly.security.password.impl;

import static org.wildfly.common.math.HashMath.multiHashOrdered;

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import org.wildfly.common.Assert;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.password.interfaces.MaskedPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.IteratedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;

final class MaskedPasswordImpl extends AbstractPasswordImpl implements MaskedPassword {
    private static final long serialVersionUID = - 4107081797004604247L;

    @SuppressWarnings("SpellCheckingInspection")
    private static final char[] DEFAULT_PBE_KEY = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
    // Required size for many schemes according to RFC 2898
    private static final int DEFAULT_SALT_SIZE = 8;
    // Recommended minimum by RFC 2898
    private static final int DEFAULT_ITERATION_COUNT = 1000;

    private final String algorithm;
    private final char[] initialKeyMaterial;
    private final int iterationCount;
    private final byte[] salt;
    private final byte[] maskedPasswordBytes;
    private final byte[] initializationVector;


    private MaskedPasswordImpl(final String algorithm, final char[] initialKeyMaterial, final int iterationCount, final byte[] salt, final byte[] initializationVector, final byte[] maskedPasswordBytes) throws InvalidKeySpecException {
        Assert.checkMinimumParameter("iterationCount", 1, iterationCount);
        this.algorithm = algorithm;
        this.initialKeyMaterial = initialKeyMaterial;
        this.iterationCount = iterationCount;
        this.salt = salt;
        this.maskedPasswordBytes = maskedPasswordBytes;
        this.initializationVector = initializationVector;
        unmask(); //preform an unmask to validate parameters
    }

    private MaskedPasswordImpl(final String algorithm, final char[] initialKeyMaterial, final int iterationCount, final byte[] salt, final char[] chars) throws InvalidKeySpecException {
        Assert.checkMinimumParameter("iterationCount", 1, iterationCount);
        this.algorithm = algorithm;
        this.initialKeyMaterial = initialKeyMaterial;
        this.iterationCount = iterationCount;
        this.salt = salt;

        try {
            Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, null);
            this.maskedPasswordBytes = cipher.doFinal(CodePointIterator.ofChars(chars).asUtf8().drain());
            this.initializationVector = cipher.getIV();
        } catch (GeneralSecurityException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    MaskedPasswordImpl(final String algorithm, final MaskedPasswordSpec passwordSpec) throws InvalidKeySpecException {
        this(algorithm, passwordSpec.getInitialKeyMaterial().clone(), passwordSpec.getIterationCount(), passwordSpec.getSalt().clone(), passwordSpec.getInitializationVector() == null ? null : passwordSpec.getInitializationVector().clone(), passwordSpec.getMaskedPasswordBytes().clone());
    }

    MaskedPasswordImpl(final String algorithm, final char[] clearPassword) throws InvalidKeySpecException {
        this(algorithm, DEFAULT_PBE_KEY, DEFAULT_ITERATION_COUNT, PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE), clearPassword);
    }

    MaskedPasswordImpl(final String algorithm, final char[] clearPassword, final MaskedPasswordAlgorithmSpec parameterSpec) throws InvalidKeySpecException {
        this(algorithm, parameterSpec.getInitialKeyMaterial().clone(), parameterSpec.getIterationCount(), parameterSpec.getSalt().clone(), clearPassword);
    }

    MaskedPasswordImpl(final String algorithm, final char[] clearPassword, final IteratedSaltedPasswordAlgorithmSpec parameterSpec) throws InvalidKeySpecException {
        this(algorithm, DEFAULT_PBE_KEY, parameterSpec.getIterationCount(), parameterSpec.getSalt().clone(), clearPassword);
    }

    MaskedPasswordImpl(final String algorithm, final char[] clearPassword, final SaltedPasswordAlgorithmSpec parameterSpec) throws InvalidKeySpecException {
        this(algorithm, DEFAULT_PBE_KEY, DEFAULT_ITERATION_COUNT, parameterSpec.getSalt().clone(), clearPassword);
    }

    MaskedPasswordImpl(final String algorithm, final char[] clearPassword, final IteratedPasswordAlgorithmSpec parameterSpec) throws InvalidKeySpecException {
        this(algorithm, DEFAULT_PBE_KEY, parameterSpec.getIterationCount(), PasswordUtil.generateRandomSalt(DEFAULT_SALT_SIZE), clearPassword);
    }

    MaskedPasswordImpl(final String algorithm, final ClearPasswordSpec keySpec) throws InvalidKeySpecException {
        this(algorithm, keySpec.getEncodedPassword());
    }

    MaskedPasswordImpl(final MaskedPassword password) throws InvalidKeySpecException {
        this(password.getAlgorithm(), password.getInitialKeyMaterial().clone(), password.getIterationCount(), password.getSalt().clone(), password.getInitializationVector() == null ? null : password.getInitializationVector().clone(), password.getMaskedPasswordBytes().clone());
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public char[] getInitialKeyMaterial() {
        return initialKeyMaterial.clone();
    }

    public int getIterationCount() {
        return iterationCount;
    }

    public byte[] getSalt() {
        return salt.clone();
    }

    public byte[] getMaskedPasswordBytes() {
        return maskedPasswordBytes.clone();
    }

    public byte[] getInitializationVector() {
        return initializationVector == null ? null : initializationVector.clone();
    }

    <S extends KeySpec> S getKeySpec(final Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(MaskedPasswordSpec.class)) {
            return keySpecType.cast(new MaskedPasswordSpec(initialKeyMaterial.clone(), iterationCount, salt.clone(), maskedPasswordBytes.clone()));
        } else if (keySpecType.isAssignableFrom(ClearPasswordSpec.class)) {
            return keySpecType.cast(new ClearPasswordSpec(unmask()));
        } else {
            throw new InvalidKeySpecException();
        }
    }

    boolean verify(final char[] guess) throws InvalidKeyException {
        try {
            return Arrays.equals(guess, unmask());
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    boolean verify(char[] guess, Charset hashCharset) throws InvalidKeyException {
        return verify(guess);
    }

    <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(MaskedPasswordSpec.class) || keySpecType.isAssignableFrom(ClearPasswordSpec.class);
    }

    public MaskedPasswordImpl clone() {
        return this;
    }

    private char[] unmask() throws InvalidKeySpecException {
        try {
            final Cipher cipher = getCipher(Cipher.DECRYPT_MODE, initializationVector);
            return ByteIterator.ofBytes(cipher.doFinal(maskedPasswordBytes)).asUtf8String().drainToString().toCharArray();
        } catch (GeneralSecurityException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    private Cipher getCipher(int cipherMode, byte[] initializationVector) throws GeneralSecurityException {
        final String pbeName = MaskedPassword.getPBEName(algorithm);
        Assert.assertNotNull(pbeName);
        final SecretKeyFactory factory = SecretKeyFactory.getInstance(pbeName);
        final Cipher cipher = Cipher.getInstance(pbeName);

        final AlgorithmParameterSpec parameterSpec = initializationVector == null ?
                null : new IvParameterSpec(initializationVector);

        // Create the PBE secret key
        final PBEParameterSpec cipherSpec = new PBEParameterSpec(salt, iterationCount, parameterSpec);
        final PBEKeySpec keySpec = new PBEKeySpec(initialKeyMaterial);
        final SecretKey cipherKey = factory.generateSecret(keySpec);

        cipher.init(cipherMode, cipherKey, cipherSpec);
        return cipher;
    }

    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(multiHashOrdered(multiHashOrdered(multiHashOrdered(Arrays.hashCode(initialKeyMaterial), Arrays.hashCode(salt)), Arrays.hashCode(maskedPasswordBytes)), iterationCount), Arrays.hashCode(initializationVector)), algorithm.hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof MaskedPasswordImpl)) {
            return false;
        }
        MaskedPasswordImpl other = (MaskedPasswordImpl) obj;
        return iterationCount == other.iterationCount && Arrays.equals(initialKeyMaterial, other.initialKeyMaterial)
                && MessageDigest.isEqual(salt, other.salt) && MessageDigest.isEqual(maskedPasswordBytes, other.maskedPasswordBytes)
                && MessageDigest.isEqual(initializationVector, other.initializationVector) && algorithm.equals(other.algorithm);
    }

    Object writeReplace() {
        return MaskedPassword.createRaw(algorithm, initialKeyMaterial.clone(), iterationCount, salt.clone(), maskedPasswordBytes.clone());
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }
}
