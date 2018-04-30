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
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.wildfly.common.Assert;
import org.wildfly.security.password.interfaces.MaskedPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.IteratedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.util.PasswordUtil;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.CodePointIterator;

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

    private MaskedPasswordImpl(final String algorithm, final char[] initialKeyMaterial, final int iterationCount, final byte[] salt, final byte[] maskedPasswordBytes, final boolean validated) throws InvalidKeySpecException {
        Assert.checkMinimumParameter("iterationCount", 1, iterationCount);
        // perform an unmask to validate parameters
        if (! validated) unmask(algorithm, initialKeyMaterial, iterationCount, salt, maskedPasswordBytes);
        this.algorithm = algorithm;
        this.initialKeyMaterial = initialKeyMaterial;
        this.iterationCount = iterationCount;
        this.salt = salt;
        this.maskedPasswordBytes = maskedPasswordBytes;
    }

    private MaskedPasswordImpl(final String algorithm, final char[] initialKeyMaterial, final int iterationCount, final byte[] salt, final char[] chars) throws InvalidKeySpecException {
        this(algorithm, initialKeyMaterial, iterationCount, salt, mask(algorithm, initialKeyMaterial, iterationCount, salt, chars), true);
    }

    MaskedPasswordImpl(final String algorithm, final MaskedPasswordSpec passwordSpec) throws InvalidKeySpecException {
        this(algorithm, passwordSpec.getInitialKeyMaterial().clone(), passwordSpec.getIterationCount(), passwordSpec.getSalt().clone(), passwordSpec.getMaskedPasswordBytes().clone(), false);
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
        this(password.getAlgorithm(), password.getInitialKeyMaterial().clone(), password.getIterationCount(), password.getSalt().clone(), password.getMaskedPasswordBytes().clone(), false);
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

    <S extends KeySpec> S getKeySpec(final Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(MaskedPasswordSpec.class)) {
            return keySpecType.cast(new MaskedPasswordSpec(initialKeyMaterial.clone(), iterationCount, salt.clone(), maskedPasswordBytes.clone()));
        } else if (keySpecType.isAssignableFrom(ClearPasswordSpec.class)) {
            return keySpecType.cast(new ClearPasswordSpec(unmask(algorithm, initialKeyMaterial, iterationCount, salt, maskedPasswordBytes)));
        } else {
            throw new InvalidKeySpecException();
        }
    }

    boolean verify(final char[] guess) throws InvalidKeyException {
        try {
            return Arrays.equals(guess, unmask(algorithm, initialKeyMaterial, iterationCount, salt, maskedPasswordBytes));
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }

    <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(MaskedPasswordSpec.class) || keySpecType.isAssignableFrom(ClearPasswordSpec.class);
    }

    public MaskedPasswordImpl clone() {
        return this;
    }

    private static byte[] mask(final String algorithm, final char[] initialKeyMaterial, final int iterationCount, final byte[] salt, final char[] chars) throws InvalidKeySpecException {
        final String pbeName = MaskedPassword.getPBEName(algorithm);
        Assert.assertNotNull(pbeName);

        try {
            final Cipher cipher = Cipher.getInstance(pbeName);
            final SecretKeyFactory factory = SecretKeyFactory.getInstance(pbeName);

            // Create the PBE secret key
            final PBEParameterSpec cipherSpec = new PBEParameterSpec(salt, iterationCount);
            final PBEKeySpec keySpec = new PBEKeySpec(initialKeyMaterial);
            final SecretKey cipherKey = factory.generateSecret(keySpec);

            cipher.init(Cipher.ENCRYPT_MODE, cipherKey, cipherSpec);

            final byte[] encrypted = cipher.doFinal(CodePointIterator.ofChars(chars).asUtf8().drain());

            // To keep this implementation compatible with PicketBox, do not prepend the IV to the masked bytes, make
            // the result the same as in PicketBox implementation
            final byte[] iv = MaskedPassword.ALGORITHM_MASKED_MD5_DES.equals(algorithm) ? null : cipher.getIV();

            if (iv == null) {
                return encrypted;
            }

            final byte[] ivWithEncrypted = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, ivWithEncrypted, 0, iv.length);
            System.arraycopy(encrypted, 0, ivWithEncrypted, iv.length, encrypted.length);

            return ivWithEncrypted;
        } catch (GeneralSecurityException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    private static char[] unmask(final String algorithm, final char[] initialKeyMaterial, final int iterationCount, final byte[] salt, final byte[] bytes) throws InvalidKeySpecException {
        final String pbeName = MaskedPassword.getPBEName(algorithm);
        Assert.assertNotNull(pbeName);

        try {
            final Cipher cipher = Cipher.getInstance(pbeName);
            final SecretKeyFactory factory = SecretKeyFactory.getInstance(pbeName);

            // PicketBox used MD5 with DES algorithm and did not use this way of preserving the IV, but as it uses this
            // algorithms in PBES1 mode (RFC2898) the IV is derived from the secret key anyhow so it is not necessary to
            // prepend it to the masked bytes
            final int blockSize = MaskedPassword.ALGORITHM_MASKED_MD5_DES.equals(algorithm) ? 0 : cipher.getBlockSize();
            final AlgorithmParameterSpec parameterSpec;
            if (blockSize == 0) {
                parameterSpec = null;
            } else {
                parameterSpec = new IvParameterSpec(bytes, 0, blockSize);
            }

            // Create the PBE secret key
            final PBEParameterSpec cipherSpec = new PBEParameterSpec(salt, iterationCount, parameterSpec);
            final PBEKeySpec keySpec = new PBEKeySpec(initialKeyMaterial);
            final SecretKey cipherKey = factory.generateSecret(keySpec);

            cipher.init(Cipher.DECRYPT_MODE, cipherKey, cipherSpec);

            final byte[] clearText = cipher.doFinal(bytes, blockSize, bytes.length - blockSize);

            return ByteIterator.ofBytes(clearText).asUtf8String().drainToString().toCharArray();
        } catch (GeneralSecurityException e) {
            throw new InvalidKeySpecException(e);
        }
    }

    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(multiHashOrdered(multiHashOrdered(Arrays.hashCode(initialKeyMaterial), Arrays.hashCode(salt)), Arrays.hashCode(maskedPasswordBytes)), iterationCount), algorithm.hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof MaskedPasswordImpl)) {
            return false;
        }
        MaskedPasswordImpl other = (MaskedPasswordImpl) obj;
        return iterationCount == other.iterationCount && Arrays.equals(initialKeyMaterial, other.initialKeyMaterial) && Arrays.equals(salt, other.salt) && Arrays.equals(maskedPasswordBytes, other.maskedPasswordBytes) && algorithm.equals(other.algorithm);
    }

    Object writeReplace() {
        return MaskedPassword.createRaw(algorithm, initialKeyMaterial.clone(), iterationCount, salt.clone(), maskedPasswordBytes.clone());
    }

    private void readObject(ObjectInputStream ignored) throws NotSerializableException {
        throw new NotSerializableException();
    }
}
