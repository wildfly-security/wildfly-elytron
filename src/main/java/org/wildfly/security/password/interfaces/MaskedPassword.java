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

package org.wildfly.security.password.interfaces;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.wildfly.common.Assert;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.IteratedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;

/**
 * A password which has been masked, PicketBox style.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface MaskedPassword extends TwoWayPassword {

    String ALGORITHM_MASKED_MD5_DES = "masked-MD5-DES";
    String ALGORITHM_MASKED_MD5_DES_CBC_PKCS5 = "masked-MD5-DES-CBC-PKCS5";
    String ALGORITHM_MASKED_MD5_3DES = "masked-MD5-3DES";
    String ALGORITHM_MASKED_MD5_3DES_CBC_PKCS5 = "masked-MD5-3DES-CBC-PKCS5";
    String ALGORITHM_MASKED_SHA1_DES_EDE = "masked-SHA1-DES-EDE";
    String ALGORITHM_MASKED_SHA1_DES_EDE_CBC_PKCS5 = "masked-SHA1-DES-EDE-CBC-PKCS5";
    String ALGORITHM_MASKED_SHA1_RC2_40 = "masked-SHA1-RC2-40";
    String ALGORITHM_MASKED_SHA1_RC2_40_CBC_PKCS5 = "masked-SHA1-RC2-40-CBC-PKCS5";
    String ALGORITHM_MASKED_SHA1_RC2_128 = "masked-SHA1-RC2-128";
    String ALGORITHM_MASKED_SHA1_RC2_128_CBC_PKCS5 = "masked-SHA1-RC2-128-CBC-PKCS5";
    String ALGORITHM_MASKED_SHA1_RC4_40 = "masked-SHA1-RC4-40";
    String ALGORITHM_MASKED_SHA1_RC4_40_ECB = "masked-SHA1-RC4-40-ECB";
    String ALGORITHM_MASKED_SHA1_RC4_128 = "masked-SHA1-RC4-128";
    String ALGORITHM_MASKED_SHA1_RC4_128_ECB = "masked-SHA1-RC4-128-ECB";
    String ALGORITHM_MASKED_HMAC_SHA1_AES_128 = "masked-HMAC-SHA1-AES-128";
    String ALGORITHM_MASKED_HMAC_SHA224_AES_128 = "masked-HMAC-SHA224-AES-128";
    String ALGORITHM_MASKED_HMAC_SHA256_AES_128 = "masked-HMAC-SHA256-AES-128";
    String ALGORITHM_MASKED_HMAC_SHA384_AES_128 = "masked-HMAC-SHA384-AES-128";
    String ALGORITHM_MASKED_HMAC_SHA512_AES_128 = "masked-HMAC-SHA512-AES-128";
    String ALGORITHM_MASKED_HMAC_SHA1_AES_256 = "masked-HMAC-SHA1-AES-256";
    String ALGORITHM_MASKED_HMAC_SHA224_AES_256 = "masked-HMAC-SHA224-AES-256";
    String ALGORITHM_MASKED_HMAC_SHA256_AES_256 = "masked-HMAC-SHA256-AES-256";
    String ALGORITHM_MASKED_HMAC_SHA384_AES_256 = "masked-HMAC-SHA384-AES-256";
    String ALGORITHM_MASKED_HMAC_SHA512_AES_256 = "masked-HMAC-SHA512-AES-256";
    String ALGORITHM_MASKED_PBKDF_HMAC_SHA1 = "masked-PBKDF-HMAC-SHA1";
    String ALGORITHM_MASKED_PBKDF_HMAC_SHA224 = "masked-PBKDF-HMAC-SHA224";
    String ALGORITHM_MASKED_PBKDF_HMAC_SHA256 = "masked-PBKDF-HMAC-SHA256";
    String ALGORITHM_MASKED_PBKDF_HMAC_SHA384 = "masked-PBKDF-HMAC-SHA384";
    String ALGORITHM_MASKED_PBKDF_HMAC_SHA512 = "masked-PBKDF-HMAC-SHA512";

    /**
     * Determine if the given algorithm name is a valid masked password algorithm name.
     *
     * @param name the algorithm name
     * @return {@code true} if the algorithm name is valid for this password type, {@code false} otherwise
     */
    static boolean isMaskedAlgorithm(String name) {
        return getPBEName(name) != null;
    }

    /**
     * Get the name of the PBE algorithm that goes with the given password algorithm name.
     *
     * @param name the password algorithm name
     * @return the PBE algorithm name, or {@code null} if the password algorithm name was {@code null} or not recognized
     */
    @SuppressWarnings("SpellCheckingInspection")
    static String getPBEName(String name) {
        if (name == null) return null;
        switch (name) {
            case ALGORITHM_MASKED_MD5_DES: return "PBEWithMD5ANDdes";
            case ALGORITHM_MASKED_MD5_DES_CBC_PKCS5: return "PBEWithMD5ANDtripledes";
            case ALGORITHM_MASKED_MD5_3DES: return "PBEWithMD5ANDtripledes";
            case ALGORITHM_MASKED_MD5_3DES_CBC_PKCS5: return "PBEWithMD5AndTRIPLEDES";
            case ALGORITHM_MASKED_SHA1_DES_EDE: return "PBEwithSHA1AndDESede";
            case ALGORITHM_MASKED_SHA1_DES_EDE_CBC_PKCS5: return "PBEwithSHA1AndDESede";
            case ALGORITHM_MASKED_SHA1_RC2_40: return "PBEwithSHA1AndRC2_40";
            case ALGORITHM_MASKED_SHA1_RC2_40_CBC_PKCS5: return "PBEwithSHA1Andrc2_40";
            case ALGORITHM_MASKED_SHA1_RC2_128: return "PBEWithSHA1AndRC2_128";
            case ALGORITHM_MASKED_SHA1_RC2_128_CBC_PKCS5: return "PBEWithSHA1andRC2_128";
            case ALGORITHM_MASKED_SHA1_RC4_40: return "PBEWithSHA1AndRC4_40";
            case ALGORITHM_MASKED_SHA1_RC4_40_ECB: return "PBEWithsha1AndRC4_40";
            case ALGORITHM_MASKED_SHA1_RC4_128: return "PBEWithSHA1AndRC4_128";
            case ALGORITHM_MASKED_SHA1_RC4_128_ECB: return "pbeWithSHA1AndRC4_128";
            case ALGORITHM_MASKED_HMAC_SHA1_AES_128: return "PBEWithHmacSHA1AndAES_128";
            case ALGORITHM_MASKED_HMAC_SHA224_AES_128: return "PBEWithHmacSHA224AndAES_128";
            case ALGORITHM_MASKED_HMAC_SHA256_AES_128: return "PBEWithHmacSHA256AndAES_128";
            case ALGORITHM_MASKED_HMAC_SHA384_AES_128: return "PBEWithHmacSHA384AndAES_128";
            case ALGORITHM_MASKED_HMAC_SHA512_AES_128: return "PBEWithHmacSHA512AndAES_128";
            case ALGORITHM_MASKED_HMAC_SHA1_AES_256: return "PBEWithHmacSHA1AndAES_256";
            case ALGORITHM_MASKED_HMAC_SHA224_AES_256: return "PBEWithHmacSHA224AndAES_256";
            case ALGORITHM_MASKED_HMAC_SHA256_AES_256: return "PBEWithHmacSHA256AndAES_256";
            case ALGORITHM_MASKED_HMAC_SHA384_AES_256: return "PBEWithHmacSHA384AndAES_256";
            case ALGORITHM_MASKED_HMAC_SHA512_AES_256: return "PBEWithHmacSHA512AndAES_256";
            case ALGORITHM_MASKED_PBKDF_HMAC_SHA1: return "PBKDF2WithHmacSHA1";
            case ALGORITHM_MASKED_PBKDF_HMAC_SHA224: return "PBKDF2WithHmacSHA224";
            case ALGORITHM_MASKED_PBKDF_HMAC_SHA256: return "PBKDF2WithHmacSHA256";
            case ALGORITHM_MASKED_PBKDF_HMAC_SHA384: return "PBKDF2WithHmacSHA384";
            case ALGORITHM_MASKED_PBKDF_HMAC_SHA512: return "PBKDF2WithHmacSHA512";
            default: return null;
        }
    }

    /**
     * Get the initial key material.
     *
     * @return the initial key material (must not be {@code null})
     */
    char[] getInitialKeyMaterial();

    /**
     * Get the iteration count.
     *
     * @return the iteration count
     */
    int getIterationCount();

    /**
     * Get the salt bytes.
     *
     * @return the salt bytes (must not be {@code null})
     */
    byte[] getSalt();

    /**
     * Get the masked password bytes.
     *
     * @return the masked password bytes (must not be {@code null})
     */
    byte[] getMaskedPasswordBytes();

    default MaskedPasswordAlgorithmSpec getParameterSpec() {
        return new MaskedPasswordAlgorithmSpec(getInitialKeyMaterial(), getIterationCount(), getSalt());
    }

    default boolean impliesParameters(AlgorithmParameterSpec parameterSpec) {
        Assert.checkNotNullParam("parameterSpec", parameterSpec);
        if (parameterSpec instanceof MaskedPasswordAlgorithmSpec) {
            MaskedPasswordAlgorithmSpec spec = (MaskedPasswordAlgorithmSpec) parameterSpec;
            return Arrays.equals(getInitialKeyMaterial(), spec.getInitialKeyMaterial())
                && getIterationCount() <= spec.getIterationCount()
                && Arrays.equals(getSalt(), spec.getSalt());
        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
            final SaltedPasswordAlgorithmSpec spec = (SaltedPasswordAlgorithmSpec) parameterSpec;
            return Arrays.equals(getSalt(), spec.getSalt());
        } else if (parameterSpec instanceof IteratedPasswordAlgorithmSpec) {
            final IteratedPasswordAlgorithmSpec spec = (IteratedPasswordAlgorithmSpec) parameterSpec;
            return getIterationCount() <= spec.getIterationCount();
        } else if (parameterSpec instanceof IteratedSaltedPasswordAlgorithmSpec) {
            final IteratedSaltedPasswordAlgorithmSpec spec = (IteratedSaltedPasswordAlgorithmSpec) parameterSpec;
            return Arrays.equals(getSalt(), spec.getSalt()) && getIterationCount() <= spec.getIterationCount();
        } else {
            return false;
        }
    }

    @Override
    MaskedPassword clone();

    /**
     * Create a raw instance of this password type.
     *
     * @param algorithm the algorithm name (must not be {@code null})
     * @param initialKeyMaterial the initial key material (must not be {@code null})
     * @param iterationCount the iteration count
     * @param salt the salt (must not be {@code null})
     * @param maskedPasswordBytes the masked password bytes (must not be {@code null})
     * @return the raw instance (not {@code null})
     */
    static MaskedPassword createRaw(String algorithm, char[] initialKeyMaterial, int iterationCount, byte[] salt, byte[] maskedPasswordBytes) {
        Assert.checkNotNullParam("algorithm", algorithm);
        Assert.checkNotNullParam("initialKeyMaterial", initialKeyMaterial);
        Assert.checkNotNullParam("salt", salt);
        Assert.checkNotNullParam("maskedPasswordBytes", maskedPasswordBytes);
        return new RawMaskedPassword(algorithm, initialKeyMaterial.clone(), iterationCount, salt.clone(), maskedPasswordBytes.clone());
    }
}
