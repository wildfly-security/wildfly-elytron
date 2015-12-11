/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.credential.external.impl;

import org.wildfly.common.Assert;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.external.ExternalCredentialException;
import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.ByteIterator;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * Provider handling password decoding from masked string using PBE algorithms.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public class MaskedPasswordCredentialProvider extends ExternalCredentialProvider {

    private final String nameSpace;

    /**
     * Parameter name which denotes masked password string
     */
    public static final String PASSWORD = "password";
    /**
     * Parameter name which denotes salt
     */
    public static final String SALT = "salt";
    /**
     * Parameter name which denotes iteration count
     */
    public static final String ITERATION_COUNT = "iteration";
    /**
     * Parameter name which denotes PBE algorithm
     */
    public static final String PBE_ALGORITHM = "algorithm";
    /**
     * Parameter name which denotes initial key for PBE algorithm
     */
    public static final String INITIAL_KEY = "initialKey";

    private final Set<String> supportedParameters;

    /**
     * Prefix to used when masked password needs to be detected.
     */
    public static String PASS_MASK_PREFIX = "MASK-";

    private static final char[] DEFAULT_PBE_KEY = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
    static final String DEFAULT_PBE_ALGORITHM = "PBEwithMD5andDES";


    /**
     * Constructor of {@code MaskedPasswordCredentialProvider} using namespace to distinguish among more
     * masked passwords in the same set of parameters.
     * @param nameSpace a base on which parameter names will be used
     */
    public MaskedPasswordCredentialProvider(String nameSpace) {
        Assert.assertNotNull(nameSpace);
        this.nameSpace = nameSpace;
        supportedParameters = Collections.unmodifiableSet(new HashSet<>(
                Arrays.asList(this.nameSpace + "." + SALT,
                        this.nameSpace + "." + ITERATION_COUNT,
                        this.nameSpace + "." + PBE_ALGORITHM,
                        this.nameSpace + "." + INITIAL_KEY)));
    }

    @Override
    public <C extends Credential> C resolveCredential(Map<String, String> parameters, Class<C> credentialType) throws ExternalCredentialException {
        try {
            return credentialType.cast(
                    createCredentialFromPassword(
                            decode(getPassword(parameters),
                                    getSalt(parameters),
                                    getIterationCount(parameters),
                                    getPbeAlgorithm(parameters),
                                    getInitialKey(parameters))));
        } catch (Exception e) {
            throw new ExternalCredentialException(e);
        }
    }

    /**
     * Method is not supported in this provider.
     * @param passwordCommand to obtain external password
     * @param credentialType type of {@link Credential} to get back form this method
     * @param <C> type parameter of {@link Credential}
     * @return {@link Credential} from service provider
     * @throws ExternalCredentialException if anything goes wrong while resolving the credential
     */
    @Override
    public <C extends Credential> C resolveCredential(String passwordCommand, Class<C> credentialType) throws ExternalCredentialException {
        throw new UnsupportedOperationException();
    }

    /**
     * This method provides parameters supported by external credential provider. The {@code Set} can be used
     * to filter parameters supplied {@link #resolveCredential(Map, Class)} or {@link #resolveCredential(String, Class)}
     * methods.
     *
     * @return {@code Set<String>} of supported parameters
     */
    @Override
    public Set<String> supportedParameters() {
        return supportedParameters;
    }

    /**
     * This decodes password encoded using {@code PBEUtils} class of PicketBox.
     *
     * Method ported from PicketBox to maintain backward compatibility.
     *
     * @param maskedString masked password string including (masked) prefix
     * @param salt salt
     * @param iterationCount iteration count
     * @param pbeAlgorithm PBE algorithm. {@code null} for default value.
     * @param initialKey initial key. {@code null} for default value.
     * @return returns clear text password
     * @throws Exception when anything goes wrong
     */
    static char[] decode(final String maskedString, final String salt, final int iterationCount,
                                final String pbeAlgorithm, final String initialKey) throws Exception {

        String algorithm = pbeAlgorithm != null ? pbeAlgorithm : DEFAULT_PBE_ALGORITHM;
        String encryptedBase64EncodedSecret = maskedString.startsWith(PASS_MASK_PREFIX) ? maskedString.substring(PASS_MASK_PREFIX.length()) : maskedString;
        // Create the PBE secret key
        SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);

        char[] initialKeyMaterial = initialKey != null ? initialKey.toCharArray() : DEFAULT_PBE_KEY;
        PBEParameterSpec cipherSpec = new PBEParameterSpec(salt.getBytes(StandardCharsets.UTF_8), iterationCount);
        PBEKeySpec keySpec = new PBEKeySpec(initialKeyMaterial);
        SecretKey cipherKey = factory.generateSecret(keySpec);

        return decode64(encryptedBase64EncodedSecret, algorithm, cipherKey, cipherSpec).toCharArray();
    }

    private static String decode64(String secret, String cipherAlgorithm, SecretKey cipherKey, PBEParameterSpec cipherSpec)
            throws Exception {
        byte[] encoding;
        try {
            encoding = ByteIterator.ofBytes(secret.getBytes(StandardCharsets.UTF_8)).base64Decode(Alphabet.Base64Alphabet.PICKETBOX_BASE_64).drain();
        } catch (IllegalArgumentException e) {
            // fallback when original string is was created with faulty version of Base64
            String fallBack = "0" + secret;
            encoding = ByteIterator.ofBytes((fallBack).getBytes(StandardCharsets.UTF_8)).base64Decode().drain();
            log.warnWrongBase64EncodedString(fallBack);
        }
        byte[] decoded = decode(encoding, cipherAlgorithm, cipherKey, cipherSpec);

        return new String(decoded, StandardCharsets.UTF_8);
    }

    private static byte[] decode(byte[] secret, String cipherAlgorithm, SecretKey cipherKey, PBEParameterSpec cipherSpec)
            throws Exception {
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, cipherKey, cipherSpec);
        byte[] decode = cipher.doFinal(secret);
        return decode;
    }

    String getSalt(final Map<String, String> parameters) {
        return parameters.get(nameSpace + "." + SALT);
    }

    int getIterationCount(final Map<String, String> parameters) {
        String iterationCount = parameters.get(nameSpace + "." + ITERATION_COUNT);
        if (iterationCount != null) {
            return Integer.parseInt(iterationCount);
        } else {
            throw new IllegalArgumentException(nameSpace + "." + ITERATION_COUNT);
        }
    }

    String getPbeAlgorithm(final Map<String, String> parameters) {
        return parameters.get(nameSpace + "." + PBE_ALGORITHM);
    }

    String getInitialKey(final Map<String, String> parameters) {
        return parameters.get(nameSpace + "." + INITIAL_KEY);
    }

    String getPassword(final Map<String, String> parameters) {
        return parameters.get(nameSpace + "." + PASSWORD);
    }
}
