/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.credential.store.impl;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.wildfly.common.Assert;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.CodePointIterator;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

/**
 * Password Based Encryption based credential store.
 * This credential store is used to decrypt PBE encrypted credentials.
 * It cannot contain/store/remove any alias.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public final class PasswordBasedEncryptionCredentialStore extends CredentialStoreSpi {

    /**
     * The name of this credential store implementation.
     */
    public static final String PBE_CREDENTIAL_STORE = PasswordBasedEncryptionCredentialStore.class.getSimpleName();

    // attribute string keys
    private static String KEY_ALGORITHM = "keyAlgorithm";
    private static String TRANSFORMATION = "transformation";
    private static String PARAMETERS_ALGORITHM = "parametersAlgorithm";
    private static String ITERATION = "iteration";
    private static String SALT = "salt";
    private static String ENCODED_SALT = "encodedSalt";
    private static String KEY_LENGTH = "keyLength";
    private static String CIPHER_ITERATION = "cipherIteration";
    private static String CIPHER_SALT = "cipherSalt";
    private static String ENCODED_CIPHER_SALT = "encodedCipherSalt";
    private static String ALPHABET = "alphabet";
    private static String ENCODED_IV = "encodedIV";
    private static String MASK_PREFIX = "maskPrefix";

    private Alphabet alphabet = null;
    private PasswordBasedEncryptionUtil passwordBasedEncryptionUtil = null;
    private String maskPrefix = "MASK-";


    @Override
    public void initialize(Map<String, String> attributes, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        Assert.checkNotNullParam("attributes", attributes);
        if (attributes.containsKey(MASK_PREFIX))
            maskPrefix = attributes.get(MASK_PREFIX);

        PasswordBasedEncryptionUtil.Builder pbeBuilder = new PasswordBasedEncryptionUtil.Builder();
        if (protectionParameter != null) {
            if (protectionParameter instanceof CredentialStore.CredentialSourceProtectionParameter) {
                final CredentialSource credentialSource = ((CredentialStore.CredentialSourceProtectionParameter) protectionParameter).getCredentialSource();
                try {
                    char[] initialKey = credentialSource.applyToCredential(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
                    pbeBuilder.password(initialKey);
                } catch (IOException e) {
                    throw log.cannotAcquireCredentialFromStore(e);
                }
            } else {
                throw log.invalidProtectionParameter(protectionParameter);
            }
        } else {
            // PicketBox default initial key (copied from org.picketbox.plugins.vault.PicketBoxSecurityVault#decode)
            pbeBuilder.password("somearbitrarycrazystringthatdoesnotmatter");
        }
        if (attributes.containsKey(KEY_ALGORITHM))
            pbeBuilder.keyAlgorithm(attributes.get(KEY_ALGORITHM));
        if (attributes.containsKey(TRANSFORMATION))
            pbeBuilder.transformation(attributes.get(TRANSFORMATION));
        if (attributes.containsKey(PARAMETERS_ALGORITHM))
            pbeBuilder.parametersAlgorithm(attributes.get(PARAMETERS_ALGORITHM));
        if (attributes.containsKey(KEY_LENGTH))
            pbeBuilder.keyLength(Integer.parseInt(attributes.get(KEY_LENGTH)));

        alphabet = attributes.containsKey(ALPHABET) ? Alphabet.mapToAlphabet(attributes.get(ALPHABET)) : Alphabet.Base64Alphabet.STANDARD;
        pbeBuilder.alphabet(alphabet);
        if (attributes.containsKey(ENCODED_IV))
            pbeBuilder.iv(attributes.get(ENCODED_IV));
        if (attributes.containsKey(CIPHER_SALT))
            pbeBuilder.cipherSalt(attributes.get(CIPHER_SALT));
        if (attributes.containsKey(ENCODED_CIPHER_SALT)) {
            if (alphabet instanceof Alphabet.Base32Alphabet)
                pbeBuilder.cipherSalt(CodePointIterator.ofString(attributes.get(CIPHER_SALT)).base32Decode().drain());
            else
                pbeBuilder.cipherSalt(CodePointIterator.ofString(attributes.get(CIPHER_SALT)).base64Decode().drain());
        }
        boolean saltSet = false;
        if (attributes.containsKey(SALT)) {
            pbeBuilder.salt(attributes.get(SALT));
            saltSet = true;
        }
        if (attributes.containsKey(ENCODED_SALT)) {
            if (alphabet instanceof Alphabet.Base32Alphabet)
                pbeBuilder.salt(CodePointIterator.ofString(attributes.get(SALT)).base32Decode().drain());
            else
                pbeBuilder.salt(CodePointIterator.ofString(attributes.get(SALT)).base64Decode().drain());
            saltSet = true;
        }
        if (!saltSet) {
            throw log.attributeIsMandatory(PBE_CREDENTIAL_STORE, SALT);
        }
        if (attributes.containsKey(CIPHER_ITERATION))
            pbeBuilder.cipherIteration(Integer.parseInt(attributes.get(CIPHER_ITERATION)));
        if (attributes.containsKey(ITERATION))
            pbeBuilder.iteration(Integer.parseInt(attributes.get(ITERATION)));
        else
            throw log.attributeIsMandatory(PBE_CREDENTIAL_STORE, ITERATION);

        try {
            passwordBasedEncryptionUtil = pbeBuilder.decryptMode().build();
        } catch (GeneralSecurityException e) {
            throw log.cannotInitializeCredentialStore(e);
        }
        initialized = true;
    }

    @Override
    public boolean isModifiable() {
        return false;
    }

    @Override
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        return Collections.emptySet();
    }

    @Override
    public void store(String credentialAlias, Credential credential, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        throw log.methodNotImplemented("store", PBE_CREDENTIAL_STORE);
    }

    @Override
    public <C extends Credential> C retrieve(String credentialAlias, Class<C> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        Assert.checkNotNullParam("credentialAlias", credentialAlias);
        try {
            String payload = credentialAlias.startsWith(maskPrefix) ?
                    credentialAlias.substring(maskPrefix.length())
                    :
                    credentialAlias;
            return credentialType.cast(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR,
                    passwordBasedEncryptionUtil.decodeAndDecrypt(payload))));
        } catch (GeneralSecurityException e) {
            throw new CredentialStoreException(e);
        }
    }

    @Override
    public void remove(String credentialAlias, Class<? extends Credential> credentialType, String credentialAlgorithm, AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {
        throw log.methodNotImplemented("remove", PBE_CREDENTIAL_STORE);
    }
}
