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

package org.wildfly.security.sasl.digest;

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.mechanism.digest.DigestUtil.getTwoWayPasswordChars;
import static org.wildfly.security.mechanism.digest.DigestUtil.userRealmPasswordDigest;
import static org.wildfly.security.sasl.digest._private.DigestUtil.HASH_algorithm;
import static org.wildfly.security.sasl.digest._private.DigestUtil.HMAC_algorithm;
import static org.wildfly.security.sasl.digest._private.DigestUtil.computeHMAC;
import static org.wildfly.security.sasl.digest._private.DigestUtil.create3desSecretKey;
import static org.wildfly.security.sasl.digest._private.DigestUtil.createDesSecretKey;
import static org.wildfly.security.sasl.digest._private.DigestUtil.decodeByteOrderedInteger;
import static org.wildfly.security.sasl.digest._private.DigestUtil.integerByteOrdered;
import static org.wildfly.security.sasl.digest._private.DigestUtil.messageDigestAlgorithm;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Supplier;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.SaslMechanismInformation;
import org.wildfly.security.sasl.util.SaslWrapper;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.DefaultTransformationMapper;
import org.wildfly.security.util.TransformationMapper;
import org.wildfly.security.util.TransformationSpec;
import org.wildfly.security.util._private.Arrays2;

/**
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
abstract class AbstractDigestMechanism extends AbstractSaslParticipant {

    public static enum FORMAT {CLIENT, SERVER};


    private static int NONCE_SIZE = 36;

    public static final int DEFAULT_MAXBUF = 65536;
    public static final char DELIMITER = ',';
    public static final String[] CIPHER_OPTS = {"des", "3des", "rc4", "rc4-40", "rc4-56"};

    private FORMAT format;
    protected final String digestURI;
    protected Charset charset = StandardCharsets.ISO_8859_1;
    protected MessageDigest digest;

    // selected cipher
    protected String cipher;
    // selected qop
    protected String qop;
    // wrap message sequence number
    protected int wrapSeqNum;
    // unwrap message sequence number
    protected int unwrapSeqNum;
    // nonce
    protected byte[] nonce;
    // cnonce
    protected byte[] cnonce;
    // authz-id
    protected String authzid;
    // H(A1)
    protected byte[] hA1;

    protected SecureRandom secureRandomGenerator;
    protected Mac hmacMD5;

    protected Cipher wrapCipher = null;
    protected Cipher unwrapCipher = null;

    protected byte[] wrapHmacKeyIntegrity;
    protected byte[] unwrapHmacKeyIntegrity;

    protected final MessageDigest messageDigest;
    private final Supplier<Provider[]> providers;

    /**
     * @param mechanismName
     * @param protocol
     * @param serverName
     * @param callbackHandler
     */
    public AbstractDigestMechanism(String mechanismName, String protocol, String serverName, CallbackHandler callbackHandler, FORMAT format, Charset charset, String[] ciphers, Supplier<Provider[]> providers) throws SaslException {
        super(mechanismName, protocol, serverName, callbackHandler);

        secureRandomGenerator = new SecureRandom();
        hmacMD5 = getHmac();

        final String algorithm = messageDigestAlgorithm(mechanismName);
        if (algorithm == null) {
            throw log.mechMacAlgorithmNotSupported(getMechanismName(), null).toSaslException();
        }
        try { // H()
            this.messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw log.mechMacAlgorithmNotSupported(getMechanismName(), e).toSaslException();
        }

        try { // MD5()
            this.digest = MessageDigest.getInstance(HASH_algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw log.mechMacAlgorithmNotSupported(getMechanismName(), e).toSaslException();
        }

        this.format = format;
        this.digestURI = getProtocol() + "/" + getServerName();
        if (charset != null) {
            this.charset = charset;
        } else {
            this.charset = StandardCharsets.ISO_8859_1;
        }
        this.providers = providers;
    }

    /**
     * Get supported ciphers as comma separated list of cipher-opts by Digest MD5 spec.
     *
     * @return comma separated list of ciphers
     */
    static String getSupportedCiphers(String[] demandedCiphers) {
        TransformationMapper trans = new DefaultTransformationMapper();
        if (demandedCiphers == null) {
            demandedCiphers = CIPHER_OPTS;
        }
        StringBuilder ciphers = new StringBuilder();
        for (TransformationSpec ts: trans.getTransformationSpecByStrength(SaslMechanismInformation.Names.DIGEST_MD5, demandedCiphers)) {
            if (ciphers.length() > 0) {
                ciphers.append(DELIMITER);
            }
            ciphers.append(ts.getToken());
        }
        return ciphers.toString();
    }

    static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonceData = new byte[NONCE_SIZE];
        random.nextBytes(nonceData);
        return ByteIterator.ofBytes(nonceData).base64Encode().drainToString().getBytes(StandardCharsets.US_ASCII);
    }

    protected boolean arrayContains(String[] array, String searched){
        for(String item : array){
            if(searched.equals(item)) return true;
        }
        return false;
    }

    public Charset getCharset() {
        return charset;
    }

    protected class DigestWrapper implements SaslWrapper {

        private boolean confidential;

        /**
         * @param confidential
         */
        protected DigestWrapper(boolean confidential) {
            this.confidential = confidential;
        }

        /* (non-Javadoc)
         * @see org.wildfly.security.sasl.util.SaslWrapper#wrap(byte[], int, int)
         */
        @Override
        public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
            if (confidential) {
                return AbstractDigestMechanism.this.wrapConfidentialityProtectedMessage(outgoing, offset, len);
            } else {
                return AbstractDigestMechanism.this.wrapIntegrityProtectedMessage(outgoing, offset, len);
            }
        }

        /* (non-Javadoc)
         * @see org.wildfly.security.sasl.util.SaslWrapper#unwrap(byte[], int, int)
         */
        @Override
        public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
            if (confidential) {
                return AbstractDigestMechanism.this.unwrapConfidentialityProtectedMessage(incoming, offset, len);
            } else {
                return AbstractDigestMechanism.this.unwrapIntegrityProtectedMessage(incoming, offset, len);
            }
        }

    }

    private static final String CLIENT_MAGIC_INTEGRITY = "Digest session key to client-to-server signing key magic constant";
    private static final String SERVER_MAGIC_INTEGRITY = "Digest session key to server-to-client signing key magic constant";

    private byte[] wrapIntegrityProtectedMessage(byte[] message, int offset, int len) throws SaslException {

        byte[] messageMac = computeHMAC(wrapHmacKeyIntegrity, wrapSeqNum, hmacMD5, message, offset, len);

        byte[] result = new byte[len + 16];
        System.arraycopy(message, offset, result, 0, len);
        System.arraycopy(messageMac, 0, result, len, 10);
        integerByteOrdered(1, result, len + 10, 2);  // 2-byte message type number in network byte order with value 1
        integerByteOrdered(wrapSeqNum, result, len + 12, 4); // 4-byte sequence number in network byte order
        wrapSeqNum++;
        return result;
    }

    private byte[] unwrapIntegrityProtectedMessage(byte[] message, int offset, int len) throws SaslException {

        int messageType = decodeByteOrderedInteger(message, offset + len - 6, 2);
        int extractedSeqNum = decodeByteOrderedInteger(message, offset + len - 4, 4);

        if (messageType != 1) {
            throw log.mechMessageTypeMustEqual(getMechanismName(), 1, messageType).toSaslException();
        }

        if (extractedSeqNum != unwrapSeqNum) {
            throw log.mechBadSequenceNumberWhileUnwrapping(getMechanismName(), unwrapSeqNum, extractedSeqNum).toSaslException();
        }

        byte[] extractedMessageMac = new byte[10];
        byte[] extractedMessage = new byte[len - 16];
        System.arraycopy(message, offset, extractedMessage, 0, len - 16);
        System.arraycopy(message, offset + len - 16, extractedMessageMac, 0, 10);

        byte[] expectedHmac = computeHMAC(unwrapHmacKeyIntegrity, extractedSeqNum, hmacMD5, extractedMessage, 0, extractedMessage.length);

        // validate MAC block
        if (Arrays2.equals(expectedHmac, 0, extractedMessageMac, 0, 10) == false) {
            return NO_BYTES;
        }

        unwrapSeqNum++; // increment only if MAC is valid
        return extractedMessage;
    }

    private byte[] wrapConfidentialityProtectedMessage(byte[] message, int offset, int len) throws SaslException {

        byte[] messageMac = computeHMAC(wrapHmacKeyIntegrity, wrapSeqNum, hmacMD5, message, offset, len);

        int paddingLength = 0;
        byte[] pad = null;
        int blockSize = wrapCipher.getBlockSize();
        if (blockSize > 0) {
            paddingLength = blockSize - ((len + 10) % blockSize);
            pad = new byte[paddingLength];
            Arrays.fill(pad, (byte)paddingLength);
        }

        byte[] toCipher = new byte[len + paddingLength + 10];
        System.arraycopy(message, offset, toCipher, 0, len);
        if (paddingLength > 0) {
            System.arraycopy(pad, 0, toCipher, len, paddingLength);
        }
        System.arraycopy(messageMac, 0, toCipher, len + paddingLength, 10);

        byte[] cipheredPart = null;
        try {
            cipheredPart = wrapCipher.update(toCipher);
        } catch (Exception e) {
            throw log.mechProblemDuringCrypt(getMechanismName(), e).toSaslException();
        }
        if (cipheredPart == null){
            throw log.mechProblemDuringCryptResultIsNull(getMechanismName()).toSaslException();
        }

        byte[] result = new byte[cipheredPart.length + 6];
        System.arraycopy(cipheredPart, 0, result, 0, cipheredPart.length);
        integerByteOrdered(1, result, cipheredPart.length, 2);  // 2-byte message type number in network byte order with value 1
        integerByteOrdered(wrapSeqNum, result, cipheredPart.length + 2, 4); // 4-byte sequence number in network byte order

        wrapSeqNum++;
        return result;
    }

    private byte[] unwrapConfidentialityProtectedMessage(byte[] message, int offset, int len) throws SaslException {

        int messageType = decodeByteOrderedInteger(message, offset + len - 6, 2);
        int extractedSeqNum = decodeByteOrderedInteger(message, offset + len - 4, 4);

        if (messageType != 1) {
            throw log.mechMessageTypeMustEqual(getMechanismName(), 1, messageType).toSaslException();
        }

        if (extractedSeqNum != unwrapSeqNum) {
            throw log.mechBadSequenceNumberWhileUnwrapping(getMechanismName(), unwrapSeqNum, extractedSeqNum).toSaslException();
        }

        byte[] clearText = null;
        try {
            clearText = unwrapCipher.update(message, offset, len - 6);
        } catch (Exception e) {
            throw log.mechProblemDuringDecrypt(getMechanismName(), e).toSaslException();
        }
        if (clearText == null){
            throw log.mechProblemDuringDecryptResultIsNull(getMechanismName()).toSaslException();
        }

        byte[] hmac = new byte[10];
        System.arraycopy(clearText, clearText.length - 10, hmac, 0, 10);

        byte[] decryptedMessage = null;
        // strip potential padding
        if (unwrapCipher.getBlockSize() > 0) {
            int padSize = clearText[clearText.length - 10 - 1];
            int decryptedMessageSize = clearText.length - 10;
            if (padSize < 8) {
                int i = clearText.length - 10 - 1;
                while (clearText[i] == padSize) {
                    i--;
                }
                decryptedMessageSize = i + 1;
            }
            decryptedMessage = new byte[decryptedMessageSize];
            System.arraycopy(clearText, 0, decryptedMessage, 0, decryptedMessageSize);
        } else {
            decryptedMessage = new byte[clearText.length - 10];
            System.arraycopy(clearText, 0, decryptedMessage, 0, clearText.length - 10);
        }

        byte[] expectedHmac = computeHMAC(unwrapHmacKeyIntegrity, extractedSeqNum, hmacMD5, decryptedMessage, 0, decryptedMessage.length);

        // check hmac-s
        if (Arrays2.equals(expectedHmac, 0, hmac, 0, 10) == false) {
            return NO_BYTES;
        }

        unwrapSeqNum++; // increment only if MAC is valid
        return decryptedMessage;
    }

    protected void createCiphersAndKeys() throws SaslException {

        wrapHmacKeyIntegrity = createIntegrityKey(true);
        unwrapHmacKeyIntegrity = createIntegrityKey(false);

        if (cipher == null || cipher.length() == 0) {
            return;
        }

        wrapCipher = createCipher(true);
        unwrapCipher = createCipher(false);
    }

    protected byte[] createIntegrityKey(boolean wrap){
        ByteStringBuilder key = new ByteStringBuilder(hA1);
        if (wrap) {
            key.append(format == FORMAT.CLIENT ? CLIENT_MAGIC_INTEGRITY : SERVER_MAGIC_INTEGRITY);
        } else {
            key.append(format == FORMAT.CLIENT ? SERVER_MAGIC_INTEGRITY : CLIENT_MAGIC_INTEGRITY);
        }
        digest.reset();
        return digest.digest(key.toArray());
    }

    private static final String CLIENT_MAGIC_CONFIDENTIALITY = "Digest H(A1) to client-to-server sealing key magic constant";
    private static final String SERVER_MAGIC_CONFIDENTIALITY = "Digest H(A1) to server-to-client sealing key magic constant";

    protected Cipher createCipher(boolean wrap) throws SaslException {

        int n = gethA1PrefixLength(cipher);

        ByteStringBuilder key = new ByteStringBuilder();
        key.append(hA1, 0, n);

        byte[] hmacKey;

        if (wrap) {
            key.append(format == FORMAT.CLIENT ? CLIENT_MAGIC_CONFIDENTIALITY : SERVER_MAGIC_CONFIDENTIALITY);
            hmacKey = digest.digest(key.toArray());
        } else {
            key.append(format == FORMAT.CLIENT ? SERVER_MAGIC_CONFIDENTIALITY : CLIENT_MAGIC_CONFIDENTIALITY);
            hmacKey = digest.digest(key.toArray());
        }

        TransformationMapper trans = new DefaultTransformationMapper();
        Cipher ciph;
        byte[] cipherKeyBytes;
        byte[] IV = null; // Initial Vector
        SecretKey cipherKey;

        try {
            TransformationSpec transformationSpec = trans.getTransformationSpec(SaslMechanismInformation.Names.DIGEST_MD5, cipher);
            if (transformationSpec == null ) {
                throw log.mechUnknownCipher(getMechanismName(), cipher).toSaslException();
            }
            ciph = Cipher.getInstance(transformationSpec.getTransformation());
            int slash = ciph.getAlgorithm().indexOf('/');
            String alg = (slash > -1 ? ciph.getAlgorithm().substring(0, slash) : ciph.getAlgorithm());

            if (cipher.startsWith("rc")) {
                cipherKeyBytes = hmacKey.clone();
                cipherKey = new SecretKeySpec(cipherKeyBytes, alg);
            } else if (cipher.equals("des")) {
                cipherKeyBytes = Arrays.copyOf(hmacKey, 7); // first 7 bytes
                IV = Arrays.copyOfRange(hmacKey, 8, 16); // last 8 bytes
                cipherKey = createDesSecretKey(cipherKeyBytes);
            } else if (cipher.equals("3des")) {
                cipherKeyBytes = Arrays.copyOf(hmacKey, 14); // first 14 bytes
                IV = Arrays.copyOfRange(hmacKey, 8, 16); // last 8 bytes
                cipherKey = create3desSecretKey(cipherKeyBytes);
            } else {
                throw log.mechUnknownCipher(getMechanismName(), cipher).toSaslException();
            }

            if (IV != null) {
                ciph.init((wrap ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE), cipherKey, new IvParameterSpec(IV), secureRandomGenerator);
            } else {
                ciph.init((wrap ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE), cipherKey, secureRandomGenerator);
            }
        } catch (Exception e) {
            throw log.mechProblemGettingRequiredCipher(getMechanismName(), e).toSaslException();
        }

        return ciph;
    }

    private int gethA1PrefixLength(String cipher) {
        if (cipher.equals("rc4-40")) {
            return 5;
        } else if (cipher.equals("rc4-56")) {
            return 7;
        } else {
            return 16;
        }
    }

    private Mac getHmac() throws SaslException {
        try {
          return Mac.getInstance(HMAC_algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw log.mechMacAlgorithmNotSupported(getMechanismName(), e).toSaslException();
        }
    }

    protected byte[] getPredigestedSaltedPassword(RealmCallback realmCallback, NameCallback nameCallback) throws SaslException {
        final String realmName = realmCallback.getDefaultText();
        final String userName = nameCallback.getDefaultName();
        final DigestPasswordAlgorithmSpec parameterSpec;
        if (realmName != null && userName != null) {
            parameterSpec = new DigestPasswordAlgorithmSpec(userName, realmName);
        } else {
            parameterSpec = null;
        }
        CredentialCallback credentialCallback = new CredentialCallback(PasswordCredential.class, passwordAlgorithm(getMechanismName()), parameterSpec);
        try {
            tryHandleCallbacks(realmCallback, nameCallback, credentialCallback);
            return credentialCallback.applyToCredential(PasswordCredential.class, c -> c.getPassword().castAndApply(DigestPassword.class, DigestPassword::getDigest));
        } catch (UnsupportedCallbackException e) {
            if (e.getCallback() == credentialCallback) {
                return null;
            } else if (e.getCallback() == nameCallback) {
                throw log.mechCallbackHandlerDoesNotSupportUserName(getMechanismName(), e).toSaslException();
            } else {
                throw log.mechCallbackHandlerFailedForUnknownReason(getMechanismName(), e).toSaslException();
            }
        }
    }

    protected byte[] getSaltedPasswordFromTwoWay(RealmCallback realmCallback, NameCallback nameCallback, boolean readOnlyRealmUsername) throws SaslException {
        CredentialCallback credentialCallback = new CredentialCallback(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR);
        try {
            tryHandleCallbacks(realmCallback, nameCallback, credentialCallback);
        } catch (UnsupportedCallbackException e) {
            if (e.getCallback() == credentialCallback) {
                return null;
            } else if (e.getCallback() == nameCallback) {
                throw log.mechCallbackHandlerDoesNotSupportUserName(getMechanismName(), e).toSaslException();
            } else {
                throw log.mechCallbackHandlerFailedForUnknownReason(getMechanismName(), e).toSaslException();
            }
        }
        TwoWayPassword password = credentialCallback.applyToCredential(PasswordCredential.class, c -> c.getPassword().castAs(TwoWayPassword.class));
        char[] passwordChars;
        try {
            passwordChars = getTwoWayPasswordChars(getMechanismName(), password, providers);
        } catch (AuthenticationMechanismException e) {
            throw e.toSaslException();
        }
        try {
            password.destroy();
        } catch(DestroyFailedException e) {
            log.credentialDestroyingFailed(e);
        }
        String realm = readOnlyRealmUsername ? realmCallback.getDefaultText() : realmCallback.getText();
        String username = readOnlyRealmUsername ? nameCallback.getDefaultName() : nameCallback.getName();
        byte[] digest_urp = userRealmPasswordDigest(messageDigest, username, realm, passwordChars);
        Arrays.fill(passwordChars, (char)0); // wipe out the password
        return digest_urp;
    }

    protected byte[] getSaltedPasswordFromPasswordCallback(RealmCallback realmCallback, NameCallback nameCallback, boolean readOnlyRealmUsername) throws SaslException {
        PasswordCallback passwordCallback = new PasswordCallback("User password", false);
        try {
            tryHandleCallbacks(realmCallback, nameCallback, passwordCallback);
        } catch (UnsupportedCallbackException e) {
            if (e.getCallback() == passwordCallback) {
                return null;
            } else if (e.getCallback() == nameCallback) {
                throw log.mechCallbackHandlerDoesNotSupportUserName(getMechanismName(), e).toSaslException();
            } else {
                throw log.mechCallbackHandlerFailedForUnknownReason(getMechanismName(), e).toSaslException();
            }
        }
        char[] passwordChars = passwordCallback.getPassword();
        passwordCallback.clearPassword();
        if (passwordChars == null) {
            throw log.mechNoPasswordGiven(getMechanismName()).toSaslException();
        }
        if ( ! readOnlyRealmUsername && nameCallback.getName() == null) {
            throw log.mechNotProvidedUserName(getMechanismName()).toSaslException();
        }
        String realm = readOnlyRealmUsername ? realmCallback.getDefaultText() : realmCallback.getText();
        String username = readOnlyRealmUsername ? nameCallback.getDefaultName() : nameCallback.getName();
        byte[] digest_urp = userRealmPasswordDigest(messageDigest, username, realm, passwordChars);
        Arrays.fill(passwordChars, (char)0); // wipe out the password
        return digest_urp;
    }

    private String passwordAlgorithm(final String mechanismName) {
        switch (mechanismName) {
            case SaslMechanismInformation.Names.DIGEST_SHA:     return DigestPassword.ALGORITHM_DIGEST_SHA;
            case SaslMechanismInformation.Names.DIGEST_SHA_256: return DigestPassword.ALGORITHM_DIGEST_SHA_256;
            case SaslMechanismInformation.Names.DIGEST_SHA_384: return DigestPassword.ALGORITHM_DIGEST_SHA_384;
            case SaslMechanismInformation.Names.DIGEST_SHA_512: return DigestPassword.ALGORITHM_DIGEST_SHA_512;
            case SaslMechanismInformation.Names.DIGEST_MD5:     return DigestPassword.ALGORITHM_DIGEST_MD5;
            default: throw Assert.impossibleSwitchCase(mechanismName);
        }
    }

}
