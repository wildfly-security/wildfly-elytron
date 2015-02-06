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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

import org.wildfly.security.sasl.digest._private.DigestUtil;
import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.ByteStringBuilder;
import org.wildfly.security.sasl.util.SaslWrapper;
import org.wildfly.security.util.ByteIterator;
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

    private static final int MAX_PARSED_RESPONSE_SIZE = 13;
    private static final String HMAC_algorithm = "HmacMD5";
    private static int NONCE_SIZE = 36;

    public static final int DEFAULT_MAXBUF = 65536;
    public static final char DELIMITER = ',';
    public static final String[] CIPHER_OPTS = {"des", "3des", "rc4", "rc4-40", "rc4-56"};

    private FORMAT format;
    protected String digestURI;
    private Charset charset = StandardCharsets.ISO_8859_1;
    protected MessageDigest md5;
    protected Mac hmacMD5;

    // selected cipher
    protected String cipher;
    // selected qop
    protected String qop;
    // wrap message sequence number
    protected int seqNum;
    // nonce
    protected byte[] nonce;
    // cnonce
    protected byte[] cnonce;
    // authz-id
    protected String authzid;
    // H(A1)
    protected byte[] hA1;

    protected SecureRandom secureRandomGenerator;

    protected Cipher wrapCipher = null;

    protected Cipher unwrapCipher = null;

    protected byte[] wrapHmacKeyIntegrity;
    protected byte[] unwrapHmacKeyIntegrity;

    protected byte[] wrapHmacKeyConfidentiality;
    protected byte[] unwrapHmacKeyConfidentiality;

    /**
     * @param mechanismName
     * @param protocol
     * @param serverName
     * @param callbackHandler
     */
    public AbstractDigestMechanism(String mechanismName, String protocol, String serverName, CallbackHandler callbackHandler, FORMAT format, Charset charset, String[] ciphers) throws SaslException {
        super(mechanismName, protocol, serverName, callbackHandler);

        secureRandomGenerator = new SecureRandom();

        try {
            this.md5 = MessageDigest.getInstance(DigestUtil.HASH_algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new SaslException("Algorithm not supported", e);
        }

        this.format = format;
        this.digestURI = getProtocol() + "/" + getServerName();
        if (charset != null) {
            this.charset = charset;
        } else {
            this.charset = StandardCharsets.ISO_8859_1;
        }
    }


    public static int skipWhiteSpace(byte[] buffer, int startPoint) {
        int i = startPoint;
        while (i < buffer.length && isWhiteSpace(buffer[i])) {
            i++;
        }
        return i;
    }

    public static boolean isWhiteSpace(byte b) {
        if (b == 13)   // CR
            return true;
        else if (b == 10) // LF
            return true;
        else if (b == 9) // TAB
            return true;
        else if (b == 32) // SPACE
            return true;
        else
            return false;
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
        for (TransformationSpec ts: trans.getTransformationSpecByStrength(Digest.DIGEST_MD5, demandedCiphers)) {
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

    /**
     * Client side method to parse challenge sent by server.
     *
     * @param challenge
     * @return
     */
    HashMap<String, byte[]> parseResponse(byte [] challenge) throws SaslException {

        HashMap<String, byte[]> response = new HashMap<String, byte[]> (MAX_PARSED_RESPONSE_SIZE);
        int i = skipWhiteSpace(challenge, 0);

        StringBuilder key = new StringBuilder(10);
        ByteStringBuilder value = new ByteStringBuilder();

        Integer realmNumber = new Integer(0);

        boolean insideKey = true;
        boolean insideQuotedValue = false;
        boolean expectSeparator = false;

        byte b;
        while (i < challenge.length) {
            b = challenge[i];
            // parsing keyword
            if (insideKey) {
                if (b == ',') {
                    throw new SaslException("DIGEST-MD5 keyword cannot contain ',' " + key.toString());
                }
                else if (b == '=') {
                    if (key.length() == 0) {
                        throw new SaslException("DIGEST-MD5 keyword cannot be empty");
                    }
                    insideKey = false;
                    i = skipWhiteSpace(challenge, i + 1);

                    if (i < challenge.length) {
                        if (challenge[i] == '"') {
                            insideQuotedValue = true;
                            ++i; // Skip quote
                        }
                    }
                    else {
                        throw new SaslException("No value found for keyword: " + key.toString());
                    }
                }
                else if (isWhiteSpace(b)) {
                    i = skipWhiteSpace(challenge, i + 1);

                    if (i < challenge.length) {
                        if (challenge[i] != '=') {
                            throw new SaslException("'=' expected after keyword: " + key.toString());
                        }
                    }
                    else {
                         throw new SaslException("'=' expected after keyword: " + key.toString());
                    }
                }
                else {
                    key.append((char)(b & 0xff));
                    i++;
                }
            }
            // parsing quoted value
            else if (insideQuotedValue) {
                if (b == '\\') {
                    i++; // skip the escape char
                    if (i < challenge.length) {
                        value.append(challenge[i]);
                        i++;
                    }
                    else {
                        throw new SaslException("Unmatched quote found for value: " + value.toString());
                    }
                }
                else if (b == '"') {
                    // closing quote
                    i++;
                    insideQuotedValue = false;
                    expectSeparator = true;
                }
                else {
                    value.append(b);
                    i++;
                }
            }
            // terminated value
            else if (isWhiteSpace(b) || b == ',') {
                realmNumber = addToParsedChallenge(response, key, value, realmNumber);
                key = new StringBuilder();
                value = new ByteStringBuilder();
                i = skipWhiteSpace(challenge, i);
                if (i < challenge.length && challenge[i] == ',') {
                    expectSeparator = false;
                    insideKey = true;
                    i++;
                }
            }
            // expect separator
            else if (expectSeparator) {
                String val = new String(value.toArray(), charset);
                throw new SaslException("Expecting comma or linear whitespace after quoted string: \"" + val + "\"");
            }
            else {
                value.append(b);
                i++;
            }
        }

        if (insideQuotedValue) {
            throw new SaslException("Unmatched quote found for value: " + value.toString());
        }

        if (key.length() > 0) {
            realmNumber = addToParsedChallenge(response, key, value, realmNumber);
        }

        return response;
    }

    private int addToParsedChallenge(HashMap<String, byte[]> response, StringBuilder keyBuilder, ByteStringBuilder valueBuilder, int realmNumber) {
        String k = keyBuilder.toString();
        byte[] v = valueBuilder.toArray();
        if (format == FORMAT.CLIENT && "realm".equals(k)) {
            response.put(k + ":" + String.valueOf(realmNumber), v);
            realmNumber++;
        }
        else {
            response.put(k, v);
        }
        return realmNumber;
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

        ByteStringBuilder key = new ByteStringBuilder(hA1);
        if (format == FORMAT.CLIENT) {
            key.append(CLIENT_MAGIC_INTEGRITY);
        } else {
            key.append(SERVER_MAGIC_INTEGRITY);
        }
        md5.reset();
        byte[] ki = md5.digest(key.toArray());

        byte[] messageMac = computeHMAC(ki, seqNum, message, offset, len);

        byte[] result = new byte[len + 16];
        System.arraycopy(message, offset, result, 0, len);
        System.arraycopy(messageMac, 0, result, len, 10);
        integerByteOrdered(1, result, len + 10, 2);  // 2-byte message type number in network byte order with value 1
        integerByteOrdered(seqNum, result, len + 12, 4); // 4-byte sequence number in network byte order
        seqNum++;
        return result;
    }

    private byte[] unwrapIntegrityProtectedMessage(byte[] message, int offset, int len) throws SaslException {

        int messageType = decodeByteOrderedInteger(message, offset + len - 6, 2);
        int extractedSeqNum = decodeByteOrderedInteger(message, offset + len - 4, 4);

        if (messageType != 1) {
            throw new SaslException("MessageType must equal to 1, but is different");
        }

        ByteStringBuilder key = new ByteStringBuilder(hA1);
        if (format == FORMAT.CLIENT) {
            key.append(SERVER_MAGIC_INTEGRITY);
        } else {
            key.append(CLIENT_MAGIC_INTEGRITY);
        }
        md5.reset();
        byte[] ki = md5.digest(key.toArray());

        byte[] extractedMessageMac = new byte[10];
        byte[] extractedMessage = new byte[len - 16];
        System.arraycopy(message, offset, extractedMessage, 0, len - 16);
        System.arraycopy(message, offset + len - 16, extractedMessageMac, 0, 10);

        byte[] expectedHmac = computeHMAC(ki, extractedSeqNum, extractedMessage, 0, extractedMessage.length);

        // validate MAC block
        if (Arrays2.equals(expectedHmac, 0, extractedMessageMac, 0, 10) == false) {
            throw new SaslException("MAC validation failed while unwrapping");
        }
        return extractedMessage;
    }

    private static final String CLIENT_MAGIC_CONFIDENTIALITY = "Digest H(A1) to client-to-server sealing key magic constant";
    private static final String SERVER_MAGIC_CONFIDENTIALITY = "Digest H(A1) to server-to-client sealing key magic constant";

    private byte[] wrapConfidentialityProtectedMessage(byte[] message, int offset, int len) throws SaslException {

        byte[] messageMac = computeHMAC(wrapHmacKeyConfidentiality, seqNum, message, offset, len);

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
            cipheredPart = wrapCipher.doFinal(toCipher);
        } catch (Exception e) {
            throw new SaslException("Problem during crypt.", e);
        }

        byte[] result = new byte[cipheredPart.length + 6];
        System.arraycopy(cipheredPart, 0, result, 0, cipheredPart.length);
        integerByteOrdered(1, result, cipheredPart.length, 2);  // 2-byte message type number in network byte order with value 1
        integerByteOrdered(seqNum, result, cipheredPart.length + 2, 4); // 4-byte sequence number in network byte order

        seqNum++;
        return result;
    }

    private byte[] computeHMAC(byte[] kc, int sequenceNumber, byte[] message, int offset, int len) throws SaslException {
        Mac mac = getHmac();
        SecretKeySpec ks = new SecretKeySpec(kc, HMAC_algorithm);
        try {
            mac.init(ks);
        } catch (InvalidKeyException e) {
            throw new SaslException("Invalid key provided", e);
        }
        byte[] buffer = new byte[len + 4];
        integerByteOrdered(sequenceNumber, buffer, 0, 4);
        System.arraycopy(message, offset, buffer, 4, len);
        return mac.doFinal(buffer);
    }

    private byte[] unwrapConfidentialityProtectedMessage(byte[] message, int offset, int len) throws SaslException {

        int messageType = decodeByteOrderedInteger(message, offset + len - 6, 2);
        int extractedSeqNum = decodeByteOrderedInteger(message, offset + len - 4, 4);

        if (messageType != 1) {
            throw new SaslException("MessageType must equal to 1, but is different");
        }

        byte[] clearText = null;
        try {
            clearText = unwrapCipher.doFinal(message, offset, len - 6);
        } catch (Exception e) {
            throw new SaslException("Problem during decrypt.", e);
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

        byte[] expectedHmac = computeHMAC(unwrapHmacKeyConfidentiality, extractedSeqNum, decryptedMessage, 0, decryptedMessage.length);

        // check hmac-s
        if (Arrays2.equals(expectedHmac, 0, hmac, 0, 10) == false) {
            throw new SaslException("MAC validation failed after decrypting the message");
        }

        return decryptedMessage;
    }

    protected void createCiphersAndKeys() throws SaslException {

        if (cipher == null || cipher.length() == 0) {
            return;
        }

        wrapCipher = createCipher(true);
        unwrapCipher = createCipher(false);
    }


    protected Cipher createCipher(boolean wrap) throws SaslException {

        int n = gethA1PrefixLength(cipher);

        ByteStringBuilder key = new ByteStringBuilder();
        key.append(hA1, 0, n);

        byte[] hmacKey;

        if (wrap) {
            if (format == FORMAT.CLIENT) {
                key.append(CLIENT_MAGIC_CONFIDENTIALITY);
                wrapHmacKeyConfidentiality = md5.digest(key.toArray());
                hmacKey = wrapHmacKeyConfidentiality;
            } else {
                key.append(SERVER_MAGIC_CONFIDENTIALITY);
                wrapHmacKeyConfidentiality = md5.digest(key.toArray());
                hmacKey = wrapHmacKeyConfidentiality;
            }
        } else {
            if (format == FORMAT.CLIENT) {
                key.append(SERVER_MAGIC_CONFIDENTIALITY);
                unwrapHmacKeyConfidentiality = md5.digest(key.toArray());
                hmacKey = unwrapHmacKeyConfidentiality;
            } else {
                key.append(CLIENT_MAGIC_CONFIDENTIALITY);
                unwrapHmacKeyConfidentiality = md5.digest(key.toArray());
                hmacKey = unwrapHmacKeyConfidentiality;
            }
        }


        byte[] cipherKeyBytes;
        byte[] IV = null;                             // Initial Vector
        if (cipher.startsWith("rc")) {
            cipherKeyBytes = hmacKey.clone();
        } else if (cipher.equals("des")) {
            cipherKeyBytes = Arrays.copyOf(hmacKey, 7);    // first 7 bytes
            IV = Arrays.copyOfRange(hmacKey, 8, 16);  // last 8 bytes
        } else if (cipher.equals("3des")) {
            cipherKeyBytes = Arrays.copyOf(hmacKey, 14);   // first 14 bytes
            IV = Arrays.copyOfRange(hmacKey, 8, 16);  // last 8 bytes
        } else {
            throw new SaslException("Unknown ciper (" + cipher + ")");
        }

        TransformationMapper trans = new DefaultTransformationMapper();
        Cipher ciph;
        SecretKey cipherKey;
        try {
            ciph = Cipher.getInstance(trans.getTransformationSpec(Digest.DIGEST_MD5, cipher).getTransformation());
            int slash = ciph.getAlgorithm().indexOf('/');
            String alg = (slash > -1 ? ciph.getAlgorithm().substring(0, slash) : ciph.getAlgorithm());

            if (cipher.startsWith("rc")) {
                cipherKey = new SecretKeySpec(cipherKeyBytes, alg);
            } else if (cipher.equals("des")) {
                cipherKey = createDesSecretKey(cipherKeyBytes, 0, cipherKeyBytes.length);
            } else if (cipher.equals("3des")) {
                //cipherKey = makeDesKeys(cipherKeyBytes, alg);
                cipherKey = create3desSecretKey(cipherKeyBytes, 0, cipherKeyBytes.length);
            } else {
                throw new SaslException("Unsupported cipher (" + cipher + ")");
            }

            if (IV != null) {
                ciph.init((wrap ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE), cipherKey, new IvParameterSpec(IV), secureRandomGenerator);
            } else {
                ciph.init((wrap ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE), cipherKey, secureRandomGenerator);
            }
        } catch (Exception e) {
            throw new SaslException("Problem getting required cipher. Check your transformation mapper settings.", e);
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
          if (hmacMD5 == null) {
              hmacMD5 = Mac.getInstance(HMAC_algorithm);
          }
          return hmacMD5;
        } catch (NoSuchAlgorithmException e) {
            throw new SaslException("", e);
        }
    }

    protected static void integerByteOrdered(int num, byte[] buf, int offset, int len) {
        if (len > 4 || len < 1) {
            throw new IllegalArgumentException("integerByteOrdered can handle up to 4 bytes");
        }
        for (int i = len - 1; i >= 0; i--) {
            buf[offset + i] = (byte) (num & 0xff);
            num >>>= 8;
        }
    }

    protected static int decodeByteOrderedInteger(byte[] buf, int offset, int len) {
        if (len > 4 || len < 1) {
            throw new IllegalArgumentException("integerByteOrdered can handle up to 4 bytes");
        }
        int result = buf[offset];
        for (int i = 1; i < len; i++) {
            result <<= 8;
            result |= buf[offset + i];
        }
        return result;
    }

    private byte[] create3desSubKey(byte[] keyBits, int offset, int len) {
        if (len != 7) {
            throw new InvalidParameterException("Only 7 byte long keyBits are transformable to 3des subkey");
        }
        int hiMask = 0x00;
        int loMask = 0xfe;
        byte[] subkey = new byte[8];

        subkey[0] = (byte)(keyBits[0] & loMask);
        subkey[0] = fixParityBit(subkey[0]);   // fix for real parity bit
        for (int i = offset + 1; i < len; i++) {
            int bitNumber = i - offset;
            hiMask |= 2 ^ (bitNumber - 1);
            loMask &= 2 ^ bitNumber;
            int hibits = keyBits[i - 1] & hiMask;
            hibits <<= 8 - i - 1;
            int lobits = keyBits[i] & loMask;
            lobits >>= i;
            subkey[i] = (byte) (hibits | lobits);
            subkey[i] = fixParityBit(subkey[i]);  // fix real parity bits
        }

        return subkey;
    }

    /**
     * Create DES secret key according to http://www.cryptosys.net/3des.html.
     *
     * @param keyBits
     * @param offset
     * @param len
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    private SecretKey createDesSecretKey(byte[] keyBits, int offset, int len) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        if (len != 7) {
            throw new InvalidParameterException("Only 7 bytes long keyBits are transformable to des key");
        }

        KeySpec spec = new DESKeySpec(create3desSubKey(keyBits, 0, 7), 0);
        SecretKeyFactory desFact = SecretKeyFactory.getInstance("DES");

        return desFact.generateSecret(spec);
    }

    /**
     * Create 3des secret key according to http://www.cryptosys.net/3des.html.
     *
     * @param keyBits
     * @param offset
     * @param len
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    private SecretKey create3desSecretKey(byte[] keyBits, int offset, int len) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        if (len != 14) {
            throw new InvalidParameterException("Only 14 bytes long keyBits are transformable to 3des key option2");
        }

        byte[] key = new byte[24];
        System.arraycopy(create3desSubKey(keyBits, 0, 7), 0, key, 0, 8);   // subkey1
        System.arraycopy(create3desSubKey(keyBits, 7, 7), 0, key, 8, 8);   // subkey2
        System.arraycopy(key, 0, key, 16, 8);                              // subkey3 == subkey1 (in option2 of 3des key

        KeySpec spec = new DESedeKeySpec(key, 0);
        SecretKeyFactory desFact = SecretKeyFactory.getInstance("DESede");

        return desFact.generateSecret(spec);
    }

    /**
     * Fix the rightmost bit to maintain odd parity for the whole byte.
     *
     * @param toFix - byte to fix
     * @return fixed byte with odd parity
     */
    private byte fixParityBit(byte toFix) {
        return (Integer.bitCount(toFix & 0xff) & 1) == 0 ? (byte) (toFix ^ 1) : toFix;
    }
}
