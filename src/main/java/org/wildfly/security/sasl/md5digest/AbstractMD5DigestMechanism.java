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

package org.wildfly.security.sasl.md5digest;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.ByteStringBuilder;
import org.wildfly.security.sasl.util.Charsets;
import org.wildfly.security.sasl.util.HexConverter;
import org.wildfly.security.util.Base64;
import org.wildfly.security.sasl.util.SaslWrapper;
import org.wildfly.security.util.DefaultTransformationMapper;
import org.wildfly.security.util.TransformationMapper;
import org.wildfly.security.util.TransformationSpec;

/**
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
abstract class AbstractMD5DigestMechanism extends AbstractSaslParticipant {

    public static final String UTF8_PROPERTY = "com.sun.security.sasl.digest.utf8";
    public static final String QOP_PROPERTY = "javax.security.sasl.qop";
    public static final String REALM_PROPERTY = "com.sun.security.sasl.digest.realm";
    public static final String SUPPORTED_CIPHERS_PROPERTY = "org.jboss.security.sasl.digest.ciphers";

    public static enum FORMAT {CLIENT, SERVER};

    private static final int MAX_PARSED_RESPONSE_SIZE = 13;
    private static final String HASH_algorithm = "MD5";
    private static final String HMAC_algorithm = "HmacMD5";
    static String authMethod = "AUTHENTICATE";
    private static String SECURITY_MARK = "00000000000000000000000000000000";   // 32 zeros
    private static int NONCE_SIZE = 36;


    public static final String QOP_AUTH = "auth";
    public static final String QOP_AUTH_INT = "auth-int";
    public static final String QOP_AUTH_CONF = "auth-conf";
    public static final String[] QOP_VALUES = {QOP_AUTH, QOP_AUTH_INT, QOP_AUTH_CONF};

    public static final int DEFAULT_MAXBUF = 65536;
    public static final char DELIMITER = ',';
    public static final String[] CIPHER_OPTS = {"des", "3des", "rc4", "rc4-40", "rc4-56"};

    private FORMAT format;
    protected String digestURI;
    private Charset charset = Charsets.LATIN_1;
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

    /**
     * @param mechanismName
     * @param protocol
     * @param serverName
     * @param callbackHandler
     */
    public AbstractMD5DigestMechanism(String mechanismName, String protocol, String serverName, CallbackHandler callbackHandler, FORMAT format, Charset charset, String[] ciphers) throws SaslException {
        super(mechanismName, protocol, serverName, callbackHandler);

        try {
            this.md5 = MessageDigest.getInstance(HASH_algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new SaslException("Algorithm not supported", e);
        }

        this.format = format;
        this.digestURI = getProtocol() + "/" + getServerName();
        if (charset != null) {
            this.charset = charset;
        } else {
            this.charset = Charsets.LATIN_1;
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
        for (TransformationSpec ts: trans.getTransformationSpecByStrength(MD5DigestServerFactory.JBOSS_DIGEST_MD5, demandedCiphers)) {
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

        ByteStringBuilder nonceBase64 = new ByteStringBuilder();
        Base64.base64EncodeStandard(nonceBase64, new ByteArrayInputStream(nonceData), true);

        return nonceBase64.toArray();
    }

    /**
     * Converts input to HEX and pad it from left with zeros to totalLength.
     *
     * @param input to be converted to HEX
     * @param totalLength length of returned array of bytes
     * @return
     */
    static byte[] convertToHexBytesWithLeftPadding(int input, int totalLength) {
        byte[] retValue = new byte[totalLength];
        Arrays.fill(retValue, (byte) '0');
        byte[] hex = Integer.valueOf(String.valueOf(input), 16).toString().getBytes(Charsets.UTF_8);
        if (hex.length > totalLength) {
            throw new IllegalArgumentException("totalLength ("+totalLength+") is less than length of conversion result.");
        }

        int from = totalLength - hex.length;
        for (int i = 0; i < hex.length; i++) {
            retValue[from + i] = hex[i];
        }
        return retValue;
    }

    /**
     * Method to produce digest-response:
     * response-value  =
     *    HEX( KD ( HEX(H(A1)),
     *             { nonce-value, ":" nc-value, ":",
     *               cnonce-value, ":", qop-value, ":", HEX(H(A2)) }))
     *
     */
    static byte[] digestResponse(MessageDigest md5, byte[] H_A1,
            byte[] nonce, int nonce_count, byte[] cnonce,
            String authzid, String qop, String digest_uri, Charset responseCharset) {

       // byte[] H_A1 = H_A1(md5, username, realm, password, nonce, cnonce, authzid, responseCharset);

        // QOP
        String qop_value;
        if (qop != null && ! "".equals(qop)) {
            qop_value = qop;
        } else {
            qop_value = QOP_AUTH;
        }

        // A2
        ByteStringBuilder A2 = new ByteStringBuilder();
        A2.append(authMethod);
        A2.append(':');
        A2.append(digest_uri);
        if (QOP_AUTH_CONF.equals(qop_value) || QOP_AUTH_INT.equals(qop_value)) {
            A2.append(':');
            A2.append(SECURITY_MARK);
        }

        byte[] digest_A2 = md5.digest(A2.toArray());

        ByteStringBuilder KD = new ByteStringBuilder();
        KD.append(HexConverter.convertToHexBytes(H_A1));
        KD.append(':');
        KD.append(nonce);
        KD.append(':');
        KD.append(convertToHexBytesWithLeftPadding(nonce_count, 8));
        KD.append(':');
        KD.append(cnonce);
        KD.append(':');
        KD.append(qop_value);
        KD.append(':');
        KD.append(HexConverter.convertToHexBytes(digest_A2));

        KD.updateDigest(md5);
        return HexConverter.convertToHexBytes(md5.digest());
    }

    /**
     * Calculates H(A1).
     *
     * @param md5
     * @param username
     * @param realm
     * @param password
     * @param nonce
     * @param cnonce
     * @param authzid
     * @param responseCharset
     * @return
     */
    static byte[] H_A1(MessageDigest md5, String username, String realm, char[] password,
            byte[] nonce, byte[] cnonce, String authzid, Charset responseCharset) {

        CharsetEncoder latin1Encoder = Charsets.LATIN_1.newEncoder();
        latin1Encoder.reset();
        boolean bothLatin1 = latin1Encoder.canEncode(username);
        latin1Encoder.reset();
        if (bothLatin1) {
            for (char c: password) {
                bothLatin1 = bothLatin1 && latin1Encoder.canEncode(c);
            }
        }

        ByteStringBuilder urp = new ByteStringBuilder(); // username:realm:password
        urp.append(username.getBytes((bothLatin1 ? Charsets.LATIN_1 : responseCharset)));
        urp.append(':');
        if (realm != null) {
            urp.append(realm.getBytes((bothLatin1 ? Charsets.LATIN_1 : responseCharset)));
        } else {
            urp.append("");
        }
        urp.append(':');
        urp.append(new String(password).getBytes((bothLatin1 ? Charsets.LATIN_1 : responseCharset)));

        byte[] digest_urp = md5.digest(urp.toArray());

        // A1
        ByteStringBuilder A1 = new ByteStringBuilder();
        A1.append(digest_urp);
        A1.append(':');
        A1.append(nonce);
        A1.append(':');
        A1.append(cnonce);
        if (authzid != null) {
            A1.append(':');
            A1.append(authzid);
        }
        return md5.digest(A1.toArray());
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
                    if (key.length() != 0) {
                        throw new SaslException("DIGEST-MD5 keyword cannot contain ',' " + key.toString());
                    }
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

    protected class MD5DigestWrapper implements SaslWrapper {

        private boolean confidential;

        /**
         * @param confidential
         */
        protected MD5DigestWrapper(boolean confidential) {
            this.confidential = confidential;
        }

        /* (non-Javadoc)
         * @see org.wildfly.security.sasl.util.SaslWrapper#wrap(byte[], int, int)
         */
        @Override
        public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
            if (confidential) {
                return AbstractMD5DigestMechanism.this.wrapConfidentialityProtectedMessage(outgoing, offset, len);
            } else {
                return AbstractMD5DigestMechanism.this.wrapIntegrityProtectedMessage(outgoing, offset, len);
            }
        }

        /* (non-Javadoc)
         * @see org.wildfly.security.sasl.util.SaslWrapper#unwrap(byte[], int, int)
         */
        @Override
        public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
            if (confidential) {
                return AbstractMD5DigestMechanism.this.unwrapConfidentialityProtectedMessage(incoming, offset, len);
            } else {
                return AbstractMD5DigestMechanism.this.unwrapIntegrityProtectedMessage(incoming, offset, len);
            }
        }

    }

    private static final String CLIENT_MAGIC = "Digest session key to client-to-server signing key magic constant";
    private static final String SERVER_MAGIC = "Digest session key to server-to-client signing key magic constant";

    private byte[] wrapIntegrityProtectedMessage(byte[] message, int offset, int len) throws SaslException {

        ByteStringBuilder key = new ByteStringBuilder(hA1);
        if (format == FORMAT.CLIENT) {
            key.append(CLIENT_MAGIC);
        } else {
            key.append(SERVER_MAGIC);
        }
        byte[] ki = md5.digest(key.toArray());
        Mac mac = getHmac();
        SecretKeySpec ks = new SecretKeySpec(ki, HMAC_algorithm);
        try {
            mac.init(ks);
        } catch (InvalidKeyException e) {
            throw new SaslException("Invalid key provided", e);
        }
        byte[] buffer = new byte[len + 4];
        integerByteOrdered(seqNum, buffer, 0, 4);
        System.arraycopy(message, len, buffer, 4, len);
        byte[] messageMac = mac.doFinal(buffer);

        byte[] result = new byte[len + 16];
        System.arraycopy(message, offset, result, 0, len);
        System.arraycopy(messageMac, 0, result, len, 10);
        integerByteOrdered(1, result, len + 10, 2);  // 2-byte message type number in network byte order with value 1
        integerByteOrdered(seqNum, result, len + 12, 4); // 4-byte sequence number in network byte order
        seqNum++;
        return result;
    }

    private byte[] unwrapIntegrityProtectedMessage(byte[] message, int offset, int len) throws SaslException {

        ByteStringBuilder key = new ByteStringBuilder(hA1);
        if (format == FORMAT.CLIENT) {
            key.append(SERVER_MAGIC);
        } else {
            key.append(CLIENT_MAGIC);
        }
        byte[] ki = md5.digest(key.toArray());
        Mac mac = getHmac();
        SecretKeySpec ks = new SecretKeySpec(ki, HMAC_algorithm);
        try {
            mac.init(ks);
        } catch (InvalidKeyException e) {
            throw new SaslException("Invalid key provided", e);
        }

        byte[] extractedMessageMac = new byte[16];
        byte[] extractedMessage = new byte[len];
        System.arraycopy(message, offset, extractedMessage, 0, len);
        System.arraycopy(message, offset + len, extractedMessageMac, 0, 16);

        byte[] buffer = new byte[len + 4];
        System.arraycopy(extractedMessageMac, 12, buffer, 0, 4);  // locate seqNum in MAC
        System.arraycopy(extractedMessage, len, buffer, 4, len);
        byte[] messageMac = mac.doFinal(buffer);

        // validate MAC block
        if (Arrays.equals(messageMac, extractedMessageMac) == false) {
            throw new SaslException("Unwrapped MAC validation failed");
        }
        return extractedMessage;
    }

    private byte[] wrapConfidentialityProtectedMessage(byte[] message, int offset, int len) throws SaslException {
        // TODO: confidentiality support
        return null;
    }

    private byte[] unwrapConfidentialityProtectedMessage(byte[] message, int offset, int len) throws SaslException {
        // TODO: confidentiality support
        return null;
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

    protected static final void integerByteOrdered(int num, byte[] buf, int offset, int len) {
        if (len > 4) {
            throw new IllegalArgumentException("integerByteOrdered can handle up to 4 bytes");
        }
        for (int i = len - 1; i >= 0; i--) {
            buf[offset + i] = (byte) (num & 0xff);
            num >>>= 8;
        }
    }
}
