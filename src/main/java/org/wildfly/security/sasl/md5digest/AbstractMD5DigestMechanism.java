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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

import org.wildfly.security.sasl.util.AbstractSaslParticipant;
import org.wildfly.security.sasl.util.ByteStringBuilder;
import org.wildfly.security.sasl.util.Charsets;
import org.wildfly.security.sasl.util.HexConverter;
import org.wildfly.security.sasl.util.SaslBase64;

/**
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
abstract class AbstractMD5DigestMechanism extends AbstractSaslParticipant {

    public static enum FORMAT {CLIENT, SERVER};

    private static final int MAX_PARSED_RESPONSE_SIZE = 13;
    private static final String algorithm = "MD5";
    static String authMethod = "AUTHENTICATE";
    private static String SECURITY_MARK = "00000000000000000000000000000000";   // 32 zeros
    private static int NONCE_SIZE = 36;

    public static final int DEFAULT_MAXBUF = 65536;
    public static final char DELIMITER = ',';
    public static final String DEFAULT_QOP = "auth";
    public static final String[] CIPHER_OPTS = {"des", "3des", "rc4", "rc4-40", "rc4-56"};

    public static final String[] DEFAULT_CIPHER_NAMES = {
        "DESede/CBC/NoPadding",
        "RC4",
        "DES/CBC/NoPadding"
    };

    private FORMAT format;
    protected String digestURI;

    /**
     * @param mechanismName
     * @param protocol
     * @param serverName
     * @param callbackHandler
     */
    public AbstractMD5DigestMechanism(String mechanismName, String protocol, String serverName, CallbackHandler callbackHandler, FORMAT format) {
        super(mechanismName, protocol, serverName, callbackHandler);
        this.format = format;
        this.digestURI = getProtocol() + "/" + getServerName();
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

    static String getSupportedCiphers() {
        StringBuilder ciphers = new StringBuilder();
        // TODO: introduce system property to get list of ciphers to evaluate
        // for now stick with default
        for (String c : DEFAULT_CIPHER_NAMES) {
            try {
                Cipher.getInstance(c);
                if (ciphers.length() > 0) {
                    ciphers.append(DELIMITER);
                }
                ciphers.append(c);
            } catch (NoSuchAlgorithmException e) {
                // no impl found
            } catch (NoSuchPaddingException e) {
                // no impl found
            }
        }

        return ciphers.toString();
    }

    static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonceData = new byte[NONCE_SIZE];
        random.nextBytes(nonceData);

        ByteStringBuilder nonceBase64 = new ByteStringBuilder();
        SaslBase64.encode(nonceData, nonceBase64);

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
     * @param username
     * @param realm
     * @param password
     * @param nonce
     * @param nonce_count
     * @param cnonce
     * @param authzid
     * @param qop
     * @param digest_uri
     * @return
     * @throws NoSuchAlgorithmException
     */
    byte[] digestResponse(String username, String realm, char[] password,
            byte[] nonce, int nonce_count, byte[] cnonce,
            String authzid, String qop, String digest_uri) throws NoSuchAlgorithmException {

        MessageDigest md5 = MessageDigest.getInstance(algorithm);

        ByteStringBuilder urp = new ByteStringBuilder(); // username:realm:password
        urp.append(username);
        urp.append(':');
        urp.append(realm != null ? realm : "");
        urp.append(':');
        urp.append(new String(password));

        byte[] digest_urp = md5.digest(urp.toArray());
        md5.reset();

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
        byte[] digest_A1 = md5.digest(A1.toArray());
        md5.reset();

        // QOP
        String qop_value;
        if (qop != null && ! "".equals(qop)) {
            qop_value = qop;
        } else {
            qop_value = DEFAULT_QOP;
        }

        // A2
        ByteStringBuilder A2 = new ByteStringBuilder();
        A2.append(authMethod);
        A2.append(':');
        A2.append(digest_uri);
        if ("auth-conf".equals(qop_value) || "auth-int".equals(qop_value)) {
            A2.append(':');
            A2.append(SECURITY_MARK);
        }

        byte[] digest_A2 = md5.digest(A2.toArray());
        md5.reset();

        ByteStringBuilder KD = new ByteStringBuilder();
        KD.append(HexConverter.convertToHexBytes(digest_A1));
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
                    key.append((char)b);
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
                String val = new String(value.toArray());
                throw new SaslException("Expecting comma or linear whitespace after quoted string: \"" + val + "\"");
            }
            else {
                value.append((char)b);
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
}
