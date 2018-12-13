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
package org.wildfly.security.sasl.digest._private;

import static org.wildfly.security.mechanism._private.ElytronMessages.saslDigest;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslException;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>.
 */
public final class DigestUtil {

    public static final String QOP_AUTH = "auth";
    public static final String QOP_AUTH_INT = "auth-int";
    public static final String QOP_AUTH_CONF = "auth-conf";
    public static final String[] QOP_VALUES = {QOP_AUTH, QOP_AUTH_INT, QOP_AUTH_CONF};

    public static final String AUTH_METHOD = "AUTHENTICATE";
    public static final String SECURITY_MARK = "00000000000000000000000000000000";   // 32 zeros

    public static final String HASH_algorithm = "MD5";
    public static final String HMAC_algorithm = "HmacMD5";

    public static String passwordAlgorithm(String digestAlgorithm) {
        switch (digestAlgorithm) {
            case SaslMechanismInformation.Names.DIGEST_MD5: return DigestPassword.ALGORITHM_DIGEST_MD5;
            case SaslMechanismInformation.Names.DIGEST_SHA: return DigestPassword.ALGORITHM_DIGEST_SHA;
            case SaslMechanismInformation.Names.DIGEST_SHA_256: return DigestPassword.ALGORITHM_DIGEST_SHA_256;
            case SaslMechanismInformation.Names.DIGEST_SHA_384: return DigestPassword.ALGORITHM_DIGEST_SHA_384;
            case SaslMechanismInformation.Names.DIGEST_SHA_512: return DigestPassword.ALGORITHM_DIGEST_SHA_512;
            case SaslMechanismInformation.Names.DIGEST_SHA_512_256: return DigestPassword.ALGORITHM_DIGEST_SHA_512_256;
            default: return null;
        }
    }

    public static String messageDigestAlgorithm(String digestAlgorithm) {
        switch (digestAlgorithm) {
            case SaslMechanismInformation.Names.DIGEST_MD5: return "MD5";
            case SaslMechanismInformation.Names.DIGEST_SHA: return "SHA";
            case SaslMechanismInformation.Names.DIGEST_SHA_256: return "SHA-256";
            case SaslMechanismInformation.Names.DIGEST_SHA_384: return "SHA-384";
            case SaslMechanismInformation.Names.DIGEST_SHA_512: return "SHA-512";
            case SaslMechanismInformation.Names.DIGEST_SHA_512_256: return "SHA-512-256";
            default: return null;
        }
    }

    /**
     * Calculates H(A1).
     *
     *
     * @param messageDigest
     * @param digest_urp
     * @param nonce
     * @param cnonce
     * @param authzid
     * @param responseCharset
     * @return
     */
    public static byte[] H_A1(MessageDigest messageDigest, byte[] digest_urp,
                       byte[] nonce, byte[] cnonce, String authzid, Charset responseCharset) {
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
        return messageDigest.digest(A1.toArray());
    }

    /**
     * Method to produce digest-response:
     * response-value  =
     *    HEX( KD ( HEX(H(A1)),
     *             { nonce-value, ":" nc-value, ":",
     *               cnonce-value, ":", qop-value, ":", HEX(H(A2)) }))
     *
     */
    public static byte[] digestResponse(MessageDigest messageDigest, byte[] H_A1,
                                 byte[] nonce, int nonce_count, byte[] cnonce,
                                 String authzid, String qop, String digest_uri, boolean auth) {

        // QOP
        String qop_value;
        if (qop != null && ! "".equals(qop)) {
            qop_value = qop;
        } else {
            qop_value = QOP_AUTH;
        }

        // A2
        ByteStringBuilder A2 = new ByteStringBuilder();
        if(auth) A2.append(AUTH_METHOD); // for "response", but not for "rspauth"
        A2.append(':');
        A2.append(digest_uri);
        if (QOP_AUTH_CONF.equals(qop_value) || QOP_AUTH_INT.equals(qop_value)) {
            A2.append(':');
            A2.append(SECURITY_MARK);
        }

        byte[] digest_A2 = messageDigest.digest(A2.toArray());

        ByteStringBuilder KD = new ByteStringBuilder();
        KD.append(ByteIterator.ofBytes(H_A1).hexEncode().drainToString().getBytes(StandardCharsets.US_ASCII));
        KD.append(':');
        KD.append(nonce);
        KD.append(':');
        KD.append(convertToHexBytesWithLeftPadding(nonce_count, 8));
        KD.append(':');
        KD.append(cnonce);
        KD.append(':');
        KD.append(qop_value);
        KD.append(':');
        KD.append(ByteIterator.ofBytes(digest_A2).hexEncode().drainToString().getBytes(StandardCharsets.US_ASCII));

        KD.updateDigest(messageDigest);
        return ByteIterator.ofBytes(messageDigest.digest()).hexEncode().drainToString().getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Converts input to HEX and pad it from left with zeros to totalLength.
     *
     * @param input to be converted to HEX
     * @param totalLength length of returned array of bytes
     * @return
     */
    public static byte[] convertToHexBytesWithLeftPadding(int input, int totalLength) {
        byte[] retValue = new byte[totalLength];
        Arrays.fill(retValue, (byte) '0');
        byte[] hex = Integer.toString(input, 16).getBytes(StandardCharsets.UTF_8);
        if (hex.length > totalLength) {
            throw saslDigest.requiredNegativePadding(totalLength, hex.length);
        }

        int from = totalLength - hex.length;
        for (int i = 0; i < hex.length; i++) {
            retValue[from + i] = hex[i];
        }
        return retValue;
    }

    public static byte[] computeHMAC(byte[] kc, int sequenceNumber, Mac mac, byte[] message, int offset, int len) throws SaslException {
        SecretKeySpec ks = new SecretKeySpec(kc, HMAC_algorithm);
        try {
            mac.init(ks);
        } catch (InvalidKeyException e) {
            throw saslDigest.mechInvalidKeyForDigestHMAC().toSaslException();
        }
        byte[] buffer = new byte[len + 4];
        integerByteOrdered(sequenceNumber, buffer, 0, 4);
        System.arraycopy(message, offset, buffer, 4, len);
        byte[] macBuffer = new byte[10];
        System.arraycopy(mac.doFinal(buffer), 0, macBuffer, 0, 10);
        return macBuffer;
    }

    public static void integerByteOrdered(int num, byte[] buf, int offset, int len) {
        assert len >= 1 && len <= 4;

        for (int i = len - 1; i >= 0; i--) {
            buf[offset + i] = (byte) (num & 0xff);
            num >>>= 8;
        }
    }

    public static int decodeByteOrderedInteger(byte[] buf, int offset, int len) {
        assert len >= 1 && len <= 4;

        int result = buf[offset];
        for (int i = 1; i < len; i++) {
            result <<= 8;
            result |= (buf[offset + i] & 0xff);
        }
        return result;
    }

    static byte[] create3desSubKey(byte[] keyBits, int offset) {
        assert keyBits.length >= offset + 7;

        byte[] subkey = new byte[8];
        subkey[0] = fixParityBit((byte)                          (keyBits[offset]   & 0xFF));
        subkey[1] = fixParityBit((byte)(keyBits[offset]   << 7 | (keyBits[offset+1] & 0xFF) >> 1));
        subkey[2] = fixParityBit((byte)(keyBits[offset+1] << 6 | (keyBits[offset+2] & 0xFF) >> 2));
        subkey[3] = fixParityBit((byte)(keyBits[offset+2] << 5 | (keyBits[offset+3] & 0xFF) >> 3));
        subkey[4] = fixParityBit((byte)(keyBits[offset+3] << 4 | (keyBits[offset+4] & 0xFF) >> 4));
        subkey[5] = fixParityBit((byte)(keyBits[offset+4] << 3 | (keyBits[offset+5] & 0xFF) >> 5));
        subkey[6] = fixParityBit((byte)(keyBits[offset+5] << 2 | (keyBits[offset+6] & 0xFF) >> 6));
        subkey[7] = fixParityBit((byte)(keyBits[offset+6] << 1));
        return subkey;
    }

    /**
     * Create DES secret key according to http://www.cryptosys.net/3des.html.
     *
     * @param keyBits
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public static SecretKey createDesSecretKey(byte[] keyBits) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        assert keyBits.length >= 7;

        KeySpec spec = new DESKeySpec(create3desSubKey(keyBits, 0), 0);
        SecretKeyFactory desFact = SecretKeyFactory.getInstance("DES");

        return desFact.generateSecret(spec);
    }

    /**
     * Create 3des secret key according to http://www.cryptosys.net/3des.html.
     *
     * @param keyBits
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public static SecretKey create3desSecretKey(byte[] keyBits) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        assert keyBits.length >= 14;

        byte[] key = new byte[24];
        System.arraycopy(create3desSubKey(keyBits, 0), 0, key, 0, 8);   // subkey1
        System.arraycopy(create3desSubKey(keyBits, 7), 0, key, 8, 8);   // subkey2
        System.arraycopy(key, 0, key, 16, 8);                           // subkey3 == subkey1 (in option2 of 3des key)

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
    private static byte fixParityBit(byte toFix) {
        return (Integer.bitCount(toFix & 0xff) & 1) == 0 ? (byte) (toFix ^ 1) : toFix;
    }

}
