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

import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.sasl.digest.Digest;
import org.wildfly.security.sasl.util.HexConverter;
import org.wildfly.security.util.ByteStringBuilder;

import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
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
            case Digest.DIGEST_MD5: return DigestPassword.ALGORITHM_DIGEST_MD5;
            case Digest.DIGEST_SHA: return DigestPassword.ALGORITHM_DIGEST_SHA;
            case Digest.DIGEST_SHA_256: return DigestPassword.ALGORITHM_DIGEST_SHA_256;
            case Digest.DIGEST_SHA_512: return DigestPassword.ALGORITHM_DIGEST_SHA_512;
            default: return null;
        }
    }

    public static String messageDigestAlgorithm(String digestAlgorithm) {
        switch (digestAlgorithm) {
            case Digest.DIGEST_MD5: return "MD5";
            case Digest.DIGEST_SHA: return "SHA";
            case Digest.DIGEST_SHA_256: return "SHA-256";
            case Digest.DIGEST_SHA_512: return "SHA-512";
            default: return null;
        }
    }

    /**
     * Calculates H(A1).
     *
     *
     * @param messageDigest
     * @param username
     * @param realm
     * @param password
     * @param nonce
     * @param cnonce
     * @param authzid
     * @param responseCharset
     * @return
     */
    public static byte[] H_A1(MessageDigest messageDigest, String username, String realm, char[] password,
                       byte[] nonce, byte[] cnonce, String authzid, Charset responseCharset) {

        CharsetEncoder latin1Encoder = StandardCharsets.ISO_8859_1.newEncoder();
        latin1Encoder.reset();
        boolean bothLatin1 = latin1Encoder.canEncode(username);
        latin1Encoder.reset();
        if (bothLatin1) {
            for (char c: password) {
                bothLatin1 = bothLatin1 && latin1Encoder.canEncode(c);
            }
        }

        ByteStringBuilder urp = new ByteStringBuilder(); // username:realm:password
        urp.append(username.getBytes((bothLatin1 ? StandardCharsets.ISO_8859_1 : responseCharset)));
        urp.append(':');
        if (realm != null) {
            urp.append(realm.getBytes((bothLatin1 ? StandardCharsets.ISO_8859_1 : responseCharset)));
        } else {
            urp.append("");
        }
        urp.append(':');
        urp.append(new String(password).getBytes((bothLatin1 ? StandardCharsets.ISO_8859_1 : responseCharset)));

        byte[] digest_urp = messageDigest.digest(urp.toArray());

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
                                 String authzid, String qop, String digest_uri) {

        // QOP
        String qop_value;
        if (qop != null && ! "".equals(qop)) {
            qop_value = qop;
        } else {
            qop_value = QOP_AUTH;
        }

        // A2
        ByteStringBuilder A2 = new ByteStringBuilder();
        A2.append(AUTH_METHOD);
        A2.append(':');
        A2.append(digest_uri);
        if (QOP_AUTH_CONF.equals(qop_value) || QOP_AUTH_INT.equals(qop_value)) {
            A2.append(':');
            A2.append(SECURITY_MARK);
        }

        byte[] digest_A2 = messageDigest.digest(A2.toArray());

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

        KD.updateDigest(messageDigest);
        return HexConverter.convertToHexBytes(messageDigest.digest());
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
        byte[] hex = Integer.valueOf(String.valueOf(input), 16).toString().getBytes(StandardCharsets.UTF_8);
        if (hex.length > totalLength) {
            throw new IllegalArgumentException("totalLength ("+totalLength+") is less than length of conversion result.");
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
            throw new SaslException("Invalid key provided", e);
        }
        byte[] buffer = new byte[len + 4];
        integerByteOrdered(sequenceNumber, buffer, 0, 4);
        System.arraycopy(message, offset, buffer, 4, len);
        return mac.doFinal(buffer);
    }

    public static void integerByteOrdered(int num, byte[] buf, int offset, int len) {
        if (len > 4 || len < 1) {
            throw new IllegalArgumentException("integerByteOrdered can handle up to 4 bytes");
        }
        for (int i = len - 1; i >= 0; i--) {
            buf[offset + i] = (byte) (num & 0xff);
            num >>>= 8;
        }
    }

    public static int decodeByteOrderedInteger(byte[] buf, int offset, int len) {
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

    static byte[] create3desSubKey(byte[] keyBits, int offset, int len) {
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
    public static SecretKey createDesSecretKey(byte[] keyBits, int offset, int len) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
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
    public static SecretKey create3desSecretKey(byte[] keyBits, int offset, int len) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
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
    private static byte fixParityBit(byte toFix) {
        return (Integer.bitCount(toFix & 0xff) & 1) == 0 ? (byte) (toFix ^ 1) : toFix;
    }

}
