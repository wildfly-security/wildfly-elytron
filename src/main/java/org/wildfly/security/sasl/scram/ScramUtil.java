/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.sasl.scram;

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslException;

import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ScramUtil {
    private static final byte[] randomCharDictionary;

    static {
        byte[] dict = new byte[93];
        int i = 0;
        for (byte c = '!'; c < ','; c ++) {
            dict[i ++] = c;
        }
        for (byte c = ',' + 1; c < 127; c ++) {
            dict[i ++] = c;
        }
        assert i == dict.length;
        randomCharDictionary = dict;
    }

    public static byte[] generateNonce(int length, Random random) {
        final byte[] chars = new byte[length];
        for (int i = 0; i < length; i ++) {
            chars[i] = randomCharDictionary[random.nextInt(93)];
        }
        return chars;
    }

    public static byte[] generateSalt(int length, Random random){
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    public static int parsePosInt(final ByteIterator i) {
        int a, c;
        if (! i.hasNext()) {
            throw log.emptyNumber();
        }
        c = i.next();
        if (c >= '1' && c <= '9') {
            a = c - '0';
        } else {
            throw log.invalidNumericCharacter();
        }
        while (i.hasNext()) {
            c = i.next();
            if (c >= '0' && c <= '9') {
                a = (a << 3) + (a << 1) + (c - '0');
                if (a < 0) {
                    throw log.tooBigNumber();
                }
            } else {
                throw log.invalidNumericCharacter();
            }
        }
        return a;
    }

    public static byte[] calculateHi(Mac mac, char[] password, byte[] salt, int saltOffs, int saltLen, int iterationCount) throws InvalidKeyException {
        try {
            final ByteStringBuilder b = new ByteStringBuilder();
            StringPrep.encode(password, b, StringPrep.PROFILE_SASL_QUERY);
            mac.init(new SecretKeySpec(b.toArray(), mac.getAlgorithm()));
            mac.update(salt, saltOffs, saltLen);
            mac.update((byte) 0);
            mac.update((byte) 0);
            mac.update((byte) 0);
            mac.update((byte) 1);
            byte[] h = mac.doFinal();
            byte[] u = h;
            for (int i = 2; i <= iterationCount; i ++) {
                u = mac.doFinal(u);
                xor(h, u);
            }
            return h;
        } finally {
            mac.reset();
        }
    }

    static void xor(final byte[] hash, final byte[] input) {
        assert hash.length == input.length;
        for (int i = 0; i < hash.length; i++) {
            hash[i] ^= input[i];
        }
    }

    static char[] getTwoWayPasswordChars(String mechName, TwoWayPassword password) throws SaslException {
        if (password == null) {
            throw log.mechNoPasswordGiven(mechName).toSaslException();
        }
        try {
            PasswordFactory pf = PasswordFactory.getInstance(password.getAlgorithm());
            return pf.getKeySpec(password, ClearPasswordSpec.class).getEncodedPassword();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw log.mechCannotGetTwoWayPasswordChars(mechName, e).toSaslException();
        }
    }

    static int getIntProperty(final Map<String, ?> props, final String name, final int defVal) {
        final Object val = props.get(name);
        if (val == null) {
            return defVal;
        } else {
            return Integer.parseInt(val.toString());
        }
    }

    static SecureRandom getSecureRandom(final Map<String, ?> props) {
        final Object propVal = props.get(WildFlySasl.SECURE_RNG);
        final String rngName = propVal instanceof String ? (String) propVal : null;
        SecureRandom secureRandom = null;
        if (rngName != null) {
            try {
                secureRandom = SecureRandom.getInstance(rngName);
            } catch (NoSuchAlgorithmException ignored) {
            }
        }
        return secureRandom;
    }
}
