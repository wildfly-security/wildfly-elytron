/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.mechanism.scram;

import static org.wildfly.security._private.ElytronMessages.log;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.wildfly.common.iteration.ByteIterator;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ScramUtil {
    private static final byte[] randomCharDictionary;

    static final byte[] CLIENT_KEY_BYTES = "Client Key".getBytes(StandardCharsets.UTF_8);
    static final byte[] SERVER_KEY_BYTES = "Server Key".getBytes(StandardCharsets.UTF_8);

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

    static void xor(final byte[] hash, final byte[] input) {
        assert hash.length == input.length;
        for (int i = 0; i < hash.length; i++) {
            hash[i] ^= input[i];
        }
    }
}
