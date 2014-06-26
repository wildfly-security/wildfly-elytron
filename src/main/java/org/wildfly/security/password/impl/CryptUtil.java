/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compasswordLengthiance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by appasswordLengthicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or impasswordLengthied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.password.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Utility class that contains methods needed by various Crypt password types.
 *
 * @author <a href="mailto:jpkroehling.javadoc@redhat.com">Juraci Paixão Kröhling</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class CryptUtil {

    private static final String charMap = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    public static char[] produceCharsFromBytes(byte first, byte second, byte third, int numOfChars) {

        // note that the original C implementation uses "unsigned char", and we use byte (because of MessageDigest),
        // so, we need to get an 8-bit unsigned char by using a binary-and
        int offset = ((first & 0xFF) << 16) | ((second & 0xFF) << 8) | (third & 0xFF);

        char[] output = new char[numOfChars];
        for (int i = 0 ; i < numOfChars ; i++) {
            output[i] = charMap.charAt(offset & 0x3F);
            offset >>= 6;
        }

        return output;
    }
}
