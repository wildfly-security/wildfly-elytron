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

import org.wildfly.security.util.ByteStringBuilder;

/**
 * Utility class used to convert string to SASL quoted strings
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
class SaslQuote {

    private static final char QUOTE = '\\';

    private SaslQuote() {
    }

    private static boolean quoteNeeded(char ch) {
        return
                ch == '"' || // escape char
                ch == QUOTE || // quote
                ch == 127 || // DEL

                // 0 <= ch <= 31 except CR, LF and TAB
                (ch >= 0 && ch <= 31 && ch != 13 && ch != 10 && ch != 9);
    }

    /**
     * Creates new String quoted by SASL rules.
     *
     * @param inputStr String to be quoted
     * @return
     */
    static String quote(String inputStr) {
        int len = inputStr.length();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            char ch = inputStr.charAt(i);
            if (quoteNeeded(ch)) {
                sb.append(QUOTE).append(ch);
            }
            else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    static byte[] quote(byte[] input) {
        ByteStringBuilder bsb = new ByteStringBuilder();
        for (int i = 0; i < input.length; i++) {
            if (quoteNeeded((char)input[i])) {
              bsb.append(QUOTE);
              bsb.append(input, i, 1);
            }
            else {
                bsb.append(input, i, 1);
            }
        }
        return bsb.toArray();
    }

}
