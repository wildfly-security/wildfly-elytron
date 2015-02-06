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

package org.wildfly.security.sasl.util;

import java.text.Normalizer;

import org.wildfly.security.util.ByteStringBuilder;

/**
 * Preparation of Internationalized Strings ("stringprep") by RFC 3454
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public final class StringPrep {
    // these flags must keep their numeric values permanently, and must not conflict

    // mappings

    public static final long MAP_TO_NOTHING             = 1L << 0;
    public static final long MAP_TO_SPACE               = 1L << 1;
    // XXX case folding would go here

    public static final long MAP_SCRAM_LOGIN_CHARS      = 1L << 30;

    // normalizations

    public static final long NORMALIZE_KC               = 1L << 2;

    // prohibitions

    public static final long FORBID_NON_ASCII_SPACES                = 1L << 3;
    public static final long FORBID_ASCII_CONTROL                   = 1L << 4;
    public static final long FORBID_NON_ASCII_CONTROL               = 1L << 5;
    public static final long FORBID_PRIVATE_USE                     = 1L << 6;
    public static final long FORBID_NON_CHARACTER                   = 1L << 7;
    public static final long FORBID_SURROGATE                       = 1L << 8;
    public static final long FORBID_INAPPROPRIATE_FOR_PLAIN_TEXT    = 1L << 9;
    public static final long FORBID_INAPPROPRIATE_FOR_CANON_REP     = 1L << 10;
    public static final long FORBID_CHANGE_DISPLAY_AND_DEPRECATED   = 1L << 11;
    public static final long FORBID_TAGGING                         = 1L << 12;
    public static final long FORBID_UNASSIGNED                      = 1L << 13;

    public static final long PROFILE_SASL_QUERY = 0
        | MAP_TO_NOTHING
        | MAP_TO_SPACE
        | NORMALIZE_KC
        | FORBID_NON_ASCII_SPACES
        | FORBID_ASCII_CONTROL
        | FORBID_NON_ASCII_CONTROL
        | FORBID_PRIVATE_USE
        | FORBID_NON_CHARACTER
        | FORBID_SURROGATE
        | FORBID_INAPPROPRIATE_FOR_PLAIN_TEXT
        | FORBID_INAPPROPRIATE_FOR_CANON_REP
        | FORBID_CHANGE_DISPLAY_AND_DEPRECATED
        | FORBID_TAGGING;

    public static final long PROFILE_SASL_STORED = 0
        | PROFILE_SASL_QUERY
        | FORBID_UNASSIGNED;

    // StringPrep section 3 - Mapping

    public static boolean mapCodePointToNothing(int input) {
        return input == 0xAD
            || input == 0x034F
            || input == 0x1806
            || input >= 0x180B && input <= 0x180D
            || input >= 0x200B && input <= 0x200D
            || input == 0x2060
            || input >= 0xFE00 && input <= 0xFE0F
            || input == 0xFEFF;
    }

    public static boolean mapCodePointToSpace(int input) {
        return input == 0xA0
            || input == 0x1680
            || input >= 0x2000 && input <= 0x200B
            || input == 0x202F
            || input == 0x205F
            || input == 0x3000;
    }

    // StringPrep section 5 - Prohibited I/O

    public static void forbidNonAsciiSpaces(int input) {
        if (mapCodePointToSpace(input)) {
            throw new IllegalArgumentException("Invalid non-ASCII space");
        }
    }

    public static void forbidAsciiControl(int input) {
        if (input < 0x20 || input == 0x7F) {
            throw new IllegalArgumentException("Invalid ASCII control");
        }
    }

    public static void forbidNonAsciiControl(int input) {
        if (input >= 0x80 && input <= 0x9F
            || input == 0x06DD
            || input == 0x070F
            || input == 0x180E
            || input >= 0x200C && input <= 0x200D
            || input >= 0x2028 && input <= 0x2029
            || input >= 0x2060 && input <= 0x2063
            || input >= 0x206A && input <= 0x206F
            || input == 0xFEFF
            || input >= 0xFFF9 && input <= 0xFFFC
            || input >= 0x01D173 && input <= 0x01D17A
        ) {
            throw new IllegalArgumentException("Invalid non-ASCII control");
        }
    }

    public static void forbidPrivateUse(int input) {
        if (input >= 0xE000 && input <= 0xF8FF || input >= 0xF0000 && input <= 0xFFFFD || input >= 0x100000 && input <= 0x10FFFD) {
            throw new IllegalArgumentException("Invalid private use character");
        }
    }

    public static void forbidNonCharacter(int input) {
        if ((input & 0xFFFE) == 0xFFFE || input >= 0xFDD0 && input <= 0xFDEF) {
            throw new IllegalArgumentException("Invalid non-character code point");
        }
    }

    public static void forbidSurrogate(int input) {
        if (input >= 0xD800 && input <= 0xDFFF) {
            throw new IllegalArgumentException("Invalid surrogate code point");
        }
    }

    public static void forbidInappropriateForPlainText(int input) {
        if (input >= 0xFFF9 && input <= 0xFFFD) {
            throw new IllegalArgumentException("Invalid plain text code point");
        }
    }

    public static void forbidInappropriateForCanonicalRepresentation(int input) {
        if (input >= 0x2FF0 && input <= 0x2FFB) {
            throw new IllegalArgumentException("Invalid non-canonical code point");
        }
    }

    public static void forbidChangeDisplayPropertiesOrDeprecated(int input) {
        if (input >= 0x0340 && input <= 0x0341
            || input >= 0x200E && input <= 0x200F
            || input >= 0x202A && input <= 0x202E
            || input >= 0x206A && input <= 0x206F) {
            throw new IllegalArgumentException("Invalid control character");
        }
    }

    public static void forbidTagging(int input) {
        if (input == 0x0E0001 || input >= 0x0E0020 && input <= 0x0E007F) {
            throw new IllegalArgumentException("Invalid tagging character");
        }
    }

    public static void forbidUnassigned(int input) {
        if (Character.getType(input) == Character.UNASSIGNED) {
            throw new IllegalArgumentException("Unassigned code point");
        }
    }

    private static boolean isSet(long test, long bit) {
        return (test & bit) != 0L;
    }

    // Encoding

    public static void encode(char[] string, ByteStringBuilder target, long profile) {
        encode(new String(string), target, profile);
    }

    public static void encode(String string, ByteStringBuilder target, long profile) {
        // technically we're supposed to normalize after mapping, but it should be equivalent if we don't
        if (isSet(profile, NORMALIZE_KC)) string = Normalizer.normalize(string, Normalizer.Form.NFKC);
        final int len = string.length();
        boolean isRALString = false;
        boolean first = true;
        int i = 0;
        while (i < len) {
            char ch = string.charAt(i++);
            int cp;
            if (Character.isHighSurrogate(ch)) {
                if (i == len) {
                    throw new IllegalArgumentException("Invalid surrogate pair (high at end of string)");
                }
                char low = string.charAt(i++);
                if (!Character.isLowSurrogate(low)) {
                    throw new IllegalArgumentException("Invalid surrogate pair (second is not low)");
                }
                cp = Character.toCodePoint(ch, low);
            } else if (Character.isLowSurrogate(ch)) {
                throw new IllegalArgumentException("Invalid surrogate pair (low without high)");
            } else {
                cp = ch;
            }

            if (! Character.isValidCodePoint(cp)) {
                throw new IllegalArgumentException("Invalid code point");
            }

            assert Character.MIN_CODE_POINT <= cp && cp <= Character.MAX_CODE_POINT;

            // StringPrep 6 - Bidirectional Characters
            switch (Character.getDirectionality(cp)) {
                case Character.DIRECTIONALITY_RIGHT_TO_LEFT_ARABIC:
                case Character.DIRECTIONALITY_RIGHT_TO_LEFT: // R/AL character
                    if (first) {
                        isRALString = true;
                    } else if (!isRALString) {
                        throw new IllegalArgumentException("Disallowed R/AL directionality character in L string");
                    }
                    break;
                case Character.DIRECTIONALITY_LEFT_TO_RIGHT: // L character
                    if (isRALString) {
                        throw new IllegalArgumentException("Disallowed L directionality character in R/AL string");
                    }
                    break;
                default: // neutral character
                    if (i == len && isRALString) {
                        throw new IllegalArgumentException("Missing trailing R/AL directionality character");
                    }
            }
            if (first) {
                first = false;
            }

            // StringPrep 3 - Mapping
            if (isSet(profile, MAP_TO_NOTHING) && mapCodePointToNothing(cp)) continue;
            if (isSet(profile, MAP_TO_SPACE) && mapCodePointToSpace(cp)) {
                target.append(' ');
                continue;
            }
            if (isSet(profile, MAP_SCRAM_LOGIN_CHARS)) {
                if (cp == '=') {
                    target.append('=').append('3').append('D');
                    continue;
                } else if (cp == ',') {
                    target.append('=').append('2').append('C');
                    continue;
                }
            }

            // StringPrep 5 - Prohibition
            if (isSet(profile, FORBID_NON_ASCII_SPACES)) forbidNonAsciiSpaces(cp);
            if (isSet(profile, FORBID_ASCII_CONTROL)) forbidAsciiControl(cp);
            if (isSet(profile, FORBID_NON_ASCII_CONTROL)) forbidNonAsciiControl(cp);
            if (isSet(profile, FORBID_PRIVATE_USE)) forbidPrivateUse(cp);
            if (isSet(profile, FORBID_NON_CHARACTER)) forbidNonCharacter(cp);
            if (isSet(profile, FORBID_SURROGATE)) forbidSurrogate(cp);
            if (isSet(profile, FORBID_INAPPROPRIATE_FOR_PLAIN_TEXT)) forbidInappropriateForPlainText(cp);
            if (isSet(profile, FORBID_INAPPROPRIATE_FOR_CANON_REP)) forbidInappropriateForCanonicalRepresentation(cp);
            if (isSet(profile, FORBID_CHANGE_DISPLAY_AND_DEPRECATED)) forbidChangeDisplayPropertiesOrDeprecated(cp);
            if (isSet(profile, FORBID_TAGGING)) forbidTagging(cp);
            if (isSet(profile, FORBID_UNASSIGNED)) forbidUnassigned(cp);

            // Now, encode that one
            target.appendUtf8Raw(cp);
        }
    }
}
