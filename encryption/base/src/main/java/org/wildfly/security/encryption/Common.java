/*
 * Copyright 2021 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.encryption;

/**
 * Common methods and attributes shared by both utilities.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class Common {

    static final int VERSION = 1;

    static final char SECRET_KEY_IDENTIFIER = 'K';
    static final char CIPHER_TEXT_IDENTIFIER = 'C';

    static final String SECRET_KEY_NAME = "SecretKey";
    static final String CIPHER_TEXT_NAME = "CipherText";
    static final String UNKNOWN_NAME = "Unknown";

    private Common() {
    }

    static String toName(final char tokenIdentifier) {
        switch (tokenIdentifier) {
            case 'C':
                return CIPHER_TEXT_NAME;
            case 'K':
                return SECRET_KEY_NAME;
            default:
                return UNKNOWN_NAME;
        }
    }

}
