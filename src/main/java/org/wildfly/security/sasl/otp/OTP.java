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

package org.wildfly.security.sasl.otp;

import static org.wildfly.security._private.ElytronMessages.log;

import java.util.Map;

import javax.security.sasl.Sasl;

import org.wildfly.security.sasl.WildFlySasl;

/**
 * Constants for the OTP SASL mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class OTP {

    public static final String OTP_PREFIX = "otp-";
    public static final String EXT = "ext";

    // Supported algorithms
    public static final String MD5 = "md5";
    public static final String SHA1 = "sha1";

    // Response types
    public static final String HEX_RESPONSE = "hex";
    public static final String WORD_RESPONSE = "word";
    public static final String INIT_HEX_RESPONSE = "init-hex";
    public static final String INIT_WORD_RESPONSE = "init-word";

    // OTP parameters
    public static final int MAX_AUTHORIZATION_ID_LENGTH = 255;
    public static final int MAX_AUTHENTICATION_ID_LENGTH = 255;
    public static final int MIN_SEED_LENGTH = 1;
    public static final int MAX_SEED_LENGTH = 16;
    public static final int DEFAULT_SEED_LENGTH = 10;
    public static final int MIN_PASS_PHRASE_LENGTH = 10;
    public static final int MAX_PASS_PHRASE_LENGTH = 63;
    public static final int MIN_SEQUENCE_NUMBER = 10;
    public static final int DEFAULT_SEQUENCE_NUMBER = 499;
    public static final char DICTIONARY_DELIMITER = ' ';
    public static final int DICTIONARY_SIZE = 2048;
    public static final int LOCK_TIMEOUT = 300;

    /**
     * Get the index in the response type choices list that corresponds to the given response type.
     *
     * @param responseType the response type
     * @return the index in the response type choices list that corresponds to the given response type
     * @throws IllegalArgumentException if the given response type is invalid
     */
    public static int getResponseTypeChoiceIndex(String responseType) throws IllegalArgumentException {
        switch (responseType) {
            case WORD_RESPONSE:
                return 0;
            case INIT_WORD_RESPONSE:
                return 1;
            case HEX_RESPONSE:
                return 2;
            case INIT_HEX_RESPONSE:
                return 3;
            default: throw log.saslInvalidOTPResponseType();
        }
    }

    static boolean isMatched(final Map<String, ?> props) {
        if ("true".equals(props.get(WildFlySasl.MECHANISM_QUERY_ALL))) {
            return true;
        }
        if ("true".equals(props.get(Sasl.POLICY_NOACTIVE))) {
            return false;
        }
        if ("true".equals(props.get(Sasl.POLICY_PASS_CREDENTIALS))) {
            return false;
        }
        if ("true".equals(props.get(Sasl.POLICY_NODICTIONARY))) {
            return false;
        }
        return true;
    }
}
