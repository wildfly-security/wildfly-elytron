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

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

import javax.security.auth.callback.ChoiceCallback;
import javax.security.sasl.Sasl;

import org.wildfly.security.auth.callback.ExtendedChoiceCallback;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;
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

    /**
     * Pass phrase format.
     */
    public static final String PASS_PHRASE = "pass-phrase";

    /**
     * Direct OTP format (either hexadecimal or multi-word OTP).
     */
    public static final String DIRECT_OTP = "direct-otp";

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

    // OTP prompts
    public static final String RESPONSE_TYPE_PROMPT = "One-time password response type";
    public static final String PASSWORD_FORMAT_TYPE_PROMPT = "One-time password format type";
    public static final String NEW_PASSWORD_FORMAT_TYPE_PROMPT = "New one-time password format type";
    public static final String PASSWORD_PROMPT = "Pass phrase or one-time password";
    public static final String NEW_PASSWORD_PROMPT = "New pass phrase or one-time password";

    /**
     * A predicate which is true when the given callback type and prompt match the OTP response type choice callback.
     */
    public static final BiPredicate<Class<? extends ChoiceCallback>, String> MATCH_RESPONSE_CHOICE =
            (choiceCallbackType, prompt) -> ExtendedChoiceCallback.class.isAssignableFrom(choiceCallbackType) && RESPONSE_TYPE_PROMPT.equals(prompt);

    /**
     * A predicate which is true when the given callback type and prompt match the OTP password format type choice callback.
     */
    public static final BiPredicate<Class<? extends ChoiceCallback>, String> MATCH_PASSWORD_FORMAT_CHOICE =
            (choiceCallbackType, prompt) -> ExtendedChoiceCallback.class.isAssignableFrom(choiceCallbackType) && PASSWORD_FORMAT_TYPE_PROMPT.equals(prompt);

    /**
     * A predicate which is true when the given callback type and prompt match the OTP new password format type choice callback.
     */
    public static final BiPredicate<Class<? extends ChoiceCallback>, String> MATCH_NEW_PASSWORD_FORMAT_CHOICE =
            (choiceCallbackType, prompt) -> ExtendedChoiceCallback.class.isAssignableFrom(choiceCallbackType) && NEW_PASSWORD_FORMAT_TYPE_PROMPT.equals(prompt);

    /**
     * A predicate which is true when the given callback type and prompt match the OTP password callback.
     */
    public static final Predicate<String> MATCH_PASSWORD = (prompt) -> PASSWORD_PROMPT.equals(prompt);

    /**
     * A predicate which is true when the given callback type and prompt match the OTP new password callback.
     */
    public static final Predicate<String> MATCH_NEW_PASSWORD = (prompt) -> NEW_PASSWORD_PROMPT.equals(prompt);

    /**
     * Get the parameter specification for a one-time password generated using the given algorithm, seed, and sequence number.
     *
     * @param algorithm the algorithm
     * @param seed the seed
     * @param sequenceNumber the sequence number
     * @return the parameter specification for a one-time password generated using the given algorithm, seed, and sequence number
     */
    public static OneTimePasswordAlgorithmSpec getOTPParameterSpec(final String algorithm, final String seed, final int sequenceNumber) {
        return new OneTimePasswordAlgorithmSpec(algorithm, seed.getBytes(StandardCharsets.US_ASCII), sequenceNumber);
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
