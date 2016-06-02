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
import static org.wildfly.security.sasl.otp.OTP.*;
import static org.wildfly.security.sasl.otp.OTPUtil.*;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.ExtendedChoiceCallback;
import org.wildfly.security.auth.callback.ParameterCallback;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;
import org.wildfly.security.sasl.util.AbstractSaslClient;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;

/**
 * SaslClient for the OTP SASL mechanism as defined by
 * <a href="https://tools.ietf.org/html/rfc2444">RFC 2444</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class OTPSaslClient extends AbstractSaslClient {

    private static final int ST_NEW = 1;
    private static final int ST_CHALLENGE_RESPONSE = 2;

    private final SecureRandom secureRandom;
    private final String[] alternateDictionary;
    private NameCallback nameCallback;
    private String userName;

    OTPSaslClient(final String mechanismName, final SecureRandom secureRandom, final String[] alternateDictionary,
            final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId) {
        super(mechanismName, protocol, serverName, callbackHandler, authorizationId, true);
        this.secureRandom = secureRandom;
        this.alternateDictionary = alternateDictionary;
    }

    @Override
    public void init() {
        setNegotiationState(ST_NEW);
    }

    @Override
    protected byte[] evaluateMessage(final int state, final byte[] challenge) throws SaslException {
        switch (state) {
            case ST_NEW: {
                if ((challenge != null) && (challenge.length != 0)) {
                    throw log.mechInitialChallengeMustBeEmpty(getMechanismName()).toSaslException();
                }

                // Construct the initial response which consists of the authorization identity, if provided,
                // followed by a NUL (0) octet, followed by the username
                final ByteStringBuilder response = new ByteStringBuilder();
                final String authorizationId = getAuthorizationId();
                validateAuthorizationId(authorizationId);
                nameCallback = authorizationId == null ? new NameCallback("User name") : new NameCallback("User name", authorizationId);
                handleCallbacks(nameCallback);
                userName = nameCallback.getName();
                validateUserName(userName);
                if (authorizationId != null) {
                    StringPrep.encode(authorizationId, response, StringPrep.PROFILE_SASL_STORED);
                }
                response.append((byte) 0);
                StringPrep.encode(userName, response, StringPrep.PROFILE_SASL_STORED);
                setNegotiationState(ST_CHALLENGE_RESPONSE);
                return response.toArray();
            }
            case ST_CHALLENGE_RESPONSE: {
                final CodePointIterator cpi = CodePointIterator.ofUtf8Bytes(challenge);
                final CodePointIterator di = cpi.delimitedBy(' ');
                final String otp;

                // Parse challenge
                final String algorithm = di.drainToString();
                validateAlgorithm(algorithm);
                skipDelims(di, cpi);
                final int sequenceNumber = Integer.parseInt(di.drainToString());
                validateSequenceNumber(sequenceNumber);
                skipDelims(di, cpi);
                final String seed = di.drainToString();
                validateSeed(seed);
                skipDelims(di, cpi);
                if (! di.drainToString().startsWith(EXT)) {
                    throw log.mechInvalidMessageReceived(getMechanismName()).toSaslException();
                }
                if (cpi.hasNext()) {
                    skipDelims(di, cpi);
                    if (cpi.hasNext()) {
                        throw log.mechInvalidMessageReceived(getMechanismName()).toSaslException();
                    }
                }

                int defaultResponseTypeChoice = (sequenceNumber < MIN_SEQUENCE_NUMBER) ? getResponseTypeChoiceIndex(INIT_WORD_RESPONSE) : getResponseTypeChoiceIndex(WORD_RESPONSE);
                final ExtendedChoiceCallback responseTypeChoiceCallback = new ExtendedChoiceCallback(RESPONSE_TYPE_PROMPT,
                        RESPONSE_TYPES, defaultResponseTypeChoice, false, true);
                final ExtendedChoiceCallback passwordFormatTypeChoiceCallback = new ExtendedChoiceCallback(PASSWORD_FORMAT_TYPE_PROMPT,
                        PASSWORD_FORMAT_TYPES, getPasswordFormatTypeChoiceIndex(PASS_PHRASE), false, true);
                handleCallbacks(nameCallback, responseTypeChoiceCallback, passwordFormatTypeChoiceCallback);
                String responseType = responseTypeChoiceCallback.getSelectedIndexes() != null ? RESPONSE_TYPES[responseTypeChoiceCallback.getSelectedIndexes()[0]]
                        : RESPONSE_TYPES[responseTypeChoiceCallback.getDefaultChoice()];
                String passwordFormatType = passwordFormatTypeChoiceCallback.getSelectedIndexes() != null ? PASSWORD_FORMAT_TYPES[passwordFormatTypeChoiceCallback.getSelectedIndexes()[0]]
                        : PASSWORD_FORMAT_TYPES[passwordFormatTypeChoiceCallback.getDefaultChoice()];

                PasswordCallback passwordCallback = new PasswordCallback(PASSWORD_PROMPT, false);
                switch (passwordFormatType) {
                    case PASS_PHRASE:
                        // Try obtaining a pass phrase
                        handleCallbacks(nameCallback, passwordCallback);
                        final char[] passPhraseChars = passwordCallback.getPassword();
                        passwordCallback.clearPassword();
                        if (passPhraseChars != null) {
                            // Generate the OTP using the pass phrase and format it appropriately
                            final String passPhrase = getPasswordFromPasswordChars(passPhraseChars);
                            validatePassPhrase(passPhrase);
                            if (seed.equals(passPhrase)) {
                                throw log.mechOTPPassPhraseAndSeedMustNotMatch().toSaslException();
                            }
                            otp = formatOTP(generateOTP(algorithm, passPhrase, seed, sequenceNumber), responseType, alternateDictionary);
                        } else {
                            throw log.mechNoPasswordGiven(getMechanismName()).toSaslException();
                        }
                        break;
                    case DIRECT_OTP:
                        // Try obtaining the OTP directly
                        final ParameterCallback parameterCallback = new ParameterCallback(OneTimePasswordAlgorithmSpec.class);
                        parameterCallback.setParameterSpec(new OneTimePasswordAlgorithmSpec(algorithm, seed.getBytes(StandardCharsets.US_ASCII), sequenceNumber));
                        handleCallbacks(nameCallback, parameterCallback, passwordCallback);
                        otp = getOTP(passwordCallback);
                        break;
                    default:
                        throw log.mechInvalidOTPPasswordFormatType().toSaslException();
                }
                negotiationComplete();
                return createOTPResponse(algorithm, seed, otp, responseType);
            }
            default: throw Assert.impossibleSwitchCase(state);
        }
    }

    @Override
    public void dispose() throws SaslException {
    }

    /**
     * Create an OTP response using the extended response syntax, where:
     *
     *      hex response = hex:<hexadecimal number>
     *      word response = word:<six dictionary words>
     *      init-hex response = init-hex:<current-OTP><new-params>:<new-OTP>
     *      init-word response = init-word:<current-OTP><new-params>:<new-OTP>
     *      new-params = <algorithm identifier> <sequence integer> <seed>
     *
     * @param algorithm the OTP algorithm, must be either "otp-md5" or "otp-sha1"
     * @param seed the seed
     * @param otp the OTP as a string in either hex or multi-word format
     * @param responseType the response type, must be "hex", "word", "init-hex", or "init-word"
     * @return the OTP response
     * @throws SaslException if the given response type is invalid or if an error occurs while creating
     * the response
     */
    private byte[] createOTPResponse(final String algorithm, final String seed, final String otp,
            final String responseType) throws SaslException {
        final ByteStringBuilder response = new ByteStringBuilder();
        response.append(responseType);
        response.append(':');
        switch (responseType) {
            case HEX_RESPONSE:
            case WORD_RESPONSE: {
                response.append(otp);
                break;
            }
            case INIT_HEX_RESPONSE:
            case INIT_WORD_RESPONSE: {
                response.append(otp);
                response.append(':');

                // == Attempt to re-initialize the sequence ==
                String newOTP, newSeed, newAlgorithm;
                int newSequenceNumber;
                do {
                    Random random = secureRandom != null ? secureRandom : ThreadLocalRandom.current();
                    newSeed = generateRandomAlphanumericString(DEFAULT_SEED_LENGTH, random);
                } while (newSeed.equals(seed));

                final ExtendedChoiceCallback passwordFormatTypeChoiceCallback = new ExtendedChoiceCallback(NEW_PASSWORD_FORMAT_TYPE_PROMPT,
                        PASSWORD_FORMAT_TYPES, getPasswordFormatTypeChoiceIndex(PASS_PHRASE), false, true);
                handleCallbacks(nameCallback, passwordFormatTypeChoiceCallback);
                String newPasswordFormatType = passwordFormatTypeChoiceCallback.getSelectedIndexes() != null ? PASSWORD_FORMAT_TYPES[passwordFormatTypeChoiceCallback.getSelectedIndexes()[0]]
                        : PASSWORD_FORMAT_TYPES[passwordFormatTypeChoiceCallback.getDefaultChoice()];

                PasswordCallback passwordCallback = new PasswordCallback(NEW_PASSWORD_PROMPT, false);
                switch (newPasswordFormatType) {
                    case PASS_PHRASE:
                        // Try to obtain a new pass phrase
                        handleCallbacks(nameCallback, passwordCallback);
                        final char[] newPassPhraseChars = passwordCallback.getPassword();
                        passwordCallback.clearPassword();
                        if (newPassPhraseChars != null) {
                            // Generate the new OTP using the new pass phrase and format it appropriately
                            newSequenceNumber = DEFAULT_SEQUENCE_NUMBER;
                            newAlgorithm = algorithm;
                            final String newPassPhrase = getPasswordFromPasswordChars(newPassPhraseChars);
                            validatePassPhrase(newPassPhrase);
                            if (newSeed.equals(newPassPhrase)) {
                                throw log.mechOTPPassPhraseAndSeedMustNotMatch().toSaslException();
                            }
                            newOTP = formatOTP(generateOTP(newAlgorithm, newPassPhrase, newSeed, newSequenceNumber), responseType, alternateDictionary);
                        } else {
                            throw log.mechNoPasswordGiven(getMechanismName()).toSaslException();
                        }
                        break;
                    case DIRECT_OTP:
                        // Try obtaining the new OTP directly
                        ParameterCallback parameterCallback = new ParameterCallback(OneTimePasswordAlgorithmSpec.class);
                        handleCallbacks(nameCallback, parameterCallback, passwordCallback);
                        newOTP = getOTP(passwordCallback);
                        OneTimePasswordAlgorithmSpec algorithmSpec = (OneTimePasswordAlgorithmSpec) parameterCallback.getParameterSpec();
                        if (algorithmSpec == null) {
                            throw log.mechNoPasswordGiven(getMechanismName()).toSaslException();
                        }
                        newAlgorithm = algorithmSpec.getAlgorithm();
                        validateAlgorithm(newAlgorithm);
                        newSequenceNumber = algorithmSpec.getSequenceNumber();
                        validateSequenceNumber(newSequenceNumber);
                        newSeed = new String(algorithmSpec.getSeed(), StandardCharsets.US_ASCII);
                        validateSeed(newSeed);
                        break;
                    default:
                        throw log.mechInvalidOTPPasswordFormatType().toSaslException();
                }
                response.append(createInitResponse(newAlgorithm, newSeed, newSequenceNumber, newOTP));
                break;
            }
            default:
                throw log.mechInvalidOTPResponseType().toSaslException();
        }
        return response.toArray();
    }

    /**
     * Create an init response, excluding the response type specifier and current OTP, where:
     *
     *      init-hex response = init-hex:<current-OTP>:<new-params>:<new-OTP>
     *      init-word response = init-word:<current-OTP>:<new-params>:<new-OTP>
     *      new-params = <algorithm identifier> <sequence integer> <seed>
     *
     * @param newAlgorithm the new OTP algorithm, must be either "otp-md5" or "otp-sha1"
     * @param newSeed the new seed
     * @param newSequenceNumber the new sequence number
     * @param newOTP the new OTP as a string in either hex or multi-word format
     * @return the init response, excluding the response type specifier and current OTP
     * @throws SaslException if the given OTP algorithm is invalid
     */
    private ByteStringBuilder createInitResponse(final String newAlgorithm, final String newSeed,
            final int newSequenceNumber, final String newOTP) throws SaslException {
        final ByteStringBuilder initResponse = new ByteStringBuilder();
        String newDigestAlgorithm;
        try {
            newDigestAlgorithm = messageDigestAlgorithm(newAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw log.mechInvalidOTPAlgorithm(newAlgorithm).toSaslException();
        }
        initResponse.append(newDigestAlgorithm);
        initResponse.append(' ');
        initResponse.appendNumber(newSequenceNumber);
        initResponse.append(' ');
        initResponse.append(newSeed);
        initResponse.append(':');
        initResponse.append(newOTP);
        return initResponse;
    }

    private String getOTP(PasswordCallback passwordCallback) throws SaslException {
        final char[] passwordChars = passwordCallback.getPassword();
        passwordCallback.clearPassword();
        if (passwordChars != null) {
            return getPasswordFromPasswordChars(passwordChars);
        } else {
            throw log.mechNoPasswordGiven(getMechanismName()).toSaslException();
        }
    }

    private String getPasswordFromPasswordChars(char[] passwordChars) {
        final ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode(passwordChars, b, StringPrep.PROFILE_SASL_STORED);
        Arrays.fill(passwordChars, (char) 0); // Wipe out the password
        return new String(b.toArray(), StandardCharsets.UTF_8);
    }
}
