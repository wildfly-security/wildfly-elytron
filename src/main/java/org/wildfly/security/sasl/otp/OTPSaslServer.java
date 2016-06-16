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
import static org.wildfly.security.sasl.otp.OTP.EXT;
import static org.wildfly.security.sasl.otp.OTP.HEX_RESPONSE;
import static org.wildfly.security.sasl.otp.OTP.INIT_HEX_RESPONSE;
import static org.wildfly.security.sasl.otp.OTP.INIT_WORD_RESPONSE;
import static org.wildfly.security.sasl.otp.OTP.OTP_PREFIX;
import static org.wildfly.security.sasl.otp.OTP.WORD_RESPONSE;
import static org.wildfly.security.sasl.otp.OTPUtil.convertFromHex;
import static org.wildfly.security.sasl.otp.OTPUtil.convertFromWords;
import static org.wildfly.security.sasl.otp.OTPUtil.hashAndFold;
import static org.wildfly.security.sasl.otp.OTPUtil.skipDelims;
import static org.wildfly.security.sasl.otp.OTPUtil.validateAlgorithm;
import static org.wildfly.security.sasl.otp.OTPUtil.validateAuthorizationId;
import static org.wildfly.security.sasl.otp.OTPUtil.validateSeed;
import static org.wildfly.security.sasl.otp.OTPUtil.validateSequenceNumber;
import static org.wildfly.security.sasl.otp.OTPUtil.validateUserName;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Locale;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.CredentialUpdateCallback;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.sasl.util.AbstractSaslServer;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;

/**
 * SaslServer for the OTP SASL mechanism as defined by
 * <a href="https://tools.ietf.org/html/rfc2444">RFC 2444</a>.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
final class OTPSaslServer extends AbstractSaslServer {

    private static final int ST_CHALLENGE = 1;
    private static final int ST_PROCESS_RESPONSE = 2;

    private String previousAlgorithm;
    private String previousSeed;
    private int previousSequenceNumber;
    private byte[] previousHash;
    private NameCallback nameCallback;
    private String userName;
    private String authorizationID;

    OTPSaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler) {
        super(mechanismName, protocol, serverName, callbackHandler);
    }

    public void init() {
        setNegotiationState(ST_CHALLENGE);
    }

    public String getAuthorizationID() {
        if (! isComplete()) {
            throw log.mechAuthenticationNotComplete(getMechanismName());
        }
        return authorizationID;
    }

    protected byte[] evaluateMessage(final int state, final byte[] response) throws SaslException {
        switch (state) {
            case ST_CHALLENGE: {
                final CodePointIterator cpi = CodePointIterator.ofUtf8Bytes(response);
                final CodePointIterator di = cpi.delimitedBy(0);

                authorizationID = di.hasNext() ? di.drainToString() : null;
                cpi.next(); // Skip delimiter
                userName = di.drainToString();
                validateUserName(userName);
                if ((authorizationID == null) || (authorizationID.isEmpty())) {
                    authorizationID = userName;
                }
                validateAuthorizationId(authorizationID);

                // Construct an OTP extended challenge, where:
                // OTP extended challenge = <standard OTP challenge> ext[,<extension set id>[, ...]]
                // standard OTP challenge = otp-<algorithm identifier> <sequence integer> <seed>
                nameCallback = new NameCallback("Remote authentication name", userName);
                CredentialCallback credentialCallback = new CredentialCallback(PasswordCredential.class);
                handleCallbacks(nameCallback, credentialCallback);
                final PasswordCredential credential = credentialCallback.getCredential(PasswordCredential.class);
                final OneTimePassword previousPassword = credential.getPassword(OneTimePassword.class);
                if (previousPassword == null) {
                    throw log.mechUnableToRetrievePassword(getMechanismName(), userName).toSaslException();
                }
                previousAlgorithm = previousPassword.getAlgorithm();
                validateAlgorithm(previousAlgorithm);
                previousSeed = new String(previousPassword.getSeed(), StandardCharsets.US_ASCII);
                validateSeed(previousSeed);
                previousSequenceNumber = previousPassword.getSequenceNumber();
                validateSequenceNumber(previousSequenceNumber);
                previousHash = previousPassword.getHash();

                final ByteStringBuilder challenge = new ByteStringBuilder();
                challenge.append(previousAlgorithm);
                challenge.append(' ');
                challenge.appendNumber(previousSequenceNumber - 1);
                challenge.append(' ');
                challenge.append(previousSeed);
                challenge.append(' ');
                challenge.append(EXT);
                setNegotiationState(ST_PROCESS_RESPONSE);
                return challenge.toArray();
            }
            case ST_PROCESS_RESPONSE: {
                final CodePointIterator cpi = CodePointIterator.ofUtf8Bytes(response);
                final CodePointIterator di = cpi.delimitedBy(':');
                final String responseType = di.drainToString().toLowerCase(Locale.ENGLISH);
                final byte[] currentHash;
                OneTimePasswordSpec passwordSpec;
                String algorithm;
                skipDelims(di, cpi, ':');
                switch (responseType) {
                    case HEX_RESPONSE:
                    case WORD_RESPONSE: {
                        if (responseType.equals(HEX_RESPONSE)) {
                            currentHash = convertFromHex(di.drainToString());
                        } else {
                            currentHash = convertFromWords(di.drainToString(), previousAlgorithm);
                        }
                        passwordSpec = new OneTimePasswordSpec(currentHash, previousSeed.getBytes(StandardCharsets.US_ASCII), previousSequenceNumber - 1);
                        algorithm = previousAlgorithm;
                        break;
                    }
                    case INIT_HEX_RESPONSE:
                    case INIT_WORD_RESPONSE: {
                        if (responseType.equals(INIT_HEX_RESPONSE)) {
                            currentHash = convertFromHex(di.drainToString());
                        } else {
                            currentHash = convertFromWords(di.drainToString(), previousAlgorithm);
                        }
                        try {
                            // Attempt to parse the new params and new OTP
                            skipDelims(di, cpi, ':');
                            final CodePointIterator si = di.delimitedBy(' ');
                            String newAlgorithm = OTP_PREFIX + si.drainToString();
                            validateAlgorithm(newAlgorithm);
                            skipDelims(si, di, ' ');
                            int newSequenceNumber = Integer.parseInt(si.drainToString());
                            validateSequenceNumber(newSequenceNumber);
                            skipDelims(si, di, ' ');
                            String newSeed = si.drainToString();
                            validateSeed(newSeed);
                            skipDelims(di, cpi, ':');
                            final byte[] newHash;
                            if (responseType.equals(INIT_HEX_RESPONSE)) {
                                newHash = convertFromHex(di.drainToString());
                            } else {
                                newHash = convertFromWords(di.drainToString(), newAlgorithm);
                            }
                            passwordSpec = new OneTimePasswordSpec(newHash, newSeed.getBytes(StandardCharsets.US_ASCII), newSequenceNumber);
                            algorithm = newAlgorithm;
                        } catch (SaslException e) {
                            // If the new params or new OTP could not be processed for any reason, the sequence
                            // number should be decremented if a valid current OTP is provided
                            passwordSpec = new OneTimePasswordSpec(currentHash, previousSeed.getBytes(StandardCharsets.US_ASCII), previousSequenceNumber - 1);
                            algorithm = previousAlgorithm;
                            verifyAndUpdateCredential(currentHash, algorithm, passwordSpec);
                            throw log.mechOTPReinitializationFailed(e).toSaslException();
                        }
                        break;
                    }
                    default:
                        throw log.mechInvalidOTPResponseType().toSaslException();
                }
                if (cpi.hasNext()) {
                    throw log.mechInvalidMessageReceived(getMechanismName()).toSaslException();
                }
                verifyAndUpdateCredential(currentHash, algorithm, passwordSpec);

                // Check the authorization id
                if (authorizationID == null) {
                    authorizationID = userName;
                }
                final AuthorizeCallback authorizeCallback = new AuthorizeCallback(userName, authorizationID);
                handleCallbacks(authorizeCallback);
                if (! authorizeCallback.isAuthorized()) {
                    throw log.mechAuthorizationFailed(getMechanismName(), userName, authorizationID).toSaslException();
                }
                negotiationComplete();
                return null;
            }
            case COMPLETE_STATE: {
                  if (response != null && response.length != 0) {
                      throw log.mechMessageAfterComplete(getMechanismName()).toSaslException();
                  }
                  return null;
            }
            default: throw Assert.impossibleSwitchCase(state);
        }
    }

    public void dispose() throws SaslException {
        previousHash = null;
        previousSeed = null;
    }

    /**
     * Verify that the result of passing the user's password through the hash function once matches
     * the stored password and then update the stored password.
     *
     * @param currentHash the current OTP hash
     * @param newAlgorithm the new OTP algorithm
     * @param newPasswordSpec the new OTP password spec
     * @throws SaslException if the password was not verified
     */
    private void verifyAndUpdateCredential(final byte[] currentHash, final String newAlgorithm,
            final OneTimePasswordSpec newPasswordSpec) throws SaslException {
        if (! Arrays.equals(previousHash, hashAndFold(previousAlgorithm, currentHash))) {
            throw log.mechPasswordNotVerified(getMechanismName()).toSaslException();
        }
        updateCredential(newAlgorithm, newPasswordSpec);
    }

    private void updateCredential(final String newAlgorithm, final OneTimePasswordSpec newPasswordSpec) throws SaslException {
        try {
            final PasswordFactory passwordFactory = PasswordFactory.getInstance(newAlgorithm);
            final OneTimePassword newPassword = (OneTimePassword) passwordFactory.generatePassword(newPasswordSpec);
            final CredentialUpdateCallback credentialUpdateCallback = new CredentialUpdateCallback(new PasswordCredential(newPassword));
            handleCallbacks(nameCallback, credentialUpdateCallback);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw log.mechUnableToUpdatePassword(getMechanismName(), userName).toSaslException();
        }
    }

}
