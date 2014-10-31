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

import static java.util.Arrays.copyOfRange;
import static org.wildfly.security.sasl.util.HexConverter.convertToHexString;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.callback.ParameterCallback;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.sasl.util.AbstractSaslServer;
import org.wildfly.security.sasl.util.ByteStringBuilder;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.util.Base64;
import org.wildfly.security.util._private.Arrays2;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class ScramSaslServer extends AbstractSaslServer {

    private static final int S_NO_MESSAGE = 1;
    private static final int S_FIRST_MESSAGE = 2;
    private static final int S_FINAL_MESSAGE = 3;

    private final boolean plus;
    private final MessageDigest messageDigest;
    private final Mac mac;
    private final SecureRandom secureRandom;
    private final int minimumIterationCount;
    private final int maximumIterationCount;
    private final String bindingType;
    private final byte[] bindingData;

    private int state;
    private String authorizationID;
    private byte[] clientFirstMessage;
    private byte[] serverFirstMessage;
    private byte[] saltedPassword;
    private final boolean sendErrors = false;
    private int clientFirstMessageBareStart;

    ScramSaslServer(final String mechanismName, final String protocol, final String serverName, final CallbackHandler callbackHandler, final boolean plus, final Map<String, ?> props, final MessageDigest messageDigest, final Mac mac, final SecureRandom secureRandom, final String bindingType, final byte[] bindingData) {
        super(mechanismName, protocol, serverName, callbackHandler);
        this.messageDigest = messageDigest;
        this.mac = mac;
        minimumIterationCount = getIntProperty(props, WildFlySasl.SCRAM_MIN_ITERATION_COUNT, 4096);
        maximumIterationCount = getIntProperty(props, WildFlySasl.SCRAM_MAX_ITERATION_COUNT, 32768);
        this.secureRandom = secureRandom;
        this.plus = plus;
        this.bindingType = bindingType;
        this.bindingData = bindingData;
    }

    public void init() {
        setNegotiationState(S_NO_MESSAGE);
    }

    public String getAuthorizationID() {
        return authorizationID;
    }

    private static final boolean DEBUG = false;

    protected byte[] evaluateMessage(final int state, final byte[] response) throws SaslException {
        boolean ok = false;
        try {
            switch (state) {
                case S_NO_MESSAGE: {
                    if (response == null || response.length == 0) {
                        setNegotiationState(S_FIRST_MESSAGE);
                        // initial challenge
                        ok = true;
                        return NO_BYTES;
                    }
                    // fall through
                }
                case S_FIRST_MESSAGE: {
                    if (response == null || response.length == 0) {
                        throw new SaslException("Client refuses to initiate authentication");
                    }
                    if (DEBUG) System.out.printf("[S] Client first message: %s%n", convertToHexString(response));

                    final ByteStringBuilder b = new ByteStringBuilder();
                    final StringBuilder sb = new StringBuilder();
                    int i = 0;
                    int c;

                    // == parse message ==

                    // binding type
                    c = response[i++] & 0xff;
                    if (c == 'p' && plus) {
                        assert bindingType != null; // because {@code plus} is true
                        assert bindingData != null;
                        if (response[i++] != '=') {
                            throw invalidClientMessage();
                        }
                        i += ScramUtils.parseString(response, i, ',', sb);
                        i++;
                        if (! bindingType.equals(sb.toString())) {
                            // nope, auth must fail because we cannot acquire the same binding
                            throw new SaslException("Channel binding type mismatch between client and server");
                        }
                        sb.setLength(0);
                    } else if ((c == 'y' || c == 'n') && !plus) {
                        if (response[i++] != ',') {
                            throw invalidClientMessage();
                        }
                    } else {
                        throw invalidClientMessage();
                    }

                    // authorization ID
                    c = response[i++] & 0xff;
                    if (c == 'a') {
                        if (response[i++] != '=') {
                            throw invalidClientMessage();
                        }
                        i += ScramUtils.parseString(response, i, ',', sb);
                        authorizationID = sb.toString();
                        sb.setLength(0);
                    } else if (c != ',') {
                        throw invalidClientMessage();
                    }

                    clientFirstMessageBareStart = i;
                    // login name
                    String loginName;
                    c = response[i++] & 0xff;
                    if (c == 'n') {
                        if (response[i++] != '=') {
                            throw invalidClientMessage();
                        }
                        i += ScramUtils.parseString(response, i, ',', sb);
                        loginName = sb.toString();
                        sb.setLength(0);
                    } else {
                        throw invalidClientMessage();
                    }

                    // random nonce (skip over for now)
                    if (response[i++] != 'r' || response[i++] != '=') {
                        throw invalidClientMessage();
                    }
                    int nonce = i;
                    while (i < response.length && response[i++] != ',') {}
                    int nonceEnd = i;
                    if (DEBUG) System.out.printf("[S] Client nonce: %s%n", convertToHexString(copyOfRange(response, nonce, nonceEnd)));

                    if (i < response.length) {
                        throw invalidClientMessage();
                    }

                    clientFirstMessage = response;

                    // == send first challenge ==

                    // get password

                    final NameCallback nameCallback = new NameCallback("Remote authentication name");
                    nameCallback.setName(loginName);

                    // first try pre-digested

                    CredentialCallback credentialCallback = new CredentialCallback(ScramDigestPassword.class);
                    try {
                        tryHandleCallbacks(nameCallback, credentialCallback);
                    } catch (UnsupportedCallbackException e) {
                        final Callback callback = e.getCallback();
                        if (callback == nameCallback) {
                            throw new SaslException("Callback handler does not support user name", e);
                        } else if (callback == credentialCallback) {
                            throw new SaslException("Callback handler does not support credential acquisition", e);
                        } else {
                            throw new SaslException("Callback handler failed for unknown reason", e);
                        }
                    }
                    int iterationCount;
                    byte[] salt;
                    Password password = (Password) credentialCallback.getCredential();
                    if (password != null) {
                        // got a scram password
                        iterationCount = ((ScramDigestPassword) password).getIterationCount();
                        salt = ((ScramDigestPassword) password).getSalt();
                        if (DEBUG) System.out.printf("[S] Salt (pre digested): %s%n", convertToHexString(salt));
                        if (iterationCount < minimumIterationCount) {
                            throw new SaslException("Iteration count " + iterationCount + " is below the minimum of " + minimumIterationCount);
                        } else if (iterationCount > maximumIterationCount) {
                            throw new SaslException("Iteration count " + iterationCount + " is above the maximum of " + maximumIterationCount);
                        }
                        if (salt == null) {
                            throw new SaslException("Salt must be specified");
                        }
                        saltedPassword = ((ScramDigestPassword)password).getDigest();
                        if (DEBUG) System.out.printf("[S] Salted password (pre digested): %s%n", convertToHexString(saltedPassword));
                    } else {
                        // try two-way passwords
                        credentialCallback = new CredentialCallback(TwoWayPassword.class);
                        final ParameterCallback parameterCallback = new ParameterCallback(HashedPasswordAlgorithmSpec.class);
                        HashedPasswordAlgorithmSpec algorithmSpec;
                        try {
                            tryHandleCallbacks(nameCallback, parameterCallback, credentialCallback);
                            algorithmSpec = (HashedPasswordAlgorithmSpec) parameterCallback.getParameterSpec();
                            if (algorithmSpec == null) throw new FastUnsupportedCallbackException(parameterCallback);
                        } catch (UnsupportedCallbackException e) {
                            Callback callback = e.getCallback();
                            if (callback == nameCallback) {
                                throw new SaslException("Callback handler does not support user name", e);
                            } else if (callback == credentialCallback) {
                                throw new SaslException("Callback handler does not support credential acquisition", e);
                            } else if (callback == parameterCallback) {
                                // one more try, with default parameters
                                salt = new byte[16];
                                getRandom().nextBytes(salt);
                                if (DEBUG) System.out.printf("[S] Salt (random): %s%n", convertToHexString(salt));
                                algorithmSpec = new HashedPasswordAlgorithmSpec(minimumIterationCount, salt);
                                try {
                                    tryHandleCallbacks(nameCallback, credentialCallback);
                                } catch (UnsupportedCallbackException e1) {
                                    callback = e.getCallback();
                                    if (callback == nameCallback) {
                                        throw new SaslException("Callback handler does not support user name", e);
                                    } else if (callback == credentialCallback) {
                                        throw new SaslException("Callback handler does not support credential acquisition", e);
                                    } else {
                                        throw new SaslException("Callback handler failed for unknown reason", e);
                                    }
                                }
                            } else {
                                throw new SaslException("Callback handler failed for unknown reason", e);
                            }
                        }
                        password = (Password) credentialCallback.getCredential();
                        PasswordFactory pf;
                        try {
                            pf = PasswordFactory.getInstance(password.getAlgorithm());
                        } catch (NoSuchAlgorithmException e) {
                            throw new SaslException("Invalid password algorithm");
                        }
                        char[] passwordChars;
                        try {
                            passwordChars = pf.getKeySpec(password, ClearPasswordSpec.class).getEncodedPassword();
                        } catch (InvalidKeySpecException e) {
                            throw new SaslException("Unsupported password algorithm type");
                        }
                        // get the clear password
                        StringPrep.encode(passwordChars, b, StringPrep.NORMALIZE_KC);
                        passwordChars = new String(b.toArray(), StandardCharsets.UTF_8).toCharArray();
                        b.setLength(0);
                        iterationCount = algorithmSpec.getIterationCount();
                        salt = algorithmSpec.getSalt();
                        if (iterationCount < minimumIterationCount) {
                            throw new SaslException("Iteration count " + iterationCount + " is below the minimum of " + minimumIterationCount);
                        } else if (iterationCount > maximumIterationCount) {
                            throw new SaslException("Iteration count " + iterationCount + " is above the maximum of " + maximumIterationCount);
                        }
                        if (salt == null) {
                            throw new SaslException("Salt must be specified");
                        }
                        try {
                            saltedPassword = ScramUtils.calculateHi(mac, passwordChars, salt, 0, salt.length, iterationCount);
                            if (DEBUG) System.out.printf("[S] Salted password: %s%n", convertToHexString(saltedPassword));
                        } catch (InvalidKeyException e) {
                            throw new SaslException("Invalid MAC initialization key");
                        }
                    }

                    // nonce (client + server nonce)
                    b.append('r').append('=');
                    b.append(response, nonce, nonceEnd - nonce);
                    b.append(ScramUtils.generateRandomString(28, getRandom()));
                    b.append(',');

                    // salt
                    b.append('s').append('=');
                    Base64.base64EncodeStandard(b, new ByteArrayInputStream(salt), true);
                    b.append(',');
                    b.append('i').append('=');
                    b.append(Integer.toString(iterationCount));

                    setNegotiationState(S_FINAL_MESSAGE);
                    ok = true;
                    return serverFirstMessage = b.toArray();
                }
                case S_FINAL_MESSAGE: {
                    final ByteStringBuilder b = new ByteStringBuilder();
                    int i = 0;

                    // == parse message ==

                    // first comes the channel binding
                    if (response[i++] != 'c' || response[i++] != '=') {
                        throw invalidClientMessage();
                    }
                    int channelBindingStart = i;
                    while (response[i++] != ',') {}
                    int channelBindingEnd = i - 1;
                    Base64.base64DecodeStandard(response, channelBindingStart, channelBindingEnd - channelBindingStart, b);

                    // -- sub-parse of binding data --
                    final byte[] subResponse = b.toArray();
                    int j = 0;
                    b.setLength(0);
                    switch (subResponse[j++]) {
                        case 'n': {
                            if (plus) throw new SaslException("Channel binding not provided by client for mechanism " + getMechanismName());
                            if (subResponse[j++] != ',') {
                                throw invalidClientMessage();
                            }
                            switch (subResponse[j++]) {
                                case ',': break;
                                case 'a': {
                                    if (subResponse[j++] != '=') {
                                        throw invalidClientMessage();
                                    }
                                    int authzIdStart = j;
                                    while (subResponse[j++] != ',') {}
                                    int authzIdEnd = j - 1;
                                    authorizationID = new String(subResponse, authzIdStart, authzIdEnd - authzIdStart, StandardCharsets.UTF_8);
                                    break;
                                }
                                default: throw invalidClientMessage();
                            }
                            if (j < subResponse.length) {
                                // extra data
                                throw invalidClientMessage();
                            }
                            break;
                        }
                        case 'y': {
                            if (plus) throw new SaslException("Channel binding not provided by client for mechanism " + getMechanismName());
                            if (subResponse[j++] != ',') {
                                throw invalidClientMessage();
                            }
                            switch (subResponse[j++]) {
                                case ',': break;
                                case 'a': {
                                    if (subResponse[j++] != '=') {
                                        throw invalidClientMessage();
                                    }
                                    int authzIdStart = j;
                                    while (subResponse[j++] != ',') {}
                                    int authzIdEnd = j - 1;
                                    authorizationID = new String(subResponse, authzIdStart, authzIdEnd - authzIdStart, StandardCharsets.UTF_8);
                                    break;
                                }
                                default: throw invalidClientMessage();
                            }
                            if (j < subResponse.length) {
                                // extra data
                                throw invalidClientMessage();
                            }
                            break;
                        }
                        case 'p': {
                            if (! plus) {
                                throw new SaslException("Channel binding not supported for mechanism " + getMechanismName());
                            }
                            if (subResponse[j++] != '=') {
                                throw invalidClientMessage();
                            }
                            int btsStart = j;
                            // next comes the binding type string
                            while (subResponse[j++] != ',') {}
                            int btsEnd = j - 1;
                            if (! bindingType.equals(new String(subResponse, btsStart, btsEnd - btsStart, StandardCharsets.UTF_8))) {
                                throw new SaslException("Channel binding type mismatch for mechanism " + getMechanismName());
                            }
                            if (subResponse[j++] != ',') {
                                throw invalidClientMessage();
                            }
                            switch (subResponse[j++]) {
                                case ',': break;
                                case 'a': {
                                    if (subResponse[j++] != '=') {
                                        throw invalidClientMessage();
                                    }
                                    int authzIdStart = j;
                                    while (subResponse[j++] != ',') {}
                                    int authzIdEnd = j - 1;
                                    authorizationID = new String(subResponse, authzIdStart, authzIdEnd - authzIdStart, StandardCharsets.UTF_8);
                                    break;
                                }
                                default: throw invalidClientMessage();
                            }
                            if (DEBUG) System.out.printf("[S] Binding data from client: %s%n", convertToHexString(copyOfRange(subResponse, j, subResponse.length)));
                            // following is the raw channel binding data
                            if (! Arrays2.equals(subResponse, j, bindingData)) {
                                throw new SaslException("Channel binding data mismatch for mechanism " + getMechanismName());
                            }
                            // all clear!
                            break;
                        }
                    }

                    // nonce
                    if (response[i++] != 'r' || response[i++] != '=') {
                        throw invalidClientMessage();
                    }
                    while (response[i++] != ',') {}

                    // proof
                    int s = i - 1; // start of proof
                    if (response[i++] != 'p' || response[i++] != '=') {
                        throw invalidClientMessage();
                    }
                    while (response[i++] != ',' && i < response.length) {}

                    // == verify proof ==

                    // client key
                    byte[] clientKey;
                    mac.reset();
                    mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                    mac.update(Scram.CLIENT_KEY_BYTES);
                    clientKey = mac.doFinal();
                    if (DEBUG) System.out.printf("[S] Client key: %s%n", convertToHexString(clientKey));

                    // stored key
                    byte[] storedKey;
                    messageDigest.reset();
                    messageDigest.update(clientKey);
                    storedKey = messageDigest.digest();
                    if (DEBUG) System.out.printf("[S] Stored key: %s%n", convertToHexString(storedKey));

                    // client signature
                    mac.reset();
                    mac.init(new SecretKeySpec(storedKey, mac.getAlgorithm()));
                    mac.update(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length - clientFirstMessageBareStart);
                    if (DEBUG) System.out.printf("[S] Using client first message: %s%n", convertToHexString(copyOfRange(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length)));
                    mac.update((byte) ',');
                    mac.update(serverFirstMessage);
                    if (DEBUG) System.out.printf("[S] Using server first message: %s%n", convertToHexString(serverFirstMessage));
                    mac.update((byte) ',');
                    mac.update(response, 0, s); // client-final-message-without-proof
                    if (DEBUG) System.out.printf("[S] Using client final message without proof: %s%n", convertToHexString(copyOfRange(response, 0, s)));
                    byte[] clientSignature = mac.doFinal();
                    if (DEBUG) System.out.printf("[S] Client signature: %s%n", convertToHexString(clientSignature));

                    // server key
                    byte[] serverKey;
                    mac.reset();
                    mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                    mac.update(Scram.SERVER_KEY_BYTES);
                    serverKey = mac.doFinal();
                    if (DEBUG) System.out.printf("[S] Server key: %s%n", convertToHexString(serverKey));

                    // server signature
                    byte[] serverSignature;
                    mac.reset();
                    mac.init(new SecretKeySpec(serverKey, mac.getAlgorithm()));
                    mac.update(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length - clientFirstMessageBareStart);
                    mac.update((byte) ',');
                    mac.update(serverFirstMessage);
                    mac.update((byte) ',');
                    mac.update(response, 0, s); // client-final-message-without-proof
                    serverSignature = mac.doFinal();
                    if (DEBUG) System.out.printf("[S] Server signature: %s%n", convertToHexString(serverSignature));

                    if (DEBUG) System.out.printf("[S] Client proof string: %s%n", new String(response, s + 3, i - s - 3, StandardCharsets.UTF_8));
                    b.setLength(0);
                    Base64.base64DecodeStandard(response, s + 3, i - s - 3, b);
                    byte[] recoveredClientProof = b.toArray();
                    if (DEBUG) System.out.printf("[S] Client proof: %s%n", convertToHexString(recoveredClientProof));

                    // now check the proof
                    byte[] recoveredClientKey = clientSignature.clone();
                    ScramUtils.xor(recoveredClientKey, recoveredClientProof);
                    if (DEBUG) System.out.printf("[S] Recovered client key: %s%n", convertToHexString(recoveredClientKey));
                    if (! Arrays.equals(recoveredClientKey, clientKey)) {
                        // bad auth, send error
                        if (sendErrors) {
                            b.setLength(0);
                            b.append("e=invalid-proof");
                            setNegotiationState(FAILED_STATE);
                            return b.toArray();
                        }
                        throw new SaslException("Authentication rejected (invalid proof)");
                    }

                    // == send response ==
                    b.setLength(0);
                    b.append('v').append('=');
                    Base64.base64EncodeStandard(b, new ByteArrayInputStream(serverSignature), true);

                    ok = true;
                    return b.toArray();
                }
                case COMPLETE_STATE: {
                    if (response != null && response.length != 0) {
                        throw new SaslException("Client sent extra response");
                    }
                    ok = true;
                    return null;
                }
                case FAILED_STATE: {
                    throw new SaslException("Authentication failed");
                }
                default: {
                    throw new IllegalStateException();
                }
            }
        } catch (ArrayIndexOutOfBoundsException | InvalidKeyException ignored) {
            throw invalidClientMessage();
        } finally {
            if (! ok) {
                setNegotiationState(FAILED_STATE);
            }
        }
    }

    Random getRandom() {
        return secureRandom != null ? secureRandom : ThreadLocalRandom.current();
    }

    public void dispose() throws SaslException {
        clientFirstMessage = null;
        serverFirstMessage = null;
        state = FAILED_STATE;
        mac.reset();
        messageDigest.reset();
    }

    public boolean isComplete() {
        return state == COMPLETE_STATE;
    }

    static SaslException invalidClientMessage() {
        return new SaslException("Invalid client message");
    }
}
