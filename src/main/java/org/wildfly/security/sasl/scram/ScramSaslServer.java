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
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;

import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.FastUnsupportedCallbackException;
import org.wildfly.security.auth.callback.ParameterCallback;
import org.wildfly.security.password.spec.HashedPasswordAlgorithmSpec;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.sasl.util.AbstractSaslServer;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;
import org.wildfly.security.util.CodePointIterator;

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

    private String userName;
    private String authorizationID;
    private byte[] clientFirstMessage;
    private byte[] serverFirstMessage;
    private byte[] saltedPassword;
    private final boolean sendErrors = false;
    private int clientFirstMessageBareStart;
    private int cbindFlag;

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

    private static final boolean DEBUG = true;

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
                    if (DEBUG) System.out.printf("[S] Client first message: %s%n", ByteIterator.ofBytes(response).hexEncode().drainToString());

                    final ByteStringBuilder b = new ByteStringBuilder();
                    int c;
                    ByteIterator bi = ByteIterator.ofBytes(response);
                    ByteIterator di = bi.delimitedBy(',');
                    CodePointIterator cpi = di.asUtf8String();

                    // == parse message ==

                    // binding type
                    cbindFlag = bi.next();
                    if (cbindFlag == 'p' && plus) {
                        assert bindingType != null; // because {@code plus} is true
                        assert bindingData != null;
                        if (bi.next() != '=') {
                            throw invalidClientMessage();
                        }
                        if (! bindingType.equals(cpi.drainToString())) {
                            // nope, auth must fail because we cannot acquire the same binding
                            throw new SaslException("Channel binding type mismatch between client and server");
                        }
                        bi.next(); // skip delimiter
                    } else if ((cbindFlag == 'y' || cbindFlag == 'n') && !plus) {
                        if (bi.next() != ',') {
                            throw invalidClientMessage();
                        }
                    } else {
                        throw invalidClientMessage();
                    }

                    // authorization ID
                    c = bi.next();
                    if (c == 'a') {
                        if (bi.next() != '=') {
                            throw invalidClientMessage();
                        }
                        authorizationID = cpi.drainToString();
                        bi.next(); // skip delimiter
                    } else if (c != ',') {
                        throw invalidClientMessage();
                    }

                    clientFirstMessageBareStart = bi.offset();

                    // user name
                    if (bi.next() == 'n') {
                        if (bi.next() != '=') {
                            throw invalidClientMessage();
                        }
                        ByteStringBuilder bsb = new ByteStringBuilder();
                        StringPrep.encode(cpi.drainToString(), bsb, StringPrep.PROFILE_SASL_QUERY | StringPrep.UNMAP_SCRAM_LOGIN_CHARS);
                        userName = new String(bsb.toArray(), StandardCharsets.UTF_8);
                        bi.next(); // skip delimiter
                    } else {
                        throw invalidClientMessage();
                    }

                    // random nonce
                    if (bi.next() != 'r' || bi.next() != '=') {
                        throw invalidClientMessage();
                    }
                    byte[] nonce = di.drain();
                    if (DEBUG) System.out.printf("[S] Client nonce: %s%n", ByteIterator.ofBytes(nonce).hexEncode().drainToString());

                    if (bi.hasNext()) {
                        throw invalidClientMessage();
                    }

                    clientFirstMessage = response;

                    // == send first challenge ==

                    // get password

                    final NameCallback nameCallback = new NameCallback("Remote authentication name", userName);

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
                        if (DEBUG) System.out.printf("[S] Salt (pre digested): %s%n", ByteIterator.ofBytes(salt).hexEncode().drainToString());
                        if (iterationCount < minimumIterationCount) {
                            throw new SaslException("Iteration count " + iterationCount + " is below the minimum of " + minimumIterationCount);
                        } else if (iterationCount > maximumIterationCount) {
                            throw new SaslException("Iteration count " + iterationCount + " is above the maximum of " + maximumIterationCount);
                        }
                        if (salt == null) {
                            throw new SaslException("Salt must be specified");
                        }
                        saltedPassword = ((ScramDigestPassword)password).getDigest();
                        if (DEBUG) System.out.printf("[S] Salted password (pre digested): %s%n", ByteIterator.ofBytes(saltedPassword).hexEncode().drainToString());
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
                                salt = ScramUtil.generateSalt(16, getRandom());
                                if (DEBUG) System.out.printf("[S] Salt (random): %s%n", ByteIterator.ofBytes(salt).hexEncode().drainToString());
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
                        if (password == null) {
                            throw new SaslException("No password provided");
                        }
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
                        StringPrep.encode(passwordChars, b, StringPrep.PROFILE_SASL_STORED);
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
                            saltedPassword = ScramUtil.calculateHi(mac, passwordChars, salt, 0, salt.length, iterationCount);
                            if (DEBUG) System.out.printf("[S] Salted password: %s%n", ByteIterator.ofBytes(saltedPassword).hexEncode().drainToString());
                        } catch (InvalidKeyException e) {
                            throw new SaslException("Invalid MAC initialization key");
                        }
                    }

                    // nonce (client + server nonce)
                    b.append('r').append('=');
                    b.append(nonce);
                    b.append(ScramUtil.generateNonce(28, getRandom()));
                    b.append(',');

                    // salt
                    b.append('s').append('=');
                    b.appendLatin1(ByteIterator.ofBytes(salt).base64Encode());
                    b.append(',');
                    b.append('i').append('=');
                    b.append(Integer.toString(iterationCount));

                    setNegotiationState(S_FINAL_MESSAGE);
                    ok = true;
                    return serverFirstMessage = b.toArray();
                }
                case S_FINAL_MESSAGE: {
                    final ByteStringBuilder b = new ByteStringBuilder();

                    ByteIterator bi = ByteIterator.ofBytes(response);
                    ByteIterator di = bi.delimitedBy(',');

                    // == parse message ==

                    // first comes the channel binding
                    if (bi.next() != 'c' || bi.next() != '=') {
                        throw invalidClientMessage();
                    }

                    final ByteIterator bindingIterator = di.base64Decode();

                    // -- sub-parse of binding data --
                    if(bindingIterator.next() != cbindFlag) {
                        throw invalidClientMessage();
                    }
                    switch (cbindFlag) {
                        case 'n': case 'y': { // n,[a=authzid],
                            if (plus) throw new SaslException("Channel binding not provided by client for mechanism " + getMechanismName());

                            parseAuthorizationId(bindingIterator);

                            if (bindingIterator.hasNext()) { // require end
                                throw invalidClientMessage();
                            }
                            break;
                        }
                        case 'p': { // p=bindingType,[a=authzid],bindingData
                            if (! plus) {
                                throw new SaslException("Channel binding not supported for mechanism " + getMechanismName());
                            }
                            if (bindingIterator.next() != '=') {
                                throw invalidClientMessage();
                            }
                            if (! bindingType.equals(bindingIterator.delimitedBy(',').asUtf8String().drainToString())) {
                                throw new SaslException("Channel binding type mismatch for mechanism " + getMechanismName());
                            }
                            parseAuthorizationId(bindingIterator);

                            // following is the raw channel binding data
                            if (! bindingIterator.contentEquals(ByteIterator.ofBytes(bindingData))) {
                                throw new SaslException("Channel binding data mismatch for mechanism " + getMechanismName());
                            }
                            if (bindingIterator.hasNext()) { // require end
                                throw invalidClientMessage();
                            }
                            break;
                        }
                    }
                    bi.next(); // skip delimiter

                    // nonce
                    if (bi.next() != 'r' || bi.next() != '=') {
                        throw invalidClientMessage();
                    }
                    while (di.hasNext()) { di.next(); }

                    // proof
                    final int proofOffset = bi.offset();
                    bi.next(); // skip delimiter
                    if (bi.next() != 'p' || bi.next() != '=') {
                        throw invalidClientMessage();
                    }
                    byte[] recoveredClientProofEncoded = di.drain();
                    if (bi.hasNext()) {
                        throw invalidClientMessage();
                    }

                    // == verify proof ==

                    // client key
                    byte[] clientKey;
                    mac.reset();
                    mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                    mac.update(Scram.CLIENT_KEY_BYTES);
                    clientKey = mac.doFinal();
                    if (DEBUG) System.out.printf("[S] Client key: %s%n", ByteIterator.ofBytes(clientKey).hexEncode().drainToString());

                    // stored key
                    byte[] storedKey;
                    messageDigest.reset();
                    messageDigest.update(clientKey);
                    storedKey = messageDigest.digest();
                    if (DEBUG) System.out.printf("[S] Stored key: %s%n", ByteIterator.ofBytes(storedKey).hexEncode().drainToString());

                    // client signature
                    mac.reset();
                    mac.init(new SecretKeySpec(storedKey, mac.getAlgorithm()));
                    mac.update(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length - clientFirstMessageBareStart);
                    if (DEBUG) System.out.printf("[S] Using client first message: %s%n", ByteIterator.ofBytes(copyOfRange(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length)).hexEncode().drainToString());
                    mac.update((byte) ',');
                    mac.update(serverFirstMessage);
                    if (DEBUG) System.out.printf("[S] Using server first message: %s%n", ByteIterator.ofBytes(serverFirstMessage).hexEncode().drainToString());
                    mac.update((byte) ',');
                    mac.update(response, 0, proofOffset); // client-final-message-without-proof
                    if (DEBUG) System.out.printf("[S] Using client final message without proof: %s%n", ByteIterator.ofBytes(copyOfRange(response, 0, proofOffset)).hexEncode().drainToString());
                    byte[] clientSignature = mac.doFinal();
                    if (DEBUG) System.out.printf("[S] Client signature: %s%n", ByteIterator.ofBytes(clientSignature).hexEncode().drainToString());

                    // server key
                    byte[] serverKey;
                    mac.reset();
                    mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                    mac.update(Scram.SERVER_KEY_BYTES);
                    serverKey = mac.doFinal();
                    if (DEBUG) System.out.printf("[S] Server key: %s%n", ByteIterator.ofBytes(serverKey).hexEncode().drainToString());

                    // server signature
                    byte[] serverSignature;
                    mac.reset();
                    mac.init(new SecretKeySpec(serverKey, mac.getAlgorithm()));
                    mac.update(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length - clientFirstMessageBareStart);
                    mac.update((byte) ',');
                    mac.update(serverFirstMessage);
                    mac.update((byte) ',');
                    mac.update(response, 0, proofOffset); // client-final-message-without-proof
                    serverSignature = mac.doFinal();
                    if (DEBUG) System.out.printf("[S] Server signature: %s%n", ByteIterator.ofBytes(serverSignature).hexEncode().drainToString());

                    if (DEBUG) System.out.printf("[S] Client proof string: %s%n", CodePointIterator.ofUtf8Bytes(recoveredClientProofEncoded).drainToString());
                    b.setLength(0);
                    byte[] recoveredClientProof = ByteIterator.ofBytes(recoveredClientProofEncoded).base64Decode().drain();
                    if (DEBUG) System.out.printf("[S] Client proof: %s%n", ByteIterator.ofBytes(recoveredClientProof).hexEncode().drainToString());

                    // now check the proof
                    byte[] recoveredClientKey = clientSignature.clone();
                    ScramUtil.xor(recoveredClientKey, recoveredClientProof);
                    if (DEBUG) System.out.printf("[S] Recovered client key: %s%n", ByteIterator.ofBytes(recoveredClientKey).hexEncode().drainToString());
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

                    if (authorizationID == null) {
                        authorizationID = userName;
                    }else{
                        ByteStringBuilder bsb = new ByteStringBuilder();
                        StringPrep.encode(authorizationID, bsb, StringPrep.PROFILE_SASL_QUERY | StringPrep.UNMAP_SCRAM_LOGIN_CHARS);
                        authorizationID = new String(bsb.toArray(), StandardCharsets.UTF_8);
                    }
                    final AuthorizeCallback authorizeCallback = new AuthorizeCallback(userName, authorizationID);
                    try {
                        tryHandleCallbacks(authorizeCallback);
                    } catch (UnsupportedCallbackException e) {
                        throw new SaslException("Callback handler does not support authorization", e);
                    }
                    if ( ! authorizeCallback.isAuthorized()) {
                        throw new SaslException(userName + " not authorized to act as " + authorizationID);
                    }

                    // == send response ==
                    b.setLength(0);
                    b.append('v').append('=');
                    b.appendUtf8(ByteIterator.ofBytes(serverSignature).base64Encode());

                    setNegotiationState(COMPLETE_STATE);
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

    private void parseAuthorizationId(ByteIterator bindingIterator) throws SaslException {
        if (bindingIterator.next() != ',') {
            throw invalidClientMessage();
        }
        switch (bindingIterator.next()) {
            case ',':
                if (authorizationID != null) {
                    throw invalidClientMessage();
                }
                break;
            case 'a': {
                if (bindingIterator.next() != '=') {
                    throw invalidClientMessage();
                }
                if (! bindingIterator.delimitedBy(',').asUtf8String().drainToString().equals(authorizationID)) {
                    throw invalidClientMessage();
                }
                if (bindingIterator.next() != ',') {
                    throw invalidClientMessage();
                }
                break;
            }
            default: throw invalidClientMessage();
        }
    }

    Random getRandom() {
        return secureRandom != null ? secureRandom : ThreadLocalRandom.current();
    }

    public void dispose() throws SaslException {
        clientFirstMessage = null;
        serverFirstMessage = null;
        setNegotiationState(FAILED_STATE);
        mac.reset();
        messageDigest.reset();
    }

    static SaslException invalidClientMessage() {
        return new SaslException("Invalid client message");
    }
}
