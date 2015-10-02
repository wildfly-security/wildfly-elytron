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

import static org.wildfly.security._private.ElytronMessages.log;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.AbstractSaslClient;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class ScramSaslClient extends AbstractSaslClient {

    private static final int ST_NEW = 1;
    private static final int ST_R1_SENT = 2;
    private static final int ST_R2_SENT = 3;

    private final int minimumIterationCount;
    private final int maximumIterationCount;
    private final MessageDigest messageDigest;
    private final Mac mac;
    private final SecureRandom secureRandom;
    private final boolean plus;
    private final byte[] bindingData;
    private final String bindingType;
    private byte[] clientFirstMessage;
    private int bareStart;
    private byte[] clientFinalMessage;
    private byte[] nonce;
    private int proofStart;
    private byte[] saltedPassword;
    private byte[] serverFirstMessage;
    private char[] clearPassword = null;

    ScramSaslClient(final String mechanismName, final MessageDigest messageDigest, final Mac mac, final SecureRandom secureRandom, final String protocol, final String serverName, final CallbackHandler callbackHandler, final String authorizationId, final Map<String, ?> props, final boolean plus, final String bindingType, final byte[] bindingData) {
        super(mechanismName, protocol, serverName, callbackHandler, authorizationId, true);
        this.bindingType = bindingType;
        minimumIterationCount = getIntProperty(props, WildFlySasl.SCRAM_MIN_ITERATION_COUNT, 4096);
        maximumIterationCount = getIntProperty(props, WildFlySasl.SCRAM_MAX_ITERATION_COUNT, 32768);
        this.secureRandom = secureRandom;
        this.messageDigest = messageDigest;
        this.mac = mac;
        this.plus = plus;
        this.bindingData = bindingData;
    }

    MessageDigest getMessageDigest() {
        return messageDigest;
    }

    public void dispose() throws SaslException {
        messageDigest.reset();
        setNegotiationState(FAILED_STATE);
    }

    public void init() {
        setNegotiationState(ST_NEW);
    }

    protected byte[] evaluateMessage(final int state, final byte[] challenge) throws SaslException {
        boolean trace = log.isTraceEnabled();
        switch (state) {
            case ST_NEW: {
                // initial response
                if (challenge.length != 0) throw log.mechInitialChallengeMustBeEmpty(getMechanismName()).toSaslException();
                final ByteStringBuilder b = new ByteStringBuilder();
                final String authorizationId = getAuthorizationId();
                final NameCallback nameCallback = authorizationId == null ? new NameCallback("User name") : new NameCallback("User name", authorizationId);
                final CredentialCallback twoWayCredentialCallback = new CredentialCallback(Collections.singletonMap(TwoWayPassword.class, Collections.emptySet()));
                final PasswordCallback passwordCallback = new PasswordCallback("User password", false);

                try {
                    tryHandleCallbacks(nameCallback, passwordCallback);
                    clearPassword = passwordCallback.getPassword();
                    passwordCallback.clearPassword();
                } catch (UnsupportedCallbackException e) {
                    // clear credential if clear password not supported
                    if (e.getCallback() == passwordCallback) {
                        handleCallbacks(nameCallback, twoWayCredentialCallback);
                        clearPassword = ScramUtil.getTwoWayPasswordChars(getMechanismName(), (TwoWayPassword) twoWayCredentialCallback.getCredential());
                    } else {
                        throw log.mechCallbackHandlerFailedForUnknownReason(getMechanismName(), e).toSaslException();
                    }
                }
                if(clearPassword == null){
                    throw log.mechNoPasswordGiven(getMechanismName()).toSaslException();
                }

                // gs2-cbind-flag
                if (bindingData != null) {
                    if (plus) {
                        b.append("p=");
                        b.append(bindingType);
                        b.append(',');
                    } else {
                        b.append("y,");
                    }
                } else {
                    b.append("n,");
                }
                if (authorizationId != null) {
                    b.append('a').append('=');
                    StringPrep.encode(authorizationId, b, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
                }
                b.append(',');
                bareStart = b.length();
                b.append('n').append('=');
                StringPrep.encode(nameCallback.getName(), b, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
                b.append(',').append('r').append('=');
                Random random = secureRandom != null ? secureRandom : ThreadLocalRandom.current();
                b.append(nonce = ScramUtil.generateNonce(48, random));
                if(trace) log.tracef("[C] Client nonce: %s%n", ByteIterator.ofBytes(nonce).hexEncode().drainToString());
                setNegotiationState(ST_R1_SENT);
                if(trace) log.tracef("[C] Client first message: %s%n", ByteIterator.ofBytes(b.toArray()).hexEncode().drainToString());
                return clientFirstMessage = b.toArray();
            }
            case ST_R1_SENT: {
                serverFirstMessage = challenge;
                final ByteIterator bi = ByteIterator.ofBytes(challenge);
                final ByteIterator di = bi.delimitedBy(',');
                if(trace) log.tracef("[C] Server first message: %s%n", ByteIterator.ofBytes(challenge).hexEncode().drainToString());
                final ByteStringBuilder b = new ByteStringBuilder();
                final Mac mac = ScramSaslClient.this.mac;
                final MessageDigest messageDigest = ScramSaslClient.this.messageDigest;
                try {
                    if (bi.next() == 'r' && bi.next() == '=') {
                        // nonce
                        if (! di.limitedTo(nonce.length).contentEquals(ByteIterator.ofBytes(nonce))) {
                            throw log.mechNoncesDoNotMatch(getMechanismName()).toSaslException();
                        }
                        final byte[] serverNonce = di.drain();
                        if (serverNonce.length < 18) {
                            throw log.mechServerNonceIsTooShort(getMechanismName()).toSaslException();
                        }
                        bi.next(); // skip delimiter
                        if (bi.next() == 's' && bi.next() == '=') {
                            final byte[] salt = di.base64Decode().drain();
                            bi.next(); // skip delimiter
                            if(trace) log.tracef("[C] Server sent salt: %s%n", ByteIterator.ofBytes(salt).hexEncode().drainToString());
                            if (bi.next() == 'i' && bi.next() == '=') {
                                final int iterationCount = ScramUtil.parsePosInt(di);
                                if (iterationCount < minimumIterationCount) {
                                    throw log.mechIterationCountIsTooLow(getMechanismName(), iterationCount, minimumIterationCount).toSaslException();
                                } else if (iterationCount > maximumIterationCount) {
                                    throw log.mechIterationCountIsTooHigh(getMechanismName(), iterationCount, maximumIterationCount).toSaslException();
                                }
                                if (bi.hasNext()) {
                                    if (bi.next() == ',') {
                                        throw log.mechExtensionsUnsupported(getMechanismName()).toSaslException();
                                    } else {
                                        throw log.mechInvalidServerMessage(getMechanismName()).toSaslException();
                                    }
                                }
                                // client-final-message
                                // binding data
                                b.append('c').append('=');
                                ByteStringBuilder b2 = new ByteStringBuilder();
                                if (bindingData != null) {
                                    if(trace) log.tracef("[C] Binding data: %s%n", ByteIterator.ofBytes(bindingData).hexEncode().drainToString());
                                    if (plus) {
                                        b2.append("p=");
                                        b2.append(bindingType);
                                    } else {
                                        b2.append('y');
                                    }
                                    b2.append(',');
                                    if (getAuthorizationId() != null) {
                                        b2.append("a=");
                                        StringPrep.encode(getAuthorizationId(), b2, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
                                    }
                                    b2.append(',');
                                    if (plus) {
                                        b2.append(bindingData);
                                    }
                                    b.appendLatin1(b2.iterate().base64Encode());
                                } else {
                                    b2.append('n');
                                    b2.append(',');
                                    if (getAuthorizationId() != null) {
                                        b2.append("a=");
                                        StringPrep.encode(getAuthorizationId(), b2, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
                                    }
                                    b2.append(',');
                                    assert !plus;
                                    b.appendLatin1(b2.iterate().base64Encode());
                                }
                                // nonce
                                b.append(',').append('r').append('=').append(nonce).append(serverNonce);
                                // no extensions

                                saltedPassword = ScramUtil.calculateHi(mac, clearPassword, salt, 0, salt.length, iterationCount);
                                if (trace) log.tracef("[C] Client salted password: %s%n", ByteIterator.ofBytes(saltedPassword).hexEncode().drainToString());
                                mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                                final byte[] clientKey = mac.doFinal(Scram.CLIENT_KEY_BYTES);
                                if(trace) log.tracef("[C] Client key: %s%n", ByteIterator.ofBytes(clientKey).hexEncode().drainToString());
                                final byte[] storedKey = messageDigest.digest(clientKey);
                                if(trace) log.tracef("[C] Stored key: %s%n", ByteIterator.ofBytes(storedKey).hexEncode().drainToString());
                                mac.init(new SecretKeySpec(storedKey, mac.getAlgorithm()));
                                mac.update(clientFirstMessage, bareStart, clientFirstMessage.length - bareStart);
                                if(trace) log.tracef("[C] Using client first message: %s%n", ByteIterator.ofBytes(Arrays.copyOfRange(clientFirstMessage, bareStart, clientFirstMessage.length)).hexEncode().drainToString());
                                mac.update((byte) ',');
                                mac.update(challenge);
                                if(trace) log.tracef("[C] Using server first message: %s%n", ByteIterator.ofBytes(challenge).hexEncode().drainToString());
                                mac.update((byte) ',');
                                b.updateMac(mac);
                                if(trace) log.tracef("[C] Using client final message without proof: %s%n", ByteIterator.ofBytes(b.toArray()).hexEncode().drainToString());
                                final byte[] clientProof = mac.doFinal();
                                if(trace) log.tracef("[C] Client signature: %s%n", ByteIterator.ofBytes(clientProof).hexEncode().drainToString());
                                ScramUtil.xor(clientProof, clientKey);
                                if(trace) log.tracef("[C] Client proof: %s%n", ByteIterator.ofBytes(clientProof).hexEncode().drainToString());
                                this.proofStart = b.length();
                                // proof
                                b.append(',').append('p').append('=');
                                b.appendLatin1(ByteIterator.ofBytes(clientProof).base64Encode());
                                setNegotiationState(ST_R2_SENT);
                                if(trace) log.tracef("[C] Client final message: %s%n", ByteIterator.ofBytes(b.toArray()).hexEncode().drainToString());
                                return clientFinalMessage = b.toArray();
                            }
                        }
                    }
                } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException | InvalidKeyException ignored) {
                    throw log.mechInvalidServerMessage(getMechanismName()).toSaslException();
                } finally {
                    Arrays.fill(clearPassword, (char)0); // wipe out the password
                    messageDigest.reset();
                    mac.reset();
                }
                throw log.mechInvalidServerMessage(getMechanismName()).toSaslException();
            }
            case ST_R2_SENT: {
                if(trace) log.tracef("[C] Server final message: %s%n", new String(challenge, StandardCharsets.UTF_8));
                final Mac mac = ScramSaslClient.this.mac;
                final MessageDigest messageDigest = ScramSaslClient.this.messageDigest;
                final ByteIterator bi = ByteIterator.ofBytes(challenge);
                final ByteIterator di = bi.delimitedBy(',');
                int c;
                try {
                    c = bi.next();
                    if (c == 'e') {
                        if (bi.next() == '=') {
                            throw log.mechServerRejectedAuthentication(di.asUtf8String().drainToString()).toSaslException();
                        }
                        throw log.mechServerRejectedAuthentication(getMechanismName()).toSaslException();
                    } else if (c == 'v' && bi.next() == '=') {
                        // verify server signature
                        mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                        byte[] serverKey = mac.doFinal(Scram.SERVER_KEY_BYTES);
                        if(trace) log.tracef("[C] Server key: %s%n", ByteIterator.ofBytes(serverKey).hexEncode().drainToString());
                        mac.init(new SecretKeySpec(serverKey, mac.getAlgorithm()));
                        mac.update(clientFirstMessage, bareStart, clientFirstMessage.length - bareStart);
                        mac.update((byte) ',');
                        mac.update(serverFirstMessage);
                        mac.update((byte) ',');
                        mac.update(clientFinalMessage, 0, proofStart);
                        byte[] serverSignature = mac.doFinal();
                        if(trace) log.tracef("[C] Recovered server signature: %s%n", ByteIterator.ofBytes(serverSignature).hexEncode().drainToString());
                        if (! di.base64Decode().contentEquals(ByteIterator.ofBytes(serverSignature))) {
                            setNegotiationState(FAILED_STATE);
                            throw log.mechServerAuthenticityCannotBeVerified(getMechanismName()).toSaslException();
                        }
                        setNegotiationState(COMPLETE_STATE);
                        return null; // done
                    }
                } catch (IllegalArgumentException | InvalidKeyException ignored) {
                } finally {
                    messageDigest.reset();
                    mac.reset();
                }
                setNegotiationState(FAILED_STATE);
                throw log.mechInvalidServerMessage(getMechanismName()).toSaslException();
            }
        }
        throw Assert.impossibleSwitchCase(state);
    }
}
