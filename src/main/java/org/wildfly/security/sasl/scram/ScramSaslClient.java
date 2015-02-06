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

import static org.wildfly.security.sasl.util.HexConverter.convertToHexString;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.SaslException;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.AbstractSaslClient;
import org.wildfly.security.sasl.util.ByteStringBuilder;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteIterator;

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
    private PasswordCallback passwordCallback;
    private int proofStart;
    private byte[] saltedPassword;
    private byte[] serverFirstMessage;

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

    private static final boolean DEBUG = true;

    protected byte[] evaluateMessage(final int state, final byte[] challenge) throws SaslException {
        switch (state) {
            case ST_NEW: {
                // initial response
                if (challenge.length != 0) throw new SaslException("Initial challenge must be empty");
                final ByteStringBuilder b = new ByteStringBuilder();
                final String authorizationId = getAuthorizationId();
                final NameCallback nameCallback = authorizationId == null ? new NameCallback("User name") : new NameCallback("User name", authorizationId);
                handleCallbacks(nameCallback, passwordCallback = new PasswordCallback("Password", false));
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
                b.append(nonce = ScramUtil.generateRandomString(48, random));
                if (DEBUG) System.out.printf("[C] Client nonce: %s%n", convertToHexString(nonce));
                setNegotiationState(ST_R1_SENT);
                if (DEBUG) System.out.printf("[C] Client first message: %s%n", convertToHexString(b.toArray()));
                return clientFirstMessage = b.toArray();
            }
            case ST_R1_SENT: {
                serverFirstMessage = challenge;
                final ByteIterator bi = ByteIterator.ofBytes(challenge);
                final ByteIterator di = bi.delimitedBy(',');
                if (DEBUG) System.out.printf("[C] Server first message: %s%n", convertToHexString(challenge));
                final ByteStringBuilder b = new ByteStringBuilder();
                final Mac mac = ScramSaslClient.this.mac;
                final MessageDigest messageDigest = ScramSaslClient.this.messageDigest;
                try {
                    if (bi.next() == 'r' && bi.next() == '=') {
                        // nonce
                        if (! di.limitedTo(nonce.length).contentEquals(ByteIterator.ofBytes(nonce))) {
                            throw new SaslException("Nonces do not match");
                        }
                        final byte[] serverNonce = di.drain();
                        if (serverNonce.length < 18) {
                            throw new SaslException("Server nonce is too short");
                        }
                        bi.next(); // skip delimiter
                        if (bi.next() == 's' && bi.next() == '=') {
                            final byte[] salt = di.base64Decode().drain();
                            bi.next(); // skip delimiter
                            if (DEBUG) System.out.printf("[C] Server sent salt: %s%n", convertToHexString(salt));
                            if (bi.next() == 'i' && bi.next() == '=') {
                                final int iterationCount = ScramUtil.parsePosInt(di);
                                if (iterationCount < minimumIterationCount) {
                                    throw new SaslException("Iteration count is too low");
                                } else if (iterationCount > maximumIterationCount) {
                                    throw new SaslException("Iteration count is too high");
                                }
                                if (bi.hasNext()) {
                                    if (bi.next() == ',') {
                                        throw new SaslException("Extensions unsupported");
                                    } else {
                                        throw new SaslException("Invalid server message");
                                    }
                                }
                                // client-final-message
                                // binding data
                                b.append('c').append('=');
                                ByteStringBuilder b2 = new ByteStringBuilder();
                                if (bindingData != null) {
                                    if (DEBUG) System.out.printf("[C] Binding data: %s%n", convertToHexString(bindingData));
                                    if (plus) {
                                        b2.append("p=");
                                        b2.append(bindingType);
                                    } else {
                                        b2.append('y');
                                    }
                                    b2.append(',');
                                    if (getAuthorizationId() != null) {
                                        b2.append("a=").append(getAuthorizationId());
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
                                        b2.append("a=").append(getAuthorizationId());
                                    }
                                    b2.append(',');
                                    assert !plus;
                                    b.appendLatin1(b2.iterate().base64Encode());
                                }
                                // nonce
                                b.append(',').append('r').append('=').append(nonce).append(serverNonce);
                                // no extensions
                                this.saltedPassword = ScramUtil.calculateHi(mac, passwordCallback.getPassword(), salt, 0, salt.length, iterationCount);
                                if (DEBUG) System.out.printf("[C] Client salted password: %s%n", convertToHexString(saltedPassword));
                                mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                                final byte[] clientKey = mac.doFinal(Scram.CLIENT_KEY_BYTES);
                                if (DEBUG) System.out.printf("[C] Client key: %s%n", convertToHexString(clientKey));
                                final byte[] storedKey = messageDigest.digest(clientKey);
                                if (DEBUG) System.out.printf("[C] Stored key: %s%n", convertToHexString(storedKey));
                                mac.init(new SecretKeySpec(storedKey, mac.getAlgorithm()));
                                mac.update(clientFirstMessage, bareStart, clientFirstMessage.length - bareStart);
                                if (DEBUG) System.out.printf("[C] Using client first message: %s%n", convertToHexString(Arrays.copyOfRange(clientFirstMessage, bareStart, clientFirstMessage.length)));
                                mac.update((byte) ',');
                                mac.update(challenge);
                                if (DEBUG) System.out.printf("[C] Using server first message: %s%n", convertToHexString(challenge));
                                mac.update((byte) ',');
                                b.updateMac(mac);
                                if (DEBUG) System.out.printf("[C] Using client final message without proof: %s%n", convertToHexString(b.toArray()));
                                final byte[] clientProof = mac.doFinal();
                                if (DEBUG) System.out.printf("[C] Client signature: %s%n", convertToHexString(clientProof));
                                ScramUtil.xor(clientProof, clientKey);
                                if (DEBUG) System.out.printf("[C] Client proof: %s%n", convertToHexString(clientProof));
                                this.proofStart = b.length();
                                // proof
                                b.append(',').append('p').append('=');
                                b.appendLatin1(ByteIterator.ofBytes(clientProof).base64Encode());
                                setNegotiationState(ST_R2_SENT);
                                if (DEBUG) System.out.printf("[C] Client final message: %s%n", convertToHexString(b.toArray()));
                                return clientFinalMessage = b.toArray();
                            }
                        }
                    }
                } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException | InvalidKeyException ignored) {
                    throw new SaslException("Invalid server message");
                } finally {
                    messageDigest.reset();
                    mac.reset();
                }
                throw new SaslException("Invalid server message");
            }
            case ST_R2_SENT: {
                if (DEBUG) System.out.printf("[C] Server final message: %s%n", new String(challenge, StandardCharsets.UTF_8));
                final Mac mac = ScramSaslClient.this.mac;
                final MessageDigest messageDigest = ScramSaslClient.this.messageDigest;
                final ByteIterator bi = ByteIterator.ofBytes(challenge);
                final ByteIterator di = bi.delimitedBy(',');
                int c;
                try {
                    c = bi.next();
                    if (c == 'e') {
                        if (bi.next() == '=') {
                            throw new SaslException("Server rejected authentication: " + di.asUtf8String().drainToString());
                        }
                        throw new SaslException("Server rejected authentication");
                    } else if (c == 'v' && bi.next() == '=') {
                        // verify server signature
                        mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
                        byte[] serverKey = mac.doFinal(Scram.SERVER_KEY_BYTES);
                        if (DEBUG) System.out.printf("[C] Server key: %s%n", convertToHexString(serverKey));
                        mac.init(new SecretKeySpec(serverKey, mac.getAlgorithm()));
                        mac.update(clientFirstMessage, bareStart, clientFirstMessage.length - bareStart);
                        mac.update((byte) ',');
                        mac.update(serverFirstMessage);
                        mac.update((byte) ',');
                        mac.update(clientFinalMessage, 0, proofStart);
                        byte[] serverSignature = mac.doFinal();
                        if (DEBUG) System.out.printf("[C] Recovered server signature: %s%n", convertToHexString(serverSignature));
                        if (! di.base64Decode().contentEquals(ByteIterator.ofBytes(serverSignature))) {
                            setNegotiationState(FAILED_STATE);
                            throw new SaslException("Server authenticity cannot be verified");
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
                throw new SaslException("Invalid server message");
            }
            default: throw new IllegalStateException();
        }
    }
}
