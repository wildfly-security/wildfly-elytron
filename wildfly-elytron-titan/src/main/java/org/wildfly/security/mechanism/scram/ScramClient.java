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

package org.wildfly.security.mechanism.scram;

import static org.wildfly.security._private.ElytronMessages.saslScram;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.mechanism._private.MechanismUtil;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.DecodeException;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ScramClient {
    private final Supplier<Provider[]> providers;
    private final ScramMechanism mechanism;
    private final String authorizationId;
    private final CallbackHandler callbackHandler;
    private final SecureRandom secureRandom;
    private final byte[] bindingData;
    private final String bindingType;
    private final int minimumIterationCount;
    private final int maximumIterationCount;

    ScramClient(final ScramMechanism mechanism, final String authorizationId, final CallbackHandler callbackHandler, final SecureRandom secureRandom, final byte[] bindingData, final String bindingType, final int minimumIterationCount, final int maximumIterationCount, final Supplier<Provider[]> providers) {
        this.mechanism = mechanism;
        this.authorizationId = authorizationId;
        this.callbackHandler = callbackHandler;
        this.secureRandom = secureRandom;
        this.bindingData = bindingData;
        this.bindingType = bindingType;
        this.minimumIterationCount = minimumIterationCount;
        this.maximumIterationCount = maximumIterationCount;
        this.providers = providers;
    }

    Random getRandom() {
        return secureRandom != null ? secureRandom : ThreadLocalRandom.current();
    }

    public ScramMechanism getMechanism() {
        return mechanism;
    }

    public String getAuthorizationId() {
        return authorizationId;
    }

    public String getBindingType() {
        return bindingType;
    }

    byte[] getRawBindingData() {
        return bindingData;
    }

    public byte[] getBindingData() {
        final byte[] bindingData = this.bindingData;
        return bindingData == null ? null : bindingData.clone();
    }

    /**
     * Create an initial response.  This will cause the callback handler to be initialized with an authentication name.
     *
     * @return the initial response to send to the server
     * @throws AuthenticationMechanismException if the client authentication failed for some reason
     */
    public ScramInitialClientMessage getInitialResponse() throws AuthenticationMechanismException {
        final NameCallback nameCallback = authorizationId == null || authorizationId.isEmpty() ?
                new NameCallback("User name") : new NameCallback("User name", authorizationId);
        try {
            MechanismUtil.handleCallbacks(saslScram, callbackHandler, nameCallback);
        } catch (UnsupportedCallbackException e) {
            throw saslScram.mechCallbackHandlerDoesNotSupportUserName(e);
        }
        final String name = nameCallback.getName();
        if (name == null) {
            throw saslScram.mechNoLoginNameGiven();
        }
        final ByteStringBuilder encoded = new ByteStringBuilder();
        final boolean binding;
        if (bindingData != null) {
            binding = true;
            if (mechanism.isPlus()) {
                encoded.append("p=");
                encoded.append(bindingType);
                encoded.append(',');
            } else {
                encoded.append("y,");
            }
        } else {
            binding = false;
            encoded.append("n,");
        }
        if (authorizationId != null) {
            encoded.append('a').append('=');
            StringPrep.encode(authorizationId, encoded, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
        }
        encoded.append(',');
        final int initialPartIndex = encoded.length();
        encoded.append('n').append('=');
        StringPrep.encode(name, encoded, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
        encoded.append(',').append('r').append('=');
        final byte[] nonce = ScramUtil.generateNonce(48, getRandom());
        encoded.append(nonce);

        return new ScramInitialClientMessage(this, name, binding, nonce, initialPartIndex, encoded.toArray());
    }

    public ScramInitialServerMessage parseInitialServerMessage(final ScramInitialClientMessage initialResponse, final byte[] bytes) throws AuthenticationMechanismException {
        final byte[] challenge = bytes.clone();
        final ByteIterator bi = ByteIterator.ofBytes(challenge);
        final byte[] serverNonce;
        final byte[] salt;
        final int iterationCount;
        try {
            if (bi.peekNext() == 'e') {
                bi.next();
                if (bi.next() == '=') {
                    throw saslScram.scramServerRejectedAuthentication(ScramServerErrorCode.fromErrorString(bi.delimitedBy(',').asUtf8String().drainToString()));
                }
                throw saslScram.mechInvalidMessageReceived();
            }
            if (bi.next() != 'r' || bi.next() != '=') {
                throw saslScram.mechInvalidMessageReceived();
            }
            final byte[] clientNonce = initialResponse.getRawNonce();
            if (! bi.limitedTo(clientNonce.length).contentEquals(ByteIterator.ofBytes(clientNonce))) {
                throw saslScram.mechNoncesDoNotMatch();
            }
            serverNonce = bi.delimitedBy(',').drain();
            bi.next(); // it's a ,
            if (bi.next() != 's' || bi.next() != '=') {
                throw saslScram.mechInvalidMessageReceived();
            }
            salt = bi.delimitedBy(',').asUtf8String().base64Decode().drain();
            bi.next(); // it's a ,
            if (bi.next() != 'i' || bi.next() != '=') {
                throw saslScram.mechInvalidMessageReceived();
            }
            iterationCount = ScramUtil.parsePosInt(bi);
            if (iterationCount < minimumIterationCount) {
                throw saslScram.mechIterationCountIsTooLow(iterationCount, minimumIterationCount);
            }
            if (iterationCount > maximumIterationCount) {
                throw saslScram.mechIterationCountIsTooHigh(iterationCount, maximumIterationCount);
            }
        } catch (NoSuchElementException | DecodeException | NumberFormatException ex) {
            throw saslScram.mechInvalidMessageReceived();
        }
        return new ScramInitialServerMessage(initialResponse, serverNonce, salt, iterationCount, challenge);
    }

    public ScramFinalClientMessage handleInitialChallenge(ScramInitialClientMessage initialResponse, ScramInitialServerMessage initialChallenge) throws AuthenticationMechanismException {
        boolean trace = saslScram.isTraceEnabled();

        if (initialResponse.getMechanism() != mechanism) {
            throw saslScram.mechUnmatchedMechanism(mechanism.toString(), initialResponse.getMechanism().toString());
        }
        if (initialChallenge.getMechanism() != mechanism) {
            throw saslScram.mechUnmatchedMechanism(mechanism.toString(), initialChallenge.getMechanism().toString());
        }

        final boolean plus = mechanism.isPlus();

        final ByteStringBuilder encoded = new ByteStringBuilder();
        encoded.append('c').append('=');
        ByteStringBuilder b2 = new ByteStringBuilder();
        if (bindingData != null) {
            if(trace) saslScram.tracef("[C] Binding data: %s%n", ByteIterator.ofBytes(bindingData).hexEncode().drainToString());
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
            encoded.appendLatin1(b2.iterate().base64Encode());
        } else {
            b2.append('n');
            b2.append(',');
            if (getAuthorizationId() != null) {
                b2.append("a=");
                StringPrep.encode(getAuthorizationId(), b2, StringPrep.PROFILE_SASL_STORED | StringPrep.MAP_SCRAM_LOGIN_CHARS);
            }
            b2.append(',');
            assert !plus;
            encoded.appendLatin1(b2.iterate().base64Encode());
        }
        // nonce
        encoded.append(',').append('r').append('=').append(initialResponse.getRawNonce()).append(initialChallenge.getRawServerNonce());
        // no extensions

        final IteratedSaltedPasswordAlgorithmSpec parameters = new IteratedSaltedPasswordAlgorithmSpec(
            initialChallenge.getIterationCount(),
            initialChallenge.getRawSalt()
        );
        ScramDigestPassword password = MechanismUtil.getPasswordCredential(
            initialResponse.getAuthenticationName(),
            callbackHandler,
            ScramDigestPassword.class,
            mechanism.getPasswordAlgorithm(),
            parameters,
            parameters,
            providers,
            saslScram);
        final byte[] saltedPassword = password.getDigest();
        if (trace) saslScram.tracef("[C] Client salted password: %s", ByteIterator.ofBytes(saltedPassword).hexEncode().drainToString());

        try {
            final Mac mac = Mac.getInstance(getMechanism().getHmacName());
            final MessageDigest messageDigest = MessageDigest.getInstance(getMechanism().getMessageDigestName());

            mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
            final byte[] clientKey = mac.doFinal(ScramUtil.CLIENT_KEY_BYTES);
            if(trace) saslScram.tracef("[C] Client key: %s", ByteIterator.ofBytes(clientKey).hexEncode().drainToString());
            final byte[] storedKey = messageDigest.digest(clientKey);
            if(trace) saslScram.tracef("[C] Stored key: %s%n", ByteIterator.ofBytes(storedKey).hexEncode().drainToString());
            mac.init(new SecretKeySpec(storedKey, mac.getAlgorithm()));
            final byte[] initialResponseBytes = initialResponse.getRawMessageBytes();
            mac.update(initialResponseBytes, initialResponse.getInitialPartIndex(), initialResponseBytes.length - initialResponse.getInitialPartIndex());
            if (trace) saslScram.tracef("[C] Using client first message: %s%n", ByteIterator.ofBytes(initialResponseBytes, initialResponse.getInitialPartIndex(), initialResponseBytes.length - initialResponse.getInitialPartIndex()).hexEncode().drainToString());
            mac.update((byte) ',');
            mac.update(initialChallenge.getRawMessageBytes());
            if(trace) saslScram.tracef("[C] Using server first message: %s%n", ByteIterator.ofBytes(initialChallenge.getRawMessageBytes()).hexEncode().drainToString());
            mac.update((byte) ',');
            encoded.updateMac(mac);
            if(trace) saslScram.tracef("[C] Using client final message without proof: %s%n", ByteIterator.ofBytes(encoded.toArray()).hexEncode().drainToString());
            final byte[] clientProof = mac.doFinal();
            if(trace) saslScram.tracef("[C] Client signature: %s%n", ByteIterator.ofBytes(clientProof).hexEncode().drainToString());
            ScramUtil.xor(clientProof, clientKey);
            if(trace) saslScram.tracef("[C] Client proof: %s%n", ByteIterator.ofBytes(clientProof).hexEncode().drainToString());
            int proofStart = encoded.length();
            // proof
            encoded.append(',').append('p').append('=');
            encoded.appendLatin1(ByteIterator.ofBytes(clientProof).base64Encode());
            if(trace) saslScram.tracef("[C] Client final message: %s%n", ByteIterator.ofBytes(encoded.toArray()).hexEncode().drainToString());
            return new ScramFinalClientMessage(initialResponse, initialChallenge, password, clientProof, encoded.toArray(), proofStart);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw saslScram.mechMacAlgorithmNotSupported(e);
        }
    }

    public ScramFinalServerMessage parseFinalServerMessage(final byte[] messageBytes) throws AuthenticationMechanismException {
        final ByteIterator bi = ByteIterator.ofBytes(messageBytes);
        final byte[] sig;
        try {
            int c = bi.next();
            if (c == 'e') {
                if (bi.next() == '=') {
                    throw saslScram.scramServerRejectedAuthentication(ScramServerErrorCode.fromErrorString(bi.delimitedBy(',').asUtf8String().drainToString()));
                }
                throw saslScram.mechInvalidMessageReceived();
            } else if (c == 'v' && bi.next() == '=') {
                sig = bi.delimitedBy(',').asUtf8String().base64Decode().drain();
            } else {
                throw saslScram.mechInvalidMessageReceived();
            }
            if (bi.hasNext()) {
                throw saslScram.mechInvalidMessageReceived();
            }
        } catch (IllegalArgumentException e) {
            throw saslScram.mechInvalidMessageReceived();
        }
        return new ScramFinalServerMessage(sig, messageBytes);
    }

    public void verifyFinalChallenge(final ScramFinalClientMessage finalResponse, final ScramFinalServerMessage finalChallenge) throws AuthenticationMechanismException {
        boolean trace = saslScram.isTraceEnabled();

        try {
            final Mac mac = Mac.getInstance(getMechanism().getHmacName());

            // verify server signature
            ScramDigestPassword password = finalResponse.getPassword();
            mac.init(new SecretKeySpec(password.getDigest(), mac.getAlgorithm()));
            byte[] serverKey = mac.doFinal(ScramUtil.SERVER_KEY_BYTES);
            if(trace) saslScram.tracef("[C] Server key: %s%n", ByteIterator.ofBytes(serverKey).hexEncode().drainToString());
            mac.init(new SecretKeySpec(serverKey, mac.getAlgorithm()));
            byte[] clientFirstMessage = finalResponse.getInitialResponse().getRawMessageBytes();
            int bareStart = finalResponse.getInitialResponse().getInitialPartIndex();
            mac.update(clientFirstMessage, bareStart, clientFirstMessage.length - bareStart);
            mac.update((byte) ',');
            byte[] serverFirstMessage = finalResponse.getInitialChallenge().getRawMessageBytes();
            mac.update(serverFirstMessage);
            mac.update((byte) ',');
            byte[] clientFinalMessage = finalResponse.getRawMessageBytes();
            mac.update(clientFinalMessage, 0, finalResponse.getProofOffset());
            byte[] serverSignature = mac.doFinal();
            if(trace) saslScram.tracef("[C] Recovered server signature: %s%n", ByteIterator.ofBytes(serverSignature).hexEncode().drainToString());
            if (! Arrays.equals(finalChallenge.getRawServerSignature(), serverSignature)) {
                throw saslScram.mechServerAuthenticityCannotBeVerified();
            }
        } catch (IllegalArgumentException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw saslScram.mechMacAlgorithmNotSupported(e);
        }
    }
}
