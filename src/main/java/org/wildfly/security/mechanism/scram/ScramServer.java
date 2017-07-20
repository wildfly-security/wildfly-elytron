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

import static java.lang.Math.max;
import static java.lang.Math.min;
import static java.util.Arrays.copyOfRange;
import static org.wildfly.security._private.ElytronMessages.log;

import java.nio.charset.StandardCharsets;
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
import javax.security.sasl.AuthorizeCallback;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.mechanism.MechanismUtil;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.spec.IteratedPasswordAlgorithmSpec;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ScramServer {
    private final Supplier<Provider[]> providers;
    private final ScramMechanism mechanism;
    private final CallbackHandler callbackHandler;
    private final SecureRandom random;
    private final byte[] bindingData;
    private final String bindingType;
    private final int minimumIterationCount;
    private final int maximumIterationCount;

    ScramServer(final ScramMechanism mechanism, final CallbackHandler callbackHandler, final SecureRandom random, final byte[] bindingData, final String bindingType, final int minimumIterationCount, final int maximumIterationCount, final Supplier<Provider[]> providers) {
        this.mechanism = mechanism;
        this.callbackHandler = callbackHandler;
        this.random = random;
        this.bindingData = bindingData;
        this.bindingType = bindingType;
        this.minimumIterationCount = minimumIterationCount;
        this.maximumIterationCount = maximumIterationCount;
        this.providers = providers;
    }

    /**
     * Construct an initial response object from a byte array.
     *
     * @param bindingCallback the optional channel binding callback result (may be {@code null})
     * @param bytes the message bytes (must not be {@code null})
     * @return the constructed initial response (not {@code null})
     * @throws AuthenticationMechanismException if the content of the message is invalid
     */
    public ScramInitialClientMessage parseInitialClientMessage(ChannelBindingCallback bindingCallback, byte[] bytes) throws AuthenticationMechanismException {
        byte[] response = bytes.clone();
        ByteIterator bi = ByteIterator.ofBytes(response);
        try {
            final char cbindFlag = (char) bi.next();
            final boolean binding;
            final String bindingType;
            final byte[] bindingData;
            if (bindingCallback != null) {
                bindingType = bindingCallback.getBindingType();
                bindingData = bindingCallback.getBindingData();
            } else {
                bindingType = null;
                bindingData = null;
            }
            if (cbindFlag == 'p') {
                if (! mechanism.isPlus()) {
                    throw new ScramServerException(log.mechChannelBindingNotSupported(mechanism.toString()), ScramServerErrorCode.SERVER_DOES_NOT_SUPPORT_CHANNEL_BINDING);
                }
                if (bindingType == null || bindingData == null) {
                    throw new ScramServerException(log.mechChannelBindingNotProvided(mechanism.toString()), ScramServerErrorCode.CHANNEL_BINDING_NOT_PROVIDED);
                }
                if (bi.next() != '=') {
                    throw ElytronMessages.log.mechInvalidMessageReceived(mechanism.toString());
                }
                if (! bindingType.equals(bi.delimitedBy(',').asUtf8String().drainToString())) {
                    throw log.mechChannelBindingTypeMismatch(mechanism.toString());
                }
                binding = true;
            } else if (cbindFlag == 'y') {
                if (mechanism.isPlus()) {
                    throw new ScramServerException(log.mechChannelBindingTypeMismatch(mechanism.toString()), ScramServerErrorCode.SERVER_DOES_SUPPORT_CHANNEL_BINDING);
                }
                if (bindingType != null || bindingData != null) {
                    throw new ScramServerException(log.mechChannelBindingNotSupported(mechanism.toString()), ScramServerErrorCode.SERVER_DOES_NOT_SUPPORT_CHANNEL_BINDING);
                }
                binding = true;
            } else if (cbindFlag == 'n') {
                if (mechanism.isPlus()) {
                    throw new ScramServerException(log.mechChannelBindingTypeMismatch(mechanism.toString()), ScramServerErrorCode.SERVER_DOES_SUPPORT_CHANNEL_BINDING);
                }
                if (bindingType != null || bindingData != null) {
                    throw new ScramServerException(log.mechChannelBindingNotSupported(mechanism.toString()), ScramServerErrorCode.SERVER_DOES_NOT_SUPPORT_CHANNEL_BINDING);
                }
                binding = false;
            } else {
                throw ElytronMessages.log.mechInvalidMessageReceived(mechanism.toString());
            }
            if (bi.next() != ',') {
                throw ElytronMessages.log.mechInvalidMessageReceived(mechanism.toString());
            }

            // authorization ID
            final int c = bi.next();
            final String authorizationID;
            if (c == 'a') {
                if (bi.next() != '=') {
                    throw log.mechInvalidClientMessage(mechanism.toString());
                }
                authorizationID = bi.delimitedBy(',').asUtf8String().drainToString();
                bi.next(); // skip delimiter
            } else if (c == ',') {
                authorizationID = null;
            } else {
                throw log.mechInvalidClientMessage(mechanism.toString());
            }

            final int initialPartIndex = bi.offset();

            // user name
            final String authenticationName;
            if (bi.next() == 'n') {
                if (bi.next() != '=') {
                    throw log.mechInvalidClientMessage(mechanism.toString());
                }
                ByteStringBuilder bsb = new ByteStringBuilder();
                StringPrep.encode(bi.delimitedBy(',').asUtf8String().drainToString(), bsb, StringPrep.PROFILE_SASL_QUERY | StringPrep.UNMAP_SCRAM_LOGIN_CHARS);
                authenticationName = new String(bsb.toArray(), StandardCharsets.UTF_8);
                bi.next(); // skip delimiter
            } else {
                throw log.mechInvalidClientMessage(mechanism.toString());
            }

            // random nonce
            if (bi.next() != 'r' || bi.next() != '=') {
                throw log.mechInvalidClientMessage(mechanism.toString());
            }
            final byte[] nonce = bi.delimitedBy(',').drain();

            if (bi.hasNext()) {
                throw log.mechInvalidClientMessage(mechanism.toString());
            }

            return new ScramInitialClientMessage(mechanism, authorizationID, authenticationName, binding, bindingType, bindingData, nonce, initialPartIndex, response);
        } catch (NoSuchElementException ignored) {
            throw ElytronMessages.log.mechInvalidMessageReceived(mechanism.toString());
        }
    }

    public ScramInitialServerResult evaluateInitialResponse(final ScramInitialClientMessage clientMessage) throws AuthenticationMechanismException {
        final boolean trace = log.isTraceEnabled();

        if (clientMessage.getMechanism() != mechanism) {
            throw log.mechUnmatchedMechanism(mechanism.toString(), clientMessage.getMechanism().toString());
        }

        // get salted password
        final NameCallback nameCallback = new NameCallback("Remote authentication name", clientMessage.getAuthenticationName());

        try {
            MechanismUtil.handleCallbacks(mechanism.toString(), callbackHandler, nameCallback);
        } catch (UnsupportedCallbackException e) {
            throw log.mechCallbackHandlerDoesNotSupportUserName(mechanism.toString(), e);
        }

        final IteratedPasswordAlgorithmSpec generateParameters = new IteratedPasswordAlgorithmSpec(
            max(minimumIterationCount, min(maximumIterationCount, ScramDigestPassword.DEFAULT_ITERATION_COUNT))
        );
        final ScramDigestPassword password = MechanismUtil.getPasswordCredential(clientMessage.getAuthenticationName(), callbackHandler, ScramDigestPassword.class, mechanism.getPasswordAlgorithm(), null, generateParameters, providers);

        final byte[] saltedPasswordBytes = password.getDigest();
        final int iterationCount = password.getIterationCount();
        if (iterationCount < minimumIterationCount) {
            throw log.mechIterationCountIsTooLow(mechanism.toString(), iterationCount, minimumIterationCount);
        }
        if (iterationCount > maximumIterationCount) {
            throw log.mechIterationCountIsTooHigh(mechanism.toString(), iterationCount, maximumIterationCount);
        }
        final byte[] salt = password.getSalt();

        if(trace) log.tracef("[S] Salt: %s%n", ByteIterator.ofBytes(salt).hexEncode().drainToString());
        if(trace) log.tracef("[S] Salted password: %s%n", ByteIterator.ofBytes(saltedPasswordBytes).hexEncode().drainToString());

        ByteStringBuilder b = new ByteStringBuilder();

        // nonce (client + server nonce)
        b.append('r').append('=');
        b.append(clientMessage.getRawNonce());
        final byte[] serverNonce = ScramUtil.generateNonce(28, getRandom());
        b.append(serverNonce);
        b.append(',');

        // salt
        b.append('s').append('=');
        b.appendLatin1(ByteIterator.ofBytes(salt).base64Encode());
        b.append(',');
        b.append('i').append('=');
        b.append(Integer.toString(iterationCount));

        byte[] messageBytes = b.toArray();

        return new ScramInitialServerResult(new ScramInitialServerMessage(clientMessage, serverNonce, salt, iterationCount, messageBytes), password);
    }

    public ScramFinalClientMessage parseFinalClientMessage(final ScramInitialClientMessage initialResponse, final ScramInitialServerResult initialResult, final byte[] bytes) throws AuthenticationMechanismException {
        final ScramInitialServerMessage initialChallenge = initialResult.getScramInitialChallenge();
        Assert.checkNotNullParam("initialResponse", initialResponse);
        Assert.checkNotNullParam("initialChallenge", initialChallenge);
        final ScramMechanism mechanism = initialResponse.getMechanism();
        if (mechanism != initialChallenge.getMechanism()) {
            throw log.mechUnmatchedMechanism(mechanism.toString(), initialChallenge.getMechanism().toString());
        }
        byte[] response = bytes.clone();
        ByteIterator bi = ByteIterator.ofBytes(response);
        try {
            if (bi.next() != 'c' || bi.next() != '=') {
                throw log.mechInvalidMessageReceived(mechanism.toString());
            }
            ByteIterator ibi = bi.delimitedBy(',').base64Decode();
            char cbindFlag = (char) ibi.next();
            final String bindingType = initialResponse.getBindingType();
            final byte[] bindingData = initialResponse.getRawBindingData();
            final boolean binding = initialResponse.isBinding();
            if (cbindFlag == 'p') {
                if (! binding) {
                    throw log.mechChannelBindingNotSupported(mechanism.toString());
                }
                if (bindingType == null || bindingData == null) {
                    throw log.mechChannelBindingNotProvided(mechanism.toString());
                }
                if (ibi.next() != '=') {
                    throw log.mechInvalidMessageReceived(mechanism.toString());
                }
                if (! bindingType.equals(ibi.delimitedBy(',').asUtf8String().drainToString())) {
                    throw log.mechChannelBindingTypeMismatch(mechanism.toString());
                }
            } else if (cbindFlag == 'y') {
                if (! binding) {
                    throw log.mechChannelBindingNotSupported(mechanism.toString());
                }
                if (mechanism.isPlus()) {
                    throw log.mechChannelBindingNotProvided(mechanism.toString());
                }
                if (bindingType != null || bindingData != null) {
                    throw log.mechChannelBindingNotSupported(mechanism.toString());
                }
            } else if (cbindFlag == 'n') {
                if (binding) {
                    throw log.mechChannelBindingNotSupported(mechanism.toString());
                }
                if (mechanism.isPlus()) {
                    throw log.mechChannelBindingNotProvided(mechanism.toString());
                }
            } else {
                throw log.mechInvalidMessageReceived(mechanism.toString());
            }
            if (ibi.next() != ',') {
                throw log.mechInvalidMessageReceived(mechanism.toString());
            }

            // authorization ID
            int c = ibi.next();
            final String authorizationID;
            if (c == 'a') {
                if (ibi.next() != '=') {
                    throw log.mechInvalidClientMessage(mechanism.toString());
                }
                authorizationID = ibi.delimitedBy(',').asUtf8String().drainToString();
                ibi.next(); // skip delimiter
                if (! authorizationID.equals(initialResponse.getAuthorizationId())) {
                    throw log.mechAuthorizationIdChanged(mechanism.toString());
                }
            } else if (c == ',') {
                if (initialResponse.getAuthorizationId() != null) {
                    throw log.mechAuthorizationIdChanged(mechanism.toString());
                }
            } else {
                throw log.mechInvalidClientMessage(mechanism.toString());
            }

            // channel binding data
            if (bindingData != null && ! ibi.contentEquals(ByteIterator.ofBytes(bindingData))) {
                throw log.mechChannelBindingChanged(mechanism.toString());
            }

            bi.next(); // skip delim

            // random nonce
            if (bi.next() != 'r' || bi.next() != '=') {
                throw log.mechInvalidClientMessage(mechanism.toString());
            }
            final byte[] clientNonce = initialResponse.getRawNonce();
            final byte[] serverNonce = initialChallenge.getRawServerNonce();
            if (! bi.delimitedBy(',').limitedTo(clientNonce.length).contentEquals(ByteIterator.ofBytes(clientNonce)) ||
                ! bi.delimitedBy(',').limitedTo(serverNonce.length).contentEquals(ByteIterator.ofBytes(serverNonce))) {
                throw log.mechNoncesDoNotMatch(mechanism.toString());
            }

            final int proofOffset = bi.offset();

            bi.next(); // skip delimiter

            // proof
            if (bi.next() != 'p' || bi.next() != '=') {
                throw log.mechInvalidClientMessage(mechanism.toString());
            }
            final byte[] proof;
            proof = bi.delimitedBy(',').base64Decode().drain();

            if (bi.hasNext()) {
                throw log.mechInvalidClientMessage(mechanism.toString());
            }
            return new ScramFinalClientMessage(initialResponse, initialChallenge, initialResult.getScramDigestPassword(), proof, response, proofOffset);
        } catch (NoSuchElementException ignored) {
            throw log.mechInvalidMessageReceived(mechanism.toString());
        }
    }

    public ScramFinalServerMessage evaluateFinalClientMessage(final ScramInitialServerResult initialResult, final ScramFinalClientMessage clientMessage) throws AuthenticationMechanismException {
        final boolean trace = log.isTraceEnabled();

        if (clientMessage.getMechanism() != mechanism) {
            throw log.mechUnmatchedMechanism(mechanism.toString(), clientMessage.getMechanism().toString());
        }

        ByteStringBuilder b = new ByteStringBuilder();

        try {

            final Mac mac = Mac.getInstance(getMechanism().getHmacName());
            final MessageDigest messageDigest = MessageDigest.getInstance(getMechanism().getMessageDigestName());

            // == verify proof ==

            // client key
            byte[] clientKey;
            mac.reset();
            byte[] saltedPassword = initialResult.getScramDigestPassword().getDigest();
            mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
            mac.update(ScramUtil.CLIENT_KEY_BYTES);
            clientKey = mac.doFinal();
            if(trace) log.tracef("[S] Client key: %s%n", ByteIterator.ofBytes(clientKey).hexEncode().drainToString());

            // stored key
            byte[] storedKey;
            messageDigest.reset();
            messageDigest.update(clientKey);
            storedKey = messageDigest.digest();
            if(trace) log.tracef("[S] Stored key: %s%n", ByteIterator.ofBytes(storedKey).hexEncode().drainToString());

            // client signature
            mac.reset();
            mac.init(new SecretKeySpec(storedKey, mac.getAlgorithm()));
            final byte[] clientFirstMessage = clientMessage.getInitialResponse().getRawMessageBytes();
            final int clientFirstMessageBareStart = clientMessage.getInitialResponse().getInitialPartIndex();
            mac.update(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length - clientFirstMessageBareStart);
            if(trace) log.tracef("[S] Using client first message: %s%n", ByteIterator.ofBytes(copyOfRange(clientFirstMessage, clientFirstMessageBareStart, clientFirstMessage.length)).hexEncode().drainToString());
            mac.update((byte) ',');
            final byte[] serverFirstMessage = initialResult.getScramInitialChallenge().getRawMessageBytes();
            mac.update(serverFirstMessage);
            if(trace) log.tracef("[S] Using server first message: %s%n", ByteIterator.ofBytes(serverFirstMessage).hexEncode().drainToString());
            mac.update((byte) ',');
            final byte[] response = clientMessage.getRawMessageBytes();
            final int proofOffset = clientMessage.getProofOffset();
            mac.update(response, 0, proofOffset); // client-final-message-without-proof
            if(trace) log.tracef("[S] Using client final message without proof: %s%n", ByteIterator.ofBytes(copyOfRange(response, 0, proofOffset)).hexEncode().drainToString());
            byte[] clientSignature = mac.doFinal();
            if(trace) log.tracef("[S] Client signature: %s%n", ByteIterator.ofBytes(clientSignature).hexEncode().drainToString());

            // server key
            byte[] serverKey;
            mac.reset();
            mac.init(new SecretKeySpec(saltedPassword, mac.getAlgorithm()));
            mac.update(ScramUtil.SERVER_KEY_BYTES);
            serverKey = mac.doFinal();
            if(trace) log.tracef("[S] Server key: %s%n", ByteIterator.ofBytes(serverKey).hexEncode().drainToString());

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
            if(trace) log.tracef("[S] Server signature: %s%n", ByteIterator.ofBytes(serverSignature).hexEncode().drainToString());

            final byte[] recoveredClientProof = clientMessage.getRawClientProof();
            if(trace) log.tracef("[S] Client proof: %s%n", ByteIterator.ofBytes(recoveredClientProof).hexEncode().drainToString());

            // now check the proof
            byte[] recoveredClientKey = clientSignature.clone();
            ScramUtil.xor(recoveredClientKey, recoveredClientProof);
            if(trace) log.tracef("[S] Recovered client key: %s%n", ByteIterator.ofBytes(recoveredClientKey).hexEncode().drainToString());
            if (! Arrays.equals(recoveredClientKey, clientKey)) {
                throw log.mechAuthenticationRejectedInvalidProof(mechanism.toString());
            }

            String userName = clientMessage.getInitialResponse().getAuthenticationName();
            String authorizationID = clientMessage.getInitialResponse().getAuthorizationId();
            if (authorizationID == null || authorizationID.isEmpty()) {
                authorizationID = userName;
            } else {
                ByteStringBuilder bsb = new ByteStringBuilder();
                StringPrep.encode(authorizationID, bsb, StringPrep.PROFILE_SASL_QUERY | StringPrep.UNMAP_SCRAM_LOGIN_CHARS);
                authorizationID = new String(bsb.toArray(), StandardCharsets.UTF_8);
            }
            final AuthorizeCallback authorizeCallback = new AuthorizeCallback(userName, authorizationID);
            try {
                MechanismUtil.handleCallbacks(mechanism.toString(), callbackHandler, authorizeCallback);
            } catch (UnsupportedCallbackException e) {
                throw log.mechAuthorizationUnsupported(mechanism.toString(), e);
            }
            if ( ! authorizeCallback.isAuthorized()) {
                throw log.mechAuthorizationFailed(mechanism.toString(), userName, authorizationID);
            }

            // == send response ==
            b.setLength(0);
            b.append('v').append('=');
            b.appendUtf8(ByteIterator.ofBytes(serverSignature).base64Encode());

            return new ScramFinalServerMessage(serverSignature, b.toArray());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw log.mechMacAlgorithmNotSupported(mechanism.toString(), e);
        }
    }

    public ScramMechanism getMechanism() {
        return mechanism;
    }

    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    Random getRandom() {
        return random != null ? random : ThreadLocalRandom.current();
    }

    public byte[] getBindingData() {
        return bindingData == null ? null : bindingData.clone();
    }

    byte[] getRawBindingData() {
        return bindingData;
    }

    public String getBindingType() {
        return bindingType;
    }
}
