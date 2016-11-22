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

import java.security.Provider;
import java.security.SecureRandom;
import java.util.function.Supplier;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.sasl.WildFlySasl;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ScramMechanism {
    /** Hash size; may be less than the output size of the MD/MAC */
    private final int hashSize;
    private final String messageDigestName;
    private final String hmacName;
    private final boolean plus;
    private final String passwordAlgorithm;
    private final String toString;

    private ScramMechanism(final int hashSize, final String messageDigestName, final String hmacName, final boolean plus, final String passwordAlgorithm) {
        this.hashSize = hashSize;
        this.messageDigestName = messageDigestName;
        this.hmacName = hmacName;
        this.plus = plus;
        this.passwordAlgorithm = passwordAlgorithm;
        StringBuilder b = new StringBuilder();
        b.append("SCRAM ").append(messageDigestName).append(' ');
        if (plus) b.append("(PLUS channel binding) ");
        b.append(hashSize * 8).append(" bits");
        toString = b.toString();
    }

    public static final ScramMechanism SCRAM_SHA_1 = new ScramMechanism(20, "SHA-1", "HmacSHA1", false, ScramDigestPassword.ALGORITHM_SCRAM_SHA_1);
    public static final ScramMechanism SCRAM_SHA_1_PLUS = new ScramMechanism(20, "SHA-1", "HmacSHA1", true, ScramDigestPassword.ALGORITHM_SCRAM_SHA_1);

    public static final ScramMechanism SCRAM_SHA_256 = new ScramMechanism(32, "SHA-256", "HmacSHA256", false, ScramDigestPassword.ALGORITHM_SCRAM_SHA_256);
    public static final ScramMechanism SCRAM_SHA_256_PLUS = new ScramMechanism(32, "SHA-256", "HmacSHA256", true, ScramDigestPassword.ALGORITHM_SCRAM_SHA_256);

    public static final ScramMechanism SCRAM_SHA_384 = new ScramMechanism(48, "SHA-384", "HmacSHA384", false, ScramDigestPassword.ALGORITHM_SCRAM_SHA_384);
    public static final ScramMechanism SCRAM_SHA_384_PLUS = new ScramMechanism(32, "SHA-384", "HmacSHA384", true, ScramDigestPassword.ALGORITHM_SCRAM_SHA_384);

    public static final ScramMechanism SCRAM_SHA_512 = new ScramMechanism(64, "SHA-512", "HmacSHA512", false, ScramDigestPassword.ALGORITHM_SCRAM_SHA_512);
    public static final ScramMechanism SCRAM_SHA_512_PLUS = new ScramMechanism(64, "SHA-512", "HmacSHA512", true, ScramDigestPassword.ALGORITHM_SCRAM_SHA_512);

    /**
     * Create a SCRAM client for this mechanism.
     *
     * @param authorizationId the authorization ID ({@code null} if none is given)
     * @param callbackHandler the callback handler (may not be {@code null})
     * @param secureRandom an optional secure random implementation to use (may be {@code null})
     * @param bindingCallback the optional channel binding callback result (may be {@code null})
     * @param minimumIterationCount the minimum iteration count to allow
     * @param maximumIterationCount the maximum iteration count to allow
     * @return the SCRAM client, or {@code null} if the client cannot be created from this mechanism variant
     * @throws AuthenticationMechanismException if the mechanism fails for some reason
     * @see WildFlySasl#SCRAM_MIN_ITERATION_COUNT
     * @see WildFlySasl#SCRAM_MAX_ITERATION_COUNT
     */
    public ScramClient createClient(final String authorizationId, final CallbackHandler callbackHandler, final SecureRandom secureRandom, final ChannelBindingCallback bindingCallback, final int minimumIterationCount, final int maximumIterationCount, final Supplier<Provider[]> providers) throws AuthenticationMechanismException {
        final byte[] bindingData;
        final String bindingType;
        if (bindingCallback != null) {
            bindingData = bindingCallback.getBindingData();
            bindingType = bindingCallback.getBindingType();
        } else {
            if (plus) return null;
            bindingData = null;
            bindingType = null;
        }
        return new ScramClient(this, authorizationId, callbackHandler, secureRandom, bindingData, bindingType, minimumIterationCount, maximumIterationCount, providers);
    }

    public ScramServer createServer(final CallbackHandler callbackHandler, final SecureRandom random, final ChannelBindingCallback bindingCallback, final int minimumIterationCount, final int maximumIterationCount, final Supplier<Provider[]> providers) throws AuthenticationMechanismException {
        final byte[] bindingData;
        final String bindingType;
        if (bindingCallback != null) {
            bindingData = bindingCallback.getBindingData();
            bindingType = bindingCallback.getBindingType();
        } else {
            if (plus) return null;
            bindingData = null;
            bindingType = null;
        }
        return new ScramServer(this, callbackHandler, random, bindingData, bindingType, minimumIterationCount, maximumIterationCount, providers);
    }

    public int getHashSize() {
        return hashSize;
    }

    public String getMessageDigestName() {
        return messageDigestName;
    }

    public String getHmacName() {
        return hmacName;
    }

    public boolean isPlus() {
        return plus;
    }

    public String getPasswordAlgorithm() {
        return passwordAlgorithm;
    }

    public String toString() {
        return toString;
    }
}
