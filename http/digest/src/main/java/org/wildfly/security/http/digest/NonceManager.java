/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.digest;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicInteger;

import org.wildfly.security.mechanism._private.ElytronMessages;
import org.wildfly.security.mechanism.AuthenticationMechanismException;

import static org.wildfly.security.http.HttpConstants.SHA256;

/**
 * A utility responsible for managing nonces.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class NonceManager {

    private final ScheduledExecutorService executor;
    private final AtomicInteger nonceCounter = new AtomicInteger();
    private final Map<String, NonceManagerUtils.NonceState> usedNonces = new HashMap<>();

    private final byte[] privateKey;

    private final long validityPeriodNano;
    private final long nonceSessionTime;
    private final boolean singleUse;
    private final String algorithm;
    private ElytronMessages log;

    /**
     * initialize with default values
     */
    NonceManager() {
        this.validityPeriodNano = NonceManagerUtils.DEFAULT_VALIDITY_PERIOD * 1000000;
        nonceSessionTime = NonceManagerUtils.DEFAULT_NONCE_SESSION_TIME;
        singleUse = true;
        this.privateKey = new byte[NonceManagerUtils.DEFAULT_KEY_SIZE];
        new SecureRandom().nextBytes(privateKey);
        algorithm = SHA256;
        log = ElytronMessages.httpDigest;
        ScheduledThreadPoolExecutor INSTANCE = new ScheduledThreadPoolExecutor(1);
        INSTANCE.setRemoveOnCancelPolicy(true);
        INSTANCE.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        executor = INSTANCE;
    }

    /**
     * @param validityPeriod the time in ms that nonces are valid for in ms.
     * @param nonceSessionTime the time in ms a nonce is usable for after it's last use where nonce counts are in use.
     * @param singleUse are nonces single use?
     * @param keySize the number of bytes to use in the private key of this node.
     * @param algorithm the message digest algorithm to use when creating the digest portion of the nonce.
     */

    @Deprecated
    NonceManager(long validityPeriod, long nonceSessionTime, boolean singleUse, int keySize, String algorithm) {
        this.validityPeriodNano = validityPeriod * 1000000;
        this.nonceSessionTime = nonceSessionTime;
        this.singleUse = singleUse;
        this.algorithm = algorithm;
        this.log = ElytronMessages.log;

        this.privateKey = new byte[keySize];
        new SecureRandom().nextBytes(privateKey);
        ScheduledThreadPoolExecutor INSTANCE = new ScheduledThreadPoolExecutor(1);
        INSTANCE.setRemoveOnCancelPolicy(true);
        INSTANCE.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        executor = INSTANCE;
    }

    /**
     * @param validityPeriod the time in ms that nonces are valid for in ms.
     * @param nonceSessionTime the time in ms a nonce is usable for after it's last use where nonce counts are in use.
     * @param singleUse are nonces single use?
     * @param keySize the number of bytes to use in the private key of this node.
     * @param algorithm the message digest algorithm to use when creating the digest portion of the nonce.
     * @param log mechanism specific logger.
     */
    NonceManager(long validityPeriod, long nonceSessionTime, boolean singleUse, int keySize, String algorithm, ElytronMessages log) {
        this.validityPeriodNano = validityPeriod * 1000000;
        this.nonceSessionTime = nonceSessionTime;
        this.singleUse = singleUse;
        this.algorithm = algorithm;
        this.log = log;

        this.privateKey = new byte[keySize];
        new SecureRandom().nextBytes(privateKey);
        ScheduledThreadPoolExecutor INSTANCE = new ScheduledThreadPoolExecutor(1);
        INSTANCE.setRemoveOnCancelPolicy(true);
        INSTANCE.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        executor = INSTANCE;
    }

    /**
     * @param validityPeriod the time in ms that nonces are valid for in ms.
     * @param nonceSessionTime the time in ms a nonce is usable for after it's last use where nonce counts are in use.
     * @param singleUse are nonces single use?
     * @param keySize the number of bytes to use in the private key of this node.
     * @param algorithm the message digest algorithm to use when creating the digest portion of the nonce.
     * @param log mechanism specific logger.
     * @param customExecutor a custom ScheduledExecutorService to be used
     */
    NonceManager(long validityPeriod, long nonceSessionTime, boolean singleUse, int keySize, String algorithm, ElytronMessages log, ScheduledExecutorService customExecutor) {
        this.validityPeriodNano = validityPeriod * 1000000;
        this.nonceSessionTime = nonceSessionTime;
        this.singleUse = singleUse;
        this.algorithm = algorithm;
        this.log = log;

        this.privateKey = new byte[keySize];
        new SecureRandom().nextBytes(privateKey);
        if (customExecutor == null) {
            ScheduledThreadPoolExecutor INSTANCE = new ScheduledThreadPoolExecutor(1);
            INSTANCE.setRemoveOnCancelPolicy(true);
            INSTANCE.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
            executor = INSTANCE;
        }
        else {
            executor = customExecutor;
        }
    }

    /**
     * Generate a new encoded nonce to send to the client.
     *
     * @return a new encoded nonce to send to the client.
     */
    String generateNonce() {
        return generateNonce(null);
    }

    /**
     * Generate a new encoded nonce to send to the client.
     *
     * @param salt additional data to use when creating the overall signature for the nonce.
     * @return a new encoded nonce to send to the client.
     */
    String generateNonce(byte[] salt) {
        return NonceManagerUtils.generateNonce(salt, algorithm, nonceCounter, privateKey);
    }

    private byte[] digest(byte[] prefix, int prefixOffset, int prefixLength, byte[] salt, MessageDigest messageDigest) throws DigestException {
        return NonceManagerUtils.digest(prefix, prefixOffset, prefixLength, salt, messageDigest, privateKey);
    }

    /**
     * Attempt to use the supplied nonce.
     *
     * A nonce might not be usable for a couple of different reasons: -
     *
     * <ul>
     *     <li>It was created too far in the past.
     *     <li>Validation of the signature fails.
     *     <li>The nonce has been used previously and re-use is disabled.
     * </ul>
     *
     * @param nonce the nonce supplied by the client.
     * @param nonceCount the nonce count, or -1 if not present
     * @return {@code true} if the nonce can be used, {@code false} otherwise.
     * @throws AuthenticationMechanismException
     */
    boolean useNonce(String nonce, int nonceCount) throws AuthenticationMechanismException {
        return useNonce(nonce, null, nonceCount);
    }

    /**
     * Attempt to use the supplied nonce.
     *
     * A nonce might not be usable for a couple of different reasons: -
     *
     * <ul>
     *     <li>It was created too far in the past.
     *     <li>Validation of the signature fails.
     *     <li>The nonce has been used previously and re-use is disabled.
     * </ul>
     *
     * @param nonce the nonce supplied by the client.
     * @param salt additional data to use when creating the overall signature for the nonce.
     * @return {@code true} if the nonce can be used, {@code false} otherwise.
     * @throws AuthenticationMechanismException
     */
    boolean useNonce(final String nonce, byte[] salt, int nonceCount) throws AuthenticationMechanismException {
        return NonceManagerUtils.useNonce(nonce,  salt,  nonceCount, algorithm, privateKey, usedNonces,  validityPeriodNano,  executor, singleUse, nonceSessionTime);
    }

    public void shutdown() {
        if (executor != null) { executor.shutdown(); }
    }
}
