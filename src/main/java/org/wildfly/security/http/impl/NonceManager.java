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

package org.wildfly.security.http.impl;

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.util._private.Arrays2;

/**
 * A utility responsible for managing nonces.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class NonceManager {

    private static final int PREFIX_LENGTH = Integer.BYTES + Long.BYTES;

    private final ScheduledExecutorService executor = new ScheduledThreadPoolExecutor(1);
    private final AtomicInteger nonceCounter = new AtomicInteger();
    private final Map<String, NonceState> usedNonces = new HashMap<>();

    private final byte[] privateKey;

    private final long validityPeriodNano;
    private final long nonceSessionTime;
    private final boolean singleUse;
    private final String algorithm;
    private ElytronMessages log;


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
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);

            ByteBuffer byteBuffer = ByteBuffer.allocate(PREFIX_LENGTH + messageDigest.getDigestLength());
            byteBuffer.putInt(nonceCounter.incrementAndGet());
            byteBuffer.putLong(System.nanoTime());
            byteBuffer.put(digest(byteBuffer.array(), 0, PREFIX_LENGTH, salt, messageDigest));

            String nonce = ByteIterator.ofBytes(byteBuffer.array()).base64Encode().drainToString();
            if (log.isTraceEnabled()) {
                String saltString = salt == null ? "null" : ByteIterator.ofBytes(salt).hexEncode().drainToString();
                log.tracef("New nonce generated %s, using seed %s", nonce, saltString);
            }
            return nonce;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] digest(byte[] prefix, int prefixOffset, int prefixLength, byte[] salt, MessageDigest messageDigest) throws DigestException {
        messageDigest.update(prefix, prefixOffset, prefixLength);
        if (salt != null) {
            messageDigest.update(salt);
        }

        return messageDigest.digest(privateKey);
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
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            ByteIterator byteIterator = CodePointIterator.ofChars(nonce.toCharArray()).base64Decode();
            byte[] nonceBytes = byteIterator.drain();
            if (nonceBytes.length != PREFIX_LENGTH + messageDigest.getDigestLength()) {
                throw log.invalidNonceLength();
            }

            if (Arrays2.equals(nonceBytes, PREFIX_LENGTH, digest(nonceBytes, 0, PREFIX_LENGTH, salt, messageDigest)) == false) {
                if (log.isTraceEnabled()) {
                    String saltString = salt == null ? "null" : ByteIterator.ofBytes(salt).hexEncode().drainToString();
                    log.tracef("Nonce %s rejected due to failed comparison using secret key with seed %s.", nonce,
                            saltString);
                }
                return false;
            }

            long age = System.nanoTime() - ByteBuffer.wrap(nonceBytes, Integer.BYTES, Long.BYTES).getLong();
            if(nonceCount > 0) {
                synchronized (usedNonces) {
                    NonceState nonceState = usedNonces.get(nonce);
                    if (nonceState != null && nonceState.highestNonceCount < 0) {
                        log.tracef("Nonce %s rejected due to previously being used without a nonce count", nonce);
                        return false;
                    } else if (nonceState != null) {
                        if (nonceCount > nonceState.highestNonceCount) {
                            if (nonceState.futureCleanup.cancel(true)) {
                                nonceState.highestNonceCount = nonceCount;
                            } else {
                                log.tracef("Nonce %s rejected as unable to cancel clean up, likely at expiration time", nonce);
                                return false;
                            }
                        } else {
                            log.tracef("Nonce %s rejected due to highest seen nonce count %d being equal to or higher than the nonce count received %d",
                                    nonce, nonceState.highestNonceCount, nonceCount);
                            return false;
                        }
                    } else {
                        if (age < 0 || age > validityPeriodNano) {
                            log.tracef("Nonce %s rejected due to age %d (ns) being less than 0 or greater than the validity period %d (ns)",
                                    nonce, age, validityPeriodNano);
                            return false;
                        }
                        nonceState = new NonceState();
                        nonceState.highestNonceCount = nonceCount;
                        usedNonces.put(nonce, nonceState);
                        if (log.isTraceEnabled()) {
                            log.tracef("Currently %d nonces being tracked", usedNonces.size());
                        }
                    }

                    nonceState.futureCleanup = executor.schedule(() -> {
                        synchronized (usedNonces) {
                            usedNonces.remove(nonce);
                        }
                    }, nonceSessionTime, TimeUnit.MILLISECONDS);
                }
            } else {
                if (age < 0 || age > validityPeriodNano) {
                    log.tracef("Nonce %s rejected due to age %d (ns) being less than 0 or greater than the validity period %d (ns)", nonce, age, validityPeriodNano);
                    return false;
                }

                if (singleUse) {
                    synchronized(usedNonces) {
                        NonceState nonceState = usedNonces.get(nonce);
                        if (nonceState != null) {
                            log.tracef("Nonce %s rejected due to previously being used", nonce);
                            return false;
                        } else {
                            nonceState = new NonceState();
                            usedNonces.put(nonce, nonceState);
                            if (log.isTraceEnabled()) {
                                log.tracef("Currently %d nonces being tracked", usedNonces.size());
                            }
                            executor.schedule(() -> {
                                synchronized(usedNonces) {
                                    usedNonces.remove(nonce);
                                }
                            }, validityPeriodNano - age, TimeUnit.NANOSECONDS);
                        }
                    }
                }
            }

            return true;

        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static class NonceState {
        private ScheduledFuture futureCleanup;
        private int highestNonceCount = -1;
    }
}
