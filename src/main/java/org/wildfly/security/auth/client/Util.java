/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.client;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class Util {
    private Util() {
    }

    /**
     * Multiply two integers, XOR the high-order bits on to the low-order bits, and add the next hash, wrapping the carry
     * around to an XOR on the low-order bit, so that hash codes don't lose information over many multiplies.
     * <p>
     * "Hashiply" = "hash + multiply".
     *
     * @param accumulatedHash the hash code of the previous stage
     * @param prime a prime multiplier
     * @param nextHash the hash code of the next item
     * @return the result of the multiply-XOR operation
     */
    static int hashiply(int accumulatedHash, int prime, int nextHash) {
        long r1 = (long) accumulatedHash * prime;
        long r3 = (long) ((int) r1 ^ (int) (r1 >>> 32)) + nextHash;
        return (int) r3 ^ (int) (r3 >>> 32);
    }
}
