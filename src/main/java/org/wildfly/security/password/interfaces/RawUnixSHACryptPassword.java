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

package org.wildfly.security.password.interfaces;

import static org.wildfly.common.math.HashMath.multiHashOrdered;

import java.util.Arrays;

class RawUnixSHACryptPassword extends RawPassword implements UnixSHACryptPassword {

    private static final long serialVersionUID = 5026934973986804126L;

    private final byte[] salt;
    private final byte[] hash;
    private final int iterationCount;

    RawUnixSHACryptPassword(final String algorithm, final byte[] salt, final byte[] hash, final int iterationCount) {
        super(algorithm);
        this.salt = salt;
        this.hash = hash;
        this.iterationCount = iterationCount;
    }

    public byte[] getSalt() {
        return salt.clone();
    }

    public byte[] getHash() {
        return hash.clone();
    }

    public int getIterationCount() {
        return iterationCount;
    }

    public RawUnixSHACryptPassword clone() {
        return this;
    }

    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(multiHashOrdered(Arrays.hashCode(hash), Arrays.hashCode(salt)), iterationCount), getAlgorithm().hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof RawUnixSHACryptPassword)) {
            return false;
        }
        RawUnixSHACryptPassword other = (RawUnixSHACryptPassword) obj;
        return iterationCount == other.iterationCount && getAlgorithm().equals(other.getAlgorithm()) && Arrays.equals(hash, other.hash) && Arrays.equals(salt, other.salt);
    }
}
