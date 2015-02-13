/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.password.spec;

public final class UnixSHACryptPasswordSpec implements AlgorithmPasswordSpec {
    private final byte[] hashBytes;
    private final byte[] salt;
    private final int iterationCount;
    private final String algorithm;

    /**
     * Creates a new password specification, with the parameters that will be used
     * when hashing the plain text.
     *
     * @param algorithm         the algorithm to be used. Possible values are available as constants on {link}UnixSHACryptPassword{link}
     * @param hashBytes         the plain text, as bytes
     * @param salt              the salt. If none is provided, a new one is randomly generated
     * @param iterationCount    the iteration count
     */
    public UnixSHACryptPasswordSpec(final String algorithm, final byte[] hashBytes, final byte[] salt, final int iterationCount) {
        this.algorithm = algorithm;
        this.hashBytes = hashBytes;
        this.salt = salt;
        this.iterationCount = iterationCount;
    }

    public byte[] getHash() {
        return hashBytes;
    }

    public byte[] getSalt() {
        return salt;
    }

    public int getIterationCount() {
        return iterationCount;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }
}
