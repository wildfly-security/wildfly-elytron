/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

/**
 * A {@link PasswordSpec} for a SCRAM digest password.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public final class ScramDigestPasswordSpec implements AlgorithmPasswordSpec {

    private final String algorithm;
    private final byte[] digest;
    private final byte[] salt;
    private final int iterationCount;

    /**
     * Create a new instance of {@code ScramDigestPasswordSpec} with the specified parameters.
     *
     * @param algorithm to be used to create the digest (SCRAM-SHA-1 or SCRAM-SHA-256).
     * @param digest a byte[] representing the digest.
     * @param salt a byte[] representing the salt used to create the digest.
     * @param iterationCount an int representing the iteration count used to create the digest.
     */
    public ScramDigestPasswordSpec(final String algorithm, final byte[] digest, final byte[] salt, final int iterationCount) {
        this.algorithm = algorithm;
        this.digest = digest;
        this.salt = salt;
        this.iterationCount = iterationCount;
    }

    @Override
    public String getAlgorithm() {
        return this.algorithm;
    }

    public byte[] getDigest() {
        return this.digest;
    }

    public byte[] getSalt() {
        return this.salt;
    }

    public int getIterationCount() {
        return this.iterationCount;
    }
}
