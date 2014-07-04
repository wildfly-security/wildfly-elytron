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

import java.nio.charset.Charset;

public final class UnixSHACryptPasswordSpec implements PasswordSpec {
    private final byte[] hashBytes;
    private final byte[] salt;
    private final int iterationCount;
    private final String algorithm;
    private final Charset charset;

    /**
     * Creates a new password specification, declaring how a password should be
     * hashed.
     *
     * @param algorithm         the algorithm to be used. Possible values are available as constants on {link}UnixSHACryptPassword{link}
     * @param hashBytes         the bytes to be hashed
     * @param salt              the salt to use. If none is provided, a new one is randomly generated
     * @param iterationCount    the iteration count, between 1,000 and 999,999,999. Any values outside of the boundaries
     *                          will be shifted to the closest boundary (1,000 if it's lower than 1,000, or 999,999,999
     *                          if bigger than that).
     */
    public UnixSHACryptPasswordSpec(final String algorithm, final byte[] hashBytes, final byte[] salt, final int iterationCount, Charset charset) {
        this.algorithm = algorithm;
        this.hashBytes = hashBytes;
        this.salt = salt;
        this.iterationCount = iterationCount;
        this.charset = charset;
    }

    public UnixSHACryptPasswordSpec(final String algorithm, final byte[] hashBytes, final byte[] salt, final int iterationCount) {
        this(algorithm, hashBytes, salt, iterationCount, Charset.forName("UTF-8"));
    }

    public byte[] getHashBytes() {
        return hashBytes;
    }

    public byte[] getSalt() {
        return salt;
    }

    public int getIterationCount() {
        return iterationCount;
    }

    public Charset getCharset() {
        return charset;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
