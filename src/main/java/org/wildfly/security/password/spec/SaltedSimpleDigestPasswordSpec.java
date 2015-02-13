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

/**
 * A {@link PasswordSpec} for a password represented by a simple digest including a salt.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SaltedSimpleDigestPasswordSpec implements AlgorithmPasswordSpec {

    private final String algorithm;
    private final byte[] digest;
    private final byte[] salt;

    public SaltedSimpleDigestPasswordSpec(final String algorithm, final byte[] digest, final byte[] salt) {
        this.algorithm = algorithm;
        this.digest = digest;
        this.salt = salt;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    public byte[] getDigest() {
        return digest;
    }

    public byte[] getSalt() {
        return salt;
    }

}
