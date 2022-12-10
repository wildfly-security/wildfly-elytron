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

import java.security.MessageDigest;
import java.util.Arrays;

class RawSimpleDigestPassword extends RawPassword implements SimpleDigestPassword {

    private static final long serialVersionUID = -4517729891352607948L;

    private final byte[] digest;

    RawSimpleDigestPassword(final String algorithm, final byte[] digest) {
        super(algorithm);
        this.digest = digest;
    }

    public byte[] getDigest() {
        return digest.clone();
    }

    public RawSimpleDigestPassword clone() {
        return this;
    }

    public int hashCode() {
        return multiHashOrdered(Arrays.hashCode(digest), getAlgorithm().hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof RawSimpleDigestPassword)) {
            return false;
        }
        RawSimpleDigestPassword other = (RawSimpleDigestPassword) obj;
        return getAlgorithm().equals(other.getAlgorithm()) && MessageDigest.isEqual(digest, other.digest);
    }
}
