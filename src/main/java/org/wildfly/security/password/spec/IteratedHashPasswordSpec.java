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
package org.wildfly.security.password.spec;

import static org.wildfly.common.math.HashMath.multiHashOrdered;

import java.util.Arrays;

import org.wildfly.common.Assert;

/**
 * A {@link PasswordSpec} for a password represented by a hash with an iteration count or cost.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class IteratedHashPasswordSpec implements PasswordSpec {

    private final byte[] hash;
    private final int iterationCount;

    /**
     * Construct new instance.
     *
     * @param hash the password hash
     * @param iterationCount the iteration count or cost
     */
    public IteratedHashPasswordSpec(byte[] hash, int iterationCount) {
        Assert.checkNotNullParam("hash", hash);
        this.hash = hash;
        this.iterationCount = iterationCount;
    }

    /**
     * Get a password hash.
     *
     * @return the password hash
     */
    public byte[] getHash() {
        return this.hash;
    }

    /**
     * Get an iteration count or cost.
     *
     * @return the iteration count or cost
     */
    public int getIterationCount() {
        return this.iterationCount;
    }

    @Override
    public boolean equals(Object other) {
        if (! (other instanceof IteratedHashPasswordSpec)) return false;
        IteratedHashPasswordSpec o = (IteratedHashPasswordSpec) other;
        return Arrays.equals(hash, o.hash) && iterationCount == o.iterationCount;
    }

    @Override
    public int hashCode() {
        return multiHashOrdered(Arrays.hashCode(hash), iterationCount);
    }
}
