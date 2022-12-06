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

import java.security.MessageDigest;
import java.util.Arrays;
import org.wildfly.common.Assert;

/**
 * A password specification for a password represented by a hash.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class HashPasswordSpec implements PasswordSpec {

    private final byte[] digest;

    /**
     * Construct new instance.
     *
     * @param digest the password hash
     */
    public HashPasswordSpec(final byte[] digest) {
        Assert.checkNotNullParam("digest", digest);
        this.digest = digest;
    }

    /**
     * Get a password hash.
     *
     * @return the password hash
     */
    public byte[] getDigest() {
        return digest;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof HashPasswordSpec && MessageDigest.isEqual(digest, ((HashPasswordSpec)other).digest);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(digest);
    }
}
