/*
 * JBoss, Home of Professional Open Source.
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

import java.io.Serializable;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import org.wildfly.common.Assert;

/**
 * Algorithm parameter specification for salted hashed password types.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SaltedPasswordAlgorithmSpec implements AlgorithmParameterSpec, Serializable {

    private static final long serialVersionUID = 2106649716615705081L;

    private final byte[] salt;

    /**
     * Create a new instance.
     *
     * @param salt the salt bytes
     */
    public SaltedPasswordAlgorithmSpec(final byte[] salt) {
        Assert.checkNotNullParam("salt", salt);
        this.salt = salt;
    }

    /**
     * Get the salt bytes.
     *
     * @return the salt bytes
     */
    public byte[] getSalt() {
        return salt;
    }

    public boolean equals(Object other) {
        if (! (other instanceof SaltedPasswordAlgorithmSpec)) return false;
        if (this == other) return true;
        SaltedPasswordAlgorithmSpec otherSpec = (SaltedPasswordAlgorithmSpec) other;
        return Arrays.equals(salt, otherSpec.salt);
    }

    public int hashCode() {
        return Arrays.hashCode(salt);
    }
}
