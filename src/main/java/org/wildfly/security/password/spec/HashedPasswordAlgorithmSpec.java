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

/**
 * Algorithm parameter specification for common hashed password types.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class HashedPasswordAlgorithmSpec implements AlgorithmParameterSpec, Serializable {

    private static final long serialVersionUID = -13504632816489169L;

    private final int iterationCount;
    private final byte[] salt;

    /**
     * Construct a new instance.
     *
     * @param iterationCount the iteration count
     * @param salt the salt bytes
     */
    public HashedPasswordAlgorithmSpec(final int iterationCount, final byte[] salt) {
        this.iterationCount = iterationCount;
        this.salt = salt;
    }

    /**
     * Get the iteration count.
     *
     * @return the iteration count
     */
    public int getIterationCount() {
        return iterationCount;
    }

    /**
     * Get the salt bytes.
     *
     * @return the salt bytes
     */
    public byte[] getSalt() {
        return salt;
    }
}
