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

import java.io.Serializable;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Algorithm parameter specification for password types with an iteration count.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class IteratedPasswordAlgorithmSpec implements AlgorithmParameterSpec, Serializable {

    // This could extend SaltedPasswordAlgorithmSpec but final classes makes type detection safer.

    private static final long serialVersionUID = -13504632816489169L;

    private final int iterationCount;

    /**
     * Construct a new instance.
     *
     * @param iterationCount the iteration count
     */
    public IteratedPasswordAlgorithmSpec(final int iterationCount) {
        this.iterationCount = iterationCount;
    }

    /**
     * Get the iteration count.
     *
     * @return the iteration count
     */
    public int getIterationCount() {
        return iterationCount;
    }

    public boolean equals(Object other) {
        if (! (other instanceof IteratedPasswordAlgorithmSpec)) return false;
        if (this == other) return true;
        IteratedPasswordAlgorithmSpec otherSpec = (IteratedPasswordAlgorithmSpec) other;
        return iterationCount == otherSpec.iterationCount;
    }

    public int hashCode() {
        return iterationCount * 71;
    }
}
