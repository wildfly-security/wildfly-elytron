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

import java.security.spec.AlgorithmParameterSpec;

/**
 * A password specification for clear passwords which are intended to be encrypted or hashed.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class EncryptablePasswordSpec implements PasswordSpec {
    private final char[] password;
    private final AlgorithmParameterSpec algorithmParameterSpec;

    /**
     * Construct a new instance.
     *
     * @param password the password to be encrypted or hashed
     * @param algorithmParameterSpec the parameters of the algorithm to be used for encryption or hashing
     */
    public EncryptablePasswordSpec(final char[] password, final AlgorithmParameterSpec algorithmParameterSpec) {
        this.password = password;
        this.algorithmParameterSpec = algorithmParameterSpec;
    }

    /**
     * Get the password characters.
     *
     * @return the password characters
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * Get the algorithm parameter specification.
     *
     * @return the algorithm parameter specification
     */
    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return algorithmParameterSpec;
    }
}
