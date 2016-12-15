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

package org.wildfly.security.password.interfaces;

import static org.wildfly.common.Assert.checkNotNullParam;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;

/**
 * A simple clear-text password.
 */
public interface ClearPassword extends TwoWayPassword {

    /**
     * The algorithm name.
     */
    String ALGORITHM_CLEAR = "clear";

    /**
     * Get the password characters.
     *
     * @return the password characters
     */
    char[] getPassword() throws IllegalStateException;

    /**
     * Creates and returns a copy of this {@link Password}.
     *
     * @return a copy of this {@link Password}.
     */
    ClearPassword clone();

    /**
     * Create a raw implementation of this password type.  No validation of the content is performed, and the password
     * must be "adopted" in to a {@link PasswordFactory} (via the {@link PasswordFactory#translate(Password)} method)
     * before it can be validated and used to verify guesses.
     *
     * @param algorithm the algorithm name
     * @param password the password characters
     * @return the raw password implementation
     */
    static ClearPassword createRaw(String algorithm, char[] password) {
        checkNotNullParam("algorithm", algorithm);
        checkNotNullParam("password", password);
        return new RawClearPassword(algorithm, password.clone());
    }
}
