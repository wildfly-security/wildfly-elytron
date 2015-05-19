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

package org.wildfly.security.password.interfaces;

import org.wildfly.security.password.OneWayPassword;

/**
 * A password using the "bcrypt" Blowfish-based one-way password encryption algorithm.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface BCryptPassword extends OneWayPassword {

    /**
     * The algorithm name.
     */
    String ALGORITHM_BCRYPT = "bcrypt";

    /**
     * A constant representing the bcrypt salt size, in bytes.
     */
    int BCRYPT_SALT_SIZE = 16;

    /**
     * A constant representing the bcrypt hash size, in bytes.
     */
    int BCRYPT_HASH_SIZE = 23;

    /**
     * A constant representing the default iteration count for bcrypt passwords.
     */
    int DEFAULT_ITERATION_COUNT = 10;

    /**
     * Get the hash segment of this password.
     *
     * @return the hash segment
     */
    byte[] getHash();

    /**
     * Get the salt segment of this password.
     *
     * @return the salt segment
     */
    byte[] getSalt();

    /**
     * Get the iteration count of this password.
     *
     * @return the iteration count
     */
    int getIterationCount();
}
