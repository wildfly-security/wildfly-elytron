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

import org.wildfly.security.password.OneWayPassword;

/**
 * The traditional UNIX DES crypt password algorithm.
 */
public interface UnixDESCryptPassword extends OneWayPassword {

    /**
     * The algorithm name "crypt-des".
     */
    String ALGORITHM_CRYPT_DES = "crypt-des";

    /**
     * Get the salt of this password as a {@code short}.
     *
     * @return the salt
     */
    short getSalt();

    /**
     * Get the crypt bytes, not including the salt.
     *
     * @return the crypt bytes
     */
    byte[] getHash();
}
