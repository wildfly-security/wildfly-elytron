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
 * An MD5-crypt password using the Sun scheme.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public interface SunUnixMD5CryptPassword extends OneWayPassword {

    /**
     * The algorithm name "sun-crypt-md5".
     */
    String ALGORITHM_SUN_CRYPT_MD5 = "sun-crypt-md5";

    /**
     * The algorithm name "sun-crypt-md5-bare-salt".
     */
    String ALGORITHM_SUN_CRYPT_MD5_BARE_SALT = "sun-crypt-md5-bare-salt";

    /**
     * The default salt size of this password type.
     */
    int DEFAULT_SALT_SIZE = 8;

    /**
     * The default iteration count of this password type.
     */
    int DEFAULT_ITERATION_COUNT = 5500;

    /**
     * Get the salt component of this password.
     *
     * @return the salt
     */
    byte[] getSalt();

    /**
     * Get the hash component of this password.
     *
     * @return the hash
     */
    byte[] getHash();

    /**
     * Get the iteration count of this password.
     *
     * @return the iteration count
     */
    int getIterationCount();
}
