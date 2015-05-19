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
 * The UNIX modular-crypt MD5 crypt algorithm.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface UnixMD5CryptPassword extends OneWayPassword {

    /**
     * The algorithm name "crypt-md5".
     */
    String ALGORITHM_CRYPT_MD5 = "crypt-md5";

    /**
     * The maximum salt size.
     */
    int SALT_SIZE = 8;

    /**
     * Get the salt component of this password.
     *
     * @return the salt component
     */
    byte[] getSalt();

    /**
     * Get the hash component of this password.
     *
     * @return the hash component
     */
    byte[] getHash();
}
