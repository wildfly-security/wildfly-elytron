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
 * A simple password where the generated digest also includes a salt.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface SaltedSimpleDigestPassword extends OneWayPassword {

    /**
     * Algorithm name for digest created using MD5 with the password digested first followed by the salt.
     */
    String ALGORITHM_PASSWORD_SALT_DIGEST_MD5 = "password-salt-digest-md5";

    /**
     * Algorithm name for digest created using SHA-1 with the password digested first followed by the salt.
     */
    String ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1 = "password-salt-digest-sha-1";

    /**
     * Algorithm name for digest created using SHA-256 with the password digested first followed by the salt.
     */
    String ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256 = "password-salt-digest-sha-256";

    /**
     * Algorithm name for digest created using SHA-384 with the password digested first followed by the salt.
     */
    String ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384 = "password-salt-digest-sha-384";

    /**
     * Algorithm name for digest created using SHA-512 with the password digested first followed by the salt.
     */
    String ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512 = "password-salt-digest-sha-512";

    /**
     * Algorithm name for digest created using MD5 with the salt digested first followed by the password.
     */
    String ALGORITHM_SALT_PASSWORD_DIGEST_MD5 = "salt-password-digest-md5";

    /**
     * Algorithm name for digest created using SHA-1 with the salt digested first followed by the password.
     */
    String ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1 = "salt-password-digest-sha-1";

    /**
     * Algorithm name for digest created using SHA-256 with the salt digested first followed by the password.
     */
    String ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256 = "salt-password-digest-sha-256";

    /**
     * Algorithm name for digest created using SHA-384 with the salt digested first followed by the password.
     */
    String ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384 = "salt-password-digest-sha-384";

    /**
     * Algorithm name for digest created using SHA-512 with the salt digested first followed by the password.
     */
    String ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512 = "salt-password-digest-sha-512";

    /**
     * The default salt size (in bytes), used when generating a random salt.
     */
    int DEFAULT_SALT_SIZE = 12;

    /**
     * Get the digest represented by this {@link org.wildfly.security.password.Password password}
     *
     * @return The digest represented by this {@link org.wildfly.security.password.Password password}
     */
    byte[] getDigest();

    /**
     * Get the salt used to generate the digest.
     *
     * @return The salt used to generate the digest.
     */
    byte[] getSalt();

}
