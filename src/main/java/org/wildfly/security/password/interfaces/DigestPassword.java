/*
 * JBoss, Home of Professional Open Source
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

import org.wildfly.security.password.AugmentedPassword;
import org.wildfly.security.password.OneWayPassword;
import org.wildfly.security.password.Password;

/**
 * Digest MD5 (pre-digested) password.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public interface DigestPassword extends OneWayPassword, AugmentedPassword<DigestPassword.MetaData> {

    String ALGORITHM_DIGEST_MD5 = "digest-md5";
    String ALGORITHM_DIGEST_SHA = "digest-sha";
    String ALGORITHM_DIGEST_SHA_256 = "digest-sha-256";
    String ALGORITHM_DIGEST_SHA_512 = "digest-sha-512";

    /**
     * Get the username this {@link Password} is associated with.
     *
     * Generally a {@link Password} should not need to know this information but this is an integral part of how the
     * representation of this {@link Password} is created.
     *
     * @return The username this {@link Password} is associated with.
     */
    String getUsername();

    /**
     * Get the realm this {@link Password} is associated with.
     *
     * Note: This is independent of the name of the realm used to obtain the {@link Password} representation, this is the value
     * used to generate the digest.
     *
     * @return the realm this {@link Password} is associated with.
     */
    String getRealm();

    /**
     * Get the digest represented by this {@link Password}
     *
     * @return The digest represented by this {@link Password}
     */
    byte[] getDigest();

    /**
     * Additional MetaData that can be specified when querying support for a credential type or obtaining the credential type.
     *
     * In the case of the {@link DigestPassword} the realm and or algorithm can be specified.
     */
    static class MetaData {
        private final String realm;
        private final String algorithm;

        public MetaData(final String realm, final String algorithm) {
            this.realm = realm;
            this.algorithm = algorithm;
        }

        public String getRealm() {
            return realm;
        }

        public String getAlgorithm() {
            return algorithm;
        }

    }

}
