/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import static org.wildfly.common.math.HashMath.multiHashOrdered;

import java.security.MessageDigest;
import java.util.Arrays;

class RawDigestPassword extends RawPassword implements DigestPassword {

    private static final long serialVersionUID = 7084601864990731347L;

    private final String username;
    private final String realm;
    private final byte[] digest;

    RawDigestPassword(final String algorithm, final String username, final String realm, final byte[] digest) {
        super(algorithm);
        this.username = username;
        this.realm = realm;
        this.digest = digest;
    }

    public String getUsername() {
        return username;
    }

    public String getRealm() {
        return realm;
    }

    public byte[] getDigest() {
        return digest.clone();
    }

    public RawDigestPassword clone() {
        return this;
    }

    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(multiHashOrdered(Arrays.hashCode(digest), username.hashCode()), realm.hashCode()), getAlgorithm().hashCode());
    }

    public boolean equals(final Object obj) {
        if (! (obj instanceof RawDigestPassword)) {
            return false;
        }
        RawDigestPassword other = (RawDigestPassword) obj;
        return MessageDigest.isEqual(digest, other.digest) && username.equals(other.username) && realm.equals(other.realm) && getAlgorithm().equals(other.getAlgorithm());
    }
}
