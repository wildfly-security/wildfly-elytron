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
package org.wildfly.security.password.spec;

import static org.wildfly.common.math.HashMath.multiHashOrdered;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;


/**
 * A {@link PasswordSpec} for a password represented by a Digest Response as seen in Digest-MD5 SASL/HTTP mechanism.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class DigestPasswordSpec implements PasswordSpec {

    private final String username;
    private final String realm;
    private final byte[] digest;

    /**
     * @param username the username
     * @param realm the realm (name of a collection of accounts)
     * @param digest the digest: H( username ":" realm ":" password )
     */
    public DigestPasswordSpec(String username, String realm, byte[] digest) {
        this.username = username;
        this.realm = realm;
        this.digest = digest;
    }

    /**
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * @return the realm (name of a collection of accounts)
     */
    public String getRealm() {
        return realm;
    }

    /**
     * @return the digest: H( username ":" realm ":" password )
     */
    public byte[] getDigest() {
        return digest;
    }

    @Override
    public boolean equals(Object other) {
        if (! (other instanceof DigestPasswordSpec)) return false;
        DigestPasswordSpec o = (DigestPasswordSpec) other;
        return Objects.equals(username, o.username) && Objects.equals(realm, o.realm) && MessageDigest.isEqual(digest, o.digest);
    }

    @Override
    public int hashCode() {
        return multiHashOrdered(multiHashOrdered(Objects.hashCode(username), Objects.hashCode(realm)), Arrays.hashCode(digest));
    }
}
