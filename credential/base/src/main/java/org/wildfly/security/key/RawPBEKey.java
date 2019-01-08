/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.key;

import java.security.Key;
import java.util.Arrays;

import javax.crypto.interfaces.PBEKey;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class RawPBEKey extends RawKey implements PBEKey {
    private static final long serialVersionUID = 9196265211940105324L;

    private final char[] password;
    private final byte[] salt;
    private final int iterationCount;

    RawPBEKey(final PBEKey original) {
        super(original);
        final char[] password = original.getPassword();
        this.password = password == null ? null : password.clone();
        final byte[] salt = original.getSalt();
        this.salt = salt == null ? null : salt.clone();
        iterationCount = original.getIterationCount();
    }

    RawPBEKey(final Key key) {
        this((PBEKey) key);
    }

    public char[] getPassword() {
        final char[] password = this.password;
        return password == null ? null : password.clone();
    }

    public byte[] getSalt() {
        final byte[] salt = this.salt;
        return salt == null ? null : salt.clone();
    }

    public int getIterationCount() {
        return iterationCount;
    }

    boolean isEqual(final Key key) {
        return key instanceof PBEKey && isEqual((PBEKey) key);
    }

    boolean isEqual(final PBEKey key) {
        return super.isEqual(key) && Arrays.equals(password, key.getPassword()) && Arrays.equals(salt, key.getSalt()) && iterationCount == key.getIterationCount();
    }
}
