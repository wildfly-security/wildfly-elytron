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

package org.wildfly.security.password.spec;

public final class BSDUnixDESCryptPasswordSpec implements PasswordSpec {
    private final byte[] hash;
    private final int salt;
    private final int iterationCount;

    public BSDUnixDESCryptPasswordSpec(final byte[] hash, final int salt, final int iterationCount) {
        this.hash = hash;
        this.salt = salt;
        this.iterationCount = iterationCount;
    }

    public byte[] getHash() {
        return hash;
    }

    public int getSalt() {
        return salt;
    }

    public int getIterationCount() {
        return iterationCount;
    }
}
