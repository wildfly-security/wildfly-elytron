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

class RawBSDUnixDESCryptPassword extends RawPassword implements BSDUnixDESCryptPassword {

    private static final long serialVersionUID = -652173302985035000L;

    private final int iterationCount;
    private final int salt;
    private final byte[] hash;

    RawBSDUnixDESCryptPassword(final String algorithm, final int iterationCount, final int salt, final byte[] hash) {
        super(algorithm);
        this.iterationCount = iterationCount;
        this.salt = salt;
        this.hash = hash;
    }

    public int getIterationCount() {
        return iterationCount;
    }

    public int getSalt() {
        return salt;
    }

    public byte[] getHash() {
        return hash.clone();
    }

    public RawBSDUnixDESCryptPassword clone() {
        return this;
    }

}
