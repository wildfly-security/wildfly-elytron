/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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

/**
 * A {@link PasswordSpec} for a password represented by a hash with a salt.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class SaltedHashPasswordSpec implements PasswordSpec {

    private final byte[] hash;
    private final byte[] salt;

    public SaltedHashPasswordSpec(final byte[] hash, final byte[] salt) {
        this.hash = hash;
        this.salt = salt;
    }

    public byte[] getHash() {
        return this.hash;
    }

    public byte[] getSalt() {
        return this.salt;
    }
}
