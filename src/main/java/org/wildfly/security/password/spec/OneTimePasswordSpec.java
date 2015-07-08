/*
 * JBoss, Home of Professional Open Source
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
package org.wildfly.security.password.spec;

/**
 * A {@link PasswordSpec} for a one-time password.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class OneTimePasswordSpec implements PasswordSpec {

    private final byte[] hash;
    private final byte[] seed;
    private final int sequenceNumber;

    public OneTimePasswordSpec(final byte[] hash, final byte[] seed, final int sequenceNumber) {
        this.hash = hash;
        this.seed = seed;
        this.sequenceNumber = sequenceNumber;
    }

    public byte[] getHash() {
        return hash;
    }

    public byte[] getSeed() {
        return seed;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }
}
