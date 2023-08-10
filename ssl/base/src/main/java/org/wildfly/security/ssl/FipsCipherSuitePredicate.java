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

package org.wildfly.security.ssl;

final class FipsCipherSuitePredicate extends CipherSuitePredicate {
    static final FipsCipherSuitePredicate TRUE = new FipsCipherSuitePredicate(true);
    static final FipsCipherSuitePredicate FALSE = new FipsCipherSuitePredicate(false);

    private final boolean fips;

    private FipsCipherSuitePredicate(final boolean fips) {
        this.fips = fips;
    }

    void toString(final StringBuilder b) {
        b.append("is ");
        if (! fips) b.append("not ");
        b.append("FIPS");
    }

    public boolean test(final MechanismDatabase.Entry entry) {
        return fips == entry.isFips();
    }
}
