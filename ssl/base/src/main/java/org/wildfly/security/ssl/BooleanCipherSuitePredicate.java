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

final class BooleanCipherSuitePredicate extends CipherSuitePredicate {
    static final BooleanCipherSuitePredicate TRUE = new BooleanCipherSuitePredicate(true);
    static final BooleanCipherSuitePredicate FALSE = new BooleanCipherSuitePredicate(false);

    private final boolean result;

    private BooleanCipherSuitePredicate(final boolean result) {
        this.result = result;
    }

    void toString(final StringBuilder b) {
        b.append(result ? "always" : "never").append(" match");
    }

    boolean test(final MechanismDatabase.Entry entry) {
        return result;
    }

    boolean isAlwaysTrue() {
        return result;
    }

    boolean isAlwaysFalse() {
        return ! result;
    }
}
