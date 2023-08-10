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

final class AndCipherSuitePredicate extends CipherSuitePredicate {
    private final CipherSuitePredicate[] predicates;

    AndCipherSuitePredicate(final CipherSuitePredicate... predicates) {
        this.predicates = predicates;
    }

    void toString(final StringBuilder b) {
        b.append("all of (");
        final int length = predicates.length;
        if (length > 0) {
            b.append(predicates[0]);
            for (int i = 1; i < length; i++) {
                b.append(", ").append(predicates[i]);
            }
        }
        b.append(")");
    }

    boolean test(final MechanismDatabase.Entry entry) {
        for (CipherSuitePredicate predicate : predicates) {
            if (predicate != null && ! predicate.test(entry)) return false;
        }
        return true;
    }

    boolean isAlwaysTrue() {
        for (CipherSuitePredicate predicate : predicates) {
            if (predicate != null && ! predicate.isAlwaysTrue()) return false;
        }
        return true;
    }

    boolean isAlwaysFalse() {
        for (CipherSuitePredicate predicate : predicates) {
            if (predicate != null && predicate.isAlwaysFalse()) return true;
        }
        return false;
    }
}
