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

import java.util.EnumSet;
import java.util.Iterator;

final class ProtocolCipherSuitePredicate extends CipherSuitePredicate {

    private final EnumSet<Protocol> set;

    ProtocolCipherSuitePredicate(final EnumSet<Protocol> set) {
        this.set = set;
    }

    void toString(final StringBuilder b) {
        b.append("protocol is one of (");
        Iterator<Protocol> iterator = set.iterator();
        if (iterator.hasNext()) {
            Protocol protocol = iterator.next();
            b.append(protocol);
            while (iterator.hasNext()) {
                protocol = iterator.next();
                b.append(", ");
                b.append(protocol);
            }
        }
        b.append(')');
    }

    public boolean test(final MechanismDatabase.Entry entry) {
        return set.contains(entry.getProtocol());
    }

    boolean isAlwaysTrue() {
        return set.size() == Protocol.fullSize;
    }

    boolean isAlwaysFalse() {
        return set.isEmpty();
    }
}
