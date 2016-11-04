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

package org.wildfly.security.auth.client;

import java.net.URI;

class MatchAbstractTypeRule extends MatchRule {
    private final String type;

    MatchAbstractTypeRule(final MatchRule parent, final String type) {
        super(parent);
        this.type = type;
    }

    public String getMatchAbstractType() {
        return type;
    }

    public boolean isTypeMatched() {
        return true;
    }

    public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority) {
        return type.equals(abstractType) && super.matches(uri, abstractType, abstractTypeAuthority);
    }

    MatchRule reparent(final MatchRule newParent) {
        return new MatchAbstractTypeRule(newParent, type);
    }

    boolean halfEqual(final MatchRule other) {
        return type.equals(other.getMatchAbstractType()) && parentHalfEqual(other);
    }

    public int hashCode() {
        return 5693 * type.hashCode() + parentHashCode();
    }

    StringBuilder asString(final StringBuilder b) {
        return parentAsString(b).append("abstractType=").append(type).append(',');
    }
}
