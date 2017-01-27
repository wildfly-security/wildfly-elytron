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

import static org.wildfly.common.math.HashMath.multiHashOrdered;

import java.net.URI;

class MatchAbstractTypeAuthorityRule extends MatchRule {
    private final String authority;

    MatchAbstractTypeAuthorityRule(final MatchRule parent, final String authority) {
        super(parent);
        this.authority = authority;
    }

    public String getMatchAbstractTypeAuthority() {
        return authority;
    }

    public boolean isTypeAuthorityMatched() {
        return true;
    }

    public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority, final String purpose) {
        return authority.equals(abstractTypeAuthority) && super.matches(uri, abstractType, abstractTypeAuthority, purpose);
    }

    MatchRule reparent(final MatchRule newParent) {
        return new MatchAbstractTypeAuthorityRule(newParent, authority);
    }

    boolean halfEqual(final MatchRule other) {
        return authority.equals(other.getMatchAbstractTypeAuthority()) && parentHalfEqual(other);
    }

    public int hashCode() {
        return multiHashOrdered(parentHashCode(), 7879, authority.hashCode());
    }

    StringBuilder asString(final StringBuilder b) {
        return parentAsString(b).append("abstractTypeAuthority=").append(authority).append(',');
    }
}
