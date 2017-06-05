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

package org.wildfly.security.auth.client;

import static org.wildfly.common.math.HashMath.multiHashUnordered;

import java.net.URI;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class MatchSchemeRule extends MatchRule {

    private final String protoName;

    MatchSchemeRule(final MatchRule parent, final String protoName) {
        super(parent);
        this.protoName = protoName;
    }

    @Override
    public boolean isProtocolMatched() {
        return true;
    }

    @Override
    public String getMatchProtocol() {
        return protoName;
    }

    @Override
    public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority) {
        String scheme = uri.getScheme();
        return scheme != null && scheme.equals(protoName) && super.matches(uri, abstractType, abstractTypeAuthority);
    }

    @Override
    MatchRule reparent(final MatchRule newParent) {
        return new MatchSchemeRule(newParent, protoName);
    }

    @Override
    public int hashCode() {
        // our prime is 3547
        return multiHashUnordered(parentHashCode(), 3547, protoName.hashCode());
    }

    @Override
    boolean halfEqual(final MatchRule other) {
        return protoName.equals(other.getMatchProtocol()) && parentHalfEqual(other);
    }

    @Override
    StringBuilder asString(final StringBuilder b) {
        return parentAsString(b).append("scheme=").append(protoName).append(',');
    }
}
