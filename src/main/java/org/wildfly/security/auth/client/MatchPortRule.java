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

import static org.wildfly.common.math.HashMath.multiHashOrdered;

import java.net.URI;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class MatchPortRule extends MatchRule {

    private final int port;

    MatchPortRule(final MatchRule parent, final int port) {
        super(parent);
        this.port = port;
    }

    public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority, final String purpose) {
        return uri.getPort() == port && super.matches(uri, abstractType, abstractTypeAuthority, purpose);
    }

    MatchRule reparent(final MatchRule newParent) {
        return new MatchPortRule(newParent, port);
    }

    boolean halfEqual(final MatchRule other) {
        return other.getMatchPort() == port && parentHalfEqual(other);
    }

    public int hashCode() {
        return multiHashOrdered(parentHashCode(), 7919, port);
    }

    StringBuilder asString(final StringBuilder b) {
        return parentAsString(b).append("port=").append(port).append(',');
    }
}
