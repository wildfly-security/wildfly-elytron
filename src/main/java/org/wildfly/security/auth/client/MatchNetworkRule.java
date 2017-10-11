/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import org.wildfly.common.net.CidrAddress;
import org.wildfly.common.net.Inet;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class MatchNetworkRule extends MatchRule {

    private final CidrAddress cidrAddress;

    MatchNetworkRule(final MatchRule parent, CidrAddress cidrAddress) {
        super(parent.without(MatchHostRule.class));
        this.cidrAddress = cidrAddress;
    }

    @Override
    public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority) {
        String host = uri.getHost();
        if (host == null) {
            return false;
        }

        byte[] hostBytes;
        if (host.startsWith("[") && host.endsWith("]")) {
            hostBytes = Inet.parseInet6AddressToBytes(host);
        } else {
            hostBytes = Inet.parseInet4AddressToBytes(host); // null if not IPv4
        }
        return hostBytes != null && cidrAddress.matches(hostBytes) && super.matches(uri, abstractType, abstractTypeAuthority);
    }

    @Override
    MatchRule reparent(final MatchRule newParent) {
        return new MatchNetworkRule(newParent, cidrAddress);
    }

    @Override
    public boolean isNetworkMatched() {
        return true;
    }

    @Override
    public CidrAddress getMatchNetwork() {
        return cidrAddress;
    }

    @Override
    public int hashCode() {
        // our prime is 5953
        return multiHashUnordered(parentHashCode(), 5953, cidrAddress.hashCode());
    }

    @Override
    boolean halfEqual(final MatchRule other) {
        return cidrAddress.equals(other.getMatchNetwork()) && parentHalfEqual(other);
    }

    @Override
    StringBuilder asString(final StringBuilder b) {
        return parentAsString(b).append("network=").append(cidrAddress).append(',');
    }
}
