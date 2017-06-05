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
import static org.wildfly.security._private.ElytronMessages.log;

import java.net.URI;
import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Pattern;

import org.wildfly.common.net.Inet;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class MatchHostRule extends MatchRule {

    private static final Pattern validHostSpecPattern = Pattern.compile("(?i:[-a-z0-9_]+(?:\\.[-a-z0-9_]+)*)");

    private final String hostSpec;
    private final byte[] hostSpecBytes;

    MatchHostRule(final MatchRule parent, String hostSpec) {
        super(parent);
        if (hostSpec.contains(":")) { // IPv6
            this.hostSpecBytes = Inet.parseInet6AddressToBytes(hostSpec);
            if (this.hostSpecBytes == null) {
                throw log.invalidHostSpec(hostSpec);
            }
        } else { // IPv4 or domain name
            if (!validHostSpecPattern.matcher(hostSpec).matches()) {
                throw log.invalidHostSpec(hostSpec);
            }
            this.hostSpecBytes = Inet.parseInet4AddressToBytes(hostSpec); // null if not IPv4
        }
        this.hostSpec = hostSpec.toLowerCase(Locale.ROOT);
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

        // if both hostSpec and host are valid IP addresses, compare their byte representations, otherwise compare as strings
        if (hostBytes != null && this.hostSpecBytes != null) {
            return Arrays.equals(hostBytes, this.hostSpecBytes) && super.matches(uri, abstractType, abstractTypeAuthority);
        } else {
            return host.toLowerCase(Locale.ROOT).equals(hostSpec) && super.matches(uri, abstractType, abstractTypeAuthority);
        }
    }

    @Override
    MatchRule reparent(final MatchRule newParent) {
        return new MatchHostRule(newParent, hostSpec);
    }

    @Override
    public String getMatchHost() {
        return hostSpec;
    }

    @Override
    public boolean isHostMatched() {
        return true;
    }

    @Override
    public int hashCode() {
        // our prime is 2011
        return multiHashUnordered(parentHashCode(), 2011, hostSpec.hashCode());
    }

    @Override
    boolean halfEqual(final MatchRule other) {
        return hostSpec.equals(other.getMatchHost()) && parentHalfEqual(other);
    }

    @Override
    StringBuilder asString(final StringBuilder b) {
        return parentAsString(b).append("host=").append(hostSpec).append(',');
    }
}
