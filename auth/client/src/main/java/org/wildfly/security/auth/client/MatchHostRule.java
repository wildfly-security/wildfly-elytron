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
import static org.wildfly.security.auth.client._private.ElytronMessages.log;

import java.net.URI;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class MatchHostRule extends MatchRule {

    private static final Pattern validHostSpecPattern = Pattern.compile(
        "(\\*\\.)?([-a-z0-9_]+(?:\\.[-a-z0-9_]+)*)",
        Pattern.CASE_INSENSITIVE
    );

    private final boolean suffixMatch;
    private final String hostSpec;

    MatchHostRule(final MatchRule parent, String hostSpec) {
        super(parent.without(MatchNetworkRule.class));
        final Matcher matcher = validHostSpecPattern.matcher(hostSpec);
        if (! matcher.matches()) {
            throw log.invalidHostSpec(hostSpec);
        }
        suffixMatch = matcher.group(1) != null;
        this.hostSpec = matcher.group(2).toLowerCase(Locale.ROOT);
    }

    @Override
    public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority) {
        String host = uri.getHost();
        if (host == null) {
            return false;
        }
        final String canonHost = host.toLowerCase(Locale.ROOT);

        if (suffixMatch) {
            if (canonHost.equals(hostSpec)) {
                return super.matches(uri, abstractType, abstractTypeAuthority);
            }
            if (canonHost.endsWith(hostSpec)) {
                assert canonHost.length() > hostSpec.length(); // because otherwise it would be equal, which is tested above
                return canonHost.codePointBefore(canonHost.length() - hostSpec.length()) == '.' && super.matches(uri, abstractType, abstractTypeAuthority);
            }
            return false;
        } else {
            return canonHost.equals(hostSpec) && super.matches(uri, abstractType, abstractTypeAuthority);
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
