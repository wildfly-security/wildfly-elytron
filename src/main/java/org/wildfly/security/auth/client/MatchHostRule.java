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
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class MatchHostRule extends MatchRule {

    private static final Pattern validHostSpecPattern = Pattern.compile("(?i:[-a-z0-9_]+(?:\\.[-a-z0-9_]+)*\\.?)");

    private final String hostSpec;

    MatchHostRule(final MatchRule parent, final String hostSpec) {
        super(parent);
        if (! validHostSpecPattern.matcher(hostSpec).matches()) {
            throw log.invalidHostSpec(hostSpec);
        }
        if (hostSpec.endsWith(".")) {
            this.hostSpec = hostSpec.substring(0, hostSpec.length() - 1).toLowerCase(Locale.ENGLISH);
        } else {
            this.hostSpec = hostSpec.toLowerCase(Locale.ENGLISH);
        }
    }

    public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority, final String purpose) {
        String host = uri.getHost();
        return host != null && host.startsWith(hostSpec) && super.matches(uri, abstractType, abstractTypeAuthority, purpose);
    }

    MatchRule reparent(final MatchRule newParent) {
        return new MatchHostRule(newParent, hostSpec);
    }

    public String getMatchHost() {
        return hostSpec;
    }

    public boolean isHostMatched() {
        return true;
    }

    public int hashCode() {
        // our prime is 2011
        return multiHashUnordered(parentHashCode(), 2011, hostSpec.hashCode());
    }

    boolean halfEqual(final MatchRule other) {
        return hostSpec.equals(other.getMatchHost()) && parentHalfEqual(other);
    }

    StringBuilder asString(final StringBuilder b) {
        return parentAsString(b).append("host=").append(hostSpec).append(',');
    }
}
