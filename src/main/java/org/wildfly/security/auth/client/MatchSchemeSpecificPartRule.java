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

import java.net.URI;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class MatchSchemeSpecificPartRule extends MatchRule {

    private final String name;

    MatchSchemeSpecificPartRule(final MatchRule parent, final String name) {
        super(parent);
        this.name = name;
    }

    public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority, final String purpose) {
        if (! uri.isOpaque()) return false;
        String scheme = uri.getScheme();
        String name;
        if (scheme.equals("domain")) {
            // special parsing rules for security domains
            String ssp = uri.getSchemeSpecificPart();
            int idx = ssp.indexOf('@');
            if (idx != -1) {
                name = ssp.substring(idx + 1, ssp.length());
            } else {
                name = ssp;
            }
        } else {
            name = uri.getSchemeSpecificPart();
        }
        return name.equals(this.name) && super.matches(uri, abstractType, abstractTypeAuthority, purpose);
    }

    MatchRule reparent(final MatchRule newParent) {
        return new MatchSchemeSpecificPartRule(newParent, name);
    }

    boolean halfEqual(final MatchRule other) {
        return name.equals(other.getMatchUrnName()) && parentHalfEqual(other);
    }

    public int hashCode() {
        return Util.hashiply(parentHashCode(), 2143, name.hashCode());
    }

    StringBuilder asString(final StringBuilder b) {
        return parentAsString(b).append("urn=").append(name).append(',');
    }
}
