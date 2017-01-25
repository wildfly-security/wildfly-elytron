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

import org.wildfly.security.util.URIUtil;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class MatchNoUserRule extends MatchRule {

    MatchNoUserRule(final MatchRule parent) {
        super(parent.without(MatchUserRule.class));
    }

    public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority, final String purpose) {
        String userInfo = URIUtil.getUserFromURI(uri);
        return userInfo == null && super.matches(uri, abstractType, abstractTypeAuthority, purpose);
    }

    MatchRule reparent(final MatchRule newParent) {
        return new MatchNoUserRule(newParent);
    }

    boolean halfEqual(final MatchRule other) {
        return other.getMatchUser() == null && parentHalfEqual(other);
    }

    public int hashCode() {
        return Util.hashiply(parentHashCode(), 3121,0);
    }

    StringBuilder asString(final StringBuilder b) {
        return parentAsString(b).append("no user,");
    }
}
