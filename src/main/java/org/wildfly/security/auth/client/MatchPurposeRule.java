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
import java.util.Arrays;

class MatchPurposeRule extends MatchRule {
    private final String[] purposes;

    MatchPurposeRule(final MatchRule parent, final String[] purposes) {
        super(parent);
        this.purposes = purposes;
    }

    String[] getMatchPurposesRaw() {
        return purposes;
    }

    public boolean isPurposeMatched() {
        return true;
    }

    public boolean matches(final URI uri, final String abstractType, final String abstractTypeAuthority, final String purpose) {
        return Arrays.binarySearch(purposes, purpose) >= 0 && super.matches(uri, abstractType, abstractTypeAuthority, purpose);
    }

    MatchRule reparent(final MatchRule newParent) {
        return new MatchPurposeRule(newParent, purposes);
    }

    boolean halfEqual(final MatchRule other) {
        return Arrays.equals(purposes, other.getMatchPurposesRaw()) && parentHalfEqual(other);
    }

    public int hashCode() {
        return multiHashOrdered(parentHashCode(), 6733, Arrays.hashCode(purposes));
    }

    StringBuilder asString(final StringBuilder b) {
        return parentAsString(b).append("purposes=").append(Arrays.toString(purposes)).append(',');
    }
}
