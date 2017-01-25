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

import java.util.Objects;
import java.util.Set;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class FilterSaslMechanismAuthenticationConfiguration extends AuthenticationConfiguration {

    private final Set<String> allowed;
    private final Set<String> denied;

    FilterSaslMechanismAuthenticationConfiguration(final AuthenticationConfiguration parent, final Set<String> allowed, final Set<String> denied) {
        super(parent);
        this.allowed = allowed;
        this.denied = denied;
    }

    boolean saslSupportedByConfiguration(final String mechanismName) {
        return allowed.contains(mechanismName) || super.saslSupportedByConfiguration(mechanismName);
    }

    boolean saslAllowedByConfiguration(final String mechanismName) {
        return ! denied.contains(mechanismName) && super.saslAllowedByConfiguration(mechanismName);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new FilterSaslMechanismAuthenticationConfiguration(newParent, allowed, denied);
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        parentAsString(sb);
        sb.append("FilterSaslMechanism ");
        final boolean deniedEmpty = denied.isEmpty();
        if (! allowed.isEmpty()) {
            sb.append("allowed=").append(allowed).append(deniedEmpty ? ',' : ' ');
        }
        if (! deniedEmpty) {
            sb.append("denied=").append(denied).append(',');
        }

        return sb;
    }

    Set<String> getAllowedSaslMechanisms() {
        return allowed;
    }

    Set<String> getDeniedSaslMechanisms() {
        return denied;
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return Objects.equals(allowed, other.getAllowedSaslMechanisms()) && Objects.equals(denied, other.getDeniedSaslMechanisms()) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return Util.hashiply(Util.hashiply(parentHashCode(), 5393, Objects.hashCode(denied)), 3719, Objects.hashCode(allowed));
    }
}
