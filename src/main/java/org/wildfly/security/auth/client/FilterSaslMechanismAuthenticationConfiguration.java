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

import java.util.Set;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class FilterSaslMechanismAuthenticationConfiguration extends AuthenticationConfiguration {

    private final boolean allow;
    private final Set<String> names;

    FilterSaslMechanismAuthenticationConfiguration(final AuthenticationConfiguration parent, final boolean allow, final Set<String> names) {
        super(parent, true);
        this.allow = allow;
        this.names = names;
    }

    boolean filterOneSaslMechanism(final String mechanismName) {
        return names.contains(mechanismName) ? allow : super.filterOneSaslMechanism(mechanismName);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new FilterSaslMechanismAuthenticationConfiguration(newParent, allow, names);
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        parentAsString(sb);
        sb.append("FilterSaslMechanism allow=").append(allow).append(",name=[ ");
        if (names!=null) {
            names.forEach(s -> sb.append(s).append(' '));
        }
        sb.append("],");

        return sb;
    }


}
