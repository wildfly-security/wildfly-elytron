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

import java.security.Principal;

import org.wildfly.security.auth.client.AuthenticationConfiguration.UserSetting;
import org.wildfly.security.auth.principal.NamePrincipal;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetNamePrincipalAuthenticationConfiguration extends AuthenticationConfiguration implements UserSetting {

    private final NamePrincipal principal;

    SetNamePrincipalAuthenticationConfiguration(final AuthenticationConfiguration parent, final NamePrincipal principal) {
        super(parent.without(UserSetting.class, SetCallbackHandlerAuthenticationConfiguration.class));
        this.principal = principal;
    }

    Principal getPrincipal() {
        return principal;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetNamePrincipalAuthenticationConfiguration(newParent, principal);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return principal.equals(getPrincipal()) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return multiHashUnordered(parentHashCode(), 10979, principal.hashCode());
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("NamePrincipal=").append(principal != null ? principal.toString() : "").append(',');
    }

}
