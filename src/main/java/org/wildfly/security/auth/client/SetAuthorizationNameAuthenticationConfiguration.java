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

class SetAuthorizationNameAuthenticationConfiguration extends AuthenticationConfiguration {

    private final String name;

    SetAuthorizationNameAuthenticationConfiguration(final AuthenticationConfiguration parent, final String name) {
        super(parent);
        this.name = name;
    }

    String getAuthorizationName() {
        return name;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetAuthorizationNameAuthenticationConfiguration(newParent, name);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return Objects.equals(name, other.getAuthorizationName()) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return Util.hashiply(parentHashCode(), 4397, name.hashCode());
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("authorization-name=").append(name).append(',');
    }

}
