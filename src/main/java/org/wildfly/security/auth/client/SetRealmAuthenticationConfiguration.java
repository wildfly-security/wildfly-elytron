/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import org.wildfly.security.auth.client.AuthenticationConfiguration.HandlesCallbacks;

/**
 * @author <a href="mailto:kkhan@redhat.com">Kabir Khan</a>
 */
class SetRealmAuthenticationConfiguration extends AuthenticationConfiguration implements HandlesCallbacks {

    private final String realm;

    SetRealmAuthenticationConfiguration(final AuthenticationConfiguration parent, final String realm) {
        super(parent.without(SetCallbackHandlerAuthenticationConfiguration.class));
        this.realm = realm;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetRealmAuthenticationConfiguration(newParent, realm);
    }

    String getMechanismRealm() {
        return realm;
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return realm.equals(other.getMechanismRealm()) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return multiHashUnordered(parentHashCode(), 28493, realm.hashCode());
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("realm=").append(realm).append(',');
    }
}
