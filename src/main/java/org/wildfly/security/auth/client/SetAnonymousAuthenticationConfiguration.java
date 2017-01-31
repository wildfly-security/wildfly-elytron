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

import java.io.IOException;
import java.security.Principal;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.client.AuthenticationConfiguration.UserSetting;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetAnonymousAuthenticationConfiguration extends AuthenticationConfiguration implements UserSetting {

    SetAnonymousAuthenticationConfiguration(final AuthenticationConfiguration parent) {
        super(parent.without(UserSetting.class, SetCallbackHandlerAuthenticationConfiguration.class));
    }

    boolean saslSupportedByConfiguration(final String mechanismName) {
        return SaslMechanismInformation.Names.ANONYMOUS.equals(mechanismName) || super.saslSupportedByConfiguration(mechanismName);
    }

    void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException, IOException {
        Callback callback = callbacks[index];
        if (callback instanceof NameCallback) {
            ((NameCallback) callback).setName(getPrincipal().getName());
        } else {
            super.handleCallback(callbacks, index);
        }
    }

    Principal getPrincipal() {
        return AnonymousPrincipal.getInstance();
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetAnonymousAuthenticationConfiguration(newParent);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return other.delegatesThrough(SetAnonymousAuthenticationConfiguration.class) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return multiHashUnordered(parentHashCode(), 70729, 0);
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("AnonymousAuthentication,");
    }

}
