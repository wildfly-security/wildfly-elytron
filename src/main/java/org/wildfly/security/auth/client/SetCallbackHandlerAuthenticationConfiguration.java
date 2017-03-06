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

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.auth.client.AuthenticationConfiguration.HandlesCallbacks;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetCallbackHandlerAuthenticationConfiguration extends AuthenticationConfiguration implements HandlesCallbacks {

    private final CallbackHandler callbackHandler;
    private final EnumSet<CallbackKind> callbackKinds;

    SetCallbackHandlerAuthenticationConfiguration(final AuthenticationConfiguration parent, final CallbackHandler callbackHandler, final EnumSet<CallbackKind> callbackKinds) {
        super(parent.without(callbackKinds));
        this.callbackHandler = callbackHandler;
        this.callbackKinds = callbackKinds;
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetCallbackHandlerAuthenticationConfiguration(newParent, callbackHandler, callbackKinds);
    }

    Set<CallbackKind> getUserCallbackKinds() {
        return callbackKinds;
    }

    CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    boolean isFullyMatchedBy(final Set<CallbackKind> callbackKinds) {
        return callbackKinds.containsAll(this.callbackKinds);
    }

    AuthenticationConfiguration reparentWithout(final Set<CallbackKind> callbackKinds, final AuthenticationConfiguration newParent) {
        final EnumSet<CallbackKind> newCallbackKinds = this.callbackKinds.clone();
        newCallbackKinds.removeAll(callbackKinds);
        return new SetCallbackHandlerAuthenticationConfiguration(newParent, callbackHandler, newCallbackKinds);
    }

    @Override
    boolean saslSupportedByConfiguration(String mechanismName) {
        return true;
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return Objects.equals(callbackHandler, other.getCallbackHandler()) && parentHalfEqual(other);
    }

    int calcHashCode() {
        return multiHashUnordered(parentHashCode(), 1487, Objects.hashCode(callbackHandler));
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("CallbackHandler,");
    }

}
