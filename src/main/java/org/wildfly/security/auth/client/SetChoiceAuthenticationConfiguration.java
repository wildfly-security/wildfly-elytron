/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.wildfly.security.auth.client;

import java.io.IOException;
import java.util.Objects;
import java.util.function.Predicate;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmChoiceCallback;

import org.wildfly.security.auth.client.AuthenticationConfiguration.HandlesCallbacks;

/**
 * @author <a href="mailto:kkhan@redhat.com">Kabir Khan</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetChoiceAuthenticationConfiguration extends AuthenticationConfiguration implements HandlesCallbacks {
    private final Predicate<ChoiceCallback> operation;

    SetChoiceAuthenticationConfiguration(final AuthenticationConfiguration parent, final Predicate<ChoiceCallback> operation) {
        super(parent.without(SetCallbackHandlerAuthenticationConfiguration.class));
        this.operation = operation;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException, IOException {
        Callback callback = callbacks[index];
        if (callback instanceof ChoiceCallback && ! (callback instanceof RealmChoiceCallback)) {
            if (operation.test((ChoiceCallback) callback)) {
                return;
            }
        }
        super.handleCallback(callbacks, index);
    }

    @Override
    AuthenticationConfiguration reparent(AuthenticationConfiguration newParent) {
        return new SetChoiceAuthenticationConfiguration(newParent, operation);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return Objects.equals(operation, other.getChoiceOperation()) && other.parentHalfEqual(other);
    }

    int calcHashCode() {
        return Util.hashiply(parentHashCode(), 22817, Objects.hashCode(operation));
    }

    Predicate<ChoiceCallback> getChoiceOperation() {
        return operation;
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("choice=").append(operation).append(',');
    }
}
