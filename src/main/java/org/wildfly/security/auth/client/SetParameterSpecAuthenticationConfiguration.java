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
import java.security.spec.AlgorithmParameterSpec;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.ParameterCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration.HandlesCallbacks;

/**
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
class SetParameterSpecAuthenticationConfiguration extends AuthenticationConfiguration implements HandlesCallbacks {
    private final List<AlgorithmParameterSpec> parameterSpecs;

    SetParameterSpecAuthenticationConfiguration(final AuthenticationConfiguration parent, final AlgorithmParameterSpec parameterSpec) {
        this(parent, Collections.singletonList(parameterSpec));
    }

    SetParameterSpecAuthenticationConfiguration(final AuthenticationConfiguration parent, final List<AlgorithmParameterSpec> parameterSpecs) {
        super(parent.without(SetCallbackHandlerAuthenticationConfiguration.class));
        this.parameterSpecs = parameterSpecs;
    }

    void handleCallback(final Callback[] callbacks, final int index) throws UnsupportedCallbackException, IOException {
        Callback callback = callbacks[index];
        if (callback instanceof ParameterCallback) {
            ParameterCallback parameterCallback = (ParameterCallback) callback;
            if (parameterCallback.getParameterSpec() == null) {
                for (AlgorithmParameterSpec parameterSpec : parameterSpecs) {
                    if (parameterCallback.isParameterSupported(parameterSpec)) {
                        parameterCallback.setParameterSpec(parameterSpec);
                        return;
                    }
                }
            }
        }
        super.handleCallback(callbacks, index);
    }

    @Override
    AuthenticationConfiguration reparent(AuthenticationConfiguration newParent) {
        return new SetParameterSpecAuthenticationConfiguration(newParent, parameterSpecs);
    }

    boolean halfEqual(final AuthenticationConfiguration other) {
        return Objects.equals(parameterSpecs, other.getParameterSpecs());
    }

    List<AlgorithmParameterSpec> getParameterSpecs() {
        return parameterSpecs;
    }

    int calcHashCode() {
        return Util.hashiply(parentHashCode(), 7817, parameterSpecs.hashCode());
    }

    @Override
    StringBuilder asString(StringBuilder sb) {
        return parentAsString(sb).append("ParameterSpec,");
    }

}
