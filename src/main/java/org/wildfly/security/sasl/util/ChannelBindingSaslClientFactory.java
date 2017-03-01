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

package org.wildfly.security.sasl.util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.common.math.HashMath;
import org.wildfly.security.auth.callback.ChannelBindingCallback;

/**
 * A {@link SaslClientFactory} which establishes channel binding parameters.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class ChannelBindingSaslClientFactory extends AbstractDelegatingSaslClientFactory {
    private final String bindingType;
    private final byte[] bindingData;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL client factory
     * @param bindingType the binding type to use
     * @param bindingData the binding data
     */
    public ChannelBindingSaslClientFactory(final SaslClientFactory delegate, final String bindingType, final byte[] bindingData) {
        super(delegate);
        Assert.checkNotNullParam("bindingType", bindingType);
        Assert.checkNotNullParam("bindingData", bindingData);
        this.bindingType = bindingType;
        this.bindingData = bindingData;
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return delegate.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, callbacks -> {
            ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
            final Iterator<Callback> iterator = list.iterator();
            while (iterator.hasNext()) {
                Callback callback = iterator.next();
                if (callback instanceof ChannelBindingCallback) {
                    ((ChannelBindingCallback) callback).setBindingType(bindingType);
                    ((ChannelBindingCallback) callback).setBindingData(bindingData);
                    iterator.remove();
                }
            }
            if (!list.isEmpty()) {
                cbh.handle(list.toArray(new Callback[list.size()]));
            }
        });
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final Object other) {
        return other instanceof ChannelBindingSaslClientFactory && equals((ChannelBindingSaslClientFactory) other);
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final AbstractDelegatingSaslClientFactory other) {
        return other instanceof ChannelBindingSaslClientFactory && equals((ChannelBindingSaslClientFactory) other);
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final ChannelBindingSaslClientFactory other) {
        return super.equals(other) && bindingType.equals(other.bindingType) && Arrays.equals(bindingData, other.bindingData);
    }

    protected int calculateHashCode() {
        return HashMath.multiHashOrdered(HashMath.multiHashOrdered(HashMath.multiHashOrdered(super.calculateHashCode(), getClass().hashCode()), bindingType.hashCode()), Arrays.hashCode(bindingData));
    }
}
