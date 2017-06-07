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

package org.wildfly.security.sasl.util;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.wildfly.common.math.HashMath;
import org.wildfly.security.auth.callback.ChannelBindingCallback;
import org.wildfly.security.auth.callback.SSLCallback;
import org.wildfly.security.ssl.TLSServerEndPointChannelBinding;
import org.wildfly.security.x500.X500;

/**
 * A SASL client factory which implements the {@code tls-server-end-point} channel binding algorithm.  The channel
 * binding will not be activated unless this SASL client factory wraps a {@link SSLSaslClientFactory}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class TLSServerEndPointChannelBindingSaslClientFactory extends AbstractDelegatingSaslClientFactory {

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate server factory
     */
    public TLSServerEndPointChannelBindingSaslClientFactory(final SaslClientFactory delegate) {
        super(delegate);
    }

    public SaslClient createSaslClient(final String[] mechanisms, final String authorizationId, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return super.createSaslClient(mechanisms, authorizationId, protocol, serverName, props, new CallbackHandler() {
            private X509Certificate[] peerCerts;

            public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
                final Iterator<Callback> iterator = list.iterator();
                while (iterator.hasNext()) {
                    Callback callback = iterator.next();
                    if (callback instanceof SSLCallback) {
                        final SSLCallback sslCallback = (SSLCallback) callback;
                        peerCerts = X500.asX509CertificateArray(sslCallback.getSslSession().getPeerCertificates());
                    } else if (callback instanceof ChannelBindingCallback) {
                        TLSServerEndPointChannelBinding.handleChannelBindingCallback((ChannelBindingCallback) callback, peerCerts);
                        iterator.remove();
                    }
                }
                if (!list.isEmpty()) {
                    cbh.handle(list.toArray(new Callback[list.size()]));
                }
            }
        });
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final Object other) {
        return other instanceof TLSServerEndPointChannelBindingSaslClientFactory && equals((TLSServerEndPointChannelBindingSaslClientFactory) other);
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final AbstractDelegatingSaslClientFactory other) {
        return other instanceof TLSServerEndPointChannelBindingSaslClientFactory && equals((TLSServerEndPointChannelBindingSaslClientFactory) other);
    }

    @SuppressWarnings("checkstyle:equalshashcode")
    public boolean equals(final TLSServerEndPointChannelBindingSaslClientFactory other) {
        return super.equals(other);
    }

    protected int calculateHashCode() {
        return HashMath.multiHashOrdered(super.calculateHashCode(), getClass().hashCode());
    }
}
