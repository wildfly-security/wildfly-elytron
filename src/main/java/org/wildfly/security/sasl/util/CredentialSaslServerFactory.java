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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;

/**
 * A {@link SaslServerFactory} which sets the server's credential.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public final class CredentialSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    private final Object credential;
    private final String algorithm;

    /**
     * Construct a new instance.
     *
     * @param delegate the delegate SASL server factory
     * @param credential the server credential to use
     * @param algorithm the algorithm of the server credential (may be {@code null})
     */
    public CredentialSaslServerFactory(final SaslServerFactory delegate, final Object credential, final String algorithm) {
        super(delegate);
        Assert.checkNotNullParam("credential", credential);
        this.credential = credential;
        this.algorithm = algorithm;
    }

    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, final Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        return delegate.createSaslServer(mechanism, protocol, serverName, props, callbacks -> {
            ArrayList<Callback> list = new ArrayList<>(Arrays.asList(callbacks));
            final Iterator<Callback> iterator = list.iterator();
            while (iterator.hasNext()) {
                Callback callback = iterator.next();
                if (callback instanceof CredentialCallback) {
                    final CredentialCallback credentialCallback = (CredentialCallback) callback;
                    if (credentialCallback.isCredentialSupported(credential.getClass(), algorithm)) {
                        credentialCallback.setCredential(credential);
                        iterator.remove();
                    }
                }
            }
            if (!list.isEmpty()) {
                cbh.handle(list.toArray(new Callback[list.size()]));
            }
        });
    }
}
