/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.auth.callback.MechanismInformationCallback;

/**
 * A {@link SaslServerFactory} implementation that will always ensure mechanism information is passed to the {@link CallbackHandler} before the first authentication callbacks.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public final class SetMechanismInformationSaslServerFactory extends AbstractDelegatingSaslServerFactory {

    /**
     * Construct a new instance of the {@code SetMechanismInformationSaslServerFactory}.
     *
     * @param delegate the {@link SaslServerFactory} being delegated to.
     */
    public SetMechanismInformationSaslServerFactory(SaslServerFactory delegate) {
        super(delegate);
    }

    @Override
    public SaslServer createSaslServer(final String mechanism, final String protocol, final String serverName, Map<String, ?> props, final CallbackHandler cbh) throws SaslException {
        final CallbackHandler wrapper = new CallbackHandler() {

            private volatile boolean informationSent = false;

            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (informationSent == false) {
                    informationSent = true;
                    cbh.handle(new Callback[] { new MechanismInformationCallback("SASL", mechanism, serverName, protocol) });
                }
                cbh.handle(callbacks);
            }
        };

        return super.createSaslServer(mechanism, protocol, serverName, props, wrapper);
    }

}
