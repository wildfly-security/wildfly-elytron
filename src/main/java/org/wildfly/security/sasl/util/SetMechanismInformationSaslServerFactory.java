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

import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.auth.callback.MechanismInformationCallback;
import org.wildfly.security.auth.server.MechanismInformation;

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
        try {
            final MechanismInformationCallback mechanismInformationCallback = new MechanismInformationCallback(new MechanismInformation() {

                @Override
                public String getProtocol() {
                    return protocol;
                }

                @Override
                public String getMechanismType() {
                    return "SASL";
                }

                @Override
                public String getMechanismName() {
                    return mechanism;
                }

                @Override
                public String getHostName() {
                    return serverName;
                }
            });
            cbh.handle(new Callback[] { mechanismInformationCallback });
        } catch (Throwable e) {
            // The mechanism information could not be successfully resolved to a mechanism configuration
            return null;
        }
        return super.createSaslServer(mechanism, protocol, serverName, props, cbh);
    }

}
