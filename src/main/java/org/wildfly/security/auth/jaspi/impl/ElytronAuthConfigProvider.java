/*
 * Copyright 2016 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.jaspi.impl;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.AuthConfig;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ClientAuthConfig;
import javax.security.auth.message.config.ClientAuthContext;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;

/**
 * The WildFly Elytron implementation of {@link AuthConfigProvider}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class ElytronAuthConfigProvider implements AuthConfigProvider {

    /*
     * The instance of AuthConfigProvider can be obtained once per deployment, for this reason it is important not to cache
     * per-request state long term.
     */

    private static ClientAuthConfig EMPTY_CLIENT_AUTH_CONFIG = new EmptyClientAuthConfig();
    private static ServerAuthConfig EMPTY_SERVER_AUTH_CONFIG = new EmptyServerAuthConfig();

    /**
     * The messageLayer this config provider will match against, can be {@code null} for wildcard matches.
     */
    private final String messageLayer;

    /**
     * The applicationContext this config provider will match against, can be {@code null} for wildcard matches.
     */
    private final String applicationContext;

    private final List<AuthenticationModuleDefinition> serverAuthModuleDefinitions;

    public ElytronAuthConfigProvider(final String messageLayer, final String applicationContext, final List<AuthenticationModuleDefinition> serverAuthModuleDefinitions) {
        this.messageLayer = messageLayer;
        this.applicationContext = applicationContext;
        this.serverAuthModuleDefinitions = checkNotNullParam("serverAuthModuleDefinitions", serverAuthModuleDefinitions); // Can however be empty.
    }

    /*
     * The APIs allow a single AuthConfigProvider to support multiple layers and appContexts
     * and then in conjunction with how they are discovered from the AuthConfigFactory an
     * AuthConfig will be discovered, to reduce complexity each provider instance will only
     * support a single layer / appContext pair.
     */

    /**
     * @see javax.security.auth.message.config.AuthConfigProvider#getClientAuthConfig(java.lang.String, java.lang.String, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public ClientAuthConfig getClientAuthConfig(String layer, String appContext, CallbackHandler handler) throws AuthException, SecurityException {
        // Presently we only support the Servlet profile so no support for client config.
        return EMPTY_CLIENT_AUTH_CONFIG;
    }

    /**
     * @see javax.security.auth.message.config.AuthConfigProvider#getServerAuthConfig(java.lang.String, java.lang.String,
     *      javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public ServerAuthConfig getServerAuthConfig(String layer, String appContext, CallbackHandler callbackHandler) throws AuthException, SecurityException {
        // The layer and appContext values are required to match the values used to obtain this provider, however unless we
        // create a new instance each time we can not really enforce that - but it does mean as per JSR-196 2.1.1.1 these must
        // not be null.
        checkNotNullParam("layer", layer);
        checkNotNullParam("appContext", appContext);

        // We can however double check the values match the configuration this provider should be used for.
        if ( !serverAuthModuleDefinitions.isEmpty() && (messageLayer == null || messageLayer.equals(layer))
                && (applicationContext == null || applicationContext.equals(appContext))) {
            return new ElytronServerAuthConfig(this.messageLayer, this.applicationContext, callbackHandler, serverAuthModuleDefinitions);
        }
        return EMPTY_SERVER_AUTH_CONFIG;
    }

    /**
     * @see javax.security.auth.message.config.AuthConfigProvider#refresh()
     */
    @Override
    public void refresh() {
    }

    static class EmptyAuthConfig implements AuthConfig {
        // TODO Can we just use ElytronAuthConfig instead?

        @Override
        public String getAppContext() {
            return null;
        }

        @Override
        public String getMessageLayer() {
            return null;
        }

        @Override
        public String getAuthContextID(MessageInfo messageInfo) {
            return null;
        }

        @Override
        public boolean isProtected() {
            return false;
        }

        @Override
        public void refresh() {
        }

    }

    static class EmptyClientAuthConfig extends EmptyAuthConfig implements ClientAuthConfig  {

        @Override
        public ClientAuthContext getAuthContext(String authContextID, Subject clientSubject, Map properties)
                throws AuthException {
            return null;
        }

    }

    static class EmptyServerAuthConfig extends EmptyAuthConfig implements ServerAuthConfig {

        @Override
        public ServerAuthContext getAuthContext(String authContextID, Subject serviceSubject, Map properties)
                throws AuthException {
            return null;
        }

    }
}
