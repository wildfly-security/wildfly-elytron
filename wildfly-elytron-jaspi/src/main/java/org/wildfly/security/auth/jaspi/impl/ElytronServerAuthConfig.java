/*
 * Copyright 2018 Red Hat, Inc.
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
import static org.wildfly.security.auth.jaspi._private.ElytronMessages.log;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;

/**
 * The WildFly Elytron implementation of {@link ServerAuthConfig}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ElytronServerAuthConfig implements ServerAuthConfig {

    /*
     * The instance of ServerAuthConfig can be obtained once per deployment, for this reason it is important not to cache
     * per-request state long term.
     */

    /*
     * This is the configured messageLayer so could be 'null'.
     */
    private final String messageLayer;

    /*
     * This is the configured appContext so could be 'null'.
     */
    private final String appContext;
    private final CallbackHandler callbackHandler;
    private final List<AuthenticationModuleDefinition> serverAuthModuleDefinitions;

    private final Map<String, ElytronServerAuthContext> contextMap = new ConcurrentHashMap<>();

    ElytronServerAuthConfig(final String messageLayer, final String appContext, final CallbackHandler callbackHander, final List<AuthenticationModuleDefinition> serverAuthModuleDefinitions) {
        this.messageLayer = messageLayer;
        this.appContext = appContext;
        this.callbackHandler = callbackHander;
        this.serverAuthModuleDefinitions = serverAuthModuleDefinitions;
    }

    @Override
    public String getMessageLayer() {
        return messageLayer;
    }

    @Override
    public String getAppContext() {
        return appContext;
    }

    @Override
    public String getAuthContextID(MessageInfo messageInfo) {
        checkNotNullParam("messageInfo", messageInfo);
        checkNotNullParam("messageInfo.requestMessage", messageInfo.getRequestMessage());
        checkNotNullParam("messageInfo.responseMessage", messageInfo.getResponseMessage());

        ElytronServerAuthContext serverAuthContext = new ElytronServerAuthContext(serverAuthModuleDefinitions);
        serverAuthContext.testMessageInfo(messageInfo);

        String identifier = UUID.randomUUID().toString();
        contextMap.put(identifier, serverAuthContext);

        return identifier;
    }

    @Override
    public ServerAuthContext getAuthContext(String authContextId, Subject serviceSubject, Map properties) throws AuthException {
        // The runtime is required to call this method immediately after getAuthContextID.
        ElytronServerAuthContext serverAuthContext = contextMap.remove(authContextId);
        if (serverAuthContext == null) throw log.unrecognisedAuthContextId(authContextId);
        serverAuthContext.initialise(serviceSubject, callbackHandler, properties);
        return serverAuthContext;
    }

    @Override
    public boolean isProtected() {
        // TODO What is the definition of a protected ServerAuthContext?  Currently assuming as ours are 'managed' they are protected.
        return true;
    }

    @Override
    public void refresh() {
        // [ELY-1538] We do not currently support dynamic persistence so nothing to refresh here.
    }

}
