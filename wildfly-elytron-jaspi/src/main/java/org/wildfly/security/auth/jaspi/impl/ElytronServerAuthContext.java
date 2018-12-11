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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

import org.wildfly.security.auth.jaspi.Flag;
import org.wildfly.security.auth.jaspi.impl.ElytronMessageInfo.State;
/**
 * The WildFly Elytron implementation of {@link ServerAuthContext}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class ElytronServerAuthContext implements ServerAuthContext {

    // Don't bother with an intermediate ServerAuth - even though the API is reused
    // the implementations are different.

    private final List<AuthModuleWrapper> authModules;

    private boolean initialised = false;
    private Subject serviceSubject;

    /*
     * TODO - Message Policies need to be defined / calculated.
     */

    ElytronServerAuthContext(final List<AuthenticationModuleDefinition> serverAuthModuleDefinitions) {
        List<AuthModuleWrapper> authModules = new ArrayList<>(serverAuthModuleDefinitions.size());
        for (AuthenticationModuleDefinition authenticationModuleDefinition : serverAuthModuleDefinitions) {
            authModules.add(new AuthModuleWrapper(authenticationModuleDefinition.getFlag(),
                    authenticationModuleDefinition.getOptions(), authenticationModuleDefinition.getServerAuthModuleFactory().get()));
        }
        this.authModules = authModules;
    }

    /**
     * @see javax.security.auth.message.ServerAuth#validateRequest(javax.security.auth.message.MessageInfo,
     *      javax.security.auth.Subject, javax.security.auth.Subject)
     */
    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
        assert initialised : "Not initialised";
        if (messageInfo instanceof ElytronMessageInfo)
            ((ElytronMessageInfo) messageInfo).setState(State.VALIDATE);

        AuthStatus requiredResult = null;
        AuthStatus optionalResult = null;

        for (AuthModuleWrapper wrapper : authModules) {
            final ServerAuthModule sam = wrapper.getModule();

            final Object originalRequest = messageInfo.getRequestMessage();
            final Object originalResponse = messageInfo.getResponseMessage();

            final AuthStatus currentResult = sam.validateRequest(messageInfo, clientSubject, serviceSubject);

            if (currentResult == null || currentResult == AuthStatus.FAILURE) {
                throw log.invalidAuthStatus(currentResult, sam.getClass().getName());
            } else if (currentResult != AuthStatus.SUCCESS && (originalRequest != messageInfo.getRequestMessage()
                    || originalResponse != messageInfo.getResponseMessage())) {
                // If a SAM wraps the request or response message it MUST return SUCCESS Spec 3.8.3.5
                throw log.messageWrappedWithoutSuccess(sam.getClass().getName());
            }

            switch (wrapper.getFlag()) {
                case REQUIRED:
                    if (requiredResult == null || (toIndex(currentResult) > toIndex(requiredResult))) {
                        requiredResult = currentResult;
                    }
                    break;
                case REQUISITE:
                    if (currentResult != AuthStatus.SUCCESS) {
                        return currentResult;
                    } else if (requiredResult == null) {
                        requiredResult = currentResult; // SUCCESS
                    }
                    break;
                case SUFFICIENT:
                    // It is correct this flag takes into account requiredResult but manipulates optionalResult.
                    if (currentResult == AuthStatus.SUCCESS) {
                        return requiredResult == null ? currentResult : requiredResult;
                    } else if (optionalResult == null || (toIndex(currentResult) < toIndex(optionalResult))) {
                        optionalResult = currentResult;
                    }
                    break;
                case OPTIONAL:
                    if (optionalResult == null || (toIndex(currentResult) < toIndex(optionalResult))) {
                        optionalResult = currentResult;
                    }
                    break;
            }
        }

        final AuthStatus finalResult = requiredResult != null ? requiredResult : optionalResult;
        assert finalResult != null : "Resulting AuthStatus can not be null.";

        return finalResult;
    }

    private static int toIndex(final AuthStatus authStatus) {
        checkNotNullParam("authStatus", authStatus);
        if (AuthStatus.SUCCESS == authStatus) {
            return 1;
        } else if (AuthStatus.SEND_SUCCESS == authStatus) {
            return 2;
        } else if (AuthStatus.SEND_CONTINUE == authStatus) {
            return 3;
        } else if (AuthStatus.FAILURE == authStatus) {
            return 4;
        } else {
            return 5;
        }
    }

    /**
     * @see javax.security.auth.message.ServerAuth#secureResponse(javax.security.auth.message.MessageInfo, javax.security.auth.Subject)
     */
    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        assert initialised : "Not initialised";
        if (messageInfo instanceof ElytronMessageInfo) ((ElytronMessageInfo) messageInfo).setState(State.SECURE);

        AuthStatus result = null;
        for (int i = authModules.size() - 1; i >= 0; i--) {
            ServerAuthModule sam = authModules.get(i).getModule();
            AuthStatus currentResult = sam.secureResponse(messageInfo, serviceSubject);
            if (currentResult == null || currentResult == AuthStatus.SUCCESS || currentResult == AuthStatus.FAILURE) {
                throw log.invalidAuthStatus(currentResult, sam.getClass().getName());
            }

            if (result == null || toIndex(currentResult) > toIndex(result)) {
                result = currentResult;
            }

            if (currentResult == AuthStatus.SEND_FAILURE) {
                break;
            }
        }

        return result;
    }

    /**
     * @see javax.security.auth.message.ServerAuth#cleanSubject(javax.security.auth.message.MessageInfo, javax.security.auth.Subject)
     */
    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        assert initialised : "Not initialised";
        if (messageInfo instanceof ElytronMessageInfo) ((ElytronMessageInfo) messageInfo).setState(State.CLEAN);
        for (int i = authModules.size() - 1; i > 0; i--) {
            ServerAuthModule sam = authModules.get(i).getModule();
            sam.cleanSubject(messageInfo, subject);
        }
    }

    /*
     * Internal Methods
     */

    void initialise(final Subject serviceSubject, final CallbackHandler callbackHandler, final Map properties) throws AuthException {
        assert initialised == false : "Already initialised";
        this.serviceSubject = serviceSubject;
        for (AuthModuleWrapper wrapper : authModules) {
            ServerAuthModule sam = wrapper.getModule();
            Map combined = new HashMap(properties);
            combined.putAll(wrapper.getOptions());

            // TODO Pass in appropriate MessagePolicy instances.
            // TODO MessagePolicy is actually defined in 3.7.4

            sam.initialize(null, null, callbackHandler, combined);
        }

        initialised = true;
    }

    /**
     * Test that the request and response messages in the supplied {@link MessageInfo} are compatible
     *
     * @param messageInfo the {@link MessageInfo} to test is compatible with the {@link ServerAuthModule} instances.
     * @throws IllegalArgumentException
     */
    void testMessageInfo(MessageInfo messageInfo) throws IllegalArgumentException {
        Object requestMessage = messageInfo.getRequestMessage();
        Object responseMessage = messageInfo.getResponseMessage();

        for (AuthModuleWrapper wrapper : authModules) {
            ServerAuthModule sam = wrapper.getModule();
            boolean requestAccepted = false;
            boolean responseAccepted = false;
            for (Class acceptedType : sam.getSupportedMessageTypes()) {
                if (acceptedType.isInstance(requestMessage)) requestAccepted = true;
                if (acceptedType.isInstance(responseMessage)) responseAccepted = true;

                if (responseAccepted && requestAccepted) {
                    break;
                }
            }
            if (requestAccepted == false) throw log.unsupportedMessageType(requestMessage.getClass().getName(), sam.getClass().getName());
            if (responseAccepted == false) throw log.unsupportedMessageType(responseMessage.getClass().getName(), sam.getClass().getName());
        }
    }

    class AuthModuleWrapper {
        private final Flag flag;
        private final Map options;
        private final ServerAuthModule module;

        AuthModuleWrapper(Flag flag, Map options, ServerAuthModule module) {
            super();
            this.flag = flag;
            this.options = options;
            this.module = module;
        }

        Flag getFlag() {
            return flag;
        }

        Map getOptions() {
            return options;
        }

        ServerAuthModule getModule() {
            return module;
        }

    }

}
