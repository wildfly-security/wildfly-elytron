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

package org.wildfly.security.auth.jaspi;

import static java.util.Collections.EMPTY_MAP;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;

import org.junit.Before;
import org.wildfly.security.auth.jaspi.impl.ElytronMessageInfo;

/**
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
abstract class AuthModuleBase {

    static final String APP_CONTEXT = "application-context";
    static final String LAYER = "layer";
    static final String DESCRIPTION = "test description";
    final AuthConfigFactory authConfigFactory = new ElytronAuthConfigFactory();

    static final CallbackHandler HANDLER = new CallbackHandler() {

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            throw new UnsupportedCallbackException(callbacks[0]);
        }
    };

    static final MessageInfo MESSAGE_INFO;
    static Subject SUBJECT = new Subject();

    static {
        MESSAGE_INFO = new ElytronMessageInfo();
        MESSAGE_INFO.setRequestMessage(new Object());
        MESSAGE_INFO.setResponseMessage(new Object());
    }

    final AtomicInteger callCounter = new AtomicInteger();

    @Before
    public void before() {
        callCounter.set(0);
    }

    void test(final boolean validate, final AuthStatus expectedStatus, final int expectedCallCount, final String registrationId) throws Exception {
        AuthConfigProvider authConfigProvider = authConfigFactory.getConfigProvider(LAYER, APP_CONTEXT, null);
        ServerAuthConfig serverAuthConfig = authConfigProvider.getServerAuthConfig(LAYER, APP_CONTEXT, HANDLER);
        String authContextId = serverAuthConfig.getAuthContextID(MESSAGE_INFO);
        ServerAuthContext serverAuthContext = serverAuthConfig.getAuthContext(authContextId, SUBJECT, EMPTY_MAP);

        try {
            AuthStatus validateResult = validate ? serverAuthContext.validateRequest(MESSAGE_INFO, SUBJECT, SUBJECT) : serverAuthContext.secureResponse(MESSAGE_INFO, SUBJECT);

            if (expectedStatus == null) {
                fail("Expected Exception Not Thrown.");
            } else {
                assertEquals("Unexpected result", expectedStatus, validateResult);
            }
        } catch (AuthException e) {
            if (expectedStatus != null) {
                throw e;
            }
        }
        assertEquals("Unexpected Call Count", expectedCallCount, callCounter.get());

        authConfigFactory.removeRegistration(registrationId);
    }

}
