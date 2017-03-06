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
package org.wildfly.security.auth.client;

import static java.security.AccessController.doPrivileged;

import java.net.URI;

import javax.security.auth.callback.CallbackHandler;

/**
 * @author Kabir Khan
 */
public class ClientUtils {
    private static final AuthenticationContextConfigurationClient AUTH_CONFIGURATION_CLIENT = doPrivileged(AuthenticationContextConfigurationClient.ACTION);

    public static CallbackHandler getCallbackHandler(URI uri, AuthenticationContext context) {
        AuthenticationConfiguration config = AUTH_CONFIGURATION_CLIENT.getAuthenticationConfiguration(uri, context);
        final CallbackHandler callbackHandler = config.getCallbackHandler();
        return callbackHandler == null ? config.createCallbackHandler() : callbackHandler;
    }
}
