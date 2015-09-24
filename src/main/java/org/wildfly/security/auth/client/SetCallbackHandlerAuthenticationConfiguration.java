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

package org.wildfly.security.auth.client;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetCallbackHandlerAuthenticationConfiguration extends AuthenticationConfiguration {

    private final CallbackHandler callbackHandler;

    SetCallbackHandlerAuthenticationConfiguration(final AuthenticationConfiguration parent, final CallbackHandler callbackHandler) {
        super(parent.without(SetNamePrincipalAuthenticationConfiguration.class).without(SetPasswordAuthenticationConfiguration.class).without(SetKeyStoreCredentialAuthenticationConfiguration.class).without(SetAnonymousAuthenticationConfiguration.class).without(SetGSSCredentialAuthenticationConfiguration.class).without(SetKeyManagerCredentialAuthenticationConfiguration.class).without(SetCertificateCredentialAuthenticationConfiguration.class).without(SetCertificateURLCredentialAuthenticationConfiguration.class));
        this.callbackHandler = callbackHandler;
    }

    void handleCallbacks(final AuthenticationConfiguration config, final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        callbackHandler.handle(callbacks);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetCallbackHandlerAuthenticationConfiguration(newParent, callbackHandler);
    }
}
