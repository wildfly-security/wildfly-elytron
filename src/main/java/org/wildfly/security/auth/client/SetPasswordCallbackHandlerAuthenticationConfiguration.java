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
import java.util.ArrayList;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.callback.CredentialParameterCallback;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
class SetPasswordCallbackHandlerAuthenticationConfiguration extends AuthenticationConfiguration {

    private final CallbackHandler callbackHandler;

    SetPasswordCallbackHandlerAuthenticationConfiguration(final AuthenticationConfiguration parent, final CallbackHandler callbackHandler) {
        super(parent.without(SetCallbackHandlerAuthenticationConfiguration.class).without(SetNamePrincipalAuthenticationConfiguration.class).without(SetPasswordAuthenticationConfiguration.class).without(SetKeyStoreCredentialAuthenticationConfiguration.class).without(SetAnonymousAuthenticationConfiguration.class).without(SetGSSCredentialAuthenticationConfiguration.class));
        this.callbackHandler = callbackHandler;
    }

    void handleCallbacks(final AuthenticationConfiguration config, final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        ArrayList<Callback> list = null;
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback || callback instanceof CredentialCallback || callback instanceof CredentialParameterCallback) {
                if (list == null) list = new ArrayList<>(callbacks.length);
                list.add(callback);
            }
        }
        if (list != null) {
            callbackHandler.handle(list.toArray(new Callback[list.size()]));
        }
        super.handleCallbacks(config, callbacks);
    }

    void handleCallback(final Callback[] callbacks, final int index) throws IOException, UnsupportedCallbackException {
        final Callback callback = callbacks[index];
        if (callback instanceof PasswordCallback || callback instanceof CredentialCallback || callback instanceof CredentialParameterCallback) {
            return;
        }
        super.handleCallback(callbacks, index);
    }

    AuthenticationConfiguration reparent(final AuthenticationConfiguration newParent) {
        return new SetPasswordCallbackHandlerAuthenticationConfiguration(newParent, callbackHandler);
    }
}
