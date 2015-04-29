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

package org.wildfly.security.auth;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.security.Principal;

import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * A custom {@link javax.security.auth.callback.CallbackHandler} used in the JAAS security realm tests. It implements the
 * {@code setSecurityInfo} method that has been historically used to polulate custom handlers. Also, its {@code handle}
 * implementation will handle any kind of credential by calling {@code toString} and then {@code toCharArray} on the opaque
 * object.
 *
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class TestCallbackHandler implements CallbackHandler {

    private Principal principal;
    private Object credential;

    public TestCallbackHandler() {
    }

    /**
     * Sets this handler's state.
     *
     * @param principal the principal being authenticated.
     * @param credential the credential being verified.
     */
    public void setSecurityInfo(final Principal principal, final Object credential) {
        this.principal = principal;
        this.credential = credential;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (callbacks == null)
            throw new IllegalArgumentException("The callbacks argument cannot be null");

        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback nameCallback = (NameCallback) callback;
                if (principal != null)
                    nameCallback.setName(this.principal.getName());
            }
            else if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                if (this.credential instanceof char[]) {
                    passwordCallback.setPassword((char[]) credential);
                }
                else if (this.credential instanceof String) {
                    passwordCallback.setPassword(((String) credential).toCharArray());
                }
                else if (this.credential instanceof ClearPassword) {
                    passwordCallback.setPassword(((ClearPassword) credential).getPassword());
                }
                else if (this.credential != null) {
                    passwordCallback.setPassword(credential.toString().toCharArray());
                }
            }
            else {
                throw new UnsupportedCallbackException(callback, "Unsupported callback");
            }
        }
    }
}
