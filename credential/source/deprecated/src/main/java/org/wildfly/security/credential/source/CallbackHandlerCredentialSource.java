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

package org.wildfly.security.credential.source;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * A credential source which is backed by a callback handler.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@Deprecated
public final class CallbackHandlerCredentialSource implements CredentialSource {
    private final CallbackHandler callbackHandler;

    /**
     * Construct a new instance.
     *
     * @param callbackHandler the callback handler to use (must not be {@code null})
     */
    public CallbackHandlerCredentialSource(final CallbackHandler callbackHandler) {
        Assert.checkNotNullParam("callbackHandler", callbackHandler);
        this.callbackHandler = callbackHandler;
    }

    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
        return SupportLevel.POSSIBLY_SUPPORTED;
    }

    public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws IOException {
        if (PasswordCredential.class.isAssignableFrom(credentialType) && (algorithmName == null || algorithmName.equals(ClearPassword.ALGORITHM_CLEAR)) && parameterSpec == null) {
            try {
                final PasswordCallback passwordCallback = new PasswordCallback("Password", false);
                callbackHandler.handle(new Callback[] { passwordCallback });
                final char[] chars = passwordCallback.getPassword();
                return chars == null ? null : credentialType.cast(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, chars)));
            } catch (UnsupportedCallbackException e) {
                // fall out and try CredentialCallback
            }
        }
        try {
            final CredentialCallback credentialCallback = new CredentialCallback(credentialType, algorithmName, parameterSpec);
            callbackHandler.handle(new Callback[] { credentialCallback });
            return credentialCallback.getCredential(credentialType, algorithmName, parameterSpec);
        } catch (UnsupportedCallbackException e) {
            // no credentials can be acquired; fall out
        }
        return null;
    }
}
