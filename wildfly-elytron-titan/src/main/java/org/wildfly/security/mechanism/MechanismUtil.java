/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.mechanism;

import static org.wildfly.security.mechanism._private.ElytronMessages.log;

import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.mechanism._private.ElytronMessages;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;

/**
 * Utils to be used by authentication mechanism (SASL or HTTP) implementations.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 *
 * @deprecated Should not be part of public API. Moved into internal {@link org.wildfly.security.mechanism._private.MechanismUtil}.
 */
@Deprecated
public final class MechanismUtil {
    private MechanismUtil() {}

    /**
     * Get a password from a client or server callback, falling back to clear password if needed.  Note that the
     * parameters, while optional, may be required on the client side of some mechanisms in order to ensure that the
     * encoded password is compatible with the server challenge.
     *
     * @param userName the user name to report for error reporting purposes (must not be {@code null})
     * @param callbackHandler the callback handler (must not be {@code null})
     * @param passwordType the password class (must not be {@code null})
     * @param passwordAlgorithm the password algorithm name (must not be {@code null})
     * @param matchParameters the optional parameters to match (may be {@code null})
     * @param generateParameters the optional default parameters to use if the password must be generated (may be {@code null})
     * @param providers the security providers to use with the {@link PasswordFactory}
     * @param <S> the password type
     * @return the password
     */
    @Deprecated
    public static <S extends Password> S getPasswordCredential(String userName, CallbackHandler callbackHandler, Class<S> passwordType, String passwordAlgorithm, AlgorithmParameterSpec matchParameters, AlgorithmParameterSpec generateParameters, Supplier<Provider[]> providers) throws AuthenticationMechanismException {
        return getPasswordCredential(userName, callbackHandler, passwordType, passwordAlgorithm, matchParameters, generateParameters, providers, ElytronMessages.log);
    }

    /**
     * Get a password from a client or server callback, falling back to clear password if needed.  Note that the
     * parameters, while optional, may be required on the client side of some mechanisms in order to ensure that the
     * encoded password is compatible with the server challenge.
     *
     * @param userName the user name to report for error reporting purposes (must not be {@code null})
     * @param callbackHandler the callback handler (must not be {@code null})
     * @param passwordType the password class (must not be {@code null})
     * @param passwordAlgorithm the password algorithm name (must not be {@code null})
     * @param matchParameters the optional parameters to match (may be {@code null})
     * @param generateParameters the optional default parameters to use if the password must be generated (may be {@code null})
     * @param providers the security providers to use with the {@link PasswordFactory}
     * @param <S> the password type
     * @param log mechanism specific logger
     * @return the password
     */
    @Deprecated
    public static <S extends Password> S getPasswordCredential(String userName, CallbackHandler callbackHandler, Class<S> passwordType, String passwordAlgorithm, AlgorithmParameterSpec matchParameters, AlgorithmParameterSpec generateParameters, Supplier<Provider[]> providers, ElytronMessages log) throws AuthenticationMechanismException {
        return org.wildfly.security.mechanism._private.MechanismUtil.getPasswordCredential(userName, callbackHandler, passwordType, passwordAlgorithm, matchParameters, generateParameters, providers, log);
    }

    /**
     * A varargs wrapper method for callback handler invocation.
     *
     * @param log the logger for error purposes
     * @param callbackHandler the callback handler
     * @param callbacks the callbacks
     * @throws AuthenticationMechanismException if the callback handler fails for some reason
     * @throws UnsupportedCallbackException if the callback handler throws this exception
     */
    @Deprecated
    public static void handleCallbacks(ElytronMessages log, CallbackHandler callbackHandler, Callback... callbacks) throws AuthenticationMechanismException, UnsupportedCallbackException {
        org.wildfly.security.mechanism._private.MechanismUtil.handleCallbacks(log, callbackHandler, callbacks);
    }

    /**
     * A varargs wrapper method for callback handler invocation.
     *
     * @param mechName the mechanism name to report for error purposes
     * @param callbackHandler the callback handler
     * @param callbacks the callbacks
     * @throws AuthenticationMechanismException if the callback handler fails for some reason
     * @throws UnsupportedCallbackException if the callback handler throws this exception
     * @deprecated Use {@link #handleCallbacks(ElytronMessages, CallbackHandler, Callback...)} instead
     */
    @Deprecated
    public static void handleCallbacks(String mechName, CallbackHandler callbackHandler, Callback... callbacks) throws AuthenticationMechanismException, UnsupportedCallbackException {
        handleCallbacks(log, callbackHandler, callbacks);
    }
}
