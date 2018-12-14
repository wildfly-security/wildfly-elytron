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

package org.wildfly.security.mechanism._private;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.mechanism._private.ElytronMessages;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;

/**
 * Utils to be used by authentication mechanism (SASL or HTTP) implementations.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
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
     * @param log mechanism specific logger
     * @return the password
     */
    public static <S extends Password> S getPasswordCredential(String userName, CallbackHandler callbackHandler, Class<S> passwordType, String passwordAlgorithm, AlgorithmParameterSpec matchParameters, AlgorithmParameterSpec generateParameters, Supplier<Provider[]> providers, ElytronMessages log) throws AuthenticationMechanismException {
        Assert.checkNotNullParam("userName", userName);
        Assert.checkNotNullParam("callbackHandler", callbackHandler);
        Assert.checkNotNullParam("passwordType", passwordType);
        Assert.checkNotNullParam("passwordAlgorithm", passwordAlgorithm);
        Assert.checkNotNullParam("providers", providers);
        try {
            final PasswordFactory passwordFactory = PasswordFactory.getInstance(passwordAlgorithm, providers);

            CredentialCallback credentialCallback = new CredentialCallback(PasswordCredential.class, passwordAlgorithm, matchParameters);

            try {
                MechanismUtil.handleCallbacks(log, callbackHandler, credentialCallback);
                S password = credentialCallback.applyToCredential(PasswordCredential.class, c -> c.getPassword(passwordType));
                if (password != null) {
                    // update parameters to match requirement, if necessary
                    return matchParameters != null ? passwordType.cast(passwordFactory.transform(password, matchParameters)) : password;
                }
                // fall out
            } catch (UnsupportedCallbackException e) {
                if (e.getCallback() != credentialCallback) {
                    throw log.mechCallbackHandlerFailedForUnknownReason(e);
                }
                // fall out
            } catch (InvalidAlgorithmParameterException | ClassCastException e) {
                // fall out
            }

            credentialCallback = new CredentialCallback(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR);

            try {
                MechanismUtil.handleCallbacks(log, callbackHandler, credentialCallback);
                final TwoWayPassword twoWayPassword = credentialCallback.applyToCredential(PasswordCredential.class, c -> c.getPassword(TwoWayPassword.class));
                if (twoWayPassword != null) {
                    final PasswordFactory clearFactory = PasswordFactory.getInstance(twoWayPassword.getAlgorithm(), providers);
                    final ClearPasswordSpec spec = clearFactory.getKeySpec(clearFactory.translate(twoWayPassword), ClearPasswordSpec.class);
                    if (matchParameters != null) {
                        return passwordType.cast(passwordFactory.generatePassword(new EncryptablePasswordSpec(spec.getEncodedPassword(), generateParameters)));
                    } else {
                        return passwordType.cast(passwordFactory.generatePassword(spec));
                    }
                }
            } catch (UnsupportedCallbackException e) {
                if (e.getCallback() != credentialCallback) {
                    throw log.mechCallbackHandlerFailedForUnknownReason(e);
                }
                // fall out
            }

            final PasswordCallback passwordCallback = new PasswordCallback("User password", false);

            try {
                MechanismUtil.handleCallbacks(log, callbackHandler, passwordCallback);
                final char[] password = passwordCallback.getPassword();
                if (password != null) {
                    if (matchParameters != null) {
                        return passwordType.cast(passwordFactory.generatePassword(new EncryptablePasswordSpec(password, generateParameters)));
                    } else {
                        return passwordType.cast(passwordFactory.generatePassword(new ClearPasswordSpec(password)));
                    }
                }
            } catch (UnsupportedCallbackException e) {
                if (e.getCallback() != passwordCallback) {
                    throw log.mechCallbackHandlerFailedForUnknownReason(e);
                }
                // fall out
            }
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw log.mechCallbackHandlerDoesNotSupportCredentialAcquisition(e);
        }

        throw log.mechUnableToRetrievePassword(userName);
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
    public static void handleCallbacks(ElytronMessages log, CallbackHandler callbackHandler, Callback... callbacks) throws AuthenticationMechanismException, UnsupportedCallbackException {
        try {
            callbackHandler.handle(callbacks);
        } catch (AuthenticationMechanismException | UnsupportedCallbackException e) {
            throw e;
        } catch (Throwable e) {
            throw log.mechCallbackHandlerFailedForUnknownReason(e);
        }
    }

    /**
     * Get or compute the value for the given key in HttpScope, storing the computed value (if one is generated).
     * The function must not generate a {@code null} value or an unspecified exception will result.
     *
     * @param scope the HTTP scope to store computed value (must not be {@code null})
     * @param key the key to retrieve (must not be {@code null})
     * @param mappingFunction the function to apply to acquire the value (must not be {@code null})
     * @return the stored or new value (not {@code null})
     */
    public static <R> R computeIfAbsent(HttpScope scope, String key, Function<String, R> mappingFunction) {
        Assert.checkNotNullParam("scope", scope);
        Assert.checkNotNullParam("key", key);
        Assert.checkNotNullParam("mappingFunction", mappingFunction);
        synchronized (scope) {
            if (! scope.exists()) {
                scope.create();
            }
            final R existing = (R) scope.getAttachment(key);
            if (existing == null) {
                R newValue = mappingFunction.apply(key);
                Assert.assertNotNull(newValue);
                scope.setAttachment(key, newValue);
                return newValue;
            } else {
                return existing;
            }
        }
    }
}
