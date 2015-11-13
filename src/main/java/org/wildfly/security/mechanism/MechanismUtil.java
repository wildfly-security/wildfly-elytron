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

import static org.wildfly.security._private.ElytronMessages.log;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;

/**
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
     * @param defaultParameters the optional default parameters to use if the password must be generated (may be {@code null})
     * @param <S> the password type
     * @return the password
     */
    public static <S extends Password> S getPasswordCredential(String userName, CallbackHandler callbackHandler, Class<S> passwordType, String passwordAlgorithm, AlgorithmParameterSpec defaultParameters) throws AuthenticationMechanismException {
        Assert.checkNotNullParam("userName", userName);
        Assert.checkNotNullParam("callbackHandler", callbackHandler);
        Assert.checkNotNullParam("passwordType", passwordType);
        Assert.checkNotNullParam("passwordAlgorithm", passwordAlgorithm);
        try {
            final PasswordFactory passwordFactory = PasswordFactory.getInstance(passwordAlgorithm);

            CredentialCallback credentialCallback = new CredentialCallback(PasswordCredential.class, passwordAlgorithm);

            try {
                MechanismUtil.handleCallbacks(passwordAlgorithm, callbackHandler, credentialCallback);
                final Credential credential = credentialCallback.getCredential();
                if (credential instanceof PasswordCredential) {
                    S password = ((PasswordCredential) credential).getPassword(passwordType);
                    if (password != null) {
                        return password;
                    }
                }
                // fall out
            } catch (UnsupportedCallbackException e) {
                if (e.getCallback() != credentialCallback) {
                    throw log.mechCallbackHandlerFailedForUnknownReason(passwordAlgorithm, e);
                }
                // fall out
            }

            credentialCallback = new CredentialCallback(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR);

            try {
                MechanismUtil.handleCallbacks(passwordAlgorithm, callbackHandler, credentialCallback);
                final Credential credential = credentialCallback.getCredential();
                if (credential instanceof PasswordCredential) {
                    final TwoWayPassword twoWayPassword = ((PasswordCredential) credential).getPassword(TwoWayPassword.class);
                    if (twoWayPassword != null) {
                        final PasswordFactory clearFactory = PasswordFactory.getInstance(twoWayPassword.getAlgorithm());
                        final ClearPasswordSpec spec = clearFactory.getKeySpec(clearFactory.translate(twoWayPassword), ClearPasswordSpec.class);
                        if (defaultParameters != null) {
                            return passwordType.cast(passwordFactory.generatePassword(new EncryptablePasswordSpec(spec.getEncodedPassword(), defaultParameters)));
                        } else {
                            return passwordType.cast(passwordFactory.generatePassword(spec));
                        }
                    }
                }
            } catch (UnsupportedCallbackException e) {
                if (e.getCallback() != credentialCallback) {
                    throw log.mechCallbackHandlerFailedForUnknownReason(passwordAlgorithm, e);
                }
                // fall out
            }

            final PasswordCallback passwordCallback = new PasswordCallback("User password", false);

            try {
                MechanismUtil.handleCallbacks(passwordAlgorithm, callbackHandler, passwordCallback);
                final char[] password = passwordCallback.getPassword();
                if (password != null) {
                    if (defaultParameters != null) {
                        return passwordType.cast(passwordFactory.generatePassword(new EncryptablePasswordSpec(password, defaultParameters)));
                    } else {
                        return passwordType.cast(passwordFactory.generatePassword(new ClearPasswordSpec(password)));
                    }
                }
            } catch (UnsupportedCallbackException e) {
                if (e.getCallback() != passwordCallback) {
                    throw log.mechCallbackHandlerFailedForUnknownReason(passwordAlgorithm, e);
                }
                // fall out
            }
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw log.mechCallbackHandlerDoesNotSupportCredentialAcquisition(passwordAlgorithm, e);
        }

        throw log.mechUnableToRetrievePassword(passwordAlgorithm, userName);
    }

    /**
     * A varargs wrapper method for callback handler invocation.
     *
     * @param mechName the mechanism name to report for error purposes
     * @param callbackHandler the callback handler
     * @param callbacks the callbacks
     * @throws AuthenticationMechanismException if the callback handler fails for some reason
     * @throws UnsupportedCallbackException if the callback handler throws this exception
     */
    public static void handleCallbacks(String mechName, CallbackHandler callbackHandler, Callback... callbacks) throws AuthenticationMechanismException, UnsupportedCallbackException {
        try {
            callbackHandler.handle(callbacks);
        } catch (AuthenticationMechanismException | UnsupportedCallbackException e) {
            throw e;
        } catch (Throwable e) {
            throw log.mechCallbackHandlerFailedForUnknownReason(mechName, e);
        }
    }
}
