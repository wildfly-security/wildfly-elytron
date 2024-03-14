/*
 * JBoss, Home of Professional Open Source
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.mechanism.digest;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.mechanism._private.ElytronMessages;
import org.wildfly.security.mechanism.AuthenticationMechanismException;
import org.wildfly.security.password.TwoWayPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.spec.DigestPasswordAlgorithmSpec;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import java.security.MessageDigest;
import java.security.Provider;
import java.util.Arrays;
import java.util.function.Supplier;

import static org.wildfly.security.mechanism.digest.DigestUtil.getTwoWayPasswordChars;
import static org.wildfly.security.mechanism.digest.DigestUtil.userRealmPasswordDigest;

/**
 * Utility class used to obtain username+realm+password using SASL/HTTP mechanism callbacks.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class PasswordDigestObtainer {

    private final CallbackHandler callbackHandler;
    private final ElytronMessages log;
    private final String credentialAlgorithm;
    private final MessageDigest messageDigest;
    private final Supplier<Provider[]> passwordFactoryProviders;
    private final String[] realms;
    private final boolean readOnlyRealmUsername;
    private final boolean skipRealmCallbacks;

    private String username;
    private String realm;

    private RealmChoiceCallback realmChoiceCallBack;
    private RealmCallback realmCallback;
    private NameCallback nameCallback;

    /**
     * Constructs a new {@code PasswordDigestObtainer} instance.
     *
     * @param callbackHandler the callbackHandler to handle the callbacks required to obtain the username and password.
     * @param defaultUsername the default username to use if a callback is not provided.
     * @param defaultRealm the default realm to use if a callback is not provided.
     * @param log the logger to use.
     * @param credentialAlgorithm the name of the algorithm for obtaining the credential.
     * @param messageDigest the {@link MessageDigest} used for digesting the password.
     * @param passwordFactoryProviders the supplier of the providers to use when creating a {@code PasswordFactory} instance.
     * @param realms the realms to check for a user and password.
     * @param readOnlyRealmUsername {@code true} if the username passed in the callback can be modified, {@code false} otherwise.
     * @param skipRealmCallbacks {@code true} if realm callbacks should be skipped, {@code false} otherwise.
     */
    public PasswordDigestObtainer(CallbackHandler callbackHandler, String defaultUsername, String defaultRealm,
                                  ElytronMessages log, String credentialAlgorithm, MessageDigest messageDigest,
                                  Supplier<Provider[]> passwordFactoryProviders, String[] realms,
                                  boolean readOnlyRealmUsername, boolean skipRealmCallbacks) {
        this.callbackHandler = Assert.checkNotNullParam("callbackHandler", callbackHandler);
        this.username = defaultUsername;
        this.realm = defaultRealm;
        this.log = log;
        this.credentialAlgorithm = Assert.checkNotNullParam("credentialAlgorithm", credentialAlgorithm);
        this.messageDigest = Assert.checkNotNullParam("messageDigest", messageDigest);
        this.passwordFactoryProviders = Assert.checkNotNullParam("passwordFactoryProviders", passwordFactoryProviders);
        this.realms = realms;
        this.readOnlyRealmUsername = readOnlyRealmUsername;
        this.skipRealmCallbacks = skipRealmCallbacks;
    }

    /**
     * Returns the username obtained from callback or the default one.
     *
     * @return the username obtained from callback or the default one.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Returns the realm obtained from callback or the default one.
     *
     * @return the realm obtained from callback or the default one.
     */
    public String getRealm() {
        return realm;
    }

    /**
     * Handles callbacks for user and password information.
     *
     * @return the salted password.
     * @throws AuthenticationMechanismException if the callback handler does not support credential acquisition.
     */
    public byte[] handleUserRealmPasswordCallbacks() throws AuthenticationMechanismException {

        realmChoiceCallBack = skipRealmCallbacks || realms == null || realms.length <= 1 ? null :
                new RealmChoiceCallback("User realm: ", realms, 0, false);
        realmCallback = skipRealmCallbacks ? null :
                realm != null ?
                        new RealmCallback("User realm: ", realm) :
                        new RealmCallback("User realm: ");
        nameCallback = username != null && ! username.isEmpty() ?
                new NameCallback("User name: ", username) :
                new NameCallback("User name: ");

        byte[] digest = getPredigestedSaltedPassword();
        if (digest != null) return digest;

        digest = getSaltedPasswordFromTwoWay();
        if (digest != null) return digest;

        digest = getSaltedPasswordFromPasswordCallback();
        if (digest != null) return digest;

        throw log.mechCallbackHandlerDoesNotSupportCredentialAcquisition(null);
    }

    /**
     * Obtains the pre-digested salted password for the {@code username} in the {@code realm}.
     *
     * @return the pre-digested salted password if obtained, {@code null} otherwise.
     * @throws AuthenticationMechanismException if an exception occurs while handling the callbacks.
     */
    private byte[] getPredigestedSaltedPassword() throws AuthenticationMechanismException {
        if (realmChoiceCallBack != null) {
            try {
                callbackHandler.handle(new Callback[]{ realmChoiceCallBack });
                int[] selected = realmChoiceCallBack.getSelectedIndexes();
                if (selected == null || selected.length == 0) {
                    throw log.mechNotChosenRealm();
                }
                realm = realms[selected[0]];
            } catch (UnsupportedCallbackException e) {
                realmChoiceCallBack = null;
            } catch (AuthenticationMechanismException e) {
                throw e;
            } catch (Throwable t) {
                throw log.mechCallbackHandlerFailedForUnknownReason(t);
            }
        }

        // no realms to choose from or unsupported RealmChoiceCallback
        if (realmChoiceCallBack == null && realmCallback != null) {
            try {
                callbackHandler.handle(new Callback[]{ realmCallback });
                if (realmCallback.getText() != null) realm = realmCallback.getText();
            } catch (UnsupportedCallbackException e) {
                realmCallback = null;
            } catch (Throwable t) {
                throw log.mechCallbackHandlerFailedForUnknownReason(t);
            }
        }

        CredentialCallback credentialCallback = null;
        try {
            callbackHandler.handle(new Callback[]{ nameCallback });
            if ( ! readOnlyRealmUsername) {
                username = nameCallback.getName();
                if (username == null) {
                    throw log.mechNotProvidedUserName();
                }
            }

            DigestPasswordAlgorithmSpec parameterSpec = username != null && realm != null ?
                    new DigestPasswordAlgorithmSpec(username, realm) : null;

            credentialCallback = new CredentialCallback(PasswordCredential.class, credentialAlgorithm, parameterSpec);

            callbackHandler.handle(new Callback[]{ credentialCallback });

            return credentialCallback.applyToCredential(PasswordCredential.class,
                    c -> c.getPassword().castAndApply(DigestPassword.class, DigestPassword::getDigest)
            );
        } catch (UnsupportedCallbackException e) {
            if (e.getCallback() == nameCallback) {
                throw log.mechCallbackHandlerDoesNotSupportUserName(e);
            } else if (credentialCallback == null || e.getCallback() != credentialCallback) {
                throw log.mechCallbackHandlerFailedForUnknownReason(e);
            }
            // ignore unsupported CredentialCallback, continue in handling
        } catch (AuthenticationMechanismException e) {
            throw e;
        } catch (Throwable t) {
            throw log.mechCallbackHandlerFailedForUnknownReason(t);
        }
        return null;
    }

    /**
     * Obtains the salted password from a two-way callback.
     *
     * @return the byte array of the salted password if obtained, {@code null} otherwise.
     * @throws AuthenticationMechanismException if an error occurs during the process of handling callbacks or obtaining the password.
     */
    private byte[] getSaltedPasswordFromTwoWay() throws AuthenticationMechanismException {
        if (realmChoiceCallBack != null) {
            try {
                callbackHandler.handle(new Callback[]{ realmChoiceCallBack });
                int[] selected = realmChoiceCallBack.getSelectedIndexes();
                if (selected == null || selected.length == 0) {
                    throw log.mechNotChosenRealm();
                }
                realm = realms[selected[0]];
            } catch (UnsupportedCallbackException e) {
                realmChoiceCallBack = null;
            } catch (Throwable t) {
                throw log.mechCallbackHandlerFailedForUnknownReason(t);
            }
        }

        // no realms to choose from or unsupported RealmChoiceCallback
        if (realmChoiceCallBack == null && realmCallback != null) {
            try {
                callbackHandler.handle(new Callback[]{ realmCallback });
                if (realmCallback.getText() != null) realm = realmCallback.getText();
            } catch (UnsupportedCallbackException e) {
                realmCallback = null;
            } catch (Throwable t) {
                throw log.mechCallbackHandlerFailedForUnknownReason(t);
            }
        }

        CredentialCallback credentialCallback = new CredentialCallback(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR);
        TwoWayPassword password = null;
        char[] passwordChars = null;
        try {
            callbackHandler.handle(new Callback[]{ nameCallback, credentialCallback });
            if ( ! readOnlyRealmUsername) {
                username = nameCallback.getName();
                if (username == null) {
                    throw log.mechNotProvidedUserName();
                }
            }

            password = credentialCallback.applyToCredential(PasswordCredential.class,
                    c -> c.getPassword().castAs(TwoWayPassword.class)
            );
            if (password != null) {
                passwordChars = getTwoWayPasswordChars(password, passwordFactoryProviders, log);
                return userRealmPasswordDigest(messageDigest, username, realm, passwordChars);
            }
        } catch (UnsupportedCallbackException e) {
            if (e.getCallback() == nameCallback) {
                throw log.mechCallbackHandlerDoesNotSupportUserName(e);
            } else if (e.getCallback() != credentialCallback) {
                throw log.mechCallbackHandlerFailedForUnknownReason(e);
            }
            // ignore unsupported CredentialCallback, continue in handling
        } catch (AuthenticationMechanismException e) {
            throw e;
        } catch (Throwable t) {
            throw log.mechCallbackHandlerFailedForUnknownReason(t);
        } finally { // clear passwords wipe out
            if (password != null) {
                try {
                    password.destroy();
                } catch(DestroyFailedException e) {
                    log.credentialDestroyingFailed(e);
                }
            }
            if (passwordChars != null) {
                Arrays.fill(passwordChars, (char) 0);
            }
        }
        return null;
    }

    /**
     * Obtains the salted password from a password callback.
     *
     * @return the byte array of the salted password.
     * @throws AuthenticationMechanismException if an error occurs during the process of handling callbacks or obtaining the password.
     */
    private byte[] getSaltedPasswordFromPasswordCallback() throws AuthenticationMechanismException {
        PasswordCallback passwordCallback = new PasswordCallback("User password: ", false);

        if (realmChoiceCallBack != null) {
            try {
                callbackHandler.handle(new Callback[]{ realmChoiceCallBack, nameCallback, passwordCallback });
                int[] selected = realmChoiceCallBack.getSelectedIndexes();
                if (selected == null || selected.length == 0) {
                    throw log.mechNotChosenRealm();
                }
                realm = realms[selected[0]];
            } catch (UnsupportedCallbackException e) {
                if (e.getCallback() == realmChoiceCallBack) {
                    realmChoiceCallBack = null;
                } else if (e.getCallback() == nameCallback) {
                    throw log.mechCallbackHandlerDoesNotSupportUserName(e);
                } else if (e.getCallback() == passwordCallback) {
                    throw log.mechCallbackHandlerDoesNotSupportCredentialAcquisition(e);
                } else {
                    throw log.mechCallbackHandlerFailedForUnknownReason(e);
                }
            } catch (AuthenticationMechanismException e) {
                throw e;
            } catch (Throwable t) {
                throw log.mechCallbackHandlerFailedForUnknownReason(t);
            }
        }

        // no realms to choose from or unsupported RealmChoiceCallback
        if (realmChoiceCallBack == null && realmCallback != null) {
            try {
                callbackHandler.handle(new Callback[]{ realmCallback, nameCallback, passwordCallback });
                if (realmCallback.getText() != null) realm = realmCallback.getText();
            } catch (UnsupportedCallbackException e) {
                if (e.getCallback() == realmCallback) {
                    realmCallback = null;
                } else if (e.getCallback() == nameCallback) {
                    throw log.mechCallbackHandlerDoesNotSupportUserName(e);
                } else if (e.getCallback() == passwordCallback) {
                    throw log.mechCallbackHandlerDoesNotSupportCredentialAcquisition(e);
                } else {
                    throw log.mechCallbackHandlerFailedForUnknownReason(e);
                }
            } catch (Throwable t) {
                throw log.mechCallbackHandlerFailedForUnknownReason(t);
            }
        }

        // unsupported realm callbacks
        if (realmChoiceCallBack == null && realmCallback == null) {
            try {
                callbackHandler.handle(new Callback[]{ nameCallback, passwordCallback });
            } catch (UnsupportedCallbackException e) {
                if (e.getCallback() == nameCallback) {
                    throw log.mechCallbackHandlerDoesNotSupportUserName(e);
                } else if (e.getCallback() == passwordCallback) {
                    throw log.mechCallbackHandlerDoesNotSupportCredentialAcquisition(e);
                } else {
                    throw log.mechCallbackHandlerFailedForUnknownReason(e);
                }
            } catch (Throwable t) {
                throw log.mechCallbackHandlerFailedForUnknownReason(t);
            }
        }

        char[] passwordChars = passwordCallback.getPassword();
        passwordCallback.clearPassword();
        if ( ! readOnlyRealmUsername) {
            username = nameCallback.getName();
            if (username == null) {
                throw log.mechNotProvidedUserName();
            }
        }
        if (passwordChars == null) {
            throw log.mechNoPasswordGiven();
        }
        byte[] digest_urp = userRealmPasswordDigest(messageDigest, username, realm, passwordChars);
        Arrays.fill(passwordChars, (char) 0);
        return digest_urp;
    }
}
