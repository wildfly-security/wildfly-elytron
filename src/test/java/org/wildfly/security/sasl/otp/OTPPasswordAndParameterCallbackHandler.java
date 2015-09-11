/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.wildfly.security.sasl.otp;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.ParameterCallback;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;

/**
 * A callback handler for OTP which handles {@link ParameterCallback} and {@link PasswordCallback}
 *
 * @author Kabir Khan
 */
public class OTPPasswordAndParameterCallbackHandler implements CallbackHandler {
    private final PasswordFormat passwordFormat;
    private final String password; // The pass phrase or OTP
    private final String newAlgorithm;
    private final byte[] newSeed;
    private final int newSequenceNumber;
    private final PasswordFormat newPasswordFormat;
    private final String newPassword; // The new pass phrase or new OTP
    private boolean currentPasswordProvided;

    /**
     * Constructor
     *
     * @param password The password
     * @param passwordFormat The format of the password
     */
    public OTPPasswordAndParameterCallbackHandler(String password, PasswordFormat passwordFormat) {
        this(password, passwordFormat, null, null, 0, null, null);
    }

    /**
     * Constructor
     *
     * @param password The password
     * @param passwordFormat The format of the password
     * @param newAlgorithm The new algorithm to use
     * @param newSeed The new seed to use
     * @param newSequenceNumber The new sequence number to use
     * @param newPassword The new password to use
     * @param newPasswordFormat The format to use for the new password
     */
    public OTPPasswordAndParameterCallbackHandler(String password, PasswordFormat passwordFormat, String newAlgorithm, byte[] newSeed,
                                           int newSequenceNumber, String newPassword, PasswordFormat newPasswordFormat) {
        this.passwordFormat = passwordFormat;
        this.password = password;
        this.newAlgorithm = newAlgorithm;
        this.newSeed = newSeed;
        this.newSequenceNumber = newSequenceNumber;
        this.newPasswordFormat = newPasswordFormat;
        this.newPassword = newPassword;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof ParameterCallback) {
                ParameterCallback parameterCallback = (ParameterCallback) callback;
                OneTimePasswordAlgorithmSpec spec = (OneTimePasswordAlgorithmSpec) parameterCallback.getParameterSpec();
                if (currentPasswordProvided) {
                    // Set new password parameters
                    OneTimePasswordAlgorithmSpec newSpec = new OneTimePasswordAlgorithmSpec(newAlgorithm == null ? spec.getAlgorithm() : newAlgorithm,
                            newSeed == null ? spec.getSeed() : newSeed, newSequenceNumber < 1 ? spec.getSequenceNumber() : newSequenceNumber);
                    parameterCallback.setParameterSpec(newSpec);
                }
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                if (passwordCallback.getPrompt().equals("Pass phrase")) {
                    if (passwordFormat == PasswordFormat.PASS_PHRASE) {
                        currentPasswordProvided = true;
                        passwordCallback.setPassword(password.toCharArray());
                    }
                } else if (passwordCallback.getPrompt().equals("New pass phrase")) {
                    if (newPasswordFormat == PasswordFormat.PASS_PHRASE) {
                        passwordCallback.setPassword(newPassword.toCharArray());
                    }
                } else if (passwordCallback.getPrompt().equals("One-time password")) {
                    if (passwordFormat == PasswordFormat.OTP) {
                        currentPasswordProvided = true;
                        passwordCallback.setPassword(password.toCharArray());
                    }
                } else if (passwordCallback.getPrompt().equals("New one-time password")) {
                    if (newPasswordFormat == PasswordFormat.OTP) {
                        passwordCallback.setPassword(newPassword.toCharArray());
                    }
                }
            }
        }
    }
}
