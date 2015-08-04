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
package org.wildfly.security.auth.callback;

import javax.security.auth.callback.PasswordCallback;

/**
 * An extension of
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class PasswordVerifyCallback extends PasswordCallback implements ExtendedCallback {

    private boolean verified = false;

    /**
     * Constructor to create a new {@link PasswordVerifyCallback} to verify a password.
     *
     * @param password the password to verify.
     */
    public PasswordVerifyCallback(final char[] password) {
        super("Password Verification", false);
        super.setPassword(password);
    }

    /**
     * {@link PasswordCallback#setPassword(char[])} is overriden to prevent it from being accidentally used.
     */
    @Override
    public void setPassword(char[] password) {
        throw new UnsupportedOperationException();
    }

    /**
     * Indicate if the password is verified.
     *
     * @param verified has the password been verified.
     */
    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    /**
     * Get if this password has been verified.
     *
     * @return {@code true} if the password has been verified, {@code false} otherwise.
     */
    public boolean isVerified() {
        return verified;
    }

    @Override
    public boolean isOptional() {
        return false;
    }

    @Override
    public boolean needsInformation() {
        return true;
    }

}
