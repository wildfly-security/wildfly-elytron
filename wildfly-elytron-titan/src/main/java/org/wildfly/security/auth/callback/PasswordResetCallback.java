/*
 * JBoss, Home of Professional Open Source.
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

package org.wildfly.security.auth.callback;

import java.io.Serializable;
import java.util.Arrays;

import org.wildfly.common.Assert;

/**
 * A callback used when a password reset is required.  Interactive callback handlers should have the user enter the
 * password two times, comparing them for equality.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class PasswordResetCallback implements ExtendedCallback, Serializable{
    private static final long serialVersionUID = - 8789058459408593766L;

    private final String prompt;

    private char[] password;

    /**
     * Construct a new instance.
     *
     * @param prompt the password reset prompt (must not be {@code null} or empty)
     */
    public PasswordResetCallback(final String prompt) {
        Assert.checkNotNullParam("prompt", prompt);
        Assert.checkNotEmptyParam("prompt", prompt);
        this.prompt = prompt;
    }

    /**
     * Get the password reset prompt.
     *
     * @return the password reset prompt
     */
    public String getPrompt() {
        return prompt;
    }

    /**
     * Get the new password.
     *
     * @return the new password, or {@code null} if it was not set
     */
    public char[] getPassword() {
        final char[] password = this.password;
        return password == null ? null : password.clone();
    }

    /**
     * Set the new password.
     *
     * @param password the new password
     */
    public void setPassword(final char[] password) {
        this.password = password == null ? null : password.clone();
    }

    /**
     * Clear the stored password bytes by setting them to {@code ' '}.
     */
    public void clearPassword() {
        final char[] password = this.password;
        if (password != null) {
            Arrays.fill(password, ' ');
        }
    }

    public boolean isOptional() {
        return false;
    }

    public boolean needsInformation() {
        return true;
    }
}
