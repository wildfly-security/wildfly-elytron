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

package org.wildfly.security.password.interfaces;

import javax.security.auth.DestroyFailedException;
import java.util.Arrays;

class RawClearPassword extends RawPassword implements ClearPassword {

    private static final long serialVersionUID = -7982031201140935435L;

    private final char[] password;

    RawClearPassword(final String algorithm, final char[] password) {
        super(algorithm);
        this.password = password;
    }

    public char[] getPassword() throws IllegalStateException {
        return password.clone();
    }

    /**
     * Destroy this {@code Object}.
     * <p>
     * <p> Sensitive information associated with this {@code Object}
     * is destroyed or cleared.  Subsequent calls to certain methods
     * on this {@code Object} will result in an
     * {@code IllegalStateException} being thrown.
     * <p>
     * <p>
     * The default implementation throws {@code DestroyFailedException}.
     *
     * @throws DestroyFailedException if the destroy operation fails. <p>
     * @throws SecurityException      if the caller does not have permission
     *                                to destroy this {@code Object}.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (password != null)
            Arrays.fill(password, (char)0);
    }

    /**
     * Determine if this {@code Object} has been destroyed.
     * <p>
     * <p>
     * The default implementation returns false.
     *
     * @return true if this {@code Object} has been destroyed,
     * false otherwise.
     */
    @Override
    public boolean isDestroyed() {
        return password == null || password.length == 0 || password[0] == 0;
    }

    public RawClearPassword clone() {
        final char[] password = this.password;
        if (password == null || password.length == 0) {
            return this;
        }
        return new RawClearPassword(getAlgorithm(), password.clone());
    }

    public int hashCode() {
        // hashcode becomes 0 when destroyed!
        return Arrays.hashCode(password);
    }

    public boolean equals(final Object obj) {
        final char[] password = this.password;
        // destroyed passwords are equal to nothing
        if (! (obj instanceof RawClearPassword)) return false;
        final RawClearPassword other = (RawClearPassword) obj;
        return password != null && Arrays.equals(password, other.password) && getAlgorithm().equals(other.getAlgorithm());
    }
}
