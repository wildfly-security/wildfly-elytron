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

package org.wildfly.security.credential;

import org.wildfly.common.Assert;
import org.wildfly.security.password.Password;

/**
 * A credential for password authentication.
 */
public final class PasswordCredential implements AlgorithmCredential {
    private final Password password;

    /**
     * Construct a new instance.
     *
     * @param password the password (must not be {@code null})
     */
    public PasswordCredential(final Password password) {
        Assert.checkNotNullParam("password", password);
        this.password = password;
    }

    /**
     * Get the password.
     *
     * @return the password (not {@code null})
     */
    public Password getPassword() {
        return password;
    }

    /**
     * Get the password if it is of the given type; otherwise return {@code null}.
     *
     * @param type the password type class
     * @param <P> the password type
     * @return the password, or {@code null} if the password is not of the given type
     */
    public <P extends Password> P getPassword(Class<P> type) {
        return type.isInstance(password) ? type.cast(password) : null;
    }

    public String getAlgorithm() {
        return password.getAlgorithm();
    }
}

