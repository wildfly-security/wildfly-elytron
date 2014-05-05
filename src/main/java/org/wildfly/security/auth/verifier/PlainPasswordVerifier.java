/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.auth.verifier;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Set;
import org.wildfly.security.auth.login.AuthenticationException;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;

public final class PlainPasswordVerifier extends Verifier<Void> {
    private final char[] passwordGuess;

    public PlainPasswordVerifier(final char[] passwordGuess) {
        this.passwordGuess = passwordGuess;
    }

    public Set<Class<?>> getSupportedCredentialTypes() {
        return Collections.<Class<?>>singleton(Password.class);
    }

    public Void performVerification(final Object credential) throws AuthenticationException {
        try {
            final Password password = (Password) credential;
            final PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm());
            if (! passwordFactory.verify(password, passwordGuess)) {
                throw new AuthenticationException();
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AuthenticationException(e);
        }
        return null;
    }
}
