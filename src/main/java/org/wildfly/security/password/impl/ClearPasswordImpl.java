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

package org.wildfly.security.password.impl;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.security.auth.DestroyFailedException;

import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

final class ClearPasswordImpl extends AbstractPasswordImpl implements ClearPassword {

    private static final long serialVersionUID = -3949572193624333918L;

    private char[] password;

    ClearPasswordImpl(final char[] password) {
        this.password = password;
    }

    ClearPasswordImpl(ClearPassword clearPassword) {
        password = clearPassword.getPassword().clone();
    }

    public String getAlgorithm() {
        return "clear";
    }

    public char[] getPassword() throws IllegalStateException {
        try {
            return password.clone();
        } catch (NullPointerException ignored) {
            throw new IllegalStateException();
        }
    }

    public void destroy() throws DestroyFailedException {
        final char[] password = this.password;
        this.password = null;
        if (password != null) Arrays.fill(password, '\0');
    }

    public boolean isDestroyed() {
        return password == null;
    }

    <S extends KeySpec> S getKeySpec(final Class<S> keySpecType) throws InvalidKeySpecException {
        if (keySpecType.isAssignableFrom(ClearPasswordSpec.class)) {
            final char[] password = getPassword();
            return keySpecType.cast(new ClearPasswordSpec(password.clone()));
        }
        throw new InvalidKeySpecException();
    }

    boolean verify(final char[] guess) {
        return Arrays.equals(getPassword(), guess);
    }

    <T extends KeySpec> boolean convertibleTo(final Class<T> keySpecType) {
        return keySpecType.isAssignableFrom(ClearPasswordSpec.class);
    }
}
