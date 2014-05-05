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

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactorySpi;
import org.wildfly.security.password.spec.ClearPasswordSpec;

public final class PasswordFactorySpiImpl extends PasswordFactorySpi {

    protected Password engineGeneratePassword(final KeySpec keySpec) throws InvalidKeySpecException {
        // Avoid initializing implementation classes if not referenced
        switch (keySpec.getClass().getName()) {
            case "org.wildfly.security.password.spec.ClearPasswordSpec": {
                // trivial implementation
                return new ClearPasswordImpl(((ClearPasswordSpec)keySpec).getEncodedPassword().clone());
            }
            default: {
                throw new InvalidKeySpecException();
            }
        }
    }

    protected <S extends KeySpec> S engineGetKeySpec(final Password password, final Class<S> keySpecType) throws InvalidKeySpecException {
        switch (password.getClass().getName()) {
            case "org.wildfly.security.password.impl.ClearPasswordImpl": {
                switch (keySpecType.getName()) {
                    case "org.wildfly.security.password.spec.ClearPasswordSpec": {
                        return keySpecType.cast(new ClearPasswordSpec(((ClearPasswordImpl)password).getPassword()));
                    }
                    default: {
                        break;
                    }
                }
            }
            default: {
                break;
            }
        }
        throw new InvalidKeySpecException();
    }

    protected Password engineTranslatePassword(final Password password) throws InvalidKeyException {
        return null;
    }

    protected boolean engineVerify(final Password password, final char[] guess) throws InvalidKeyException {
        return false;
    }

    protected <T extends KeySpec> boolean engineConvertibleToKeySpec(final Password password, final Class<T> specType) {
        return false;
    }
}
