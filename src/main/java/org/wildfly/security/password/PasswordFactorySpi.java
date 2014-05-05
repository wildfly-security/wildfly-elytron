/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.password;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class PasswordFactorySpi {

    protected PasswordFactorySpi() {
    }

    protected abstract Password engineGeneratePassword(KeySpec keySpec) throws InvalidKeySpecException;

    protected abstract <S extends KeySpec> S engineGetKeySpec(Password password, Class<S> keySpecType) throws InvalidKeySpecException;

    protected abstract Password engineTranslatePassword(Password password) throws InvalidKeyException;

    protected abstract boolean engineVerify(final Password password, final char[] guess) throws InvalidKeyException;

    protected abstract <T extends KeySpec> boolean engineConvertibleToKeySpec(final Password password, final Class<T> specType);
}
