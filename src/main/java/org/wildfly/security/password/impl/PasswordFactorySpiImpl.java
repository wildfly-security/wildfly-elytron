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

import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactorySpi;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.UnixSHACryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.UnixSHACryptPasswordSpec;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public final class PasswordFactorySpiImpl extends PasswordFactorySpi {

    private static final String ALGORITHM_CLEAR = "clear";
    private static final String ALGORITHM_SHA256CRYPT = "sha-256-crypt";
    private static final String ALGORITHM_SHA512CRYPT = "sha-512-crypt";

    @Override
    protected Password engineGeneratePassword(final String algorithm, final KeySpec keySpec) throws InvalidKeySpecException {
        switch (algorithm) {
            case ALGORITHM_CLEAR: {
                if (keySpec instanceof ClearPasswordSpec) {
                    return new ClearPasswordImpl(((ClearPasswordSpec)keySpec).getEncodedPassword().clone());
                } else {
                    break;
                }
            }
            case ALGORITHM_SHA256CRYPT:
            case ALGORITHM_SHA512CRYPT: {
                if (keySpec instanceof UnixSHACryptPasswordSpec) {
                    UnixSHACryptPasswordSpec spec = (UnixSHACryptPasswordSpec) keySpec;
                    try {
                        return new UnixSHACryptPasswordImpl(UnixSHACryptPasswordUtil.encode(spec));
                    } catch (NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException("Cannot read key spec", e);
                    }
                } else {
                    break;
                }
            }
        }
        throw new InvalidKeySpecException();
    }

    @Override
    protected <S extends KeySpec> S engineGetKeySpec(final String algorithm, final Password password, final Class<S> keySpecType) throws InvalidKeySpecException {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword.getKeySpec(keySpecType);
            }
        }
        throw new InvalidKeySpecException();
    }

    @Override
    protected Password engineTranslatePassword(final String algorithm, final Password password) throws InvalidKeyException {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword;
            }
        }
        switch (algorithm) {
            case ALGORITHM_CLEAR: {
                if (password instanceof ClearPassword) {
                    return new ClearPasswordImpl((ClearPassword) password);
                } else {
                    break;
                }
            }
            case ALGORITHM_SHA256CRYPT:
            case ALGORITHM_SHA512CRYPT: {
                if (password instanceof UnixSHACryptPassword) {
                    return new UnixSHACryptPasswordImpl((UnixSHACryptPassword) password);
                } else {
                    break;
                }
            }
        }
        throw new InvalidKeyException();
    }

    @Override
    protected boolean engineVerify(final String algorithm, final Password password, final char[] guess) throws InvalidKeyException {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword.verify(guess);
            }
        }
        throw new InvalidKeyException();
    }

    @Override
    protected <S extends KeySpec> boolean engineConvertibleToKeySpec(final String algorithm, final Password password, final Class<S> keySpecType) {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword.convertibleTo(keySpecType);
            }
        }
        return false;
    }
}
