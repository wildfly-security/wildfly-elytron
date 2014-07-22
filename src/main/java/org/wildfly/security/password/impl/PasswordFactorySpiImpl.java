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

import static org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword.*;
import static org.wildfly.security.password.interfaces.TrivialDigestPassword.*;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.*;
import static org.wildfly.security.password.interfaces.UnixMD5CryptPassword.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactorySpi;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword;
import org.wildfly.security.password.interfaces.TrivialDigestPassword;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;
import org.wildfly.security.password.interfaces.UnixSHACryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.SunUnixMD5CryptPasswordSpec;
import org.wildfly.security.password.spec.TrivialDigestPasswordSpec;
import org.wildfly.security.password.spec.UnixMD5CryptPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.UnixSHACryptPasswordSpec;

public final class PasswordFactorySpiImpl extends PasswordFactorySpi {

    private static final String ALGORITHM_CLEAR = "clear";

    @Override
    protected Password engineGeneratePassword(final String algorithm, final KeySpec keySpec) throws InvalidKeySpecException {
        switch (algorithm) {
            case ALGORITHM_CLEAR: {
                if (keySpec instanceof ClearPasswordSpec) {
                    return new ClearPasswordImpl(((ClearPasswordSpec) keySpec).getEncodedPassword().clone());
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    return new ClearPasswordImpl(((EncryptablePasswordSpec) keySpec).getPassword().clone());
                } else {
                    break;
                }
            }
            case ALGORITHM_CRYPT_MD5: {
                if (keySpec instanceof UnixMD5CryptPasswordSpec) {
                    try {
                        return new UnixMD5CryptPasswordImpl((UnixMD5CryptPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e.getMessage());
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new UnixMD5CryptPasswordImpl((EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e.getMessage());
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_SUN_CRYPT_MD5:
            case ALGORITHM_SUN_CRYPT_MD5_BARE_SALT: {
                if (keySpec instanceof SunUnixMD5CryptPasswordSpec) {
                    try {
                        return new SunUnixMD5CryptPasswordImpl((SunUnixMD5CryptPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e.getMessage());
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new SunUnixMD5CryptPasswordImpl(algorithm, (EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e.getMessage());
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_SHA256CRYPT:
            case ALGORITHM_SHA512CRYPT: {
                if (keySpec instanceof UnixSHACryptPasswordSpec) {
                    try {
                        return new UnixSHACryptPasswordImpl((UnixSHACryptPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e.getMessage());
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        return new UnixSHACryptPasswordImpl(algorithm, (EncryptablePasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e.getMessage());
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_DIGEST_MD2:
            case ALGORITHM_DIGEST_MD5:
            case ALGORITHM_DIGEST_SHA_1:
            case ALGORITHM_DIGEST_SHA_256:
            case ALGORITHM_DIGEST_SHA_384:
            case ALGORITHM_DIGEST_SHA_512: {
                if (keySpec instanceof TrivialDigestPasswordSpec) {
                    return new TrivialDigestPasswordImpl((TrivialDigestPasswordSpec) keySpec);
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    return new TrivialDigestPasswordImpl(algorithm, (EncryptablePasswordSpec) keySpec);
                } else {
                    break;
                }
            }
        }
        throw new InvalidKeySpecException("Unknown algorithm");
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
                if (password instanceof ClearPasswordImpl) {
                    return password;
                } else if (password instanceof ClearPassword) {
                    return new ClearPasswordImpl((ClearPassword) password);
                } else {
                    break;
                }
            }
            case ALGORITHM_CRYPT_MD5: {
                if (password instanceof UnixMD5CryptPasswordImpl) {
                    return password;
                } else if (password instanceof UnixMD5CryptPassword) {
                    return new UnixMD5CryptPasswordImpl((UnixMD5CryptPassword) password);
                } else {
                    break;
                }
            }
            case ALGORITHM_SUN_CRYPT_MD5:
            case ALGORITHM_SUN_CRYPT_MD5_BARE_SALT: {
                if (password instanceof SunUnixMD5CryptPasswordImpl) {
                    return password;
                } else if (password instanceof SunUnixMD5CryptPassword) {
                    return new SunUnixMD5CryptPasswordImpl((SunUnixMD5CryptPassword) password);
                } else {
                    break;
                }
            }
            case ALGORITHM_SHA256CRYPT:
            case ALGORITHM_SHA512CRYPT: {
                if (password instanceof UnixSHACryptPasswordImpl) {
                    return password;
                } else if (password instanceof UnixSHACryptPassword) {
                    return new UnixSHACryptPasswordImpl((UnixSHACryptPassword) password);
                } else {
                    break;
                }
            }
            case ALGORITHM_DIGEST_MD2:
            case ALGORITHM_DIGEST_MD5:
            case ALGORITHM_DIGEST_SHA_1:
            case ALGORITHM_DIGEST_SHA_256:
            case ALGORITHM_DIGEST_SHA_384:
            case ALGORITHM_DIGEST_SHA_512: {
                if (password instanceof TrivialDigestPasswordImpl) {
                    return password;
                } else if (password instanceof TrivialDigestPassword) {
                    return new TrivialDigestPasswordImpl((TrivialDigestPassword) password);
                } else {
                    break;
                }
            }
        }
        throw new InvalidKeyException("Unknown password type or algorithm");
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
