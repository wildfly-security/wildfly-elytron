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

import static org.wildfly.security.password.impl.ElytronMessages.log;
import static org.wildfly.security.password.interfaces.BCryptPassword.ALGORITHM_BCRYPT;
import static org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_512_256;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_MD5;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_SHA1;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_SHA_256;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_SHA_384;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_SHA_512;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_1;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_256;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_384;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_512;
import static org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword.ALGORITHM_SUN_CRYPT_MD5;
import static org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword.ALGORITHM_SUN_CRYPT_MD5_BARE_SALT;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD2;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword.ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_256;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_512;
import static org.wildfly.security.password.interfaces.UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5;
import static org.wildfly.security.password.interfaces.UnixDESCryptPassword.ALGORITHM_CRYPT_DES;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import javax.security.sasl.SaslException;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactorySpi;
import org.wildfly.security.password.interfaces.BCryptPassword;
import org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.interfaces.DigestPassword;
import org.wildfly.security.password.interfaces.MaskedPassword;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.interfaces.SaltedSimpleDigestPassword;
import org.wildfly.security.password.interfaces.ScramDigestPassword;
import org.wildfly.security.password.interfaces.SimpleDigestPassword;
import org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword;
import org.wildfly.security.password.interfaces.UnixDESCryptPassword;
import org.wildfly.security.password.interfaces.UnixMD5CryptPassword;
import org.wildfly.security.password.interfaces.UnixSHACryptPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.DigestPasswordSpec;
import org.wildfly.security.password.spec.EncryptablePasswordSpec;
import org.wildfly.security.password.spec.HashPasswordSpec;
import org.wildfly.security.password.spec.IteratedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordAlgorithmSpec;
import org.wildfly.security.password.spec.MaskedPasswordSpec;
import org.wildfly.security.password.spec.OneTimePasswordAlgorithmSpec;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;
import org.wildfly.security.password.spec.SaltedPasswordAlgorithmSpec;

/**
 * The Elytron-provided password factory SPI implementation, which supports all the provided password types.
 */
public final class PasswordFactorySpiImpl extends PasswordFactorySpi {

    @Override
    protected Password engineGeneratePassword(final String algorithm, final KeySpec keySpec) throws InvalidKeySpecException {
        /*
         * When adding or removing an algorithm ensure that the registrations in 'WildFlyElytronProvider' are also
         * updated.
         */

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
            case ALGORITHM_BCRYPT: {
                if (keySpec instanceof IteratedSaltedHashPasswordSpec) {
                    try {
                        return new BCryptPasswordImpl((IteratedSaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new BCryptPasswordImpl((SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new BCryptPasswordImpl((ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                        final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                        if (parameterSpec == null) {
                            return new BCryptPasswordImpl(encryptableSpec.getPassword(), encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
                            return new BCryptPasswordImpl(encryptableSpec.getPassword(), (SaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof IteratedSaltedPasswordAlgorithmSpec) {
                            return new BCryptPasswordImpl(encryptableSpec.getPassword(), (IteratedSaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof IteratedPasswordAlgorithmSpec) {
                            return new BCryptPasswordImpl(encryptableSpec.getPassword(), (IteratedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else {
                            break;
                        }
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_CRYPT_MD5: {
                if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new UnixMD5CryptPasswordImpl((SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new UnixMD5CryptPasswordImpl((ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                        final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                        if (parameterSpec == null) {
                            return new UnixMD5CryptPasswordImpl(encryptableSpec.getPassword(), encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
                            return new UnixMD5CryptPasswordImpl(encryptableSpec.getPassword(), (SaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else {
                            break;
                        }
                    } catch (IllegalArgumentException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_SUN_CRYPT_MD5:
            case ALGORITHM_SUN_CRYPT_MD5_BARE_SALT: {
                if (keySpec instanceof IteratedSaltedHashPasswordSpec) {
                    try {
                        return new SunUnixMD5CryptPasswordImpl(algorithm, (IteratedSaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new SunUnixMD5CryptPasswordImpl(algorithm, (SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new SunUnixMD5CryptPasswordImpl((ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                        final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                        if (parameterSpec == null) {
                            return new SunUnixMD5CryptPasswordImpl(algorithm, encryptableSpec.getPassword(), encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
                            return new SunUnixMD5CryptPasswordImpl(algorithm, encryptableSpec.getPassword(), (SaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof IteratedSaltedPasswordAlgorithmSpec) {
                            return new SunUnixMD5CryptPasswordImpl(algorithm, encryptableSpec.getPassword(), (IteratedSaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof IteratedPasswordAlgorithmSpec) {
                            return new SunUnixMD5CryptPasswordImpl(algorithm, encryptableSpec.getPassword(), (IteratedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else {
                            break;
                        }
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_CRYPT_SHA_256:
            case ALGORITHM_CRYPT_SHA_512: {
                if (keySpec instanceof IteratedSaltedHashPasswordSpec) {
                    try {
                        return new UnixSHACryptPasswordImpl(algorithm, (IteratedSaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new UnixSHACryptPasswordImpl(algorithm, (SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new UnixSHACryptPasswordImpl(algorithm, (ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                        final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                        if (parameterSpec == null) {
                            return new UnixSHACryptPasswordImpl(algorithm, encryptableSpec.getPassword(), encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof IteratedPasswordAlgorithmSpec) {
                            return new UnixSHACryptPasswordImpl(algorithm, (IteratedPasswordAlgorithmSpec) parameterSpec, encryptableSpec.getPassword(),
                                    encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof IteratedSaltedPasswordAlgorithmSpec) {
                            return new UnixSHACryptPasswordImpl(algorithm, (IteratedSaltedPasswordAlgorithmSpec) parameterSpec, encryptableSpec.getPassword(),
                                    encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
                            return new UnixSHACryptPasswordImpl(algorithm, (SaltedPasswordAlgorithmSpec) parameterSpec, encryptableSpec.getPassword(),
                                    encryptableSpec.getHashCharset());
                        } else {
                            break;
                        }
                    } catch (IllegalArgumentException | NullPointerException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_DIGEST_MD5:
            case ALGORITHM_DIGEST_SHA:
            case ALGORITHM_DIGEST_SHA_256:
            case ALGORITHM_DIGEST_SHA_384:
            case ALGORITHM_DIGEST_SHA_512:
            case ALGORITHM_DIGEST_SHA_512_256:
                if (keySpec instanceof DigestPasswordSpec) {
                    return new DigestPasswordImpl(algorithm, (DigestPasswordSpec) keySpec);
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    return new DigestPasswordImpl(algorithm, (EncryptablePasswordSpec) keySpec);
                }
                break;
            case ALGORITHM_SIMPLE_DIGEST_MD2:
            case ALGORITHM_SIMPLE_DIGEST_MD5:
            case ALGORITHM_SIMPLE_DIGEST_SHA_1:
            case ALGORITHM_SIMPLE_DIGEST_SHA_256:
            case ALGORITHM_SIMPLE_DIGEST_SHA_384:
            case ALGORITHM_SIMPLE_DIGEST_SHA_512: {
                if (keySpec instanceof HashPasswordSpec) {
                    try {
                        return new SimpleDigestPasswordImpl(algorithm, (HashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new SimpleDigestPasswordImpl(algorithm, (ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                        final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                        if (parameterSpec == null) {
                            return new SimpleDigestPasswordImpl(algorithm, encryptableSpec.getPassword(), encryptableSpec.getHashCharset());
                        } else {
                            break;
                        }
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
            case ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512:
                if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new SaltedSimpleDigestPasswordImpl(algorithm, (SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new SaltedSimpleDigestPasswordImpl(algorithm, (ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                        final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                        if (parameterSpec == null) {
                            return new SaltedSimpleDigestPasswordImpl(algorithm, encryptableSpec.getPassword(), encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
                            return new SaltedSimpleDigestPasswordImpl(algorithm, encryptableSpec.getPassword(), (SaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else {
                            break;
                        }
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                }
                break;
            case ALGORITHM_CRYPT_DES: {
                if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new UnixDESCryptPasswordImpl((SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | InvalidParameterSpecException | InvalidKeyException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new UnixDESCryptPasswordImpl((ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | InvalidKeyException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                        final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                        if (parameterSpec == null) {
                            return new UnixDESCryptPasswordImpl(encryptableSpec.getPassword(), encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
                            return new UnixDESCryptPasswordImpl(encryptableSpec.getPassword(), (SaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else {
                            break;
                        }
                    } catch (IllegalArgumentException | InvalidParameterSpecException | InvalidKeyException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_BSD_CRYPT_DES: {
                if (keySpec instanceof IteratedSaltedHashPasswordSpec) {
                    try {
                        return new BSDUnixDESCryptPasswordImpl((IteratedSaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | InvalidParameterSpecException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new BSDUnixDESCryptPasswordImpl((SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | InvalidParameterSpecException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new BSDUnixDESCryptPasswordImpl((ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                        final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                        if (parameterSpec == null) {
                            return new BSDUnixDESCryptPasswordImpl(encryptableSpec.getPassword(), encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
                            return new BSDUnixDESCryptPasswordImpl(encryptableSpec.getPassword(), (SaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof IteratedSaltedPasswordAlgorithmSpec) {
                            return new BSDUnixDESCryptPasswordImpl(encryptableSpec.getPassword(), (IteratedSaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof IteratedPasswordAlgorithmSpec) {
                            return new BSDUnixDESCryptPasswordImpl(encryptableSpec.getPassword(), (IteratedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else {
                            break;
                        }
                    } catch (InvalidParameterSpecException | IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else {
                    break;
                }
            }
            case ALGORITHM_SCRAM_SHA_1:
            case ALGORITHM_SCRAM_SHA_256:
            case ALGORITHM_SCRAM_SHA_384:
            case ALGORITHM_SCRAM_SHA_512: {
                if (keySpec instanceof IteratedSaltedHashPasswordSpec) {
                    try {
                        return new ScramDigestPasswordImpl(algorithm, (IteratedSaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof SaltedHashPasswordSpec) {
                    try {
                        return new ScramDigestPasswordImpl(algorithm, (SaltedHashPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof ClearPasswordSpec) {
                    try {
                        return new ScramDigestPasswordImpl(algorithm, (ClearPasswordSpec) keySpec);
                    } catch (IllegalArgumentException | NullPointerException | InvalidKeyException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    try {
                        final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                        final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                        if (parameterSpec == null) {
                            return new ScramDigestPasswordImpl(algorithm, encryptableSpec.getPassword(), encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
                            return new ScramDigestPasswordImpl(algorithm, encryptableSpec.getPassword(), (SaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof IteratedSaltedPasswordAlgorithmSpec) {
                            return new ScramDigestPasswordImpl(algorithm, encryptableSpec.getPassword(), (IteratedSaltedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else if (parameterSpec instanceof IteratedPasswordAlgorithmSpec) {
                            return new ScramDigestPasswordImpl(algorithm, encryptableSpec.getPassword(), (IteratedPasswordAlgorithmSpec) parameterSpec,
                                    encryptableSpec.getHashCharset());
                        } else {
                            break;
                        }
                    } catch (IllegalArgumentException | NullPointerException | InvalidKeyException | NoSuchAlgorithmException e) {
                        throw new InvalidKeySpecException(e);
                    }
                }
                else {
                    break;
                }
            }
            case ALGORITHM_OTP_MD5:
            case ALGORITHM_OTP_SHA1:
            case ALGORITHM_OTP_SHA_256:
            case ALGORITHM_OTP_SHA_384:
            case ALGORITHM_OTP_SHA_512: {
                if (keySpec instanceof OneTimePasswordSpec) {
                    return new OneTimePasswordImpl(algorithm, (OneTimePasswordSpec) keySpec);
                } else if (keySpec instanceof EncryptablePasswordSpec) {
                    final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                    final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                    try {
                        if ( parameterSpec instanceof OneTimePasswordAlgorithmSpec){
                            return new OneTimePasswordImpl(algorithm, encryptableSpec.getPassword(), (OneTimePasswordAlgorithmSpec) parameterSpec);
                        } else {
                            break;
                        }
                    } catch (SaslException e) {
                        throw new InvalidKeySpecException(e);
                    }
                }
                break;
            }
            default: {
                if (MaskedPassword.isMaskedAlgorithm(algorithm)) {
                    if (keySpec instanceof MaskedPasswordSpec) {
                        return new MaskedPasswordImpl(algorithm, (MaskedPasswordSpec) keySpec);
                    } else if (keySpec instanceof EncryptablePasswordSpec) {
                        final EncryptablePasswordSpec encryptableSpec = (EncryptablePasswordSpec) keySpec;
                        final AlgorithmParameterSpec parameterSpec = encryptableSpec.getAlgorithmParameterSpec();
                        if (parameterSpec == null) {
                            return new MaskedPasswordImpl(algorithm, encryptableSpec.getPassword());
                        } else if (parameterSpec instanceof MaskedPasswordAlgorithmSpec) {
                            return new MaskedPasswordImpl(algorithm, encryptableSpec.getPassword(), (MaskedPasswordAlgorithmSpec) parameterSpec);
                        } else if (parameterSpec instanceof IteratedSaltedPasswordAlgorithmSpec) {
                            return new MaskedPasswordImpl(algorithm, encryptableSpec.getPassword(), (IteratedSaltedPasswordAlgorithmSpec) parameterSpec);
                        } else if (parameterSpec instanceof SaltedPasswordAlgorithmSpec) {
                            return new MaskedPasswordImpl(algorithm, encryptableSpec.getPassword(), (SaltedPasswordAlgorithmSpec) parameterSpec);
                        } else if (parameterSpec instanceof IteratedPasswordAlgorithmSpec) {
                            return new MaskedPasswordImpl(algorithm, encryptableSpec.getPassword(), (IteratedPasswordAlgorithmSpec) parameterSpec);
                        }
                    } else if (keySpec instanceof ClearPasswordSpec) {
                        return new MaskedPasswordImpl(algorithm, (ClearPasswordSpec) keySpec);
                    }
                    break;
                }
                break;
            }
        }
        throw log.invalidKeySpecUnknownAlgorithmOrIncompatiblePasswordSpec(algorithm, keySpec == null ? null : keySpec.getClass().getSimpleName());
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
    protected boolean engineIsTranslatablePassword(final String algorithm, final Password password) {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return true;
            }
        }

        /*
         * When adding or removing an algorithm ensure that the registrations in 'WildFlyElytronProvider' are also
         * updated.
         */

        switch (algorithm) {
            case ALGORITHM_CLEAR: {
                return (password instanceof ClearPassword);
            }
            case ALGORITHM_BCRYPT: {
                return (password instanceof BCryptPassword);
            }
            case ALGORITHM_CRYPT_MD5: {
                return (password instanceof UnixMD5CryptPassword);
            }
            case ALGORITHM_SUN_CRYPT_MD5:
            case ALGORITHM_SUN_CRYPT_MD5_BARE_SALT: {
                return (password instanceof SunUnixMD5CryptPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_CRYPT_SHA_256:
            case ALGORITHM_CRYPT_SHA_512: {
                return (password instanceof UnixSHACryptPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_DIGEST_MD5:
            case ALGORITHM_DIGEST_SHA:
            case ALGORITHM_DIGEST_SHA_256:
            case ALGORITHM_DIGEST_SHA_384:
            case ALGORITHM_DIGEST_SHA_512:{
                return (password instanceof DigestPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_SIMPLE_DIGEST_MD2:
            case ALGORITHM_SIMPLE_DIGEST_MD5:
            case ALGORITHM_SIMPLE_DIGEST_SHA_1:
            case ALGORITHM_SIMPLE_DIGEST_SHA_256:
            case ALGORITHM_SIMPLE_DIGEST_SHA_384:
            case ALGORITHM_SIMPLE_DIGEST_SHA_512: {
                return (password instanceof SimpleDigestPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
            case ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512: {
                return (password instanceof SaltedSimpleDigestPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_CRYPT_DES: {
                return (password instanceof UnixDESCryptPassword);
            }
            case ALGORITHM_BSD_CRYPT_DES: {
                return (password instanceof BSDUnixDESCryptPassword);
            }
            case ALGORITHM_SCRAM_SHA_1:
            case ALGORITHM_SCRAM_SHA_256:
            case ALGORITHM_SCRAM_SHA_384:
            case ALGORITHM_SCRAM_SHA_512: {
                return (password instanceof ScramDigestPassword && algorithm.equals(password.getAlgorithm()));
            }
            case ALGORITHM_OTP_MD5:
            case ALGORITHM_OTP_SHA1:
            case ALGORITHM_OTP_SHA_256:
            case ALGORITHM_OTP_SHA_384:
            case ALGORITHM_OTP_SHA_512: {
                return (password instanceof OneTimePassword && algorithm.equals(password.getAlgorithm()));
            }
            default: {
                return MaskedPassword.isMaskedAlgorithm(algorithm) && password instanceof MaskedPassword && algorithm.equals(password.getAlgorithm());
            }
        }
    }

    @Override
    protected Password engineTranslatePassword(final String algorithm, final Password password) throws InvalidKeyException {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword;
            }
        }

        /*
         * When adding or removing an algorithm ensure that the registrations in 'WildFlyElytronProvider' are also
         * updated.
         */

        switch (algorithm) {
            case ALGORITHM_CLEAR: {
                if (password instanceof ClearPasswordImpl) {
                    return password;
                } else if (password instanceof ClearPassword) {
                    return new ClearPasswordImpl((ClearPassword) password);
                }
                break;
            }
            case ALGORITHM_BCRYPT: {
                if (password instanceof BCryptPasswordImpl) {
                    return password;
                } else if (password instanceof BCryptPassword) {
                    return new BCryptPasswordImpl((BCryptPassword) password);
                }
                break;
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
                if (password instanceof SunUnixMD5CryptPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof SunUnixMD5CryptPassword && algorithm.equals(password.getAlgorithm())) {
                    return new SunUnixMD5CryptPasswordImpl((SunUnixMD5CryptPassword) password);
                } else {
                    break;
                }
            }
            case ALGORITHM_CRYPT_SHA_256:
            case ALGORITHM_CRYPT_SHA_512: {
                if (password instanceof UnixSHACryptPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof UnixSHACryptPassword  && algorithm.equals(password.getAlgorithm())) {
                    return new UnixSHACryptPasswordImpl((UnixSHACryptPassword) password);
                }
                break;
            }
            case ALGORITHM_DIGEST_MD5:
            case ALGORITHM_DIGEST_SHA:
            case ALGORITHM_DIGEST_SHA_256:
            case ALGORITHM_DIGEST_SHA_384:
            case ALGORITHM_DIGEST_SHA_512:
            case ALGORITHM_DIGEST_SHA_512_256: {
                if (password instanceof DigestPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof DigestPassword  && algorithm.equals(password.getAlgorithm())) {
                    return new SimpleDigestPasswordImpl((SimpleDigestPassword) password);
                }
                break;
            }
            case ALGORITHM_SIMPLE_DIGEST_MD2:
            case ALGORITHM_SIMPLE_DIGEST_MD5:
            case ALGORITHM_SIMPLE_DIGEST_SHA_1:
            case ALGORITHM_SIMPLE_DIGEST_SHA_256:
            case ALGORITHM_SIMPLE_DIGEST_SHA_384:
            case ALGORITHM_SIMPLE_DIGEST_SHA_512: {
                if (password instanceof SimpleDigestPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof SimpleDigestPassword  && algorithm.equals(password.getAlgorithm())) {
                    return new SimpleDigestPasswordImpl((SimpleDigestPassword) password);
                }
                break;
            }
            case ALGORITHM_PASSWORD_SALT_DIGEST_MD5:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384:
            case ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512:
            case ALGORITHM_SALT_PASSWORD_DIGEST_MD5:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384:
            case ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512: {
                if (password instanceof SaltedSimpleDigestPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof SaltedSimpleDigestPassword && algorithm.equals(password.getAlgorithm())) {
                    return new SaltedSimpleDigestPasswordImpl((SaltedSimpleDigestPassword) password);
                }
                break;
            }
            case ALGORITHM_CRYPT_DES: {
                if (password instanceof UnixDESCryptPasswordImpl) {
                    return password;
                } else if (password instanceof UnixDESCryptPassword) {
                    return new UnixDESCryptPasswordImpl((UnixDESCryptPassword) password);
                }
                break;
            }
            case ALGORITHM_BSD_CRYPT_DES: {
                if (password instanceof BSDUnixDESCryptPasswordImpl) {
                    return password;
                } else if (password instanceof BSDUnixDESCryptPassword) {
                    return new BSDUnixDESCryptPasswordImpl((BSDUnixDESCryptPassword) password);
                }
                break;
            }
            case ALGORITHM_SCRAM_SHA_1:
            case ALGORITHM_SCRAM_SHA_256:
            case ALGORITHM_SCRAM_SHA_384:
            case ALGORITHM_SCRAM_SHA_512: {
                if (password instanceof ScramDigestPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof ScramDigestPassword && algorithm.equals(password.getAlgorithm())) {
                    return new ScramDigestPasswordImpl((ScramDigestPassword) password);
                }
                break;
            }
            case ALGORITHM_OTP_MD5:
            case ALGORITHM_OTP_SHA1:
            case ALGORITHM_OTP_SHA_256:
            case ALGORITHM_OTP_SHA_384:
            case ALGORITHM_OTP_SHA_512: {
                if (password instanceof OneTimePasswordImpl && algorithm.equals(password.getAlgorithm())) {
                    return password;
                } else if (password instanceof OneTimePassword && algorithm.equals(password.getAlgorithm())) {
                    return new OneTimePasswordImpl((OneTimePassword) password);
                }
                break;
            }
            default: {
                if (MaskedPassword.isMaskedAlgorithm(algorithm)) {
                    if (password instanceof MaskedPasswordImpl && algorithm.equals(password.getAlgorithm())) {
                        return password;
                    } else if (password instanceof MaskedPassword && algorithm.equals(password.getAlgorithm())) {
                        try {
                            return new MaskedPasswordImpl((MaskedPassword) password);
                        } catch (InvalidKeySpecException e) {
                            throw new InvalidKeyException(e);
                        }
                    }
                }
                break;
            }
        }
        throw log.invalidKeyUnknownUnknownPasswordTypeOrAlgorithm();
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
    protected boolean engineVerify(final String algorithm, final Password password, final char[] guess, Charset hashCharset) throws InvalidKeyException {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword.verify(guess, hashCharset);
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

    @Override
    protected Password engineTransform(final String algorithm, final Password password, final AlgorithmParameterSpec parameterSpec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (password instanceof AbstractPasswordImpl) {
            final AbstractPasswordImpl abstractPassword = (AbstractPasswordImpl) password;
            if (algorithm.equals(abstractPassword.getAlgorithm())) {
                return abstractPassword.translate(parameterSpec);
            }
        }
        throw new InvalidKeyException();
    }
}
