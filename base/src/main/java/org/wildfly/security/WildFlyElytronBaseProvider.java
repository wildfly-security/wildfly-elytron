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

package org.wildfly.security;

import static org.wildfly.security.ElytronMessages.log;

import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The base {@link Provider} implementation for security services made available by Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class WildFlyElytronBaseProvider extends VersionedProvider {

    protected static final String HTTP_SERVER_FACTORY_TYPE = "HttpServerAuthenticationMechanismFactory";
    protected static final String SASL_CLIENT_FACTORY_TYPE = "SaslClientFactory";
    protected static final String SASL_SERVER_FACTORY_TYPE = "SaslServerFactory";
    protected static final String PASSWORD_FACTORY_TYPE = "PasswordFactory";
    protected static final String ALG_PARAMS_TYPE = "AlgorithmParameters";
    protected static final List<String> emptyList = Collections.emptyList();
    protected static final Map<String, String> emptyMap = Collections.emptyMap();

    protected WildFlyElytronBaseProvider(final String name, final String version, final String info) {
        super(name, version, info);
        put("Alg.Alias.Data.OID.1.2.840.113549.1.7.1", "Data");
    }

    protected void putPasswordImplementations() {
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "clear", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "crypt-md5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "sun-crypt-md5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "sun-crypt-md5-bare-salt", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "crypt-sha-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "crypt-sha-512", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "simple-digest-md2", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "simple-digest-md5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "simple-digest-sha-1", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "simple-digest-sha-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "simple-digest-sha-384", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "simple-digest-sha-512", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "digest-md5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "digest-sha", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "digest-sha-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "digest-sha-384", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "digest-sha-512", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "digest-sha-512-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "password-salt-digest-md5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "password-salt-digest-sha-1", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "password-salt-digest-sha-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "password-salt-digest-sha-384", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "password-salt-digest-sha-512", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "salt-password-digest-md5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "salt-password-digest-sha-1", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "salt-password-digest-sha-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "salt-password-digest-sha-384", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "salt-password-digest-sha-512", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "crypt-des", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "bsd-crypt-des", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "bcrypt", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "scram-sha-1", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "scram-sha-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "scram-sha-384", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "scram-sha-512", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "otp-md5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "otp-sha1", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "otp-sha256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "otp-sha384", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "otp-sha512", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-MD5-DES", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-MD5-DES-CBC-PKCS5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-MD5-3DES", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-MD5-3DES-CBC-PKCS5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-SHA1-DES-EDE", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-SHA1-DES-EDE-CBC-PKCS5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-SHA1-RC2-40", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-SHA1-RC2-40-CBC-PKCS5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-SHA1-RC2-128", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-SHA1-RC2-128-CBC-PKCS5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-SHA1-RC4-40", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-SHA1-RC4-40-ECB", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-SHA1-RC4-128", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-SHA1-RC4-128-ECB", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-HMAC-SHA1-AES-128", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-HMAC-SHA224-AES-128", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-HMAC-SHA256-AES-128", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-HMAC-SHA384-AES-128", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-HMAC-SHA512-AES-128", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-HMAC-SHA1-AES-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-HMAC-SHA224-AES-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-HMAC-SHA256-AES-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-HMAC-SHA384-AES-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-HMAC-SHA512-AES-256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-PBKDF-HMAC-SHA1", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-PBKDF-HMAC-SHA224", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-PBKDF-HMAC-SHA256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-PBKDF-HMAC-SHA384", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "masked-PBKDF-HMAC-SHA512", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
    }

    protected void putAlgorithmParametersImplementations() {
        putService(new Service(this, ALG_PARAMS_TYPE, "RSA", "org.wildfly.security.key.RSAParameterSpiImpl", emptyList, emptyMap));

        putService(new Service(this, ALG_PARAMS_TYPE, "crypt-md5", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "sun-crypt-md5", "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "sun-crypt-md5-bare-salt", "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "crypt-sha-256", "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "crypt-sha-512", "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "digest-md5", "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "digest-sha", "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "digest-sha-256", "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "digest-sha-384", "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "digest-sha-512", "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "digest-sha-512-256", "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "password-salt-digest-md5", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "password-salt-digest-sha-1", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "password-salt-digest-sha-256", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "password-salt-digest-sha-384", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "password-salt-digest-sha-512", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "salt-password-digest-md5", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "salt-password-digest-sha-1", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "salt-password-digest-sha-256", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "salt-password-digest-sha-384", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "salt-password-digest-sha-512", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "crypt-des", "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "bsd-crypt-des", "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "bcrypt", "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "scram-sha-1", "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "scram-sha-256", "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "scram-sha-384", "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "scram-sha-512", "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "otp-md5", "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "otp-sha1", "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "otp-sha256", "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "otp-sha384", "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "otp-sha512", "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-MD5-DES", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-MD5-DES-CBC-PKCS5", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-MD5-3DES", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-MD5-3DES-CBC-PKCS5", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-SHA1-DES-EDE", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-SHA1-DES-EDE-CBC-PKCS5", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-SHA1-RC2-40", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-SHA1-RC2-40-CBC-PKCS5", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-SHA1-RC2-128", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-SHA1-RC2-128-CBC-PKCS5", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-SHA1-RC4-40", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-SHA1-RC4-40-ECB", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-SHA1-RC4-128", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-SHA1-RC4-128-ECB", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-HMAC-SHA1-AES-128", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-HMAC-SHA224-AES-128", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-HMAC-SHA384-AES-128", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-HMAC-SHA512-AES-128", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-HMAC-SHA1-AES-256", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-HMAC-SHA224-AES-256", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-HMAC-SHA384-AES-256", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-HMAC-SHA512-AES-256", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-PBKDF-HMAC-SHA1", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-PBKDF-HMAC-SHA224", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-PBKDF-HMAC-SHA256", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-PBKDF-HMAC-SHA384", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "masked-PBKDF-HMAC-SHA512", "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
    }

    protected class ProviderService extends Service {

        private volatile Reference<Class<?>> implementationClassRef;

        public ProviderService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String,String> attributes) {
            super(provider, type, algorithm, className, aliases, attributes);
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            Class<?> implementationClass = getImplementationClass();

            try {
                Constructor<?> constructor = implementationClass.getConstructor(Provider.class);
                return constructor.newInstance(WildFlyElytronBaseProvider.this);
            } catch (Exception e) {
                throw log.noSuchAlgorithmCreateService(getType(), getAlgorithm(), e);
            }
        }

        private Class<?> getImplementationClass() throws NoSuchAlgorithmException {
            Reference<Class<?>> implementationClassRef = this.implementationClassRef;
            Class<?> implementationClass = implementationClassRef != null ? implementationClassRef.get() : null;
            if (implementationClass == null) {
                ClassLoader classLoader = WildFlyElytronBaseProvider.class.getClassLoader();
                try {
                    implementationClass = Class.forName(getClassName(), false, classLoader);
                } catch (ClassNotFoundException e) {
                    throw log.noSuchAlgorithmCreateService(getType(), getAlgorithm(), e);
                }
                this.implementationClassRef = new WeakReference<>(implementationClass);
            }

            return implementationClass;
        }

    }
}
