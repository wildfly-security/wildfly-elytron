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

import static org.wildfly.security._private.ElytronMessages.log;
import static org.wildfly.security.http.HttpConstants.BASIC_NAME;
import static org.wildfly.security.http.HttpConstants.BEARER_TOKEN;
import static org.wildfly.security.http.HttpConstants.CLIENT_CERT_NAME;
import static org.wildfly.security.http.HttpConstants.DIGEST_NAME;
import static org.wildfly.security.http.HttpConstants.FORM_NAME;
import static org.wildfly.security.http.HttpConstants.SPNEGO_NAME;
import static org.wildfly.security.password.interfaces.BCryptPassword.ALGORITHM_BCRYPT;
import static org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_HMAC_SHA1_AES_128;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_HMAC_SHA1_AES_256;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_HMAC_SHA224_AES_128;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_HMAC_SHA224_AES_256;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_HMAC_SHA256_AES_128;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_HMAC_SHA256_AES_256;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_HMAC_SHA384_AES_128;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_HMAC_SHA384_AES_256;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_HMAC_SHA512_AES_128;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_HMAC_SHA512_AES_256;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_MD5_3DES;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_MD5_3DES_CBC_PKCS5;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_MD5_DES;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_MD5_DES_CBC_PKCS5;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_PBKDF_HMAC_SHA1;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_PBKDF_HMAC_SHA224;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_PBKDF_HMAC_SHA256;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_PBKDF_HMAC_SHA384;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_PBKDF_HMAC_SHA512;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_SHA1_DES_EDE;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_SHA1_DES_EDE_CBC_PKCS5;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_SHA1_RC2_128;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_SHA1_RC2_128_CBC_PKCS5;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_SHA1_RC2_40;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_SHA1_RC2_40_CBC_PKCS5;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_SHA1_RC4_128;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_SHA1_RC4_128_ECB;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_SHA1_RC4_40;
import static org.wildfly.security.password.interfaces.MaskedPassword.ALGORITHM_MASKED_SHA1_RC4_40_ECB;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_MD5;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_SHA1;
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
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_1;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_256;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_384;
import static org.wildfly.security.password.interfaces.ScramDigestPassword.ALGORITHM_SCRAM_SHA_512;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD2;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_1;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.SimpleDigestPassword.ALGORITHM_SIMPLE_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword.ALGORITHM_SUN_CRYPT_MD5;
import static org.wildfly.security.password.interfaces.SunUnixMD5CryptPassword.ALGORITHM_SUN_CRYPT_MD5_BARE_SALT;
import static org.wildfly.security.password.interfaces.UnixDESCryptPassword.ALGORITHM_CRYPT_DES;
import static org.wildfly.security.password.interfaces.UnixMD5CryptPassword.ALGORITHM_CRYPT_MD5;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_256;
import static org.wildfly.security.password.interfaces.UnixSHACryptPassword.ALGORITHM_CRYPT_SHA_512;

import java.lang.reflect.Constructor;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServerFactory;

import org.kohsuke.MetaInfServices;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.credential.store.impl.MapCredentialStore;
import org.wildfly.security.credential.store.impl.VaultCredentialStore;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.impl.ServerMechanismFactoryImpl;
import org.wildfly.security.key.RSAParameterSpiImpl;
import org.wildfly.security.key.RawSecretKeyFactory;
import org.wildfly.security.keystore.PasswordKeyStoreSpi;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl;
import org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl;
import org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl;
import org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl;
import org.wildfly.security.password.impl.PasswordFactorySpiImpl;
import org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl;
import org.wildfly.security.sasl.WildFlySasl;


/**
 * The {@link Provider} implementation covering all security services made available by Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(Provider.class)
public class WildFlyElytronProvider extends Provider {

    private static final long serialVersionUID = 1267015094996624988L;

    private static final String HTTP_SERVER_FACTORY_TYPE = HttpServerAuthenticationMechanismFactory.class.getSimpleName();

    private static final String SASL_CLIENT_FACTORY_TYPE = SaslClientFactory.class.getSimpleName();

    private static final String SASL_SERVER_FACTORY_TYPE = SaslServerFactory.class.getSimpleName();

    private static final String PASSWORD_FACTORY_TYPE = PasswordFactory.class.getSimpleName();

    private static final String ALG_PARAMS_TYPE = AlgorithmParameters.class.getSimpleName();

    /**
     * Default constructor for this security provider.
     */
    public WildFlyElytronProvider() {
        super("WildFlyElytron", 1.0, "WildFly Elytron Provider");

        putHttpAuthenticationMechanismImplementations();
        putKeyStoreImplementations();
        putPasswordImplementations();
        putSaslMechanismImplementations();
        putCredentialStoreProviderImplementations();
        putAlgorithmParametersImplementations();
        put("Alg.Alias.Data.OID.1.2.840.113549.1.7.1", "Data");
        putService(new Service(this, "SecretKeyFactory", "1.2.840.113549.1.7.1", RawSecretKeyFactory.class.getName(), Collections.emptyList(), Collections.emptyMap()));
    }

    private void putAlgorithmParametersImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, ALG_PARAMS_TYPE, "RSA", RSAParameterSpiImpl.class.getName(), emptyList, emptyMap));

        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_CRYPT_MD5, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SUN_CRYPT_MD5, IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SUN_CRYPT_MD5_BARE_SALT, IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_CRYPT_SHA_256, IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_CRYPT_SHA_512, IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_DIGEST_MD5, DigestPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_DIGEST_SHA, DigestPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_DIGEST_SHA_256, DigestPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_DIGEST_SHA_512, DigestPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_MD5, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_MD5, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_CRYPT_DES, SaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_BSD_CRYPT_DES, IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_BCRYPT, IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SCRAM_SHA_1, IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SCRAM_SHA_256, IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SCRAM_SHA_384, IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SCRAM_SHA_512, IteratedSaltedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_OTP_MD5, OneTimePasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_OTP_SHA1, OneTimePasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_MD5_DES, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_MD5_DES_CBC_PKCS5, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_MD5_3DES, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_MD5_3DES_CBC_PKCS5, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_DES_EDE, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_DES_EDE_CBC_PKCS5, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC2_40, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC2_40_CBC_PKCS5, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC2_128, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC2_128_CBC_PKCS5, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC4_40, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC4_40_ECB, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC4_128, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC4_128_ECB, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA1_AES_128, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA224_AES_128, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA384_AES_128, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA512_AES_128, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA1_AES_256, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA224_AES_256, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA384_AES_256, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA512_AES_256, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_PBKDF_HMAC_SHA1, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_PBKDF_HMAC_SHA224, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_PBKDF_HMAC_SHA256, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_PBKDF_HMAC_SHA384, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_PBKDF_HMAC_SHA512, MaskedPasswordAlgorithmParametersSpiImpl.class.getName(), emptyList, emptyMap));
    }

    private void putKeyStoreImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, "KeyStore", "PasswordFile", PasswordKeyStoreSpi.class.getName(), emptyList, emptyMap));
    }

    private void putHttpAuthenticationMechanismImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        ExceptionSupplier<Object, Exception> supplier = toSupplier(ServerMechanismFactoryImpl.class);
        putService(new SupplierService(this, HTTP_SERVER_FACTORY_TYPE, BASIC_NAME, ServerMechanismFactoryImpl.class.getName(), emptyList, emptyMap, supplier));
        putService(new SupplierService(this, HTTP_SERVER_FACTORY_TYPE, CLIENT_CERT_NAME, ServerMechanismFactoryImpl.class.getName(), emptyList, emptyMap, supplier));
        putService(new SupplierService(this, HTTP_SERVER_FACTORY_TYPE, DIGEST_NAME, ServerMechanismFactoryImpl.class.getName(), emptyList, emptyMap, supplier));
        putService(new SupplierService(this, HTTP_SERVER_FACTORY_TYPE, FORM_NAME, ServerMechanismFactoryImpl.class.getName(), emptyList, emptyMap, supplier));
        putService(new SupplierService(this, HTTP_SERVER_FACTORY_TYPE, SPNEGO_NAME, ServerMechanismFactoryImpl.class.getName(), emptyList, emptyMap, supplier));
        putService(new SupplierService(this, HTTP_SERVER_FACTORY_TYPE, BEARER_TOKEN, ServerMechanismFactoryImpl.class.getName(), emptyList, emptyMap, supplier));
    }

    private void putPasswordImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_CLEAR, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_CRYPT_MD5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SUN_CRYPT_MD5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SUN_CRYPT_MD5_BARE_SALT, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_CRYPT_SHA_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_CRYPT_SHA_512, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_MD2, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_MD5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_SHA_1, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_SHA_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_SHA_384, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_SHA_512, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_DIGEST_MD5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_DIGEST_SHA, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_DIGEST_SHA_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_DIGEST_SHA_512, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_MD5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_MD5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_CRYPT_DES, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_BSD_CRYPT_DES, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_BCRYPT, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SCRAM_SHA_1, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SCRAM_SHA_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SCRAM_SHA_384, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SCRAM_SHA_512, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_OTP_MD5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_OTP_SHA1, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_MD5_DES, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_MD5_DES_CBC_PKCS5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_MD5_3DES, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_MD5_3DES_CBC_PKCS5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_DES_EDE, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_DES_EDE_CBC_PKCS5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC2_40, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC2_40_CBC_PKCS5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC2_128, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC2_128_CBC_PKCS5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC4_40, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC4_40_ECB, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC4_128, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC4_128_ECB, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA1_AES_128, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA224_AES_128, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA256_AES_128, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA384_AES_128, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA512_AES_128, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA1_AES_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA224_AES_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA256_AES_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA384_AES_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA512_AES_256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_PBKDF_HMAC_SHA1, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_PBKDF_HMAC_SHA224, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_PBKDF_HMAC_SHA256, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_PBKDF_HMAC_SHA384, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_PBKDF_HMAC_SHA512, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
    }

    private void putSaslMechanismImplementations() {
        final List<String> noAliases = Collections.emptyList();
        final Map<String, String> noProperties = Collections.emptyMap();
        final ClassLoader myClassLoader = WildFlyElytronProvider.class.getClassLoader();
        final String myClassName = WildFlyElytronProvider.class.getName();
        final String myPackageWithDot = myClassName.substring(0, myClassName.lastIndexOf('.') + 1);
        final ServiceLoader<SaslClientFactory> clientLoader = ServiceLoader.load(SaslClientFactory.class, myClassLoader);
        final Iterator<SaslClientFactory> clientIterator = clientLoader.iterator();
        final Map<String, String> props = Collections.singletonMap(WildFlySasl.MECHANISM_QUERY_ALL, "true");
        for (;;) try {
            if (! clientIterator.hasNext()) break;
            final SaslClientFactory factory = clientIterator.next();
            if (factory.getClass().getClassLoader() != myClassLoader) {
                continue;
            }
            final String className = factory.getClass().getName();
            if (!className.startsWith(myPackageWithDot)) {
                continue;
            }
            final String[] names = factory.getMechanismNames(props);
            ExceptionSupplier<Object, Exception> supplier = toSupplier(factory.getClass());
            for (String name : names) {
                putService(new SupplierService(this, SASL_CLIENT_FACTORY_TYPE, name, className, noAliases, noProperties, supplier));
            }
        } catch (ServiceConfigurationError | RuntimeException ignored) {}
        final ServiceLoader<SaslServerFactory> serverLoader = ServiceLoader.load(SaslServerFactory.class, myClassLoader);
        final Iterator<SaslServerFactory> serverIterator = serverLoader.iterator();
        for (;;) try {
            if (!(serverIterator.hasNext())) break;
            final SaslServerFactory factory = serverIterator.next();
            if (factory.getClass().getClassLoader() != myClassLoader) {
                continue;
            }
            final String className = factory.getClass().getName();
            if (!className.startsWith(myPackageWithDot)) {
                continue;
            }
            final String[] names = factory.getMechanismNames(props);
            ExceptionSupplier<Object, Exception> supplier = toSupplier(factory.getClass());
            for (String name : names) {
                putService(new SupplierService(this, SASL_SERVER_FACTORY_TYPE, name, className, noAliases, noProperties, supplier));
            }
        } catch (ServiceConfigurationError | RuntimeException ignored) {}
    }

    private ExceptionSupplier<Object, Exception> toSupplier(final Class<?> clazz) {
        Constructor<?>[] constructors = clazz.getDeclaredConstructors();
        Constructor<?> found = null;
        for (Constructor<?> current : constructors) {
            Class<?>[] parameterTypes = current.getParameterTypes();
            if (parameterTypes.length == 1 && parameterTypes[0].isAssignableFrom(Provider.class)) {
                found = current;
                break;
            }
        }

        if (found != null) {
            final Constructor<?> constructor = found;
            return () -> constructor.newInstance(WildFlyElytronProvider.this);
        } else {
            return clazz::newInstance;
        }
    }

    private void putCredentialStoreProviderImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();
        putService(new Service(this, CredentialStore.CREDENTIAL_STORE_TYPE, KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE, KeyStoreCredentialStore.class.getName(), emptyList, emptyMap));
        putService(new Service(this, CredentialStore.CREDENTIAL_STORE_TYPE, VaultCredentialStore.VAULT_CREDENTIAL_STORE, VaultCredentialStore.class.getName(), emptyList, emptyMap));
        putService(new Service(this, CredentialStore.CREDENTIAL_STORE_TYPE, MapCredentialStore.MAP_CREDENTIAL_STORE, MapCredentialStore.class.getName(), emptyList, emptyMap));
    }

    static class SupplierService extends Service {

        private final ExceptionSupplier<Object, Exception> supplier;

        SupplierService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String,String> attributes, ExceptionSupplier<Object, Exception> supplier) {
            super(provider, type, algorithm, className, aliases, attributes);
            this.supplier = supplier;
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            try {
                return supplier.get();
            } catch (Exception e) {
                throw log.noSuchAlgorithmCreateService(getType(), getAlgorithm(), e);
            }
        }

    }

}
