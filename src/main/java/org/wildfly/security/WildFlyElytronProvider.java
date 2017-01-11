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
import static org.wildfly.security.http.HttpConstants.DIGEST_SHA256_NAME;
import static org.wildfly.security.http.HttpConstants.DIGEST_SHA512_256_NAME;
import static org.wildfly.security.http.HttpConstants.FORM_NAME;
import static org.wildfly.security.http.HttpConstants.SPNEGO_NAME;
import static org.wildfly.security.password.interfaces.BCryptPassword.ALGORITHM_BCRYPT;
import static org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_384;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_512;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_512_256;
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
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_SHA_256;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_SHA_384;
import static org.wildfly.security.password.interfaces.OneTimePassword.ALGORITHM_OTP_SHA_512;
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

import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.credential.store.impl.MapCredentialStore;
import org.wildfly.security.credential.store.impl.VaultCredentialStore;
import org.wildfly.security.sasl.util.SaslMechanismInformation;


/**
 * The {@link Provider} implementation covering all security services made available by Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(Provider.class)
public class WildFlyElytronProvider extends VersionedProvider {

    private static final long serialVersionUID = 1267015094996624988L;

    private static final String HTTP_SERVER_FACTORY_TYPE = "HttpServerAuthenticationMechanismFactory";

    private static final String SASL_CLIENT_FACTORY_TYPE = "SaslClientFactory";

    private static final String SASL_SERVER_FACTORY_TYPE = "SaslServerFactory";

    private static final String PASSWORD_FACTORY_TYPE = "PasswordFactory";

    private static final String ALG_PARAMS_TYPE = "AlgorithmParameters";

    /**
     * Default constructor for this security provider.
     */
    public WildFlyElytronProvider() {
        super("WildFlyElytron", "1.0", "WildFly Elytron Provider");

        putHttpAuthenticationMechanismImplementations();
        putKeyStoreImplementations();
        putPasswordImplementations();
        putSaslMechanismImplementations();
        putCredentialStoreProviderImplementations();
        putAlgorithmParametersImplementations();
        put("Alg.Alias.Data.OID.1.2.840.113549.1.7.1", "Data");
        putService(new Service(this, "SecretKeyFactory", "1.2.840.113549.1.7.1", "org.wildfly.security.key.RawSecretKeyFactory", Collections.emptyList(), Collections.emptyMap()));
        putService(new Service(this, "MessageDigest", "SHA-512-256", "org.wildfly.security.digest.SHA512_256MessageDigest", Collections.emptyList(), Collections.emptyMap()));
    }

    private void putAlgorithmParametersImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, ALG_PARAMS_TYPE, "RSA", "org.wildfly.security.key.RSAParameterSpiImpl", emptyList, emptyMap));

        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_CRYPT_MD5, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SUN_CRYPT_MD5, "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SUN_CRYPT_MD5_BARE_SALT, "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_CRYPT_SHA_256, "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_CRYPT_SHA_512, "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_DIGEST_MD5, "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_DIGEST_SHA, "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_DIGEST_SHA_256, "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_DIGEST_SHA_384, "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_DIGEST_SHA_512, "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_DIGEST_SHA_512_256, "org.wildfly.security.password.impl.DigestPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_MD5, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_MD5, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_CRYPT_DES, "org.wildfly.security.password.impl.SaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_BSD_CRYPT_DES, "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_BCRYPT, "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SCRAM_SHA_1, "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SCRAM_SHA_256, "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SCRAM_SHA_384, "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_SCRAM_SHA_512, "org.wildfly.security.password.impl.IteratedSaltedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_OTP_MD5, "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_OTP_SHA1, "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_OTP_SHA_256, "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_OTP_SHA_384, "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_OTP_SHA_512, "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_MD5_DES, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_MD5_DES_CBC_PKCS5, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_MD5_3DES, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_MD5_3DES_CBC_PKCS5, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_DES_EDE, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_DES_EDE_CBC_PKCS5, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC2_40, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC2_40_CBC_PKCS5, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC2_128, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC2_128_CBC_PKCS5, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC4_40, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC4_40_ECB, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC4_128, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_SHA1_RC4_128_ECB, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA1_AES_128, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA224_AES_128, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA384_AES_128, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA512_AES_128, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA1_AES_256, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA224_AES_256, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA384_AES_256, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, ALGORITHM_MASKED_HMAC_SHA512_AES_256, "org.wildfly.security.password.impl.MaskedPasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
    }

    private void putKeyStoreImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, "KeyStore", "PasswordFile", "org.wildfly.security.keystore.PasswordKeyStoreSpi", emptyList, emptyMap));
    }

    private void putHttpAuthenticationMechanismImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, BASIC_NAME, "org.wildfly.security.http.impl.ServerMechanismFactoryImpl", emptyList, emptyMap));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, CLIENT_CERT_NAME, "org.wildfly.security.http.impl.ServerMechanismFactoryImpl", emptyList, emptyMap));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, DIGEST_NAME, "org.wildfly.security.http.impl.ServerMechanismFactoryImpl", emptyList, emptyMap));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, DIGEST_SHA256_NAME, "org.wildfly.security.http.impl.ServerMechanismFactoryImpl", emptyList, emptyMap));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, DIGEST_SHA512_256_NAME, "org.wildfly.security.http.impl.ServerMechanismFactoryImpl", emptyList, emptyMap));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, FORM_NAME, "org.wildfly.security.http.impl.ServerMechanismFactoryImpl", emptyList, emptyMap));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, SPNEGO_NAME, "org.wildfly.security.http.impl.ServerMechanismFactoryImpl", emptyList, emptyMap));

        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, BEARER_TOKEN, "org.wildfly.security.http.impl.ServerMechanismFactoryImpl", emptyList, emptyMap));
    }

    private void putPasswordImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_CLEAR, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_CRYPT_MD5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SUN_CRYPT_MD5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SUN_CRYPT_MD5_BARE_SALT, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_CRYPT_SHA_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_CRYPT_SHA_512, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_MD2, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_MD5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_SHA_1, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_SHA_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_SHA_384, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SIMPLE_DIGEST_SHA_512, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_DIGEST_MD5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_DIGEST_SHA, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_DIGEST_SHA_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_DIGEST_SHA_384, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_DIGEST_SHA_512, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_DIGEST_SHA_512_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_MD5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_1, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_384, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_PASSWORD_SALT_DIGEST_SHA_512, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_MD5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_1, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_384, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SALT_PASSWORD_DIGEST_SHA_512, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_CRYPT_DES, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_BSD_CRYPT_DES, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_BCRYPT, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SCRAM_SHA_1, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SCRAM_SHA_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SCRAM_SHA_384, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_SCRAM_SHA_512, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_OTP_MD5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_OTP_SHA1, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_OTP_SHA_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_OTP_SHA_384, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_OTP_SHA_512, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_MD5_DES, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_MD5_DES_CBC_PKCS5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_MD5_3DES, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_MD5_3DES_CBC_PKCS5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_DES_EDE, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_DES_EDE_CBC_PKCS5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC2_40, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC2_40_CBC_PKCS5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC2_128, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC2_128_CBC_PKCS5, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC4_40, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC4_40_ECB, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC4_128, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_SHA1_RC4_128_ECB, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA1_AES_128, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA224_AES_128, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA256_AES_128, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA384_AES_128, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA512_AES_128, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA1_AES_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA224_AES_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA256_AES_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA384_AES_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_MASKED_HMAC_SHA512_AES_256, "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
    }

    private void putSaslMechanismImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.ANONYMOUS,  "org.wildfly.security.sasl.anonymous.AnonymousServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_SHA_512,  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_SHA_512_256,  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_SHA_256,  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_SHA_384,  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_SHA,  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_MD5,  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC,  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC,  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_U_DSA_SHA1,  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_M_DSA_SHA1,  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_U_ECDSA_SHA1,  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_M_ECDSA_SHA1,  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.EXTERNAL,  "org.wildfly.security.sasl.external.ExternalSaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "GS2-KRB5-PLUS",  "org.wildfly.security.sasl.gs2.Gs2SaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "GS2-KRB5",  "org.wildfly.security.sasl.gs2.Gs2SaslServerFactory", emptyList, emptyMap));

        //final Map<String, String> props = Collections.singletonMap(WildFlySasl.MECHANISM_QUERY_ALL, "true");
        //SaslServerFactory gs2 = new Gs2SaslServerFactory();
        //for (String name : gs2.getMechanismNames(props)) {
        //    putService(new Service(this, SASL_SERVER_FACTORY_TYPE, name,  "org.wildfly.security.sasl.gs2.Gs2SaslServerFactory", emptyList, emptyMap));
        //}

        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.GSSAPI,  "org.wildfly.security.sasl.gssapi.GssapiServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, "JBOSS-LOCAL-USER",  "org.wildfly.security.sasl.localuser.LocalUserServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.OAUTHBEARER,  "org.wildfly.security.sasl.oauth2.OAuth2SaslServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.OTP,  "org.wildfly.security.sasl.otp.OTPSaslServerFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.PLAIN,  "org.wildfly.security.sasl.plain.PlainSaslServerFactory", emptyList, emptyMap));

        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_512_PLUS,  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_384_PLUS,  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_256_PLUS,  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS,  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_512,  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_384,  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_256,  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_1,  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap));

        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.ANONYMOUS,  "org.wildfly.security.sasl.anonymous.AnonymousClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_SHA_512,  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_SHA_512_256,  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_SHA_256,  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_SHA_384,  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_SHA,  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.DIGEST_MD5,  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_U_RSA_SHA1_ENC,  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_M_RSA_SHA1_ENC,  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_U_DSA_SHA1,  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_M_DSA_SHA1,  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_U_ECDSA_SHA1,  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.IEC_ISO_9798_M_ECDSA_SHA1,  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.EXTERNAL,  "org.wildfly.security.sasl.external.ExternalSaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "GS2-KRB5-PLUS",  "org.wildfly.security.sasl.gs2.Gs2SaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "GS2-KRB5",  "org.wildfly.security.sasl.gs2.Gs2SaslClientFactory", emptyList, emptyMap));

        //SaslClientFactory gs2Client = new Gs2SaslClientFactory();
        //for (String name : gs2Client.getMechanismNames(props)) {
        //    putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, name,  "org.wildfly.security.sasl.gs2.Gs2SaslClientFactory", emptyList, emptyMap));
        //}

        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.GSSAPI,  "org.wildfly.security.sasl.gssapi.GssapiClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, "JBOSS-LOCAL-USER",  "org.wildfly.security.sasl.localuser.LocalUserClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.OAUTHBEARER,  "org.wildfly.security.sasl.oauth2.OAuth2SaslClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.OTP,  "org.wildfly.security.sasl.otp.OTPSaslClientFactory", emptyList, emptyMap));
        putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.PLAIN,  "org.wildfly.security.sasl.plain.PlainSaslClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_512_PLUS,  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_384_PLUS,  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_256_PLUS,  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_1_PLUS,  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_512,  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_384,  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_256,  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, SaslMechanismInformation.Names.SCRAM_SHA_1,  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap));
    }

    private void putCredentialStoreProviderImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();
        putService(new Service(this, CredentialStore.CREDENTIAL_STORE_TYPE, KeyStoreCredentialStore.KEY_STORE_CREDENTIAL_STORE, "org.wildfly.security.credential.store.impl.KeyStoreCredentialStore", emptyList, emptyMap));
        putService(new Service(this, CredentialStore.CREDENTIAL_STORE_TYPE, VaultCredentialStore.VAULT_CREDENTIAL_STORE, "org.wildfly.security.credential.store.impl.VaultCredentialStore", emptyList, emptyMap));
        putService(new Service(this, CredentialStore.CREDENTIAL_STORE_TYPE, MapCredentialStore.MAP_CREDENTIAL_STORE, "org.wildfly.security.credential.store.impl.MapCredentialStore", emptyList, emptyMap));
    }

    class ProviderService extends Service {

        private volatile Reference<Class<?>> implementationClassRef;

        ProviderService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String,String> attributes) {
            super(provider, type, algorithm, className, aliases, attributes);
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            Class<?> implementationClass = getImplementationClass();

            try {
                Constructor<?> constructor = implementationClass.getConstructor(Provider.class);
                return constructor.newInstance(WildFlyElytronProvider.this);
            } catch (Exception e) {
                throw log.noSuchAlgorithmCreateService(getType(), getAlgorithm(), e);
            }
        }

        private Class<?> getImplementationClass() throws NoSuchAlgorithmException {
            Reference<Class<?>> implementationClassRef = this.implementationClassRef;
            Class<?> implementationClass = implementationClassRef != null ? implementationClassRef.get() : null;
            if (implementationClass == null) {
                ClassLoader classLoader = WildFlyElytronProvider.class.getClassLoader();
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
