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
import java.lang.ref.SoftReference;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.kohsuke.MetaInfServices;


/**
 * The {@link Provider} implementation covering all security services made available by Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
@MetaInfServices(Provider.class)
@Deprecated
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
        putService(new Service(this, "SecretKeyFactory", "1.2.840.113549.1.7.1", "org.wildfly.security.key.RawSecretKeyFactory", Collections.emptyList(), Collections.emptyMap()));
        putService(new Service(this, "MessageDigest", "SHA-512-256", "org.wildfly.security.digest.SHA512_256MessageDigest", Collections.emptyList(), Collections.emptyMap()));
    }

    private void putAlgorithmParametersImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

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
        WildFlyElytronBaseProvider.putMakedAlgorithmParametersImplementations(this::putService, this);
    }

    private void putKeyStoreImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, "KeyStore", "PasswordFile", "org.wildfly.security.keystore.PasswordKeyStoreSpi", emptyList, emptyMap));
    }

    private void putHttpAuthenticationMechanismImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "BASIC", "org.wildfly.security.http.basic.BasicMechanismFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "CLIENT_CERT", "org.wildfly.security.http.cert.ClientCertMechanismFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "DIGEST", "org.wildfly.security.http.digest.DigestMechanismFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "DIGEST-SHA-256", "org.wildfly.security.http.digest.DigestMechanismFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "DIGEST-SHA-512-256", "org.wildfly.security.http.digest.DigestMechanismFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "EXTERNAL", "org.wildfly.security.http.external.ExternalMechanismFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "FORM", "org.wildfly.security.http.form.FormMechanismFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "SPNEGO", "org.wildfly.security.http.spnego.SpnegoMechanismFactory", emptyList, emptyMap, true, true));

        putService(new ProviderService(this, HTTP_SERVER_FACTORY_TYPE, "BEARER_TOKEN", "org.wildfly.security.http.bearer.BearerMechanismFactory", emptyList, emptyMap, true, true));
    }

    private void putPasswordImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

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
        WildFlyElytronBaseProvider.putMakedPasswordImplementations(this::putService, this);
    }

    private void putSaslMechanismImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "ANONYMOUS",  "org.wildfly.security.sasl.anonymous.AnonymousServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-SHA-512",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-SHA-512-256",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-SHA-256",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-SHA-384",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-SHA",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "DIGEST-MD5",  "org.wildfly.security.sasl.digest.DigestServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "9798-U-RSA-SHA1-ENC",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "9798-M-RSA-SHA1-ENC",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "9798-U-DSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "9798-M-DSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "9798-U-ECDSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "9798-M-ECDSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "EXTERNAL",  "org.wildfly.security.sasl.external.ExternalSaslServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "GS2-KRB5-PLUS",  "org.wildfly.security.sasl.gs2.Gs2SaslServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "GS2-KRB5",  "org.wildfly.security.sasl.gs2.Gs2SaslServerFactory", emptyList, emptyMap, false, true));

        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "GSSAPI",  "org.wildfly.security.sasl.gssapi.GssapiServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "JBOSS-LOCAL-USER",  "org.wildfly.security.sasl.localuser.LocalUserServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "OAUTHBEARER",  "org.wildfly.security.sasl.oauth2.OAuth2SaslServerFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "OTP",  "org.wildfly.security.sasl.otp.OTPSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "PLAIN",  "org.wildfly.security.sasl.plain.PlainSaslServerFactory", emptyList, emptyMap, false, true));

        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-512-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-384-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-256-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-1-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-512",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-384",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-256",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "SCRAM-SHA-1",  "org.wildfly.security.sasl.scram.ScramSaslServerFactory", emptyList, emptyMap, true, true));

        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "ANONYMOUS",  "org.wildfly.security.sasl.anonymous.AnonymousClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-SHA-512",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-SHA-512-256",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-SHA-256",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-SHA-384",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-SHA",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "DIGEST-MD5",  "org.wildfly.security.sasl.digest.DigestClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "9798-U-RSA-SHA1-ENC",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "9798-M-RSA-SHA1-ENC",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "9798-U-DSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "9798-M-DSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "9798-U-ECDSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "9798-M-ECDSA-SHA1",  "org.wildfly.security.sasl.entity.EntitySaslClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "EXTERNAL",  "org.wildfly.security.sasl.external.ExternalSaslClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "GS2-KRB5-PLUS",  "org.wildfly.security.sasl.gs2.Gs2SaslClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "GS2-KRB5",  "org.wildfly.security.sasl.gs2.Gs2SaslClientFactory", emptyList, emptyMap, false, true));

        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "GSSAPI",  "org.wildfly.security.sasl.gssapi.GssapiClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "JBOSS-LOCAL-USER",  "org.wildfly.security.sasl.localuser.LocalUserClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "OAUTHBEARER",  "org.wildfly.security.sasl.oauth2.OAuth2SaslClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "OTP",  "org.wildfly.security.sasl.otp.OTPSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "PLAIN",  "org.wildfly.security.sasl.plain.PlainSaslClientFactory", emptyList, emptyMap, false, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-512-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-384-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-256-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-1-PLUS",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-512",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-384",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-256",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "SCRAM-SHA-1",  "org.wildfly.security.sasl.scram.ScramSaslClientFactory", emptyList, emptyMap, true, true));
    }

    private void putCredentialStoreProviderImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();
        putService(new Service(this, "CredentialStore", "KeyStoreCredentialStore", "org.wildfly.security.credential.store.impl.KeyStoreCredentialStore", emptyList, emptyMap));
        putService(new Service(this, "CredentialStore", "VaultCredentialStore", "org.wildfly.security.credential.store.impl.VaultCredentialStore", emptyList, emptyMap));
        putService(new Service(this, "CredentialStore", "MapCredentialStore", "org.wildfly.security.credential.store.impl.MapCredentialStore", emptyList, emptyMap));
        putService(new Service(this, "CredentialStore", "PropertiesCredentialStore", "org.wildfly.security.credential.store.impl.PropertiesCredentialStore", emptyList, emptyMap));
    }

    class ProviderService extends Service {

        private final boolean withProvider;
        private final boolean reUsable;
        private volatile Reference<Class<?>> implementationClassRef;
        private volatile Reference<Object> instance;

        ProviderService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String,String> attributes) {
            this(provider, type, algorithm, className, aliases, attributes, true, false);
        }

        ProviderService(Provider provider, String type, String algorithm, String className, List<String> aliases, Map<String,String> attributes, boolean withProvider,  boolean reUsable) {
            super(provider, type, algorithm, className, aliases, attributes);
            this.withProvider = withProvider;
            this.reUsable = reUsable;
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            if (reUsable) {
                Reference<Object> instance = this.instance;
                Object response;
                if (instance == null || (response = instance.get()) == null) {
                    synchronized(this) {
                        instance = this.instance;
                        if (instance == null || (response = instance.get()) == null) {
                            response = withProvider ? newInstance() : super.newInstance(constructorParameter);
                            this.instance = new SoftReference<Object>(response);
                        }
                    }
                }

                return response;
            }

            return withProvider ? newInstance() : super.newInstance(constructorParameter);
        }

        private Object newInstance() throws NoSuchAlgorithmException {
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
