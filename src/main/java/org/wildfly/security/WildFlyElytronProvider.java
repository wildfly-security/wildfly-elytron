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

import static org.wildfly.security.credential.external.ExternalCredential.EXTERNAL_CREDENTIAL_PROVIDER_TYPE;
import static org.wildfly.security.credential.external.impl.ExternalCredentialProviderName.CLASS;
import static org.wildfly.security.credential.external.impl.ExternalCredentialProviderName.CMD;
import static org.wildfly.security.credential.external.impl.ExternalCredentialProviderName.EXT;
import static org.wildfly.security.credential.external.impl.ExternalCredentialProviderName.MASKED;
import static org.wildfly.security.http.HttpConstants.BASIC_NAME;
import static org.wildfly.security.password.interfaces.BCryptPassword.ALGORITHM_BCRYPT;
import static org.wildfly.security.password.interfaces.BSDUnixDESCryptPassword.ALGORITHM_BSD_CRYPT_DES;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_MD5;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_256;
import static org.wildfly.security.password.interfaces.DigestPassword.ALGORITHM_DIGEST_SHA_512;
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

import java.security.Provider;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslServerFactory;

import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.impl.ServerMechanismFactoryImpl;
import org.wildfly.security.keystore.PasswordKeyStoreSpi;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.impl.PasswordFactorySpiImpl;
import org.wildfly.security.sasl.WildFlySasl;


/**
 * The {@link Provider} implementation covering all security services made available by Elytron.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class WildFlyElytronProvider extends Provider {

    private static final long serialVersionUID = 1267015094996624988L;

    private static final String HTTP_SERVER_FACTORY_TYPE = HttpServerAuthenticationMechanismFactory.class.getSimpleName();

    private static final String SASL_CLIENT_FACTORY_TYPE = SaslClientFactory.class.getSimpleName();

    private static final String SASL_SERVER_FACTORY_TYPE = SaslServerFactory.class.getSimpleName();

    private static final String PASSWORD_FACTORY_TYPE = PasswordFactory.class.getSimpleName();

    /**
     * Default constructor for this security provider.
     */
    public WildFlyElytronProvider() {
        super("WildFlyElytron", 1.0, "WildFly Elytron Provider");

        putHttpAuthenticationMechanismImplementations();
        putKeyStoreImplementations();
        putPasswordImplementations();
        putSaslMechanismImplementations();
        putExternalCredentialProviderImplementations();
    }

    private void putKeyStoreImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, "KeyStore", "PasswordFile", PasswordKeyStoreSpi.class.getName(), emptyList, emptyMap));
    }

    private void putHttpAuthenticationMechanismImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, HTTP_SERVER_FACTORY_TYPE, BASIC_NAME, ServerMechanismFactoryImpl.class.getName(), emptyList, emptyMap));
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
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_OTP_MD5, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, ALGORITHM_OTP_SHA1, PasswordFactorySpiImpl.class.getName(), emptyList, emptyMap));
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
            for (String name : names) {
                putService(new Service(this, SASL_CLIENT_FACTORY_TYPE, name, className, noAliases, noProperties));
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
            for (String name : names) {
                putService(new Service(this, SASL_SERVER_FACTORY_TYPE, name, className, noAliases, noProperties));
            }
        } catch (ServiceConfigurationError | RuntimeException ignored) {}
    }

    private void putExternalCredentialProviderImplementations() {
        final List<String> emptyList = Collections.emptyList();
        final Map<String, String> emptyMap = Collections.emptyMap();

        putService(new Service(this, EXTERNAL_CREDENTIAL_PROVIDER_TYPE, CLASS.way(), CLASS.get(), emptyList, emptyMap));
        putService(new Service(this, EXTERNAL_CREDENTIAL_PROVIDER_TYPE, EXT.way(), EXT.get(), emptyList, emptyMap));
        putService(new Service(this, EXTERNAL_CREDENTIAL_PROVIDER_TYPE, CMD.way(), CMD.get(), emptyList, emptyMap));
        putService(new Service(this, EXTERNAL_CREDENTIAL_PROVIDER_TYPE, MASKED.way(), MASKED.get(), emptyList, emptyMap));
    }

}
