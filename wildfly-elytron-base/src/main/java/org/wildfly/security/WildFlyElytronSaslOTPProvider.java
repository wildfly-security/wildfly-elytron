/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

import java.security.Provider;

import org.kohsuke.MetaInfServices;

/**
 * Provider for the OTP SASL authentication mechanism.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
@MetaInfServices(Provider.class)
public final class WildFlyElytronSaslOTPProvider extends WildFlyElytronBaseProvider {

    private static final long serialVersionUID = 8591483864968428336L;
    private static WildFlyElytronSaslOTPProvider INSTANCE = new WildFlyElytronSaslOTPProvider();

    /**
     * Construct a new instance.
     */
    private WildFlyElytronSaslOTPProvider() {
        super("WildFlyElytronSaslOTPProvider", "1.0", "WildFly Elytron SASL OTP Provider");
        putService(new ProviderService(this, SASL_SERVER_FACTORY_TYPE, "OTP",  "org.wildfly.security.sasl.otp.OTPSaslServerFactory", emptyList, emptyMap));
        putService(new ProviderService(this, SASL_CLIENT_FACTORY_TYPE, "OTP",  "org.wildfly.security.sasl.otp.OTPSaslClientFactory", emptyList, emptyMap));

        putService(new Service(this, PASSWORD_FACTORY_TYPE, "otp-md5", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "otp-sha1", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "otp-sha256", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "otp-sha384", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, PASSWORD_FACTORY_TYPE, "otp-sha512", "org.wildfly.security.password.impl.PasswordFactorySpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "otp-md5", "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "otp-sha1", "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "otp-sha256", "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "otp-sha384", "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
        putService(new Service(this, ALG_PARAMS_TYPE, "otp-sha512", "org.wildfly.security.password.impl.OneTimePasswordAlgorithmParametersSpiImpl", emptyList, emptyMap));
    }

    /**
     * Get the OTP SASL authentication mechanism provider instance.
     *
     * @return the OTP SASL authentication mechanism provider instance
     */
    public static WildFlyElytronSaslOTPProvider getInstance() {
        return INSTANCE;
    }

}
