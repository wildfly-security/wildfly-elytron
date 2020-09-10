/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.provider.util;

import org.wildfly.security.provider.util._private.ElytronMessages;

import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.ArrayList;
import java.util.function.Supplier;

import static java.lang.System.getSecurityManager;
import static org.wildfly.security.provider.util.ProviderUtil.INSTALLED_PROVIDERS;

/**
 * Utility class to obtain Supplier with providers available on the classpath.
 */
public class ProviderFactory {

    private static String[] elytronProviderClassNames = new String[]{
            "org.wildfly.security.password.WildFlyElytronPasswordProvider",
            "org.wildfly.security.credential.store.WildFlyElytronCredentialStoreProvider",
            "org.wildfly.security.digest.WildFlyElytronDigestProvider",
            "org.wildfly.security.http.basic.WildFlyElytronHttpBasicProvider",
            "org.wildfly.security.http.bearer.WildFlyElytronHttpBearerProvider",
            "org.wildfly.security.http.cert.WildFlyElytronHttpClientCertProvider",
            "org.wildfly.security.http.digest.WildFlyElytronHttpDigestProvider",
            "org.wildfly.security.http.external.WildFlyElytronHttpExternalProvider",
            "org.wildfly.security.http.form.WildFlyElytronHttpFormProvider",
            "org.wildfly.security.http.spnego.WildFlyElytronHttpSpnegoProvider",
            "org.wildfly.security.key.WildFlyElytronKeyProvider",
            "org.wildfly.security.keystore.WildFlyElytronKeyStoreProvider",
            "org.wildfly.security.sasl.anonymous.WildFlyElytronSaslAnonymousProvider",
            "org.wildfly.security.sasl.digest.WildFlyElytronSaslDigestProvider",
            "org.wildfly.security.sasl.entity.WildFlyElytronSaslEntityProvider",
            "org.wildfly.security.sasl.external.WildFlyElytronSaslExternalProvider",
            "org.wildfly.security.sasl.gs2.WildFlyElytronSaslGs2Provider",
            "org.wildfly.security.sasl.gssapi.WildFlyElytronSaslGssapiProvider",
            "org.wildfly.security.sasl.localuser.WildFlyElytronSaslLocalUserProvider",
            "org.wildfly.security.sasl.oauth2.WildFlyElytronSaslOAuth2Provider",
            "org.wildfly.security.sasl.otp.WildFlyElytronSaslOTPProvider",
            "org.wildfly.security.sasl.plain.WildFlyElytronSaslPlainProvider",
            "org.wildfly.security.sasl.scram.WildFlyElytronSaslScramProvider"
    };

    static Class[] getWildflyElytronProviderClasses(ClassLoader classLoader) {
        ArrayList<Class> providers = new ArrayList<>();
        for (String elytronProviderClassName : elytronProviderClassNames) {
            try {
                providers.add(Class.forName(elytronProviderClassName, false, classLoader));
            } catch (ClassNotFoundException e) {
                ElytronMessages.log.debug("Provider " + elytronProviderClassName + " not found.");
            }
        }
        return providers.toArray(new Class[0]);
    }

    private static Provider[] getWildflyElytronProviders(ClassLoader classLoader) {
        ArrayList<Provider> providers = new ArrayList<>();
        for (String elytronProviderClassName : elytronProviderClassNames) {
            try {
                providers.add((Provider) Class.forName(elytronProviderClassName, false, classLoader)
                        .getMethod("getInstance").invoke(null));
            } catch (IllegalAccessException | ClassNotFoundException | NoSuchMethodException | InvocationTargetException e) {
                ElytronMessages.log.debug("Provider " + elytronProviderClassName + " not found.");
            }
        }
        return providers.toArray(new Provider[0]);
    }

    public static Supplier<Provider[]> getElytronProviderSupplier(ClassLoader classLoader) {
        return ProviderUtil.aggregate(() -> getSecurityManager() != null ?
                AccessController.doPrivileged((PrivilegedAction<Provider[]>) () -> getWildflyElytronProviders(classLoader)) :
                getWildflyElytronProviders(classLoader), getSecurityManager() != null ?
                AccessController.doPrivileged((PrivilegedAction<ProviderServiceLoaderSupplier>) () ->
                        new ProviderServiceLoaderSupplier(classLoader, true)) :
                new ProviderServiceLoaderSupplier(classLoader, true));
    }

    public static Supplier<Provider[]> getDefaultProviderSupplier(ClassLoader classLoader) {
        return ProviderUtil.aggregate(getElytronProviderSupplier(classLoader), INSTALLED_PROVIDERS);
    }
}
