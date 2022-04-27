/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.auth.client;

import org.kohsuke.MetaInfServices;
import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.security.auth.client._private.ElytronMessages;
import static org.wildfly.security.auth.client._private.ElytronMessages.log;

import java.io.FileNotFoundException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.List;
import java.util.Map;

/**
 * Provider that loads Elytron client configuration and provides default SSLContext which can be returned with SSLContext.getDefault() call.
 * Default SSLContext is the configured SSL context that does not have any specific rule when it should be used, so it matches all rules.
 */
@MetaInfServices(value = Provider.class)
public final class WildFlyElytronClientDefaultSSLContextProvider extends Provider {

    private static final long serialVersionUID = -8281186085283177185L;
    public static final String ELYTRON_CLIENT_DEFAULT_SSL_CONTEXT_PROVIDER_NAME = "WildFlyElytronClientDefaultSSLContextProvider";

    /**
     * WildFlyElytronClientDefaultSSLContextProvider that uses Elytron client configuration found on classpath.
     */
    public WildFlyElytronClientDefaultSSLContextProvider() {
        this(null);
    }

    /**
     * WildFlyElytronClientDefaultSSLContextProvider that uses Elytron client configuration found on provided path.
     *
     * @param configPath path to Elytron client configuration path
     */
    public WildFlyElytronClientDefaultSSLContextProvider(String configPath) {
        super(ELYTRON_CLIENT_DEFAULT_SSL_CONTEXT_PROVIDER_NAME, 1.0, "Elytron client provider for default SSLContext");
        putService(new ClientSSLContextProviderService(this, "SSLContext", "Default", "org.wildfly.security.auth.client.provider.WildFlyElytronClientDefaultSSLContextSpi", null, null, configPath));
    }

    /**
     * Configures WildFlyElytronClientDefaultSSLContextProvider with the provided Elytron client configuration path
     *
     * @param configPath path to Elytron client configuration path
     */
    public Provider configure(String configPath) {
        Service service = getService("SSLContext", "Default");
        if (service instanceof ClientSSLContextProviderService) {
            ((ClientSSLContextProviderService) getService("SSLContext", "Default")).setConfigPath(configPath);
        } else {
            putService(new ClientSSLContextProviderService(this, "SSLContext", "Default", "org.wildfly.security.auth.client.provider.WildFlyElytronClientDefaultSSLContextSpi", null, null, configPath));
        }
        return this;
    }

    private static final class ClientSSLContextProviderService extends Provider.Service {
        String configPath;
        // this is Integer because we need to count the number of times entered
        // entered.get()==2 means we requested this provider second time, creating a loop, so we throw an sslContextForSecurityProviderCreatesInfiniteLoop exception
        // AuthenticationContextConfigurationClient receives sslContextForSecurityProviderCreatesInfiniteLoop exception during obtaining of default SSL context and will therefore request default SSL context from other providers
        // after default SSL context from other provider is returned, we must check the entered variable again and throw an exception to inform users that this provider was unsuccessful because of invalid configuration
        private final ThreadLocal<Integer> entered = new ThreadLocal<>();

        ClientSSLContextProviderService(Provider provider, String type, String algorithm, String className, List<String> aliases,
                                        Map<String, String> attributes, String configPath) {
            super(provider, type, algorithm, className, aliases, attributes);
            this.configPath = configPath;
        }

        public void setConfigPath(String configPath) {
            this.configPath = configPath;
        }

        /**
         * There is a risk of looping if the Elytron client configuration is invalid.
         * Loop will happen when Elytron client provider has configured default SSL context to be SSLContext::getDefault.
         * Entered variable counts the number of entrances in order to avoid this loop.
         * When it is equal or higher than 2 the NoSuchAlgorithmException will be thrown.
         * When this exception is encountered, JVM tries to obtain default SSLContext from providers of lower priority
         * and returns it to Elytron client as the default SSL context.
         * Since we do not want to wrap the SSL context from other provider with this provider, we will throw an exception again
         * which makes JVM escape this provider entirely and continue in the list of other providers.
         */
        @Override
        public Object newInstance(Object ignored) throws NoSuchAlgorithmException {
            Integer enteredCountTmp = entered.get();
            entered.set(enteredCountTmp == null ? 1 : enteredCountTmp + 1);
            if (entered.get() >= 2) {
                // we do not do clean up entered variable here because it is needed for the second check and possible throwing of second exception below
                throw ElytronMessages.log.sslContextForSecurityProviderCreatesInfiniteLoop();
            }

            WildFlyElytronClientDefaultSSLContextSpi sslContext;
            try {
                if (configPath == null) {
                    sslContext = new WildFlyElytronClientDefaultSSLContextSpi(AuthenticationContext.captureCurrent());
                } else {
                    sslContext = new WildFlyElytronClientDefaultSSLContextSpi(this.configPath);
                }
                // if we had an exception previously, then default SSLContext was still returned from other security provider of lower priority in
                // AuthenticationContextConfigurationClient#getSSLContextFactory method.
                // Since we do not want to wrap SSLContext from other provider with this provider, we need to check entered variable again
                // and throw an exception which makes JVM ignore this provider and probe other providers again
                if (entered.get() >= 2) {
                    throw ElytronMessages.log.sslContextForSecurityProviderCreatesInfiniteLoop();
                }
            } catch (ConfigXMLParseException | GeneralSecurityException e) {
                if (e.getCause() instanceof FileNotFoundException) {
                    throw log.clientConfigurationFileNotFound();
                }
                throw log.couldNotObtainClientDefaultSSLContext();
            } finally {
                entered.remove();
            }
            return sslContext;
        }
    }
}
