package org.wildfly.security.auth.client;

import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.security.auth.client._private.ElytronMessages;

import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.List;
import java.util.Map;

public final class ClientSSLContextProvider extends Provider {

    public ClientSSLContextProvider() {
        this(null);
    }

    public ClientSSLContextProvider(String configPath) {
        super("ClientSSLContextProvider", 1.0, "Elytron client provider for default SSLContext");
        putService(new ClientSSLContextProviderService(this, "SSLContext", "Default", "org.wildfly.security.auth.client.DefaultSSLContextSpi", null, null, configPath));
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

        @Override
        public Object newInstance(Object ignored) throws NoSuchAlgorithmException {
            Integer enteredCountTmp = entered.get();
            entered.set(enteredCountTmp == null ? 1 : enteredCountTmp + 1);
            if (entered.get() >= 2) {
                // we do not do clean up entered variable here because it is needed for the second check and possible throwing of second exception below
                throw new NoSuchAlgorithmException(ElytronMessages.log.sslContextForSecurityProviderCreatesInfiniteLoop());
            }

            DefaultSSLContextSpi sslContext;
            try {
                if (configPath == null) {
                    sslContext = new DefaultSSLContextSpi(AuthenticationContext.captureCurrent());
                } else {
                    sslContext = new DefaultSSLContextSpi(this.configPath);
                }
                // if we had an exception previously, then default ssl context was still returned from other security provider
                // which is why we need to check entered variable again
                if (entered.get() >= 2) {
                    throw new NoSuchAlgorithmException(ElytronMessages.log.sslContextForSecurityProviderCreatesInfiniteLoop());
                }
            } catch (GeneralSecurityException | URISyntaxException | ConfigXMLParseException e) {
                throw new NoSuchAlgorithmException(e);
            } finally {
                entered.remove();
            }
            return sslContext;
        }
    }
}
