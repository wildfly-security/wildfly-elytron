/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.security.AccessControlContext;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.util.Collection;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.permission.ElytronPermission;

/**
 * A client for consuming authentication context configurations.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class AuthenticationContextConfigurationClient {

    private static final ElytronPermission CREATE_PERMISSION = new ElytronPermission("createAuthenticationContextConfigurationClient");

    /**
     * A reusable privileged action to create a new configuration client.
     */
    public static final PrivilegedAction<AuthenticationContextConfigurationClient> ACTION = AuthenticationContextConfigurationClient::new;

    /**
     * Construct a new instance.  Requires the {@code createAuthenticationContextConfigurationClient} {@link ElytronPermission}.
     *
     * @throws SecurityException if the caller does not have permission to instantiate this class
     */
    public AuthenticationContextConfigurationClient() throws SecurityException {
        final SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(CREATE_PERMISSION);
        }
    }

    /**
     * Get the authentication configuration which matches the given URI, or {@link AuthenticationConfiguration#EMPTY} if there is none.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @return the matching configuration
     */
    public AuthenticationConfiguration getAuthenticationConfiguration(URI uri, AuthenticationContext authenticationContext) {
        return getAuthenticationConfiguration(uri, authenticationContext, -1);
    }

    /**
     * Get the authentication configuration which matches the given URI, or {@link AuthenticationConfiguration#EMPTY} if there is none, setting
     * a default protocol port.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @param protocolDefaultPort the protocol-default port
     * @return the matching configuration
     */
    public AuthenticationConfiguration getAuthenticationConfiguration(URI uri, AuthenticationContext authenticationContext, int protocolDefaultPort) {
        return getAuthenticationConfiguration(uri, authenticationContext, protocolDefaultPort, null, null);
    }

    /**
     * Get the authentication configuration which matches the given URI and type, or {@link AuthenticationConfiguration#EMPTY} if there is none, setting
     * a default protocol port.  The user name, host, port, and protocol from the URI are copied into the configuration when the configuration does not already
     * establish values for those fields.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @param protocolDefaultPort the protocol-default port
     * @param abstractType the abstract type (may be {@code null})
     * @param abstractTypeAuthority the abstract type authority (may be {@code null})
     * @return the matching configuration
     */
    public AuthenticationConfiguration getAuthenticationConfiguration(URI uri, AuthenticationContext authenticationContext, int protocolDefaultPort, String abstractType, String abstractTypeAuthority) {
        Assert.checkNotNullParam("uri", uri);
        Assert.checkNotNullParam("authenticationContext", authenticationContext);
        final RuleNode<AuthenticationConfiguration> node = authenticationContext.authRuleMatching(uri, abstractType, abstractTypeAuthority);
        AuthenticationConfiguration configuration = node != null ? node.getConfiguration() : AuthenticationConfiguration.empty();
        configuration = initializeConfiguration(uri, configuration);
        configuration = establishOverrides(uri, protocolDefaultPort, configuration);

        log.tracef("getAuthenticationConfiguration uri=%s, protocolDefaultPort=%d, abstractType=%s, abstractTypeAuthority=%s, MatchRule=[%s], AuthenticationConfiguration=[%s]",
                uri, protocolDefaultPort, abstractType, abstractTypeAuthority, node != null ? node.rule : null, configuration);

        return configuration;
    }

    /**
     * Get the authentication configuration which matches the given URI and type, or {@link AuthenticationConfiguration#EMPTY} if there is none.
     * The user name from the URI is copied into the configuration if the configuration does not already establish a value for that field.
     * No host, port, or protocol information is copied to the resultant configuration from the URI.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @param abstractType the abstract type (may be {@code null})
     * @param abstractTypeAuthority the abstract type authority (may be {@code null})
     * @return the matching configuration
     */
    public AuthenticationConfiguration getAuthenticationConfigurationNoOverrides(URI uri, AuthenticationContext authenticationContext, String abstractType, String abstractTypeAuthority) {
        Assert.checkNotNullParam("uri", uri);
        Assert.checkNotNullParam("authenticationContext", authenticationContext);
        final RuleNode<AuthenticationConfiguration> node = authenticationContext.authRuleMatching(uri, abstractType, abstractTypeAuthority);
        AuthenticationConfiguration configuration = node != null ? node.getConfiguration() : AuthenticationConfiguration.empty();
        configuration = initializeConfiguration(uri, configuration);

        log.tracef("getAuthenticationConfiguration uri=%s, abstractType=%s, abstractTypeAuthority=%s, MatchRule=[%s], AuthenticationConfiguration=[%s]",
                uri, abstractType, abstractTypeAuthority, node != null ? node.rule : null, configuration);

        return configuration;
    }

    @SuppressWarnings("deprecation")
    private static AuthenticationConfiguration establishOverrides(final URI uri, final int protocolDefaultPort, AuthenticationConfiguration configuration) {
        final String uriHost = uri.getHost();
        if (uriHost != null && configuration.setHost == null) {
            configuration = configuration.useHost(uriHost);
        }
        int port = uri.getPort();
        if (port == -1) port = protocolDefaultPort;
        if (port != -1 && configuration.setPort == -1) {
            // use the URI port in this configuration
            configuration = configuration.usePort(port);
        }
        final String scheme = uri.getScheme();
        if (scheme != null && configuration.setProtocol == null) {
            configuration = configuration.useProtocol(scheme);
        }
        return configuration;
    }

    private static AuthenticationConfiguration initializeConfiguration(final URI uri, AuthenticationConfiguration configuration) {
        final SecurityDomain authenticationNameForwardSecurityDomain = configuration.authenticationNameForwardSecurityDomain;
        final String userInfo = uri.getUserInfo();
        if (userInfo != null && configuration.getPrincipal() == AnonymousPrincipal.getInstance() && authenticationNameForwardSecurityDomain == null) {
            configuration = configuration.useName(userInfo);
        }
        // capture forwards
        if (authenticationNameForwardSecurityDomain != null) {
            configuration = configuration.useForwardedAuthenticationIdentity(null).usePrincipal(authenticationNameForwardSecurityDomain.getCurrentSecurityIdentity().getPrincipal());
        }
        final SecurityDomain authenticationCredentialsForwardSecurityDomain = configuration.authenticationCredentialsForwardSecurityDomain;
        if (authenticationCredentialsForwardSecurityDomain != null) {
            final SecurityIdentity securityIdentity = authenticationCredentialsForwardSecurityDomain.getCurrentSecurityIdentity();
            final IdentityCredentials privateCredentials = securityIdentity.getPrivateCredentials();
            final IdentityCredentials publicCredentials = securityIdentity.getPublicCredentials();
            // private overrides public
            configuration = configuration.useForwardedAuthenticationCredentials(null).useCredentials(publicCredentials.with(privateCredentials));
        }
        final SecurityDomain authorizationNameForwardSecurityDomain = configuration.authorizationNameForwardSecurityDomain;
        if (authorizationNameForwardSecurityDomain != null) {
            configuration = configuration.useForwardedAuthorizationIdentity(null).useAuthorizationPrincipal(authorizationNameForwardSecurityDomain.getCurrentSecurityIdentity().getPrincipal());
        }
        final boolean captureAccessControlContext = Boolean.parseBoolean(System.getProperty("wildfly.elytron.capture.access.control.context", "true"));
        if (captureAccessControlContext) {
            final AccessControlContext capturedContext = configuration.getCapturedContext();
            if (capturedContext == null) {
                configuration = configuration.withCapturedAccessControlContext();
            }
        }
        return configuration;
    }

    /**
     * Get the SSL context which matches the given URI, or {@link SSLContext#getDefault()} if there is none.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @return the matching SSL context
     */
    public SSLContext getSSLContext(URI uri, AuthenticationContext authenticationContext) throws GeneralSecurityException {
        return getSSLContext(uri, authenticationContext, null, null);
    }

    /**
     * Get the SSL context which matches the given URI and type, or {@link SSLContext#getDefault()} if there is none.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @param abstractType the abstract type (may be {@code null})
     * @param abstractTypeAuthority the abstract type authority (may be {@code null})
     * @return the matching SSL context
     */
    public SSLContext getSSLContext(URI uri, AuthenticationContext authenticationContext, String abstractType, String abstractTypeAuthority) throws GeneralSecurityException {
        return getSSLContextFactory(uri, authenticationContext, abstractType, abstractTypeAuthority).create();
    }

    /**
     * Get the SSL context factory which matches the given URI and type, or {@link SSLContext#getDefault()} if there is none.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @param abstractType the abstract type (may be {@code null})
     * @param abstractTypeAuthority the abstract type authority (may be {@code null})
     * @return the matching SSL context factory (not {@code null})
     */
    public SecurityFactory<SSLContext> getSSLContextFactory(URI uri, AuthenticationContext authenticationContext, String abstractType, String abstractTypeAuthority) {
        Assert.checkNotNullParam("uri", uri);
        Assert.checkNotNullParam("authenticationContext", authenticationContext);
        final RuleNode<SecurityFactory<SSLContext>> node = authenticationContext.sslRuleMatching(uri, abstractType, abstractTypeAuthority);
        if (node == null) return SSLContext::getDefault;
        return node.getConfiguration();
    }

    /**
     * Get an authentication callback handler for the given configuration.
     *
     * @param configuration the configuration (must not be {@code null})
     * @return the callback handler
     */
    public CallbackHandler getCallbackHandler(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        final CallbackHandler callbackHandler = configuration.getUserCallbackHandler();
        return callbackHandler == null ? configuration.createCallbackHandler() : callbackHandler;
    }

    /**
     * Get the actual host to use for the given configuration and URI.
     *
     * @param uri the URI (must not be {@code null})
     * @param configuration the configuration (must not be {@code null})
     * @return the real host to use
     * @deprecated Use {@link URI#getHost()} instead.
     */
    @Deprecated
    public String getRealHost(URI uri, AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("uri", uri);
        Assert.checkNotNullParam("configuration", configuration);
        final String configurationHost = configuration.getHost();
        return configurationHost == null ? uri.getHost() : configurationHost;
    }

    /**
     * Get the actual host to use for the given configuration.
     *
     * @param configuration the configuration (must not be {@code null})
     * @return the real host to use
     * @deprecated This configuration is not supported by most providers and will be removed in a future release.
     */
    @Deprecated
    public String getRealHost(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        return configuration.getHost();
    }

    /**
     * Get the actual port to use for the given configuration and URI.
     *
     * @param uri the URI (must not be {@code null})
     * @param configuration the configuration (must not be {@code null})
     * @return the real port to use
     * @deprecated Use {@link URI#getPort()} instead.
     */
    @Deprecated
    public int getRealPort(URI uri, AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("uri", uri);
        Assert.checkNotNullParam("configuration", configuration);
        final int configurationPort = configuration.getPort();
        return configurationPort == -1 ? uri.getPort() : configurationPort;
    }

    /**
     * Get the actual port to use for the given configuration.
     *
     * @param configuration the configuration (must not be {@code null})
     * @return the real port to use
     * @deprecated This configuration is not supported by most providers and will be removed in a future release.
     */
    @Deprecated
    public int getRealPort(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        return configuration.getPort();
    }

    /**
     * Get the actual protocol to use for the given configuration and URI.
     *
     * @param uri the URI (must not be {@code null})
     * @param configuration the configuration (must not be {@code null})
     * @return the actual protocol to use, or {@code null} if none is configured and none is present on the URI
     * @deprecated Use {@link URI#getScheme()} instead.
     */
    @Deprecated
    public String getRealProtocol(URI uri, AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("uri", uri);
        Assert.checkNotNullParam("configuration", configuration);
        final String protocol = configuration.getProtocol();
        return protocol == null ? uri.getScheme() : protocol;
    }

    /**
     * Get the actual protocol to use for the given configuration.
     *
     * @param configuration the configuration (must not be {@code null})
     * @return the actual protocol to use, or {@code null} if none is configured
     * @deprecated This configuration is not supported by most providers and will be removed in a future release.
     */
    @Deprecated
    public String getRealProtocol(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        return configuration.getProtocol();
    }

    /**
     * Get the actual sasl protocol to use for the given configuration.
     *
     * @param configuration the configuration (must not be {@code null})
     * @return the real port to use
     */
    public String getSaslProtocol(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        return configuration.getSaslProtocol();
    }

    /**
     * Get the authentication principal to use for the given configuration.
     *
     * @param configuration the configuration (must not be {@code null})
     * @return the authentication principal (not {@code null})
     */
    public Principal getPrincipal(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        return configuration.getPrincipal();
    }

    /**
     * Get the authorization principal to use for the given configuration.
     *
     * @param configuration the configuration (must not be {@code null})
     * @return the authorization principal, or {@code null} if none is specified
     */
    public Principal getAuthorizationPrincipal(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        return configuration.getAuthorizationPrincipal();
    }

    /**
     * Create a SASL client using the given URI and configuration from the given SASL client factory.
     *
     * @param uri the target URI (must not be {@code null})
     * @param configuration the authentication configuration (must not be {@code null})
     * @param offeredMechanisms the available mechanisms (must not be {@code null})
     * @return the SASL client, or {@code null} if no clients were available or could be configured
     */
    public SaslClient createSaslClient(URI uri, AuthenticationConfiguration configuration,  Collection<String> offeredMechanisms) throws SaslException {
        return createSaslClient(uri, configuration, offeredMechanisms, UnaryOperator.identity());
    }

    /**
     * Create a SASL client using the given URI and configuration from the given SASL client factory.
     *
     * @param uri the target URI (must not be {@code null})
     * @param configuration the authentication configuration (must not be {@code null})
     * @param offeredMechanisms the available mechanisms (must not be {@code null})
     * @param factoryOperator a {@link UnaryOperator} to apply to the {@link SaslClientFactory} used
     * @return the SASL client, or {@code null} if no clients were available or could be configured
     */
    public SaslClient createSaslClient(URI uri, AuthenticationConfiguration configuration,  Collection<String> offeredMechanisms, UnaryOperator<SaslClientFactory> factoryOperator) throws SaslException {
        return createSaslClient(uri, configuration, offeredMechanisms, factoryOperator, null);
    }

    /**
     * Create a SASL client using the given URI and configuration from the given SASL client factory.
     *
     * @param uri the target URI (must not be {@code null})
     * @param configuration the authentication configuration (must not be {@code null})
     * @param offeredMechanisms the available mechanisms (must not be {@code null})
     * @param factoryOperator a {@link UnaryOperator} to apply to the {@link SaslClientFactory} used
     * @param sslSession the SSL session active for this connection, or {@code null} for none
     * @return the SASL client, or {@code null} if no clients were available or could be configured
     */
    public SaslClient createSaslClient(URI uri, AuthenticationConfiguration configuration, Collection<String> offeredMechanisms, UnaryOperator<SaslClientFactory> factoryOperator, final SSLSession sslSession) throws SaslException {
        return configuration.createSaslClient(uri, offeredMechanisms, factoryOperator, sslSession);
    }

    /**
     * Get the address of the destination from a configuration and URI.  The configuration may rewrite the destination as needed.
     *
     * @param uri the connection URI (must not be {@code null})
     * @param configuration the authentication configuration to use (must not be {@code null})
     * @param protocolDefaultPort the default port for the protocol
     * @return the address of the destination
     * @deprecated Use {@link org.wildfly.common.net.Inet#getResolved(java.net.URI, int)} instead.
     */
    @Deprecated
    public InetSocketAddress getDestinationInetSocketAddress(URI uri, AuthenticationConfiguration configuration, int protocolDefaultPort) {
        Assert.checkNotNullParam("uri", uri);
        Assert.checkNotNullParam("configuration", configuration);
        String host = configuration.getHost();
        if (host == null) host = uri.getHost();
        int port = configuration.getPort();
        if (port == -1) port = uri.getPort();
        if (port == -1) port = protocolDefaultPort;
        return new InetSocketAddress(host, port);
    }

    /**
     * Get the address of the destination from a configuration.  The configuration may rewrite the destination as needed.
     *
     * @param configuration the authentication configuration to use (must not be {@code null})
     * @return the address of the destination
     * @deprecated This configuration is not supported by most providers and will be removed in a future release.
     */
    @Deprecated
    public InetSocketAddress getDestinationInetSocketAddress(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        return new InetSocketAddress(configuration.getHost(), configuration.getPort());
    }

    /**
     * Connect a plain socket to the given URI.
     *
     * @param uri the connection URI
     * @param configuration the authentication configuration to use
     * @param protocolDefaultPort the default port for the protocol used in the URI
     * @return the connected socket
     * @throws IOException if socket creation or connection fails for some reason
     * @deprecated Use {@link org.wildfly.common.net.Inet#getResolved(java.net.URI, int)} with {@link Socket#Socket(InetAddress, int)} instead.
     */
    @Deprecated
    public Socket connect(URI uri, AuthenticationConfiguration configuration, int protocolDefaultPort) throws IOException {
        final InetSocketAddress address = getDestinationInetSocketAddress(uri, configuration, protocolDefaultPort);
        return new Socket(address.getAddress(), address.getPort());
    }

    /**
     * Get a {@link Supplier} as a source for all {@link Provider} instances registered in the given {@code configuration}.
     *
     * @param configuration the authentication configuration to use (must not be {@code null})
     * @return a supplier as a source for {@link Provider} instances (not {@code null})
     */
    public Supplier<Provider[]> getProviderSupplier(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        return configuration.getProviderSupplier();
    }
}
