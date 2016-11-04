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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Collection;

import javax.net.ssl.SSLContext;
import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.wildfly.common.Assert;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
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
     * Construct a new instance.
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
     * a default protocol port.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @param protocolDefaultPort the protocol-default port
     * @param abstractType the abstract type (may be {@code null})
     * @param abstractTypeAuthority the abstract type authority (may be {@code null})
     * @return the matching configuration
     */
    public AuthenticationConfiguration getAuthenticationConfiguration(URI uri, AuthenticationContext authenticationContext, int protocolDefaultPort, String abstractType, String abstractTypeAuthority) {
        return getAuthenticationConfiguration(uri, authenticationContext, protocolDefaultPort, abstractType, abstractTypeAuthority, null);
    }

    /**
     * Get the authentication configuration which matches the given URI and type, or {@link AuthenticationConfiguration#EMPTY} if there is none, setting
     * a default protocol port.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @param protocolDefaultPort the protocol-default port
     * @param abstractType the abstract type (may be {@code null})
     * @param abstractTypeAuthority the abstract type authority (may be {@code null})
     * @param purpose the authentication purpose (may be {@code null})
     * @return the matching configuration
     */
    public AuthenticationConfiguration getAuthenticationConfiguration(URI uri, AuthenticationContext authenticationContext, int protocolDefaultPort, String abstractType, String abstractTypeAuthority, String purpose) {
        Assert.checkNotNullParam("uri", uri);
        Assert.checkNotNullParam("authenticationContext", authenticationContext);
        final RuleNode<AuthenticationConfiguration> node = authenticationContext.authRuleMatching(uri, abstractType, abstractTypeAuthority, purpose);
        if (node == null) return AuthenticationConfiguration.EMPTY;
        AuthenticationConfiguration configuration = node.getConfiguration();
        final String uriHost = uri.getHost();
        if (uriHost != null && ! configuration.delegatesThrough(SetHostAuthenticationConfiguration.class)) {
            configuration = configuration.useHost(uriHost);
        }
        int port = uri.getPort();
        if (port == -1) port = protocolDefaultPort;
        if (port != -1 && ! configuration.delegatesThrough(SetPortAuthenticationConfiguration.class)) {
            configuration = configuration.usePort(port);
        }
        final String userInfo = uri.getUserInfo();
        if (userInfo != null && configuration.getPrincipal() == AnonymousPrincipal.getInstance()) {
            configuration = configuration.useName(userInfo);
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
        return getSSLContext(uri, authenticationContext, abstractType, abstractTypeAuthority, null);
    }

    /**
     * Get the SSL context which matches the given URI and type, or {@link SSLContext#getDefault()} if there is none.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @param abstractType the abstract type (may be {@code null})
     * @param abstractTypeAuthority the abstract type authority (may be {@code null})
     * @param purpose the authentication purpose (may be {@code null})
     * @return the matching SSL context
     */
    public SSLContext getSSLContext(URI uri, AuthenticationContext authenticationContext, String abstractType, String abstractTypeAuthority, String purpose) throws GeneralSecurityException {
        return getSSLContextFactory(uri, authenticationContext, abstractType, abstractTypeAuthority, purpose).create();
    }

    /**
     * Get the SSL context factory which matches the given URI and type, or {@link SSLContext#getDefault()} if there is none.
     *
     * @param uri the URI to match (must not be {@code null})
     * @param authenticationContext the authentication context to examine (must not be {@code null})
     * @param abstractType the abstract type (may be {@code null})
     * @param abstractTypeAuthority the abstract type authority (may be {@code null})
     * @param purpose the authentication purpose (may be {@code null})
     * @return the matching SSL context factory (not {@code null})
     */
    public SecurityFactory<SSLContext> getSSLContextFactory(URI uri, AuthenticationContext authenticationContext, String abstractType, String abstractTypeAuthority, String purpose) {
        Assert.checkNotNullParam("uri", uri);
        Assert.checkNotNullParam("authenticationContext", authenticationContext);
        final RuleNode<SecurityFactory<SSLContext>> node = authenticationContext.sslRuleMatching(uri, abstractType, abstractTypeAuthority, purpose);
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
        return configuration.getCallbackHandler();
    }

    /**
     * Get the actual host to use for the given configuration and URI.
     *
     * @param uri the URI (must not be {@code null})
     * @param configuration the configuration (must not be {@code null})
     * @return the real host to use
     */
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
     */
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
     */
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
     */
    public int getRealPort(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        return configuration.getPort();
    }

    /**
     * Get the principal to use for the given configuration.
     *
     * @param configuration the configuration (must not be {@code null})
     * @return the principal
     */
    public Principal getPrincipal(AuthenticationConfiguration configuration) {
        Assert.checkNotNullParam("configuration", configuration);
        return configuration.getPrincipal();
    }

    /**
     * Create a SASL client using the given URI and configuration from the given SASL client factory.
     *
     * @param uri the target URI (must not be {@code null})
     * @param configuration the authentication configuration (must not be {@code null})
     * @param clientFactory the SASL client factory to delegate to (must not be {@code null})
     * @param offeredMechanisms the available mechanisms (must not be {@code null})
     * @return the SASL client, or {@code null} if no clients were available or could be configured
     */
    public SaslClient createSaslClient(URI uri, AuthenticationConfiguration configuration, SaslClientFactory clientFactory, Collection<String> offeredMechanisms) throws SaslException {
        return configuration.createSaslClient(uri, clientFactory, offeredMechanisms);
    }

    /**
     * Get the address of the destination from a configuration and URI.  The configuration may rewrite the destination as needed.
     *
     * @param uri the connection URI (must not be {@code null})
     * @param configuration the authentication configuration to use (must not be {@code null})
     * @param protocolDefaultPort the default port for the protocol
     * @return the address of the destination
     */
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
     */
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
     */
    public Socket connect(URI uri, AuthenticationConfiguration configuration, int protocolDefaultPort) throws IOException {
        final InetSocketAddress address = getDestinationInetSocketAddress(uri, configuration, protocolDefaultPort);
        return new Socket(address.getAddress(), address.getPort());
    }
}
