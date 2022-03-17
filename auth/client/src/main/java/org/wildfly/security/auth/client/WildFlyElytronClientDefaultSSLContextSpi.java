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

import org.wildfly.client.config.ConfigXMLParseException;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.client._private.ElytronMessages;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

/**
 * SSLContextSpi that is used by WildFlyElytronClientDefaultSSLContextProvider
 */
public class WildFlyElytronClientDefaultSSLContextSpi extends SSLContextSpi {

    private SSLContext configuredDefaultClientSSLContext;

    /**
     * SSLContextSpi used by WildFlyElytronClientDefaultSSLContextProvider that uses AuthenticationContext found on the classpath to retrieve default SSLContext.
     */
    public WildFlyElytronClientDefaultSSLContextSpi() throws GeneralSecurityException {
        this(AuthenticationContext.captureCurrent());
    }

    /**
     * SSLContextSpi used by WildFlyElytronClientDefaultSSLContextProvider that uses Elytron client configuration from provided path to retrieve default SSLContext.
     *
     * @param configPath path to the Elytron client configuration file
     */
    public WildFlyElytronClientDefaultSSLContextSpi(String configPath) throws GeneralSecurityException, ConfigXMLParseException {
        this(ElytronXmlParser.parseAuthenticationClientConfiguration(configPathUrlToUri(configPath)).create());
    }

    /**
     * SSLContextSpi used by WildFlyElytronClientDefaultSSLContextProvider that uses Elytron client configuration from provided authentication context.
     *
     * @param authenticationContext authentication context used to retrieve default SSLContext
     */
    public WildFlyElytronClientDefaultSSLContextSpi(AuthenticationContext authenticationContext) throws GeneralSecurityException {
        Assert.checkNotNullParam("authenticationContext", authenticationContext);

        AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT = AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
        this.configuredDefaultClientSSLContext = AUTH_CONTEXT_CLIENT.getSSLContext(authenticationContext);
    }

    @Override
    protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) {
        // ignore
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return this.configuredDefaultClientSSLContext.getSocketFactory();
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return this.configuredDefaultClientSSLContext.getServerSocketFactory();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return this.configuredDefaultClientSSLContext.createSSLEngine();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String s, int i) {
        return this.configuredDefaultClientSSLContext.createSSLEngine(s, i);
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return this.configuredDefaultClientSSLContext.getServerSessionContext();
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return this.configuredDefaultClientSSLContext.getClientSessionContext();
    }

    /**
     * Source: A utility method taken from https://github.com/wildfly/wildfly-client-config/blob/master/src/main/java/org/wildfly/client/config/ClientConfiguration.java on March 2022
     */
    static URI configPathUrlToUri(String wildFlyConfig) {
        if (wildFlyConfig == null || wildFlyConfig.isEmpty()) {
            throw ElytronMessages.log.clientConfigurationFileNotValid();
        }
        if (File.separator.equals("\\") && wildFlyConfig.contains("\\")) { // we are on the windows and path is for windows
            File f = new File(wildFlyConfig);
            return f.toPath().toUri();
        } else {
            try {
                URI uri = new URI(wildFlyConfig);
                if (!uri.isAbsolute()) { // URI does not include schema
                    if (uri.getPath().charAt(0) != File.separatorChar && uri.getPath().charAt(0) != '/') { // relative path
                        String userDir = System.getProperty("user.dir").replace(File.separatorChar, '/');
                        return Paths.get(userDir, uri.getPath()).toUri();
                    } else { // absolute path
                        return Paths.get(uri.getPath()).toUri();
                    }
                }
                return uri;
            } catch (URISyntaxException e) {
                // no config file there
                return null;
            }
        }
    }
}
