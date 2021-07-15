package org.wildfly.security.auth.client;

import org.wildfly.client.config.ConfigXMLParseException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

public class DefaultSSLContextSpi extends SSLContextSpi {

    private SSLContext configuredDefaultClientSSLContext;

    public DefaultSSLContextSpi() throws GeneralSecurityException {
        this(AuthenticationContext.captureCurrent());
    }

    public DefaultSSLContextSpi(String configPath) throws GeneralSecurityException, URISyntaxException, ConfigXMLParseException {
        this(ElytronXmlParser.parseAuthenticationClientConfiguration(new URI(configPath)).create());
    }

    public DefaultSSLContextSpi(AuthenticationContext authenticationContext) throws GeneralSecurityException {
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

}
