/*
 * Copyright 2022 JBoss by Red Hat.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.auth.client.spi;

import io.netty.handler.ssl.SslContext;
import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.net.ssl.SSLContext;
import org.apache.activemq.artemis.core.remoting.impl.netty.TransportConstants;
import org.apache.activemq.artemis.core.remoting.impl.ssl.DefaultSSLContextFactory;
import org.apache.activemq.artemis.spi.core.remoting.ssl.SSLContextConfig;
import org.apache.activemq.artemis.spi.core.remoting.ssl.SSLContextFactory;
import org.apache.activemq.artemis.utils.ConfigurationHelper;
import org.kohsuke.MetaInfServices;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.auth.client.ElytronXmlParser;

/**
 *
 * @author Emmanuel Hugonnet (c) 2021 Red Hat, Inc.
 */
@MetaInfServices(value = SSLContextFactory.class)
public class ArtemisClientConfigProvider extends DefaultSSLContextFactory {

    static final AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT = AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
    private static final ConcurrentMap<Object, SSLContext> sslContextCache = new ConcurrentHashMap<>(2);

    @Override
    public void clearSSLContexts() {
        sslContextCache.clear();
    }

    @Override
    public SSLContext getSSLContext(SSLContextConfig config, Map<String, Object> configuration) throws Exception {
        final Object cacheKey = getCacheKey(config, configuration);
        return sslContextCache.computeIfAbsent(cacheKey, key -> {
            try {
                SSLContext context = getElytronSSLContext(config, configuration);
                if (context == null) {
                    context = super.getSSLContext(config, configuration);
                }
                return context;
            } catch (final Exception ex) {
                throw new RuntimeException("An unexpected exception occured while creating JDK SSLContext with " + config, ex);
            }
        });
    }

    private SSLContext getElytronSSLContext(SSLContextConfig config, Map<String, Object> configuration) throws Exception {
        String host = ConfigurationHelper.getStringProperty(TransportConstants.HOST_PROP_NAME, TransportConstants.DEFAULT_HOST, configuration);
        int port = ConfigurationHelper.getIntProperty(TransportConstants.PORT_PROP_NAME, TransportConstants.DEFAULT_PORT, configuration);
        String sslContextName = ConfigurationHelper.getStringProperty(TransportConstants.SSL_CONTEXT_PROP_NAME, null, configuration);
        String path;
        if (sslContextName != null && !sslContextName.isEmpty()) {
            path = '/' + sslContextName;
        } else {
            path = "";
        }
        URI uri = new URI("artemis://" + host + ":" + port + path);
        String xmlPath = ConfigurationHelper.getStringProperty("wildfly-config-url", null, configuration);
        if (xmlPath == null) {
            xmlPath = System.getProperty("wildfly-config-url");
        }
        if (xmlPath == null) {
            xmlPath = System.getProperty("wildfly.config.url");
        }
        AuthenticationContext context;
        URI xmlConfig = null;
        if (xmlPath != null) {
            try {
                xmlConfig = new URI(xmlPath);
                if (!xmlConfig.isAbsolute()) {
                    xmlConfig = getFileURI(xmlPath);
                }
            } catch (URISyntaxException ex) {
                xmlConfig = getFileURI(xmlPath);
            }
        }
        if (xmlConfig != null) {
            context = ElytronXmlParser.parseAuthenticationClientConfiguration(xmlConfig).create();
        } else {
            context = ElytronXmlParser.parseAuthenticationClientConfiguration().create();
        }
        return AUTH_CONTEXT_CLIENT.getSSLContext(uri, context);
    }

    private URI getFileURI(String xmlPath) {
        File configFile = new File(xmlPath);
        if (configFile.exists()) {
            return configFile.toURI();
        }
        return null;
    }

    @Override
    public int getPriority() {
        return 15;
    }

    /**
     * Obtains/calculates a cache key for the corresponding
     * {@link SslContext}.<ol>
     * <li>If <code>config</code> contains an entry with key "sslContext", the
     * associated value is returned
     * <li>Otherwise, the provided {@link SSLContextConfig} is used as cache
     * key.</ol>
     *
     * @param config
     * @param additionalOpts
     * @return the SSL context name to cache/retrieve the {@link SslContext}.
     */
    private Object getCacheKey(final SSLContextConfig config, final Map<String, Object> additionalOpts) {
        final Object cacheKey = ConfigurationHelper.getStringProperty(TransportConstants.SSL_CONTEXT_PROP_NAME, null, additionalOpts);
        if (cacheKey != null) {
            return cacheKey;
        }
        return config;
    }

}
