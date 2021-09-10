/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.wildfly.security.http.oidc.ElytronMessages.log;
import static org.wildfly.security.http.oidc.Oidc.JSON_CONFIG_CONTEXT_PARAM;
import static org.wildfly.security.http.oidc.Oidc.OIDC_CLIENT_CONFIG_RESOLVER;
import static org.wildfly.security.http.oidc.Oidc.OIDC_CLIENT_CONTEXT_KEY;
import static org.wildfly.security.http.oidc.Oidc.OIDC_CONFIG_FILE_LOCATION;
import static org.wildfly.security.http.oidc.Oidc.OIDC_JSON_FILE;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;


/**
 * <p>A {@link ServletContextListener} that parses the OIDC configuration and sets the configuration
 * as a {@link ServletContext} attribute in order to provide to {@link OidcAuthenticationMechanism} a way
 * to obtain the configuration when processing requests.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class OidcConfigurationServletListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        ServletContext servletContext = sce.getServletContext();
        String configResolverClass = servletContext.getInitParameter(OIDC_CLIENT_CONFIG_RESOLVER);
        OidcClientConfigurationResolver configResolver;
        OidcClientContext clientContext = (OidcClientContext) servletContext.getAttribute(OidcClientContext.class.getName());

        if (clientContext == null) {
            if (configResolverClass != null) {
                try {
                    configResolver = (OidcClientConfigurationResolver) servletContext.getClassLoader().loadClass(configResolverClass).newInstance();
                    clientContext = new OidcClientContext(configResolver);
                } catch (Exception ex) {
                    clientContext = new OidcClientContext(new OidcClientConfiguration());
                }
            } else {
                InputStream is = getConfigInputStream(servletContext);
                OidcClientConfiguration oidcClientConfiguration;
                if (is == null) {
                    oidcClientConfiguration = new OidcClientConfiguration();
                } else {
                    oidcClientConfiguration = OidcClientConfigurationBuilder.build(is);
                }
                clientContext = new OidcClientContext(oidcClientConfiguration);
            }
        }
        servletContext.setAttribute(OIDC_CLIENT_CONTEXT_KEY, clientContext);
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
    }

    private InputStream getConfigInputStream(ServletContext servletContext) {
        InputStream is = getJsonFromServletContext(servletContext);
        if (is == null) {
            String path = servletContext.getInitParameter(OIDC_CONFIG_FILE_LOCATION);

            if (path == null) {
                is = servletContext.getResourceAsStream(OIDC_JSON_FILE);
            } else {
                try {
                    is = new FileInputStream(path);
                } catch (FileNotFoundException e) {
                    throw log.oidcConfigFileNotFound(e);
                }
            }
        }
        return is;
    }

    private InputStream getJsonFromServletContext(ServletContext servletContext) {
        String json = servletContext.getInitParameter(JSON_CONFIG_CONTEXT_PARAM);
        if (json == null) {
            return null;
        }
        return new ByteArrayInputStream(json.getBytes());
    }
}
