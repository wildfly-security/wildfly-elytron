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

package org.wildfly.security.auth.client.spi;

import org.jboss.wsf.spi.metadata.config.ClientConfig;
import org.jboss.wsf.spi.security.ClientConfigException;
import org.jboss.wsf.spi.security.ClientConfigProvider;
import org.wildfly.common.Assert;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;

import javax.net.ssl.SSLContext;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.ws.BindingProvider;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;

import org.kohsuke.MetaInfServices;

/**
 * WebServices client provider implementation.
 *
 * @author <a href="mailto:dvilkola@redhat.com">Diana Vilkolakova</a>
 */
@MetaInfServices(value = ClientConfigProvider.class)
public class WebServicesClientConfigProviderImpl implements ClientConfigProvider {

    private static final AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT = AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
    private AuthenticationContext authenticationContext = AuthenticationContext.captureCurrent();

    @Override
    public ClientConfig configure(ClientConfig config, BindingProvider bindingProvider) throws ClientConfigException {
        Assert.checkNotNullParam("bindingProvider", bindingProvider);
        URI uri = null;
        try {
            uri = new URI(bindingProvider.getRequestContext().get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY).toString());
        } catch (URISyntaxException e) {
            throw new ClientConfigException("Unable to obtain URI");
        }
        if (authenticationContext == AuthenticationContext.empty()) {
            return config;
        }
        Map<String, Object> attachments = config == null ? new HashMap<>() : new HashMap<String, Object>(config.getAttachments());

        putNotNullProperty(attachments, CLIENT_PROVIDER_CONFIGURED, "true");
        putNotNullProperty(attachments, CLIENT_USERNAME, getUsername(uri));
        putNotNullProperty(attachments, CLIENT_PASSWORD, getPassword(uri));
        putNotNullProperty(attachments, CLIENT_HTTP_MECHANISM, getHttpMechanism(uri));
        putNotNullProperty(attachments, CLIENT_WS_SECURITY_TYPE, getWsSecurityType(uri));
        attachments.put(CLIENT_SSL_CONTEXT, getSSLContext(uri));

        if (config == null) {
            ClientConfig cc = new ClientConfig(ClientConfig.WILDLFY_CLIENT_CONFIG_FILE, null, null, null, null);
            cc.getAttachments().putAll(attachments);
            return cc;
        } else {
            config.getAttachments().putAll(attachments);
            return config;
        }
    }

    private void putNotNullProperty(Map<String, Object> props, String key, String value) {
        if (value != null) {
            props.put(key, value);
        }
    }

    private SSLContext getSSLContext(URI uri) throws ClientConfigException {
        try {
            return AUTH_CONTEXT_CLIENT.getSSLContext(uri, authenticationContext);
        } catch (GeneralSecurityException e) {
            throw new ClientConfigException("Unable to obtain SSLContext");
        }
    }

    private String getUsername(URI uri) throws ClientConfigException {
        final CallbackHandler callbackHandler = AUTH_CONTEXT_CLIENT.getCallbackHandler(AUTH_CONTEXT_CLIENT.getAuthenticationConfiguration(uri, authenticationContext));
        NameCallback nameCallback = new NameCallback("user name");
        try {
            callbackHandler.handle(new Callback[]{nameCallback});
            return nameCallback.getName();
        } catch (IOException | UnsupportedCallbackException e) {
            throw new ClientConfigException("Name callback handling was unsuccessful");
        }
    }

    private String getPassword(URI uri) throws ClientConfigException {
        final CallbackHandler callbackHandler = AUTH_CONTEXT_CLIENT.getCallbackHandler(AUTH_CONTEXT_CLIENT.getAuthenticationConfiguration(uri, authenticationContext));
        PasswordCallback passwordCallback = new PasswordCallback("password", false);
        try {
            callbackHandler.handle(new Callback[]{passwordCallback});
            char[] password = passwordCallback.getPassword();
            if (password == null) {
                return null;
            }
            return new String(password);
        } catch (IOException | UnsupportedCallbackException e) {
            throw new ClientConfigException("Password callback handling was unsuccessful");
        }
    }

    private String getHttpMechanism(URI uri) {
        return AUTH_CONTEXT_CLIENT.getWsHttpMech(AUTH_CONTEXT_CLIENT.getAuthenticationConfiguration(uri, authenticationContext));
    }

    private String getWsSecurityType(URI uri) {
        return AUTH_CONTEXT_CLIENT.getWsSecurityType(AUTH_CONTEXT_CLIENT.getAuthenticationConfiguration(uri, authenticationContext));
    }
}
