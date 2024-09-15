/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.dynamic.ssl;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.util.List;

import static org.wildfly.common.Assert.checkNotNullParam;

/**
 * Elytron client implementation of DynamicSSLContextSPI. It uses configuration from either provided instance of AuthenticationContext
 * or from current AuthenticationContext if a configuration was not provided.
 *
 * @author <a href="mailto:dvilkola@redhat.com">Diana Krepinska (Vilkolakova)</a>
 */
@MetaInfServices(value = DynamicSSLContextSPI.class)
public class DynamicSSLContextImpl implements DynamicSSLContextSPI {

    private final AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT =
            AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
    private AuthenticationContext authenticationContext;
    private SSLContext configuredDefaultSSLContext;
    private List<SSLContext> configuredSSLContexts;

    public DynamicSSLContextImpl() throws GeneralSecurityException {
    }

    public DynamicSSLContextImpl(AuthenticationContext authenticationContext) throws GeneralSecurityException {
        checkNotNullParam("authenticationContext", authenticationContext);
        this.authenticationContext = authenticationContext;
        this.configuredSSLContexts = AUTH_CONTEXT_CLIENT.getConfiguredSSLContexts(authenticationContext);
        this.configuredDefaultSSLContext = AUTH_CONTEXT_CLIENT.getDefaultSSLContext(authenticationContext);
    }

    @Override
    public SSLContext getConfiguredDefault() throws DynamicSSLContextException {
        if (this.configuredDefaultSSLContext != null) {
            return this.configuredDefaultSSLContext;
        }
        try {
            return AUTH_CONTEXT_CLIENT.getDefaultSSLContext(AuthenticationContext.captureCurrent());
        } catch (GeneralSecurityException e) {
            throw ElytronMessages.log.cannotObtainDefaultSSLContext(e);
        }
    }

    @Override
    public List<SSLContext> getConfiguredSSLContexts() throws DynamicSSLContextException {
        if (this.configuredSSLContexts != null) {
            return this.configuredSSLContexts;
        }
        try {
            return AUTH_CONTEXT_CLIENT.getConfiguredSSLContexts(AuthenticationContext.captureCurrent());
        } catch (GeneralSecurityException e) {
            throw ElytronMessages.log.cannotObtainConfiguredSSLContexts(e);
        }
    }

    @Override
    public SSLContext getSSLContext(URI uri) throws DynamicSSLContextException {
        try {
            return AUTH_CONTEXT_CLIENT.getSSLContext(uri, authenticationContext == null ? AuthenticationContext.captureCurrent() : authenticationContext);
        } catch (GeneralSecurityException e) {
            throw ElytronMessages.log.cannotObtainSSLContextForGivenURI(e);
        }
    }
}
