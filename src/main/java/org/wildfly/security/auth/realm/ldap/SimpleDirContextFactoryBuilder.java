/*
 * JBoss, Home of Professional Open Source
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

package org.wildfly.security.auth.realm.ldap;

import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.client.AuthenticationConfiguration;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.password.interfaces.ClearPassword;

import static java.security.AccessController.doPrivileged;
import static org.wildfly.security._private.ElytronMessages.log;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.InitialLdapContext;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.net.URI;
import java.util.Hashtable;
import java.util.Properties;

/**
 * A simple builder for a {@link DirContextFactory} which creates new contexts on demand and disposes of them as soon as they
 * are returned.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SimpleDirContextFactoryBuilder {

    private static final String CONNECT_TIMEOUT = "com.sun.jndi.ldap.connect.timeout";
    private static final String READ_TIMEOUT = "com.sun.jndi.ldap.read.timeout";
    private static final String SOCKET_FACTORY = "java.naming.ldap.factory.socket";

    private static final int DEFAULT_CONNECT_TIMEOUT = 5000; // ms
    private static final int DEFAULT_READ_TIMEOUT = 60000; // ms
    private static final String CONNECT_PURPOSE = "dir-context-connect";
    private static final String LDAPS_SCHEME = "ldaps";

    private boolean built = false;
    private String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";
    private String providerUrl = null;
    private String securityAuthentication = "simple";
    private String securityPrincipal = null;
    private String securityCredential = null;
    private CredentialSource credentialSource = null;
    private AuthenticationContext authenticationContext = null;
    private SocketFactory socketFactory = null;
    private Properties connectionProperties;
    private int connectTimeout = DEFAULT_CONNECT_TIMEOUT;
    private int readTimeout = DEFAULT_READ_TIMEOUT;

    private static final AuthenticationContextConfigurationClient authClient = doPrivileged(AuthenticationContextConfigurationClient.ACTION);

    private SimpleDirContextFactoryBuilder() {
    }

    /**
     * Construct a new instance.
     *
     * @return the new builder
     */
    public static SimpleDirContextFactoryBuilder builder() {
        return new SimpleDirContextFactoryBuilder();
    }

    /**
     * Set the initial context factory class name.
     *
     * @param initialContextFactory the class name
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setInitialContextFactory(final String initialContextFactory) {
        assertNotBuilt();
        this.initialContextFactory = initialContextFactory;

        return this;
    }

    /**
     * Set the provider URL.
     *
     * @param providerUrl the provider URL
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setProviderUrl(final String providerUrl) {
        assertNotBuilt();
        this.providerUrl = providerUrl;

        return this;
    }

    /**
     * Set the security authentication method.
     *
     * @param securityAuthentication the authentication method
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setSecurityAuthentication(final String securityAuthentication) {
        assertNotBuilt();
        this.securityAuthentication = securityAuthentication;

        return this;
    }

    /**
     * Set the authentication principal.
     *
     * @param securityPrincipal the principal
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setSecurityPrincipal(final String securityPrincipal) {
        assertNotBuilt();
        this.securityPrincipal = securityPrincipal;

        return this;
    }

    /**
     * Set the authentication credential.
     * If not set, factory try to obtain it from {@link CredentialSource} specified by
     * {@link #setCredentialSource(org.wildfly.security.credential.source.CredentialSource)} of from
     * {@link AuthenticationContext} specified by {@link #setAuthenticationContext(AuthenticationContext)}.
     *
     * @param securityCredential the credential
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setSecurityCredential(final String securityCredential) {
        assertNotBuilt();
        this.securityCredential = securityCredential;

        return this;
    }

    /**
     * Set the authentication credential source.
     * Alternative to {@link #setSecurityCredential(String)}.
     *
     * @param credentialSource the credential source
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setCredentialSource(final CredentialSource credentialSource) {
        assertNotBuilt();
        this.credentialSource = credentialSource;

        return this;
    }

    /**
     * Set the authentication context as source of security credential.
     * Alternative to {@link #setSecurityCredential(String)}.
     *
     * @param authenticationContext the credential source
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setAuthenticationContext(final AuthenticationContext authenticationContext) {
        assertNotBuilt();
        this.authenticationContext = authenticationContext;

        return this;
    }

    /**
     * Set the socket factory to be used by LDAP context.
     * Used primarily for SSL connections.
     *
     * If not set, factory try to obtain it from {@link AuthenticationContext} specified by {@link #setAuthenticationContext(AuthenticationContext)}.
     *
     * @param socketFactory the socket factory
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setSocketFactory(final SocketFactory socketFactory) {
        assertNotBuilt();
        this.socketFactory = socketFactory;

        return this;
    }

    /**
     * Set the timeout for connecting to the server.
     * Set to 0 to ensure waiting for the response infinitely.
     * If not set, {@value #DEFAULT_CONNECT_TIMEOUT} ms will be used.
     *
     * @param connectTimeout the timeout for connecting to the server in microseconds
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setConnectTimeout(int connectTimeout) {
        assertNotBuilt();
        this.connectTimeout = connectTimeout;

        return this;
    }

    /**
     * Set the read timeout for an LDAP operation.
     * Set to 0 to ensure waiting for the response infinitely.
     * If not set, {@value #DEFAULT_READ_TIMEOUT} ms will be used.
     *
     * @param readTimeout the read timeout for an LDAP operation in microseconds
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setReadTimeout(int readTimeout) {
        assertNotBuilt();
        this.readTimeout = readTimeout;

        return this;
    }


    /**
     * <p>Set additional connection properties.
     *
     * @param connectionProperties the additional connection properties.
     * @return this builder
     */
    public SimpleDirContextFactoryBuilder setConnectionProperties(Properties connectionProperties) {
        assertNotBuilt();
        this.connectionProperties = connectionProperties;

        return this;
    }

    /**
     * Build this context factory.
     *
     * @return the context factory
     */
    public DirContextFactory build() {
        assertNotBuilt();

        if (providerUrl == null) {
            throw log.noProviderUrlSet();
        }

        built = true;
        return new SimpleDirContextFactory();
    }

    private void assertNotBuilt() {
        if (built) {
            throw log.builderAlreadyBuilt();
        }
    }

    private class SimpleDirContextFactory implements DirContextFactory {

        @Override
        public DirContext obtainDirContext(ReferralMode mode) throws NamingException {
            String securityPrincipal = SimpleDirContextFactoryBuilder.this.securityPrincipal;
            char[] charPassword = null;
            if (securityCredential != null) { // password from String
                charPassword = securityCredential.toCharArray();
            } else if (credentialSource != null) { // password from CredentialSource
                ClearPassword password = null;
                try {
                    PasswordCredential credential = credentialSource.getCredential(PasswordCredential.class);
                    if (credential == null) throw log.couldNotObtainCredential();
                    password = credential.getPassword(ClearPassword.class);
                    if (password == null) throw log.couldNotObtainCredential();
                    charPassword = password.getPassword();
                } catch (Exception e) {
                    throw log.couldNotObtainCredentialWithCause(e);
                } finally {
                    try {
                        if (password != null) password.destroy();
                    } catch (DestroyFailedException e){
                        log.credentialDestroyingFailed(e);
                    }
                }
            } else if (authenticationContext != null) { // password from AuthenticationContext
                ClearPassword password = null;
                try {
                    URI uri = new URI(providerUrl);
                    AuthenticationConfiguration configuration = authClient.getAuthenticationConfiguration(uri, authenticationContext, 0, null, null, CONNECT_PURPOSE);

                    NameCallback nameCallback = new NameCallback("LDAP principal");
                    CredentialCallback credentialCallback = new CredentialCallback(PasswordCredential.class, ClearPassword.ALGORITHM_CLEAR);
                    try {
                        authClient.getCallbackHandler(configuration).handle(new Callback[]{nameCallback, credentialCallback});
                    } catch (Exception e) {
                        throw log.couldNotObtainCredentialWithCause(e);
                    }

                    securityPrincipal = nameCallback.getName();
                    PasswordCredential credential = credentialCallback.getCredential(PasswordCredential.class);
                    if (credential == null) throw log.couldNotObtainCredential();
                    password = credential.getPassword(ClearPassword.class);
                    if (password == null) throw log.couldNotObtainCredential();
                    charPassword = password.getPassword();
                } catch (Exception e) {
                    throw log.obtainingDirContextCredentialFromAuthenticationContextFailed(e);
                } finally {
                    try {
                        if (password != null) password.destroy();
                    } catch (DestroyFailedException e){
                        log.credentialDestroyingFailed(e);
                    }
                }
            }
            return createDirContext(securityPrincipal, charPassword, mode, getSocketFactory());
        }

        @Override
        public DirContext obtainDirContext(CallbackHandler handler, ReferralMode mode) throws NamingException {
            NameCallback nameCallback = new NameCallback("Principal Name");
            PasswordCallback passwordCallback = new PasswordCallback("Password", false);

            try {
                handler.handle(new Callback[] {nameCallback, passwordCallback});
            } catch (Exception e) {
                throw log.couldNotObtainCredentialWithCause(e);
            }

            String securityPrincipal = nameCallback.getName();

            if (securityPrincipal == null) {
                throw log.couldNotObtainPrincipal();
            }

            char[] securityCredential = passwordCallback.getPassword();

            if (securityCredential == null) {
                throw log.couldNotObtainCredential();
            }

            return createDirContext(securityPrincipal, securityCredential, mode, getSocketFactory());
        }

        private SocketFactory getSocketFactory() throws NamingException {
            if (socketFactory == null && authenticationContext != null) {
                try {
                    URI uri = new URI(providerUrl);
                    if ( ! uri.getScheme().equalsIgnoreCase(LDAPS_SCHEME)) {
                        return socketFactory; // non-SSL connection
                    }
                    SecurityFactory<SSLContext> sslContextFactory = authClient.getSSLContextFactory(uri, authenticationContext, null, null, CONNECT_PURPOSE);
                    return sslContextFactory.create().getSocketFactory();
                } catch (Exception e) {
                    throw log.obtainingDirContextCredentialFromAuthenticationContextFailed(e);
                }
            }
            return socketFactory;
        }

        private DirContext createDirContext(String securityPrincipal, char[] securityCredential, ReferralMode mode, SocketFactory socketFactory) throws NamingException {
            Hashtable<String, Object> env = new Hashtable<>();

            env.put(InitialDirContext.INITIAL_CONTEXT_FACTORY, initialContextFactory);
            env.put(InitialDirContext.PROVIDER_URL, providerUrl);
            env.put(InitialDirContext.SECURITY_AUTHENTICATION, securityAuthentication);
            if (securityPrincipal != null) env.put(InitialDirContext.SECURITY_PRINCIPAL, securityPrincipal);
            if (securityCredential != null) env.put(InitialDirContext.SECURITY_CREDENTIALS, securityCredential);
            env.put(InitialDirContext.REFERRAL, mode == null ? ReferralMode.IGNORE.getValue() : mode.getValue());
            if (socketFactory != null) env.put(SOCKET_FACTORY, ThreadLocalSSLSocketFactory.class.getName());
            env.put(CONNECT_TIMEOUT, Integer.toString(connectTimeout));
            env.put(READ_TIMEOUT, Integer.toString(readTimeout));

            // set any additional connection property
            if (connectionProperties != null) {
                for (Object key : connectionProperties.keySet()) {
                    Object value = connectionProperties.get(key.toString());

                    if (value != null) {
                        env.put(key.toString(), value.toString());
                    }
                }
            }

            if (log.isDebugEnabled()) {
                log.debugf("Creating [" + InitialDirContext.class + "] with environment:");
                env.forEach((key, value) -> {
                    log.debugf("    Property [%s] with Value [%s]", key, value);
                });
            }

            InitialLdapContext initialContext;

            try {
                if (socketFactory != null) ThreadLocalSSLSocketFactory.set(socketFactory);
                initialContext = new InitialLdapContext(env, null);
            } catch (NamingException ne) {
                log.debugf(ne, "Could not create [%s]. Failed to connect to LDAP server.", InitialLdapContext.class);
                throw ne;
            } finally {
                if (socketFactory != null) ThreadLocalSSLSocketFactory.unset();
            }

            log.debugf("[%s] successfully created. Connection established to LDAP server.", initialContext);

            return new DelegatingLdapContext(initialContext, this::returnContext, socketFactory);
        }

        @Override
        public void returnContext(DirContext context) {
            if (context == null) {
                return;
            }

            if (context instanceof InitialDirContext) {
                try {
                    context.close();
                    log.debugf("Context [%s] was closed. Connection closed or just returned to the pool.", context);
                } catch (NamingException ignored) {
                }
            }
        }

    }

}
