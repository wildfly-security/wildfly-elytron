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

import static org.wildfly.security._private.ElytronMessages.log;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.InitialLdapContext;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
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

    private static final int DEFAULT_CONNECT_TIMEOUT = 5000; // ms
    private static final int DEFAULT_READ_TIMEOUT = 60000; // ms

    private boolean built = false;
    private String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";
    private String providerUrl = null;
    private String securityAuthentication = "simple";
    private String securityPrincipal = null;
    private String securityCredential = null;
    private Properties connectionProperties;
    private int connectTimeout = DEFAULT_CONNECT_TIMEOUT;
    private int readTimeout = DEFAULT_READ_TIMEOUT;

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
            return createDirContext(securityPrincipal, securityCredential.toCharArray(), null);
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

            return createDirContext(securityPrincipal, securityCredential, mode);
        }

        private DirContext createDirContext(String securityPrincipal, char[] securityCredential, ReferralMode mode) throws NamingException {
            Hashtable<String, String> env = new Hashtable<>();

            env.put(InitialDirContext.INITIAL_CONTEXT_FACTORY, initialContextFactory);
            env.put(InitialDirContext.PROVIDER_URL, providerUrl);
            env.put(InitialDirContext.SECURITY_AUTHENTICATION, securityAuthentication);
            env.put(InitialDirContext.SECURITY_PRINCIPAL, securityPrincipal);
            env.put(InitialDirContext.SECURITY_CREDENTIALS, String.valueOf(securityCredential));
            env.put(InitialDirContext.REFERRAL, mode == null ? ReferralMode.IGNORE.getValue() : mode.getValue());
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

            InitialLdapContext context;

            try {
                context = new InitialLdapContext(env, null);
            } catch (NamingException ne) {
                log.debugf(ne, "Could not create [%s]. Failed to connect to LDAP server.", InitialLdapContext.class);
                throw ne;
            }

            log.debugf("[%s] successfully created. Connection established to LDAP server.", context);

            return context;
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
