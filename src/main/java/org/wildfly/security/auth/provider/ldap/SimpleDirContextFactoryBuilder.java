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

package org.wildfly.security.auth.provider.ldap;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.util.Hashtable;

/**
 * A simple builder for a {@link DirContextFactory} which creates new contexts on demand and disposes of them as soon as they
 * are returned.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SimpleDirContextFactoryBuilder {

    // TODO - Plenty of additional options possible, this is the bare minimum to interact with LDAP.

    private boolean built = false;
    private String initialContextFactory = "com.sun.jndi.ldap.LdapCtxFactory";
    private String providerUrl = null;
    private String securityAuthentication = "simple";
    private String securityPrincipal = null;
    private String securityCredential = null;

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
     * Build this context factory.
     *
     * @return the context factory
     */
    public DirContextFactory build() {
        assertNotBuilt();

        if (providerUrl == null) {
            throw new IllegalStateException("No provider URL has been set.");
        }

        built = true;
        return new SimpleDirContextFactory();
    }

    private void assertNotBuilt() {
        if (built) {
            throw new IllegalStateException("This builder has already been built.");
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
                throw new RuntimeException("Could not obtain credentials.", e);
            }

            String securityPrincipal = nameCallback.getName();

            if (securityPrincipal == null) {
                throw new IllegalArgumentException("Could not not obtain security principal.");
            }

            char[] securityCredential = passwordCallback.getPassword();

            if (securityCredential == null) {
                throw new IllegalArgumentException("Could not not obtain security credential.");
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

            return new InitialDirContext(env);
        }

        @Override
        public void returnContext(DirContext context) {
            if (context instanceof InitialDirContext) {
                try {
                    context.close();
                } catch (NamingException ignored) {
                }
            }
        }

    }

}
