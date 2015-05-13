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

import java.util.Hashtable;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

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
            Hashtable<String, String> env = new Hashtable<String, String>();
            env.put(InitialDirContext.INITIAL_CONTEXT_FACTORY, initialContextFactory);
            env.put(InitialDirContext.PROVIDER_URL, providerUrl);
            env.put(InitialDirContext.SECURITY_AUTHENTICATION, securityAuthentication);
            if (securityPrincipal != null) {
                env.put(InitialDirContext.SECURITY_PRINCIPAL, securityPrincipal);
            }
            if (securityCredential != null) {
                env.put(InitialDirContext.SECURITY_CREDENTIALS, securityCredential);
            }

            env.put(InitialDirContext.REFERRAL, mode == null ? ReferralMode.IGNORE.getValue() : mode.getValue());

            return new InitialDirContext(env);
        }

        @Override
        public void returnContext(DirContext context) {
            if (context instanceof InitialDirContext) {
                try {
                    ((InitialDirContext) context).close();
                } catch (NamingException ignored) {
                }
            }
        }

    }

}
