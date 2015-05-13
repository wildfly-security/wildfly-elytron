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

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.wildfly.security.auth.spi.CredentialSupport;
import org.wildfly.security.auth.util.NameRewriter;

/**
 * Builder for the security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LdapSecurityRealmBuilder {

    private boolean built = false;
    private DirContextFactory dirContextFactory;
    private List<NameRewriter> nameRewriters = new LinkedList<NameRewriter>();
    private LdapSecurityRealm.PrincipalMapping principalMapping;
    private List<CredentialLoader> credentialLoaders = new LinkedList<CredentialLoader>();

    private LdapSecurityRealmBuilder() {
    }

    /**
     * Construct a new instance.
     *
     * @return the new builder instance
     */
    public static LdapSecurityRealmBuilder builder() {
        return new LdapSecurityRealmBuilder();
    }

    /**
     * Set the directory context factory.
     *
     * @param dirContextFactory the directory context factory
     * @return this builder
     */
    public LdapSecurityRealmBuilder setDirContextFactory(final DirContextFactory dirContextFactory) {
        assertNotBuilt();
        this.dirContextFactory = dirContextFactory;

        return this;
    }

    /**
     * Add a name rewriter to this builder.
     *
     * @param nameReWriter the name rewriter
     * @return this builder
     */
    public LdapSecurityRealmBuilder addNameRewriter(final NameRewriter nameReWriter) {
        assertNotBuilt();
        nameRewriters.add(nameReWriter);

        return this;
    }

    /**
     * Add a principal mapping to this builder.
     *
     * @return the builder for the principal mapping
     */
    public PrincipalMappingBuilder principalMapping() {
        assertNotBuilt();

        return new PrincipalMappingBuilder();
    }

    /**
     * Add a user/password credential loader to this builder.
     *
     * @return the builder for the user/password credential loader
     */
    public UserPasswordCredentialLoaderBuilder userPassword() {
        assertNotBuilt();

        return new UserPasswordCredentialLoaderBuilder();
    }

    /**
     * Build this realm.
     *
     * @return the built realm
     */
    public LdapSecurityRealm build() {
        assertNotBuilt();
        if (dirContextFactory == null) {
            throw new IllegalStateException("No DirContextFactory set.");
        }
        if (principalMapping == null) {
            throw new IllegalStateException("No principal mapping definition.");
        }

        built = true;
        return new LdapSecurityRealm(dirContextFactory, nameRewriters, principalMapping, credentialLoaders);
    }

    private void assertNotBuilt() {
        if (built) {
            throw new IllegalStateException("Builder has already been built.");
        }
    }

    /**
     * A builder for a principal mapping.
     */
    public class PrincipalMappingBuilder {

        private boolean built = false;
        private String searchDn = null;
        private boolean recursive = false;
        private boolean nameIsDn = false;
        private boolean principalUseDn = false;
        private String nameAttribute;
        private String dnAttribute;
        private boolean validatePresence;
        private boolean reloadPrincipalName = false;

        PrincipalMappingBuilder() {
        }

        /**
         * Set the search DN for this mapping.
         *
         * @param searchDn the search DN
         * @return this builder
         */
        public PrincipalMappingBuilder setSearchDn(final String searchDn) {
            assertNotBuilt();
            this.searchDn = searchDn;

            return this;
        }

        /**
         * Set the recursive flag for this mapping.
         *
         * @param recursive the recursive flag
         * @return this builder
         */
        public PrincipalMappingBuilder setRecursive(final boolean recursive) {
            assertNotBuilt();
            this.recursive = recursive;

            return this;
        }

        /**
         * Establish whether the name is a DN for this mapping.
         *
         * @param nameIsDn {@code true} if the name is a DN, {@code false} otherwise
         * @return this builder
         */
        public PrincipalMappingBuilder setNameIsDn(final boolean nameIsDn) {
            assertNotBuilt();
            this.nameIsDn = nameIsDn;

            return this;
        }

        /**
         * Establish whether the principal shall use the DN for this mapping.
         *
         * @param principalUseDn {@code true} to use DN, {@code false} otherwise
         * @return this builder
         */
        public PrincipalMappingBuilder setPrincipalUseDn(final boolean principalUseDn) {
            assertNotBuilt();
            this.principalUseDn = principalUseDn;

            return this;
        }

        /**
         * Set the name attribute for this mapping.
         *
         * @param nameAttribute the name attribute
         * @return this builder
         */
        public PrincipalMappingBuilder setNameAttribute(final String nameAttribute) {
            assertNotBuilt();
            this.nameAttribute = nameAttribute;

            return this;
        }

        /**
         * Set the DN attribute for this mapping.
         *
         * @param dnAttribute the DN attribute
         * @return this builder
         */
        public PrincipalMappingBuilder setDnAttribute(final String dnAttribute) {
            assertNotBuilt();
            this.dnAttribute = dnAttribute;

            return this;
        }

        /**
         * Set the validate-presence flag for this mapping.
         *
         * @param validatePresence the validate-presence flag
         * @return this builder
         */
        public PrincipalMappingBuilder setValidatePresence(final boolean validatePresence) {
            assertNotBuilt();
            this.validatePresence = validatePresence;

            return this;
        }

        /**
         * Set the reload-principal-name flag for this mapping.
         *
         * @param reloadPrincipalName the reload-principal-name flag
         * @return this builder
         */
        public PrincipalMappingBuilder setReloadPrincipalName(final boolean reloadPrincipalName) {
            assertNotBuilt();
            this.reloadPrincipalName = reloadPrincipalName;

            return this;
        }

        /**
         * Build this principal mapping.
         *
         * @return the enclosing LDAP security realm builder
         */
        public LdapSecurityRealmBuilder build() {
            assertNotBuilt();

            principalMapping = new LdapSecurityRealm.PrincipalMapping(searchDn, recursive, nameIsDn, principalUseDn,
                    nameAttribute, dnAttribute, validatePresence, reloadPrincipalName);
            built = true;
            return LdapSecurityRealmBuilder.this;
        }

        private void assertNotBuilt() {
            if (built) {
                throw new IllegalStateException("Builder has already been built.");
            }

            LdapSecurityRealmBuilder.this.assertNotBuilt();
        }

    }

    /**
     * A builder for a user/password credential loader.
     */
    public class UserPasswordCredentialLoaderBuilder {

        private boolean built = false;
        private String userPasswordAttributeName = UserPasswordCredentialLoader.DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME;
        private Map<Class<?>, CredentialSupport> credentialSupportMap = new HashMap<Class<?>, CredentialSupport>();

        UserPasswordCredentialLoaderBuilder() {
        }

        /**
         * Set the user/password attribute name.
         *
         * @param userPasswordAttributeName the attribute name
         * @return this builder
         */
        public UserPasswordCredentialLoaderBuilder setUserPasswordAttributeName(final String userPasswordAttributeName) {
            assertNotBuilt();
            this.userPasswordAttributeName = userPasswordAttributeName;

            return this;
        }

        /**
         * Add support for a specific credential type.
         *
         * @param credentialType the credential type
         * @param support the level of support for the credential type
         * @return this builder
         */
        public UserPasswordCredentialLoaderBuilder addCredentialSupport(final Class<?> credentialType, final CredentialSupport support) {
            assertNotBuilt();
            credentialSupportMap.put(credentialType, support);

            return this;
        }

        /**
         * Build this credential loader.
         *
         * @return the enclosing LDAP security realm builder
         */
        public LdapSecurityRealmBuilder build() {
            assertNotBuilt();

            built = true;
            credentialLoaders.add(new UserPasswordCredentialLoader(userPasswordAttributeName, credentialSupportMap));

            return LdapSecurityRealmBuilder.this;
        }

        private void assertNotBuilt() {
            if (built) {
                throw new IllegalStateException("Builder has already been built.");
            }

            LdapSecurityRealmBuilder.this.assertNotBuilt();
        }
    }

}
