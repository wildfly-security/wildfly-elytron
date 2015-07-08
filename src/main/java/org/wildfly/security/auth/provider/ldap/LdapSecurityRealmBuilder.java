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

import static org.wildfly.security._private.ElytronMessages.log;

import java.util.LinkedList;
import java.util.List;

import org.wildfly.security.auth.server.NameRewriter;

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

        this.nameRewriters.add(nameReWriter);

        return this;
    }

    /**
     * Add a principal mapping to this builder.
     *
     * @return the builder for the principal mapping
     */
    public LdapSecurityRealmBuilder principalMapping(LdapSecurityRealm.PrincipalMapping principalMapping) {
        assertNotBuilt();

        this.principalMapping = principalMapping;

        return this;
    }

    /**
     * Build this realm.
     *
     * @return the built realm
     */
    public LdapSecurityRealm build() {
        assertNotBuilt();
        if (dirContextFactory == null) {
            throw log.noDirContextFactorySet();
        }
        if (principalMapping == null) {
            throw log.noPrincipalMappingDefinition();
        }

        built = true;
        return new LdapSecurityRealm(dirContextFactory, nameRewriters, principalMapping);
    }

    private void assertNotBuilt() {
        if (built) {
            throw log.builderAlreadyBuilt();
        }
    }

    /**
     * A builder for a principal mapping.
     */
    public static class PrincipalMappingBuilder {

        private String searchDn = null;
        private boolean searchRecursive = false;
        private String nameAttribute;
        private String passwordAttribute = UserPasswordCredentialLoader.DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME;
        private int searchTimeLimit = 10000;

        public static PrincipalMappingBuilder builder() {
            return new PrincipalMappingBuilder();
        }

        /**
         * <p>Set the name of the context to be used when executing queries.
         *
         * <p>This option is specially useful when authenticating users based on names that don't use a X.500 format such as <em>plainUser</em>.
         * In this case, you must also provide {@link #setNameAttribute(String)} with the attribute name that contains the user name.</p>
         *
         * <p>If the names used to authenticate users are based on the X.500 format, this configuration can be suppressed.
         *
         * <p>Please note that by using this option the realm is able to authenticate users based on their simple or X.500 names.
         *
         * @param searchDn the name of the context to search
         * @return this builder
         */
        public PrincipalMappingBuilder setSearchDn(final String searchDn) {
            this.searchDn = searchDn;
            return this;
        }

        /**
         * Indicate if queries are searchRecursive, searching the entire subtree rooted at the name specified in {@link #setSearchDn(String)}.
         * Otherwise search one level of the named context.
         *
         * @return this builder
         */
        public PrincipalMappingBuilder searchRecursive() {
            this.searchRecursive = false;
            return this;
        }

        /**
         * Sets the time limit of the SearchControls in milliseconds.
         *
         * @param limit the limit in milliseconds. Defaults to 5000 milliseconds.
         * @return this builder
         */
        public PrincipalMappingBuilder setSearchTimeLimit(int limit) {
            this.searchTimeLimit = limit;
            return this;
        }

        /**
         * Set the name of the attribute in LDAP that holds the user name.
         *
         * @param nameAttribute the name attribute
         * @return this builder
         */
        public PrincipalMappingBuilder setNameAttribute(final String nameAttribute) {
            this.nameAttribute = nameAttribute;
            return this;
        }

        /**
         * <p>Set the name of the attribute in LDAP that holds the user's password. Use this this option if you want to
         * obtain credentials from Ldap based on the built-in supported types.
         *
         * @param passwordAttribute the password attribute name. Defaults to {@link UserPasswordCredentialLoader#DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME}.
         * @return this builder
         */
        public PrincipalMappingBuilder setPasswordAttribute(final String passwordAttribute) {
            this.passwordAttribute = passwordAttribute;
            return this;
        }

        /**
         * Build this principal mapping.
         *
         * @return a {@link org.wildfly.security.auth.provider.ldap.LdapSecurityRealm.PrincipalMapping} instance with all the configuration.
         */
        public LdapSecurityRealm.PrincipalMapping build() {
            return new LdapSecurityRealm.PrincipalMapping(searchDn, searchRecursive, searchTimeLimit, nameAttribute, this.passwordAttribute);
        }
    }
}
