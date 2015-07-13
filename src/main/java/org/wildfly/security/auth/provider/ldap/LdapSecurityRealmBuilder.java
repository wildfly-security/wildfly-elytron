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

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.NameRewriter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Builder for the security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LdapSecurityRealmBuilder {

    private boolean built = false;
    private DirContextFactory dirContextFactory;
    private NameRewriter nameRewriter = NameRewriter.IDENTITY_REWRITER;
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
     * @param nameRewriter the name rewriter
     * @return this builder
     */
    public LdapSecurityRealmBuilder setNameRewriter(final NameRewriter nameRewriter) {
        Assert.checkNotNullParam("nameRewriter", nameRewriter);
        assertNotBuilt();

        this.nameRewriter = nameRewriter;

        return this;
    }

    /**
     * Add a principal mapping to this builder.
     *
     * @return the builder for the principal mapping
     */
    public LdapSecurityRealmBuilder setPrincipalMapping(LdapSecurityRealm.PrincipalMapping principalMapping) {
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
        return new LdapSecurityRealm(dirContextFactory, nameRewriter, principalMapping);
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
        private List<Attribute> attributes = new ArrayList<>();

        public static PrincipalMappingBuilder builder() {
            return new PrincipalMappingBuilder();
        }

        /**
         * <p>Set the name of the context to be used when executing queries.
         *
         * <p>This option is specially useful when authenticating users based on names that don't use a X.500 format such as <em>plainUser</em>.
         * In this case, you must also provide {@link #setRdnIdentifier(String)} with the attribute name that contains the user name.</p>
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
            this.searchRecursive = true;
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
        public PrincipalMappingBuilder setRdnIdentifier(final String nameAttribute) {
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
         * Define an attribute mapping configuration.
         *
         * @param attributes one or more {@link org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder.PrincipalMappingBuilder.Attribute} configuration
         * @return this builder
         */
        public PrincipalMappingBuilder map(Attribute... attributes) {
            this.attributes.addAll(Arrays.asList(attributes));
            return this;
        }

        /**
         * Build this principal mapping.
         *
         * @return a {@link org.wildfly.security.auth.provider.ldap.LdapSecurityRealm.PrincipalMapping} instance with all the configuration.
         */
        public LdapSecurityRealm.PrincipalMapping build() {
            return new LdapSecurityRealm.PrincipalMapping(
                    searchDn, searchRecursive, searchTimeLimit, nameAttribute, this.passwordAttribute, this.attributes);
        }

        public static class Attribute {

            private final String ldapName;
            private final String searchDn;
            private final String filter;
            private String name;
            private String rdn;

            /**
             * Create an attribute mapping based on the given attribute in LDAP.
             *
             * @param ldapName the name of the attribute in LDAP from where values are obtained
             * @return this builder
             */
            public static Attribute from(String ldapName) {
                Assert.checkNotNullParam("ldapName", ldapName);
                return new Attribute(ldapName);
            }

            /**
             * <p>Create an attribute mapping based on the results of the given {@code filter}.
             *
             * <p>The {@code filter} <em>may</em> have one and exactly one <em>{0}</em> string that will be used to replace with the distinguished
             * name of the identity. In this case, the filter is specially useful when the values for this attribute should be obtained from a
             * separated entry. For instance, retrieving roles from entries with a object class of <em>groupOfNames</em> where the identity's DN is
             * a value of a <em>member</em> attribute.
             *
             * @param searchDn the name of the context to be used when executing the filter
             * @param filter the filter that is going to be used to search for entries and obtain values for this attribute
             * @param ldapName the name of the attribute in LDAP from where the values are obtained
             * @return this builder
             */
            public static Attribute fromFilter(String searchDn, String filter, String ldapName) {
                Assert.checkNotNullParam("searchDn", searchDn);
                Assert.checkNotNullParam("filter", filter);
                Assert.checkNotNullParam("ldapName", ldapName);
                return new Attribute(searchDn, filter, ldapName);
            }

            /**
             * <p>The behavior is exactly the same as {@link #fromFilter(String, String, String)}, except that it uses the
             * same name of the context defined in {@link org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder.PrincipalMappingBuilder#setSearchDn(String)}.
             *
             * @param filter the filter that is going to be used to search for entries and obtain values for this attribute
             * @param ldapName the name of the attribute in LDAP from where the values are obtained
             * @return this builder
             */
            public static Attribute fromFilter(String filter, String ldapName) {
                Assert.checkNotNullParam("filter", filter);
                Assert.checkNotNullParam("ldapName", ldapName);
                return new Attribute(null, filter, ldapName);
            }

            Attribute(String ldapName) {
                this(null, null, ldapName);
            }

            Attribute(String searchDn, String filter, String ldapName) {
                Assert.checkNotNullParam("ldapName", ldapName);
                this.searchDn = searchDn;
                this.filter = filter;
                this.ldapName = ldapName.toUpperCase();
            }

            public Attribute asRdn(String rdn) {
                Assert.checkNotNullParam("rdn", rdn);
                this.rdn = rdn;
                return this;
            }

            public Attribute to(String name) {
                Assert.checkNotNullParam("to", name);
                this.name = name;
                return this;
            }

            String getLdapName() {
                return this.ldapName;
            }

            String getName() {
                if (this.name == null) {
                    return this.ldapName;
                }

                return this.name;
            }

            String getSearchDn() {
                return this.searchDn;
            }

            String getFilter() {
                return this.filter;
            }

            String getRdn() {
                return this.rdn;
            }
        }
    }
}
