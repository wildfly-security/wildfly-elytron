/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

import java.util.Locale;

import org.wildfly.common.Assert;

import javax.naming.directory.DirContext;

/**
 * Definition of a mapping from LDAP to an Elytron attribute.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AttributeMapping {

    public static final String DEFAULT_FILTERED_NAME = "filtered";
    public static final String DEFAULT_DN_NAME = "dn";
    public static final String DEFAULT_ROLE_RECURSION_ATTRIBUTE = "CN";

    private final String ldapName;
    private final String searchDn;
    private final boolean recursiveSearch;
    private final String filter;
    private final String reference;
    private final String name;
    private final String rdn;
    private final int roleRecursionDepth;
    private final String roleRecursionName;

    String getLdapName() {
        return ldapName;
    }

    /**
     * Get name of LDAP attribute to obtain from identity entry
     * @return LDAP attribute to obtain from identity entry
     */
    String getIdentityLdapName() {
        if (filter != null) return null;
        return reference != null ? reference : ldapName;
    }

    String getName() {
        return name;
    }

    String getSearchDn() {
        return searchDn;
    }

    boolean getRecursiveSearch() {
        return recursiveSearch;
    }

    String getFilter() {
        return filter;
    }

    String getRdn() {
        return rdn;
    }

    String getReference() {
        return reference;
    }

    int getRoleRecursionDepth() {
        return roleRecursionDepth;
    }

    String getRoleRecursionName() {
        return roleRecursionName;
    }

    boolean isFilteredOrReference() {
        return filter != null || reference != null;
    }

    /**
     * Determine which context should be used to search filtered/referenced entry.
     * Has effect if the identity is behind referral, in different context.
     * If {@code true}, attribute will be searched in context, where was the identity found.
     * {@link DirContext} of the LdapRealm will be used otherwise.
     */
    boolean searchInIdentityContext() {
        return reference != null;
    }

    /**
     * <p>Create an attribute mapping using LDAP entry of identity itself.
     *
     * @return this builder
     */
    public static Builder fromIdentity() {
        Builder builder = new Builder();
        builder.ldapName = null;
        return builder;
    }

    /**
     * <p>Create an attribute mapping based on the results of the given {@code filter}.
     *
     * <p>The {@code filter} <em>may</em> have one and exactly one <em>{0}</em> string that will be used to replace with the distinguished
     * name of the identity. In this case, the filter is specially useful when the values for this attribute should be obtained from a
     * separated entry. For instance, retrieving roles from entries with a object class of <em>groupOfNames</em> where the identity's DN is
     * a value of a <em>member</em> attribute.
     *
     * @param filter the filter that is going to be used to search for entries and obtain values for this attribute
     * @return this builder
     */
    public static Builder fromFilter(String filter) {
        Assert.checkNotNullParam("filter", filter);
        Builder builder = new Builder();
        builder.filter = filter;
        return builder;
    }

    /**
     * <p>Create an attribute mapping using LDAP entry referenced by attribute of identity entry.
     *
     * @param reference the name of LDAP attribute containing DN of LDAP entry, from which should be value loaded.
     * @return this builder
     */
    public static Builder fromReference(String reference) {
        Assert.checkNotNullParam("reference", reference);
        Builder builder = new Builder();
        builder.reference = reference;
        return builder;
    }

    public static class Builder {

        private String ldapName;
        private String searchDn;
        private boolean recursiveSearch = true;
        private String filter;
        private String reference;
        private String name;
        private String rdn;
        private int roleRecursionDepth;
        private String roleRecursionName;

        /**
         * Set type of RDN, whose value will be used as identity attribute value.
         * Use in case the attribute value is in DN form or when DN of entry is used
         *
         * @param rdn the name of type of RDN
         * @return this builder
         */
        public Builder extractRdn(String rdn) {
            Assert.checkNotNullParam("rdn", rdn);
            this.rdn = rdn;
            return this;
        }

        /**
         * Set name of the attribute in LDAP from where the values are obtained.
         *
         * @param ldapName the name of the attribute in LDAP from where the values are obtained
         * @return this builder
         */
        public Builder from(String ldapName) {
            Assert.checkNotNullParam("ldapName", ldapName);
            this.ldapName = ldapName.toUpperCase(Locale.ROOT);
            return this;
        }

        /**
         * Set name of the attribute in LDAP from where are {0} in role recursion obtained.
         * Wildcard {0} is in filter replaced by user name usually. When role recursion is used,
         * roles of roles are searched using the same filter, but {0} is replaced by
         * role name - obtained from role entry attribute specified by this method.
         *
         * If not specified, attribute specified in {@link #from(String)} is used.
         *
         * @param roleRecursionName the name of the attribute in LDAP which will replace {0} in filter while role recursion
         * @return this builder
         */
        public Builder roleRecursionName(String roleRecursionName) {
            Assert.checkNotNullParam("roleRecursionName", roleRecursionName);
            this.roleRecursionName = roleRecursionName.toUpperCase(Locale.ROOT);
            return this;
        }

        /**
         * Set name of identity attribute to which will be mapping done.
         *
         * @param name the name of identity attribute (not LDAP attribute)
         * @return this builder
         */
        public Builder to(String name) {
            Assert.checkNotNullParam("name", name);
            this.name = name;
            return this;
        }

        /**
         * Set search DN of LDAP search for attribute entries.
         * If not specified, search DN from identity mapping will be used.
         * @param searchDn the name of the context (DN) to be used when executing the filter
         * @return this builder
         */
        public Builder searchDn(String searchDn) {
            Assert.checkNotNullParam("searchDn", searchDn);
            Assert.checkNotNullParam("filter", filter);
            this.searchDn = searchDn;
            return this;
        }

        /**
         * Set whether LDAP search for attribute entries should be recursive. Enabled by default.
         * @param recursiveSearch whether the LDAP search should be recursive
         * @return this builder
         */
        public Builder searchRecursively(boolean recursiveSearch) {
            Assert.checkNotNullParam("filter", filter);
            this.recursiveSearch = recursiveSearch;
            return this;
        }

        /**
         * Set recursive search of filtered attribute (for recursive roles assignment and similar)
         * @param roleRecursionDepth maximum depth of recursion, 0 by default (no recursion)
         * @return this builder
         */
        public Builder roleRecursion(int roleRecursionDepth) {
            Assert.checkMinimumParameter("roleRecursionDepth", 0, roleRecursionDepth);
            this.roleRecursionDepth = roleRecursionDepth;
            return this;
        }

        public AttributeMapping build() {
            if (name == null) {
                name = ldapName != null ? ldapName : (filter != null ? DEFAULT_FILTERED_NAME : DEFAULT_DN_NAME);
            }
            if (roleRecursionName == null) {
                roleRecursionName = ldapName != null ? ldapName : DEFAULT_ROLE_RECURSION_ATTRIBUTE;
            }
            return new AttributeMapping(searchDn, recursiveSearch, filter, reference, ldapName, name, rdn, roleRecursionDepth, roleRecursionName);
        }
    }

    AttributeMapping(String searchDn, boolean recursiveSearch, String filter,  String reference, String ldapName, String name, String rdn, int roleRecursionDepth, String roleRecursionName) {
        this.searchDn = searchDn;
        this.recursiveSearch = recursiveSearch;
        this.filter = filter;
        this.reference = reference;
        this.ldapName = ldapName;
        this.name = name;
        this.rdn = rdn;
        this.roleRecursionDepth = roleRecursionDepth;
        this.roleRecursionName = roleRecursionName;
    }

}