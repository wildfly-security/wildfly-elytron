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

/**
 * Definition of a mapping from LDAP to an Elytron attribute.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AttributeMapping {

    private final String ldapName;
    private final String searchDn;
    private final boolean recursiveSearch;
    private final String filter;
    private final String name;
    private final String rdn;
    private final int recursiveDepth;

    String getLdapName() {
        return ldapName;
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

    int getRecursiveDepth() {
        return recursiveDepth;
    }

    boolean isFiltered() {
        return filter != null;
    }

    /**
     * <p>Create an attribute mapping based on the given attribute in LDAP.
     * Attribute of the identity LDAP entry will be used as identity attribute value.
     *
     * @param ldapName the name of the attribute in LDAP from where values are obtained
     * @return this builder
     */
    public static Builder fromAttribute(String ldapName) {
        Assert.checkNotNullParam("ldapName", ldapName);
        Builder builder = new Builder();
        builder.ldapName = ldapName.toUpperCase(Locale.ROOT);
        builder.name = builder.ldapName;
        return builder;
    }

    /**
     * <p>Create an attribute mapping based on DN in LDAP.
     * The DN of LDAP entry of the identity will be used as identity attribute value.
     *
     * @return this builder
     */
    public static Builder fromDn() {
        Builder builder = new Builder();
        builder.ldapName = null;
        builder.name = "dn";
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
     * @param ldapName the name of the attribute in LDAP from where the values are obtained
     * @return this builder
     */
    public static Builder fromFilter(String filter, String ldapName) {
        Assert.checkNotNullParam("filter", filter);
        Assert.checkNotNullParam("ldapName", ldapName);
        Builder builder = new Builder();
        builder.filter = filter;
        builder.ldapName = ldapName.toUpperCase(Locale.ROOT);
        builder.name = builder.ldapName;
        return builder;
    }

    /**
     * <p>The behavior is exactly the same as {@link #fromFilter(String, String)}, except that instead
     * of attribute value is DN of found entries used. As the search DN is used search DN from identity mapping.
     *
     * @param filter the filter that is going to be used to search for entries and obtain values for this attribute
     * @return this builder
     */
    public static Builder fromFilterDn(String filter) {
        Assert.checkNotNullParam("filter", filter);
        Builder builder = new Builder();
        builder.filter = filter;
        builder.name = "dn";
        return builder;
    }

    public static class Builder {

        private String ldapName;
        private String searchDn;
        private boolean recursiveSearch = true;
        private String filter;
        private String name;
        private String rdn;
        private int recursiveDepth;

        /**
         * Set type of RDN, whose value will be used as identity attribute value.
         * Use in case the attribute value is in DN form or when DN of entry is used.
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
            this.searchDn = searchDn;
            return this;
        }

        /**
         * Set whether LDAP search for attribute entries should be recursive
         * @param recursiveSearch whether the LDAP search should be recursive
         * @return this builder
         */
        public Builder searchRecursively(boolean recursiveSearch) {
            this.recursiveSearch = recursiveSearch;
            return this;
        }

        /**
         * Set recursive search of filtered attribute (for recursive roles assignment and similar)
         * @param recursiveDepth maximum depth of recursion, 0 by default (direct only)
         * @return this builder
         */
        public Builder roleRecursion(int recursiveDepth) {
            Assert.checkMinimumParameter("recursiveDepth", 0, recursiveDepth);
            Assert.checkNotNullParam("filter", filter);
            this.recursiveDepth = recursiveDepth;
            return this;
        }

        public AttributeMapping build() {
            return new AttributeMapping(searchDn, recursiveSearch, filter, ldapName, name, rdn, recursiveDepth);
        }
    }

    AttributeMapping(String searchDn, boolean recursiveSearch, String filter, String ldapName, String name, String rdn, int recursiveDepth) {
        this.searchDn = searchDn;
        this.recursiveSearch = recursiveSearch;
        this.filter = filter;
        this.ldapName = ldapName;
        this.name = name;
        this.rdn = rdn;
        this.recursiveDepth = recursiveDepth;
    }

}