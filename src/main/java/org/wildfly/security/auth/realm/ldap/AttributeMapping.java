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
    private final String filter;
    private String name;
    private String rdn;

    /**
     * Create an attribute mapping based on the given attribute in LDAP.
     *
     * @param ldapName the name of the attribute in LDAP from where values are obtained
     * @return this builder
     */
    public static AttributeMapping from(String ldapName) {
        Assert.checkNotNullParam("ldapName", ldapName);
        return new AttributeMapping(ldapName);
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
    public static AttributeMapping fromFilter(String searchDn, String filter, String ldapName) {
        Assert.checkNotNullParam("searchDn", searchDn);
        Assert.checkNotNullParam("filter", filter);
        Assert.checkNotNullParam("ldapName", ldapName);
        return new AttributeMapping(searchDn, filter, ldapName);
    }

    /**
     * <p>The behavior is exactly the same as {@link #fromFilter(String, String, String)}, except that it uses the
     * same name of the context defined in {@link org.wildfly.security.auth.realm.ldap.LdapSecurityRealmBuilder.IdentityMappingBuilder#setSearchDn(String)}.
     *
     * @param filter the filter that is going to be used to search for entries and obtain values for this attribute
     * @param ldapName the name of the attribute in LDAP from where the values are obtained
     * @return this builder
     */
    public static AttributeMapping fromFilter(String filter, String ldapName) {
        Assert.checkNotNullParam("filter", filter);
        Assert.checkNotNullParam("ldapName", ldapName);
        return new AttributeMapping(null, filter, ldapName);
    }

    AttributeMapping(String ldapName) {
        this(null, null, ldapName);
    }

    AttributeMapping(String searchDn, String filter, String ldapName) {
        Assert.checkNotNullParam("ldapName", ldapName);
        this.searchDn = searchDn;
        this.filter = filter;
        this.ldapName = ldapName.toUpperCase(Locale.ROOT);
    }

    public AttributeMapping asRdn(String rdn) {
        Assert.checkNotNullParam("rdn", rdn);
        this.rdn = rdn;
        return this;
    }

    public AttributeMapping to(String name) {
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