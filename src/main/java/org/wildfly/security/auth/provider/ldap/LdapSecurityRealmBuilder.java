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

import org.wildfly.security.auth.provider.CredentialSupport;
import org.wildfly.security.auth.util.NameRewriter;

/**
 * Security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LdapSecurityRealmBuilder {

    private boolean built = false;
    private String realmName = null;
    private DirContextFactory dirContextFactory;
    private List<NameRewriter> nameRewriters = new LinkedList<NameRewriter>();
    private LdapSecurityRealm.PrincipalMapping principalMapping;
    private List<CredentialLoader> credentialLoaders = new LinkedList<CredentialLoader>();

    private LdapSecurityRealmBuilder() {
    }

    public static LdapSecurityRealmBuilder builder() {
        return new LdapSecurityRealmBuilder();
    }

    public LdapSecurityRealmBuilder setRealmName(final String realmName) {
        assertNotBuilt();
        this.realmName = realmName;

        return this;
    }

    public LdapSecurityRealmBuilder setDirContextFactory(final DirContextFactory dirContextFactory) {
        assertNotBuilt();
        this.dirContextFactory = dirContextFactory;

        return this;
    }

    public LdapSecurityRealmBuilder addNameRewriter(final NameRewriter nameReWriter) {
        assertNotBuilt();
        nameRewriters.add(nameReWriter);

        return this;
    }

    public PrincipalMappingBuilder principalMapping() {
        assertNotBuilt();

        return new PrincipalMappingBuilder();
    }

    public UserPasswordCredentialLoaderBuilder userPassword() {
        assertNotBuilt();

        return new UserPasswordCredentialLoaderBuilder();
    }

    public LdapSecurityRealm build() {
        assertNotBuilt();
        if (dirContextFactory == null) {
            throw new IllegalStateException("No DirContextFactory set.");
        }
        if (principalMapping == null) {
            throw new IllegalStateException("No principal mapping definition.");
        }

        built = true;
        return new LdapSecurityRealm(realmName, dirContextFactory, nameRewriters, principalMapping, credentialLoaders);
    }

    private void assertNotBuilt() {
        if (built) {
            throw new IllegalStateException("Builder has already been built.");
        }
    }

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


        public PrincipalMappingBuilder setSearchDn(final String searchDn) {
            assertNotBuilt();
            this.searchDn = searchDn;

            return this;
        }

        public PrincipalMappingBuilder setRecursive(final boolean recursive) {
            assertNotBuilt();
            this.recursive = recursive;

            return this;
        }

        public PrincipalMappingBuilder setNameIsDn(final boolean nameIsDn) {
            assertNotBuilt();
            this.nameIsDn = nameIsDn;

            return this;
        }

        public PrincipalMappingBuilder setPrincipalUseDn(final boolean principalUseDn) {
            assertNotBuilt();
            this.principalUseDn = principalUseDn;

            return this;
        }

        public PrincipalMappingBuilder setNameAttribute(final String nameAttribute) {
            assertNotBuilt();
            this.nameAttribute = nameAttribute;

            return this;
        }

        public PrincipalMappingBuilder setDnAttribute(final String dnAttribute) {
            assertNotBuilt();
            this.dnAttribute = dnAttribute;

            return this;
        }

        public PrincipalMappingBuilder setValidatePresence(final boolean validatePresence) {
            assertNotBuilt();
            this.validatePresence = validatePresence;

            return this;
        }

        public PrincipalMappingBuilder setReloadPrincipalName(final boolean reloadPrincipalName) {
            assertNotBuilt();
            this.reloadPrincipalName = reloadPrincipalName;

            return this;
        }

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

    public class UserPasswordCredentialLoaderBuilder {

        private boolean built = false;
        private String userPasswordAttributeName = UserPasswordCredentialLoader.DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME;
        private Map<Class<?>, CredentialSupport> credentialSupportMap = new HashMap<Class<?>, CredentialSupport>();

        public UserPasswordCredentialLoaderBuilder setUserPasswordAttributeName(final String userPasswordAttributeName) {
            assertNotBuilt();
            this.userPasswordAttributeName = userPasswordAttributeName;

            return this;
        }

        public UserPasswordCredentialLoaderBuilder addCredentialSupport(final Class<?> credentialType, final CredentialSupport support) {
            assertNotBuilt();
            credentialSupportMap.put(credentialType, support);

            return this;
        }

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
