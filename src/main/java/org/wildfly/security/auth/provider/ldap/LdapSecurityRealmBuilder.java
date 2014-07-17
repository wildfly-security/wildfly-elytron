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

/**
 * Security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LdapSecurityRealmBuilder {

    private boolean built = false;
    private DirContextFactory dirContextFactory;
    private LdapSecurityRealm.PrincipalMapping principalMapping;

    private LdapSecurityRealmBuilder() {
    }

    public static LdapSecurityRealmBuilder builder() {
        return new LdapSecurityRealmBuilder();
    }

    public LdapSecurityRealmBuilder setDirContextFactory(final DirContextFactory dirContextFactory) {
        assertNotBuilt();
        this.dirContextFactory = dirContextFactory;

        return this;
    }

    public PrincipalMappingBuilder principalMapping() {
        assertNotBuilt();

        return new PrincipalMappingBuilder();
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
        return new LdapSecurityRealm(dirContextFactory, principalMapping);
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

}
