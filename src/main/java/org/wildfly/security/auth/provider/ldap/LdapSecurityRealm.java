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

import java.security.Principal;
import java.util.ArrayList;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.x500.X500Principal;

import org.wildfly.security.auth.SecurityIdentity;
import org.wildfly.security.auth.login.AuthenticationException;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.provider.CredentialSupport;
import org.wildfly.security.auth.provider.SecurityRealm;
import org.wildfly.security.auth.verifier.Verifier;

/**
 * Security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class LdapSecurityRealm implements SecurityRealm {

    private final DirContextFactory dirContextFactory;
    private final PrincipalMapping principalMapping;
    private final PrincipalMapper principalMapper;

    LdapSecurityRealm(final DirContextFactory dirContextFactory, final PrincipalMapping principalMapping) {
        this.dirContextFactory = dirContextFactory;
        this.principalMapping = principalMapping;
        principalMapper = initialisePrincipalMapper(principalMapping);
    }

    private PrincipalMapper initialisePrincipalMapper(final PrincipalMapping principalMapping) {
        if (principalMapping.principalUseDn) {
            if (principalMapping.nameIsDn && principalMapping.validatePresence == false
                    && principalMapping.reloadPrincipalName == false) {
                return new ToDnMapper();
            }

            return new LoadToDnMapper();
        } else {
            if (principalMapping.nameIsDn == false && principalMapping.validatePresence == false
                    && principalMapping.reloadPrincipalName == false) {
                return new ToNameMapper();
            }

            return new LoadToNameMapper();
        }
    }

    @Override
    public Principal mapNameToPrincipal(String name) {
        try {
            return principalMapper.mapNameToPrincipal(name);
        } catch (NamingException e) {
            return null;
        }
    }

    @Override
    public <C> C getCredential(Class<C> credentialType, Principal principal) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public <P> P proveAuthentic(Principal principal, Verifier<P> verifier) throws AuthenticationException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public CredentialSupport getCredentialSupport(Class<?> credentialType) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public CredentialSupport getCredentialSupport(Principal principal, Class<?> credentialType) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public SecurityIdentity createSecurityIdentity(Principal principal) {
        // TODO Auto-generated method stub
        return null;
    }

    static class PrincipalMapping {

        private final String searchDn;
        private final boolean recursive;
        private final boolean nameIsDn;
        private final boolean principalUseDn;
        private final String nameAttribute;
        private final String dnAttribute;
        private final boolean validatePresence;
        private final boolean reloadPrincipalName;

        public PrincipalMapping(String searchDn, boolean recursive, boolean nameIsDn, boolean principalUseDn,
                String nameAttribute, String dnAttribute, boolean validatePresence, boolean reloadPrincipalName) {
            this.searchDn = searchDn;
            this.recursive = recursive;
            this.nameIsDn = nameIsDn;
            this.principalUseDn = principalUseDn;
            this.nameAttribute = nameAttribute;
            this.dnAttribute = dnAttribute;
            this.validatePresence = validatePresence;
            this.reloadPrincipalName = reloadPrincipalName;
        }

    }

    private String loadName(final String providedName, final boolean toDistinguishedName) throws NamingException {
        DirContext context = null;
        NamingEnumeration<SearchResult> searchResult = null;
        try {
            String distinguishedName = null;
            String simpleName = null;
            if (principalMapping.nameIsDn) {
                distinguishedName = providedName;

                context = dirContextFactory.obtainDirContext(null); // TODO - Referral Mode
                ArrayList<String> requiredAttributes = new ArrayList<String>(2);
                if (principalMapping.reloadPrincipalName) {
                    requiredAttributes.add(principalMapping.dnAttribute);
                }
                if (principalMapping.nameAttribute != null) {
                    requiredAttributes.add(principalMapping.nameAttribute);
                }

                Attributes attributes = context.getAttributes(distinguishedName,
                        requiredAttributes.toArray(new String[requiredAttributes.size()]));
                if (principalMapping.nameAttribute != null) {
                    Attribute nameAttribute = attributes.get(principalMapping.nameAttribute);
                    if (nameAttribute != null) {
                        simpleName = (String) nameAttribute.get();
                    }
                }

                if (principalMapping.reloadPrincipalName) {
                    Attribute dnAttribute = attributes.get(principalMapping.dnAttribute);
                    if (dnAttribute != null) {
                        distinguishedName = (String) dnAttribute.get();
                    }
                }
            } else {
                simpleName = providedName;
                SearchControls searchControls = new SearchControls();
                searchControls.setSearchScope(principalMapping.recursive ? SearchControls.SUBTREE_SCOPE
                        : SearchControls.ONELEVEL_SCOPE);
                searchControls.setTimeLimit(10000); // TODO - Make Config

                context = dirContextFactory.obtainDirContext(null); // TODO - Referral Mode
                ArrayList<String> requiredAttributes = new ArrayList<String>(2);
                if (principalMapping.reloadPrincipalName) {
                    requiredAttributes.add(principalMapping.nameAttribute);
                }
                if (principalMapping.dnAttribute != null) {
                    requiredAttributes.add(principalMapping.dnAttribute);
                }

                if (requiredAttributes.size() > 0) {
                searchControls.setReturningAttributes(requiredAttributes.toArray(new String[requiredAttributes.size()]));
                }

                Object[] filterArg = new Object[] { providedName };
                String filter = String.format("(%s={0})", principalMapping.nameAttribute);

                searchResult = context.search(principalMapping.searchDn, filter, filterArg, searchControls);
                if (searchResult.hasMore()) {
                    SearchResult result = searchResult.next();
                    if (searchResult.hasMore()) {
                        return null; // TOO Many Entries Matched.
                    }

                    Attributes attributes = result.getAttributes();
                    if (principalMapping.dnAttribute != null) {
                        Attribute dn = attributes.get(principalMapping.dnAttribute);
                        if (dn != null) {
                            distinguishedName = (String) dn.get();
                        }
                    }
                    if (distinguishedName == null) {
                        distinguishedName = result.getName()
                                + ("".equals(principalMapping.searchDn) ? "" : "," + principalMapping.searchDn);
                    }
                    if (principalMapping.reloadPrincipalName) {
                        Attribute nameAttribute = attributes.get(principalMapping.nameAttribute);
                        if (nameAttribute != null) {
                            simpleName = (String) nameAttribute.get();
                        }
                    }
                } else {
                    return null;
                }
            }

            return toDistinguishedName ? distinguishedName : simpleName;

        } finally {
            if (searchResult != null) {
                searchResult.close();
            }
            if (context != null) {
                dirContextFactory.returnContext(context);
            }
        }
    }

    private interface PrincipalMapper {
        Principal mapNameToPrincipal(String name) throws NamingException;
    }

    private class ToNameMapper implements PrincipalMapper {

        @Override
        public Principal mapNameToPrincipal(String name) throws NamingException {
            return new NamePrincipal(name);
        }

    }

    private class ToDnMapper extends ToNameMapper {

        @Override
        public Principal mapNameToPrincipal(String name) throws NamingException {
            try {
                return new X500Principal(name);
            } catch (IllegalArgumentException e) {
                return super.mapNameToPrincipal(name);
            }
        }
    }

    private class LoadToDnMapper extends ToDnMapper {

        @Override
        public Principal mapNameToPrincipal(String name) throws NamingException {
            name = loadName(name, true);
            return name == null ? null : super.mapNameToPrincipal(name);
        }

    }

    private class LoadToNameMapper extends ToNameMapper {

        @Override
        public Principal mapNameToPrincipal(String name) throws NamingException {
            name = loadName(name, false);
            return name == null ? null : super.mapNameToPrincipal(name);
        }

    }

}
