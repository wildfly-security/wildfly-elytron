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

import org.wildfly.common.Assert;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * Security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class LdapSecurityRealm implements SecurityRealm {

    private final DirContextFactory dirContextFactory;
    private final NameRewriter nameRewriter;
    private final PrincipalMapping principalMapping;
    private final List<CredentialLoader> credentialLoaders = new ArrayList<>();

    LdapSecurityRealm(final DirContextFactory dirContextFactory, final NameRewriter nameRewriter,
            final PrincipalMapping principalMapping) {
        this.dirContextFactory = dirContextFactory;
        this.nameRewriter = nameRewriter;
        this.principalMapping = principalMapping;
        this.credentialLoaders.add(new UserPasswordCredentialLoader(this.principalMapping.passwordAttribute));
    }

    @Override
    public RealmIdentity createRealmIdentity(String name) {
        name = nameRewriter.rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }

        return new LdapRealmIdentity(name);
    }

    @Override
    public CredentialSupport getCredentialSupport(Class<?> credentialType) {
        CredentialSupport response = CredentialSupport.UNSUPPORTED;

        if (Password.class.isAssignableFrom(credentialType) == false) {
            return response;
        }

        for (CredentialLoader current : credentialLoaders) {
            CredentialSupport support = current.getCredentialSupport(dirContextFactory, credentialType);
            if (support.isDefinitelyObtainable()) {
                // One claiming it is definitely supported is enough!
                return support;
            }
            if (response.compareTo(support) < 0) {
                response = support;
            }
        }

        return response;
    }

    private class LdapRealmIdentity implements RealmIdentity {

        private String name;
        private LdapIdentity identity;

        private LdapRealmIdentity(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }

        @Override
        public CredentialSupport getCredentialSupport(Class<?> credentialType) throws RealmUnavailableException {
            if (!exists()) {
                return null;
            }

            if (LdapSecurityRealm.this.getCredentialSupport(credentialType) == CredentialSupport.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return CredentialSupport.UNSUPPORTED;
            }

            CredentialSupport support = null;

            for (CredentialLoader current : credentialLoaders) {
                if (current.getCredentialSupport(dirContextFactory, credentialType).mayBeObtainable()) {
                    IdentityCredentialLoader icl = current.forIdentity(dirContextFactory, identity.getDistinguishedName());

                    CredentialSupport temp = icl.getCredentialSupport(credentialType);
                    if (temp != null && temp.isDefinitelyObtainable()) {
                        // As soon as one claims definite support we know it is supported.
                        return temp;
                    }

                    if (support == null || temp != null && support.compareTo(temp) < 0) {
                        support = temp;
                    }
                }
            }

            if (support == null) {
                return CredentialSupport.UNSUPPORTED;
            }

            return support;
        }

        @Override
        public <C> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
            if (!exists()) {
                return null;
            }

            if (LdapSecurityRealm.this.getCredentialSupport(credentialType) == CredentialSupport.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return null;
            }

            for (CredentialLoader current : credentialLoaders) {
                if (current.getCredentialSupport(dirContextFactory, credentialType).mayBeObtainable()) {
                    IdentityCredentialLoader icl = current.forIdentity(dirContextFactory, this.identity.getDistinguishedName());

                    C credential = icl.getCredential(credentialType);
                    if (credential != null) {
                        return credential;
                    }
                }
            }

            return null;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() {
            return new AuthorizationIdentity() {
            };
        }

        @Override
        public boolean verifyCredential(final Object credential) throws RealmUnavailableException {
            if (!exists()) {
                return false;
            }

            char[] password;

            if (char[].class.isInstance(credential)) {
                password = (char[]) credential;
            } else if (String.class.isInstance(credential)) {
                password = credential.toString().toCharArray();
            } else if (ClearPassword.class.isInstance(credential)) {
                ClearPassword clearPassword = (ClearPassword) credential;
                password = clearPassword.getPassword();
            } else {
                throw log.passwordBasedCredentialsMustBeStringCharsOrClearPassword();
            }

            DirContext dirContext = null;

            try {
                // TODO: for not we just create a DirContext using the provided credentials. Need to also support referrals.
                dirContext = dirContextFactory.obtainDirContext(callbacks -> {
                    for (Callback callback : callbacks) {
                        if (NameCallback.class.isInstance(callback)) {
                            NameCallback nameCallback = (NameCallback) callback;
                            nameCallback.setName(this.identity.getDistinguishedName());
                        } else if (PasswordCallback.class.isInstance(callback)) {
                            PasswordCallback nameCallback = (PasswordCallback) callback;
                            nameCallback.setPassword(password);
                        }
                    }
                }, null);

                return true;
            } catch (NamingException e) {
                log.debugf("Credential verification failed.", e);
            } finally {
                dirContextFactory.returnContext(dirContext);
            }

            return false;
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            if (identity == null) {
                identity = getIdentity(name);
            }

            return identity != null;
        }

        private LdapIdentity getIdentity(String name) throws RealmUnavailableException {
            DirContext context = null;
            NamingEnumeration<SearchResult> searchResult = null;

            try {
                SearchControls searchControls = new SearchControls();

                searchControls.setSearchScope(principalMapping.searchRecursive ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE);
                searchControls.setTimeLimit(principalMapping.searchTimeLimit);

                searchControls.setReturningAttributes(new String[] {principalMapping.nameAttribute});

                String searchDn = principalMapping.searchDn;
                String simpleName = name;

                if (name.startsWith(principalMapping.nameAttribute)) {
                    simpleName = name.substring(principalMapping.nameAttribute.length() + 1, name.indexOf(','));
                    searchDn = name.substring(name.indexOf(',') + 1);
                }

                Object[] filterArg = new Object[] {simpleName};
                String filter = String.format("(%s={0})", principalMapping.nameAttribute);

                context = dirContextFactory.obtainDirContext(null); // TODO - Referral Mode
                searchResult = context.search(searchDn, filter, filterArg, searchControls);

                if (searchResult.hasMore()) {
                    SearchResult result = searchResult.next();

                    if (searchResult.hasMore()) {
                        throw log.searchReturnedTooManyResults();
                    }

                    return new LdapIdentity(simpleName, result.getNameInNamespace());
                }
            } catch (NamingException e) {
                throw log.ldapRealmFailedObtainIdentityFromServer(e);
            } finally {
                if (searchResult != null) {
                    try {
                        searchResult.close();
                    } catch (NamingException ignore) {
                    }
                }
                dirContextFactory.returnContext(context);
            }

            return null;
        }

        private class LdapIdentity {

            private final String simpleName;
            private final String distinguishedName;
            private final Principal principal;

            LdapIdentity(String simpleName, String distinguishedName) {
                this.simpleName = simpleName;
                this.distinguishedName = distinguishedName;
                this.principal = null;
            }

            String getDistinguishedName() {
                return this.distinguishedName;
            }

            Principal toPrincipal() {
                return this.principal;
            }
        }
    }

    static class PrincipalMapping {

        private final String searchDn;
        private final boolean searchRecursive;
        private final String nameAttribute;
        private final String passwordAttribute;
        public int searchTimeLimit;

        public PrincipalMapping(String searchDn, boolean searchRecursive, int searchTimeLimit, String nameAttribute, String passwordAttribute) {
            Assert.checkNotNullParam("nameAttribute", nameAttribute);
            Assert.checkNotNullParam("passwordAttribute", passwordAttribute);
            this.searchDn = searchDn;
            this.searchRecursive = searchRecursive;
            this.searchTimeLimit = searchTimeLimit;
            this.nameAttribute = nameAttribute;
            this.passwordAttribute = passwordAttribute;
        }
    }
}
