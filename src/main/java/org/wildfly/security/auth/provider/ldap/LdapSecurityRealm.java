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
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder.PrincipalMappingBuilder;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import java.security.Key;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * Security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class LdapSecurityRealm implements ModifiableSecurityRealm {

    private final DirContextFactory dirContextFactory;
    private final NameRewriter nameRewriter;
    private final PrincipalMapping principalMapping;
    private final List<CredentialLoader> credentialLoaders = new ArrayList<>();
    private final List<CredentialPersister> credentialPersisters = new ArrayList<>();

    LdapSecurityRealm(final DirContextFactory dirContextFactory, final NameRewriter nameRewriter,
                      final PrincipalMapping principalMapping) {

        this.dirContextFactory = dirContextFactory;
        this.nameRewriter = nameRewriter;
        this.principalMapping = principalMapping;
        this.credentialLoaders.add(new UserPasswordCredentialLoader(this.principalMapping.passwordAttribute));

        if (this.principalMapping.otpAlgorithmAttribute != null) {
            OtpCredentialLoader otpCredentialLoader = new OtpCredentialLoader(
                    this.principalMapping.otpAlgorithmAttribute,
                    this.principalMapping.otpHashAttribute,
                    this.principalMapping.otpSeedAttribute,
                    this.principalMapping.otpSequenceAttribute
            );
            this.credentialLoaders.add(otpCredentialLoader);
            this.credentialPersisters.add(otpCredentialLoader);
        }
    }

    @Override
    public ModifiableRealmIdentity createRealmIdentity(String name) {
        name = nameRewriter.rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }

        return new LdapRealmIdentity(name);
    }

    @Override public Iterator<ModifiableRealmIdentity> getRealmIdentityIterator() throws RealmUnavailableException {
        return null;
    }

    @Override
    public CredentialSupport getCredentialSupport(Class<?> credentialType, final String algorithmName) {
        CredentialSupport response = CredentialSupport.UNSUPPORTED;

        if (Password.class.isAssignableFrom(credentialType) == false) {
            return response;
        }

        for (CredentialLoader loader : credentialLoaders) {
            CredentialSupport support = loader.getCredentialSupport(dirContextFactory, credentialType);
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

    private class LdapRealmIdentity implements ModifiableRealmIdentity {

        private final String name;
        private LdapIdentity identity;

        LdapRealmIdentity(final String name) {
            this.name = name;
        }

        @Override
        public CredentialSupport getCredentialSupport(Class<?> credentialType, final String algorithmName) throws RealmUnavailableException {
            if (!exists()) {
                return null;
            }

            if (LdapSecurityRealm.this.getCredentialSupport(credentialType, algorithmName) == CredentialSupport.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return CredentialSupport.UNSUPPORTED;
            }

            CredentialSupport support = null;

            for (CredentialLoader loader : credentialLoaders) {
                if (loader.getCredentialSupport(dirContextFactory, credentialType).mayBeObtainable()) {
                    IdentityCredentialLoader icl = loader.forIdentity(dirContextFactory, identity.getDistinguishedName());

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
        public <C> C getCredential(Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            if (!exists()) {
                return null;
            }

            if (LdapSecurityRealm.this.getCredentialSupport(credentialType, algorithmName) == CredentialSupport.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return null;
            }

            for (CredentialLoader loader : credentialLoaders) {
                if (loader.getCredentialSupport(dirContextFactory, credentialType).mayBeObtainable()) {
                    IdentityCredentialLoader icl = loader.forIdentity(dirContextFactory, this.identity.getDistinguishedName());

                    C credential = icl.getCredential(credentialType);
                    if (credential != null) {
                        return credential;
                    }
                }
            }

            return null;
        }

        private boolean persistCredential(Object credential) throws RealmUnavailableException {
            for (CredentialPersister persister : credentialPersisters) {
                IdentityCredentialPersister icp = persister.forIdentity(dirContextFactory, this.identity.getDistinguishedName());
                if (icp.getCredentialPersistSupport(credential)) {
                    icp.persistCredential(credential);
                    return true;
                }
            }
            return false;
        }

        @Override
        public void setCredential(Object credential) throws RealmUnavailableException {
            if (!exists()) {
                throw log.ldapRealmIdentityNotExists(name);
            }

            if ( ! persistCredential(credential)) {
                String algorithm = credential instanceof Key ? ((Key) credential).getAlgorithm() : null;
                throw log.ldapRealmsPersisterNotSupportCredentialTypeAndAlgorithm(credential.getClass().getName(), algorithm);
            }
        }

        @Override
        public void setCredentials(List<Object> credentials) throws RealmUnavailableException {
            if (!exists()) {
                throw log.ldapRealmIdentityNotExists(name);
            }

            for (CredentialPersister persister : credentialPersisters) {
                IdentityCredentialPersister icp = persister.forIdentity(dirContextFactory, this.identity.getDistinguishedName());
                icp.clearCredentials();
            }

            for (Object credential : credentials) {
                if ( ! persistCredential(credential)) {
                    String algorithm = credential instanceof Key ? ((Key) credential).getAlgorithm() : null;
                    throw log.ldapRealmsPersisterNotSupportCredentialTypeAndAlgorithm(credential.getClass().getName(), algorithm);
                }
            }
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            if (!exists()) {
                return AuthorizationIdentity.EMPTY;
            }
            return AuthorizationIdentity.basicIdentity(this.identity.attributes);
        }

        @Override
        public boolean verifyCredential(final Object credential) throws RealmUnavailableException {
            if (!exists()) {
                return false;
            }

            char[] password;

            if (char[].class.isInstance(credential)) {
                password = (char[]) credential;
            } else if (ClearPassword.class.isInstance(credential)) {
                ClearPassword clearPassword = (ClearPassword) credential;
                password = clearPassword.getPassword();
            } else {
                throw log.passwordBasedCredentialsMustBeCharsOrClearPassword();
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
            if (this.identity == null) {
                this.identity = getIdentity(this.name);
            }

            boolean exists = this.identity != null;

            if (!exists) {
                log.debugf("Principal [%s] does not exists.", this.name);
            }

            return exists;
        }

        private LdapIdentity getIdentity(String principalName) throws RealmUnavailableException {
            log.debugf("Trying to create identity for principal [%s].", this.name);
            DirContext context = null;

            try {
                context = dirContextFactory.obtainDirContext(null);

                String searchDn = principalMapping.searchDn;
                String name = principalName;

                if (principalName.startsWith(principalMapping.rdnIdentifier)) {
                    LdapName ldapName = new LdapName(principalName);
                    int rdnIdentifierPosition = ldapName.size() - 1;
                    Rdn rdnIdentifier = ldapName.getRdn(rdnIdentifierPosition);

                    name = rdnIdentifier.getValue().toString();
                    ldapName.remove(rdnIdentifierPosition);
                    searchDn = ldapName.toString();
                }

                final DirContext finalContext = context;

                LdapSearch ldapSearch = new LdapSearch(searchDn, String.format("(%s={0})", principalMapping.rdnIdentifier), name);

                ldapSearch.setReturningAttributes(
                        principalMapping.attributes.stream()
                                .map(PrincipalMappingBuilder.Attribute::getLdapName)
                                .toArray(String[]::new));

                try (
                    Stream<LdapIdentity> identityStream = ldapSearch.search(context)
                            .map(result -> {
                                MapAttributes identityAttributes = new MapAttributes();

                                identityAttributes.addAll(extractSingleAttributes(result));
                                identityAttributes.addAll(extractFilteredAttributes(result, finalContext));

                                return new LdapIdentity(result.getNameInNamespace(), identityAttributes.asReadOnly());
                            });
                ) {
                    Optional<LdapIdentity> optional = identityStream.findFirst();

                    if (optional.isPresent()) {
                        LdapIdentity identity = optional.get();

                        if (log.isDebugEnabled()) {
                            log.debugf("Successfully created identity for principal [%s].", principalName);

                            if (identity.attributes.isEmpty()) {
                                log.debugf("Identity [%s] does not have any attributes.", principalName);
                            } else {
                                log.debugf("Identity [%s] attributes are:", principalName);
                                identity.attributes.keySet().forEach(key -> {
                                    org.wildfly.security.authz.Attributes.Entry values = identity.attributes.get(key);
                                    values.forEach(value -> log.debugf("    Attribute [%s] value [%s].", key, value));
                                });
                            }

                        }

                        return identity;
                    }

                    return null;
                }

            } catch (NamingException e) {
                throw log.ldapRealmFailedObtainIdentityFromServer(e);
            } finally {
                dirContextFactory.returnContext(context);
            }
        }

        private Map<String, Collection<String>> extractFilteredAttributes(SearchResult result, DirContext context) {
            String principalDn = result.getNameInNamespace();

            return extractAttributes(attribute -> attribute.getFilter() != null, attribute -> {
                Collection<String> values = new ArrayList<>();

                String searchDn = attribute.getSearchDn();

                if (searchDn == null) {
                    searchDn = principalMapping.searchDn;
                }

                LdapSearch search = new LdapSearch(searchDn, attribute.getFilter(), principalDn);

                search.setReturningAttributes(attribute.getLdapName());

                try (
                    Stream<SearchResult> searchResult = search.search(context);
                ) {
                    searchResult.forEach(entry -> {
                        String valueRdn = attribute.getRdn();

                        if (valueRdn != null) {
                            String entryDn = entry.getNameInNamespace();

                            try {
                                for (Rdn rdn : new LdapName(entryDn).getRdns()) {
                                    if (rdn.getType().equalsIgnoreCase(valueRdn)) {
                                        values.add(rdn.getValue().toString());
                                        break;
                                    }
                                }
                            } catch (Exception cause) {
                                throw log.ldapRealmInvalidRdnForAttribute(attribute.getName(), entryDn, valueRdn);
                            }
                        } else {
                            Attributes entryAttributes = entry.getAttributes();
                            Attribute ldapAttribute = entryAttributes.get(attribute.getLdapName());
                            NamingEnumeration<?> attributeValues = null;

                            try {
                                attributeValues = ldapAttribute.getAll();

                                while (attributeValues.hasMore()) {
                                    values.add(attributeValues.next().toString());
                                }
                            } catch (Exception cause) {
                                throw ElytronMessages.log.ldapRealmFailedObtainAttributes(principalDn, cause);
                            } finally {
                                if (attributeValues != null) {
                                    try {
                                        attributeValues.close();
                                    } catch (NamingException ignore) {
                                    }
                                }
                            }
                        }
                    });
                } catch (Exception cause) {
                    throw ElytronMessages.log.ldapRealmFailedObtainAttributes(principalDn, cause);
                }

                return values;
            });
        }

        private Map<String, Collection<String>> extractSingleAttributes(SearchResult searchResult) {
            return extractAttributes(attribute -> attribute.getFilter() == null, attribute -> {
                Attributes returnedAttributes = searchResult.getAttributes();
                NamingEnumeration<? extends Attribute> attributesEnum = returnedAttributes.getAll();
                Collection<String> values = new ArrayList<>();

                try {
                    while (attributesEnum.hasMore()) {
                        Attribute ldapAttribute = attributesEnum.next();

                        if (!ldapAttribute.getID().equalsIgnoreCase(attribute.getLdapName())) {
                            continue;
                        }

                        NamingEnumeration<?> attributeValues = ldapAttribute.getAll();

                        try {
                            while (attributeValues.hasMore()) {
                                String value = attributeValues.next().toString();
                                String valueRdn = attribute.getRdn();

                                if (valueRdn != null) {
                                    try {
                                        for (Rdn rdn : new LdapName(value).getRdns()) {
                                            if (rdn.getType().equalsIgnoreCase(valueRdn)) {
                                                value = rdn.getValue().toString();
                                                break;
                                            }
                                        }
                                    } catch (Exception cause) {
                                        throw log.ldapRealmInvalidRdnForAttribute(attribute.getName(), value, valueRdn);
                                    }
                                }

                                values.add(value);
                            }
                        } finally {
                            if (attributeValues != null) {
                                try {
                                    attributeValues.close();
                                } catch (NamingException ignore) {
                                }
                            }
                        }
                    }
                } catch (NamingException cause) {
                    throw ElytronMessages.log.ldapRealmFailedObtainAttributes(searchResult.getNameInNamespace(), cause);
                }

                return values;
            });
        }

        private SearchControls createSearchControls(String... returningAttributes) {
            SearchControls searchControls = new SearchControls();

            searchControls.setSearchScope(principalMapping.searchRecursive ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE);
            searchControls.setTimeLimit(principalMapping.searchTimeLimit);
            searchControls.setReturningAttributes(returningAttributes);

            return searchControls;
        }

        private Map<String, Collection<String>> extractAttributes(Predicate<PrincipalMappingBuilder.Attribute> filter, Function<PrincipalMappingBuilder.Attribute, Collection<String>> valueFunction) {
            return principalMapping.attributes.stream()
                    .filter(filter)
                    .collect(Collectors.toMap(attribute -> attribute.getName(), valueFunction, (m1, m2) -> {
                        List<String> merged = new ArrayList<>(m1);

                        merged.addAll(m2);

                        return merged;
                    }));
        }

        @Override public void delete() throws RealmUnavailableException {
            throw Assert.unsupported();
        }

        @Override public void create() throws RealmUnavailableException {
            throw Assert.unsupported();
        }

        @Override public void setAttributes(org.wildfly.security.authz.Attributes attributes) throws RealmUnavailableException {
            throw Assert.unsupported();
        }

        private class LdapIdentity {

            private final String distinguishedName;
            private final org.wildfly.security.authz.Attributes attributes;

            LdapIdentity(String distinguishedName, org.wildfly.security.authz.Attributes attributes) {
                this.distinguishedName = distinguishedName;
                this.attributes = attributes;
            }

            String getDistinguishedName() {
                return this.distinguishedName;
            }
        }

        private class LdapSearch {

            private final String[] filterArgs;
            private final String searchDn;
            private final String filter;
            private String[] returningAttributes;

            public LdapSearch(String searchDn, String filter, String... filterArgs) {
                this.searchDn = searchDn;
                this.filter = filter;
                this.filterArgs = filterArgs;
            }

            public Stream<SearchResult> search(DirContext context) throws RealmUnavailableException {
                log.debugf("Executing search [%s] in context [%s] with arguments [%s]. Returning attributes are [%s]", this.filter, this.searchDn, this.filterArgs, this.returningAttributes);

                try {
                    NamingEnumeration<SearchResult> result = context.search(searchDn, filter, filterArgs,
                            createSearchControls(this.returningAttributes));

                    return StreamSupport.stream(new Spliterators.AbstractSpliterator<SearchResult>(Long.MAX_VALUE, Spliterator.NONNULL) {
                        @Override
                        public boolean tryAdvance(Consumer<? super SearchResult> action) {
                            try {
                                if (!result.hasMore()) {
                                    return false;
                                }

                                SearchResult entry = result.next();

                                log.debugf("Found entry [%s].", entry.getNameInNamespace());

                                action.accept(entry);

                                return true;
                            } catch (NamingException e) {
                                throw log.ldapRealmErrorWhileConsumingResultsFromSearch(searchDn, filter, filterArgs.toString(), e);
                            }
                        }
                    }, false).onClose(() -> {
                        if (result != null) {
                            try {
                                result.close();
                            } catch (NamingException ignore) {
                            }
                        }
                    });
                } catch (Exception cause) {
                    throw log.ldapRealmFailedObtainIdentityFromServer(cause);
                }
            }

            public void setReturningAttributes(String... returningAttributes) {
                this.returningAttributes = returningAttributes;
            }
        }
    }

    static class PrincipalMapping {

        private final String searchDn;
        private final boolean searchRecursive;
        private final String rdnIdentifier;
        private final String passwordAttribute;
        private final String otpAlgorithmAttribute;
        private final String otpHashAttribute;
        private final String otpSeedAttribute;
        private final String otpSequenceAttribute;
        private final List<PrincipalMappingBuilder.Attribute> attributes;
        public final int searchTimeLimit;

        public PrincipalMapping(String searchDn, boolean searchRecursive, int searchTimeLimit, String rdnIdentifier,
                                String passwordAttribute, String otpAlgorithmAttribute, String otpHashAttribute,
                                String otpSeedAttribute, String otpSequenceAttribute,
                                List<PrincipalMappingBuilder.Attribute> attributes) {
            Assert.checkNotNullParam("rdnIdentifier", rdnIdentifier);
            Assert.checkNotNullParam("passwordAttribute", passwordAttribute);
            this.searchDn = searchDn;
            this.searchRecursive = searchRecursive;
            this.searchTimeLimit = searchTimeLimit;
            this.rdnIdentifier = rdnIdentifier;
            this.passwordAttribute = passwordAttribute;
            this.otpAlgorithmAttribute = otpAlgorithmAttribute;
            this.otpHashAttribute = otpHashAttribute;
            this.otpSeedAttribute = otpSeedAttribute;
            this.otpSequenceAttribute = otpSequenceAttribute;
            this.attributes = attributes;
        }
    }
}
