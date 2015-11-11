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

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * Security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LdapSecurityRealm implements ModifiableSecurityRealm {

    private final DirContextFactory dirContextFactory;
    private final NameRewriter nameRewriter;
    private final IdentityMapping identityMapping;
    private final List<CredentialLoader> credentialLoaders;
    private final List<CredentialPersister> credentialPersisters;
    private final List<EvidenceVerifier> evidenceVerifiers;

    LdapSecurityRealm(final DirContextFactory dirContextFactory, final NameRewriter nameRewriter,
                      final IdentityMapping identityMapping,
                      final List<CredentialLoader> credentialLoaders,
                      final List<CredentialPersister> credentialPersisters,
                      final List<EvidenceVerifier> evidenceVerifiers) {

        this.dirContextFactory = dirContextFactory;
        this.nameRewriter = nameRewriter;
        this.identityMapping = identityMapping;

        this.credentialLoaders = credentialLoaders;
        this.credentialPersisters = credentialPersisters;
        this.evidenceVerifiers = evidenceVerifiers;
    }

    @Override
    public ModifiableRealmIdentity createRealmIdentity(String name) {
        name = nameRewriter.rewriteName(name);
        if (name == null) {
            throw log.invalidName();
        }

        return new LdapRealmIdentity(name);
    }

    @Override
    public Iterator<ModifiableRealmIdentity> getRealmIdentityIterator() throws RealmUnavailableException {
        return null;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final String credentialName) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialName", credentialName);
        SupportLevel response = SupportLevel.UNSUPPORTED;

        for (CredentialLoader loader : credentialLoaders) {
            SupportLevel support = loader.getCredentialAcquireSupport(dirContextFactory, credentialName);
            if (support.isDefinitelySupported()) {
                // One claiming it is definitely supported is enough!
                return support;
            }
            if (response.compareTo(support) < 0) {
                response = support;
            }
        }

        return response;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(String credentialName) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialName", credentialName);
        SupportLevel response = SupportLevel.UNSUPPORTED;

        for (EvidenceVerifier verifier : evidenceVerifiers) {
            SupportLevel support = verifier.getEvidenceVerifySupport(dirContextFactory, credentialName);
            if (support.isDefinitelySupported()) {
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
        public SupportLevel getCredentialAcquireSupport(final String credentialName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialName", credentialName);
            if (!exists()) {
                return null;
            }

            if (LdapSecurityRealm.this.getCredentialAcquireSupport(credentialName) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return SupportLevel.UNSUPPORTED;
            }

            SupportLevel support = SupportLevel.UNSUPPORTED;

            for (CredentialLoader loader : credentialLoaders) {
                if (loader.getCredentialAcquireSupport(dirContextFactory, credentialName).mayBeSupported()) {
                    IdentityCredentialLoader icl = loader.forIdentity(dirContextFactory, identity.getDistinguishedName());

                    SupportLevel temp = icl.getCredentialAcquireSupport(credentialName);
                    if (temp != null && temp.isDefinitelySupported()) {
                        // As soon as one claims definite support we know it is supported.
                        return temp;
                    }

                    if (temp != null && support.compareTo(temp) < 0) {
                        support = temp;
                    }
                }
            }

            return support;
        }

        @Override
        public Credential getCredential(final String credentialName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialName", credentialName);
            if (!exists()) {
                return null;
            }

            if (LdapSecurityRealm.this.getCredentialAcquireSupport(credentialName) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return null;
            }

            for (CredentialLoader loader : credentialLoaders) {
                if (loader.getCredentialAcquireSupport(dirContextFactory, credentialName).mayBeSupported()) {
                    IdentityCredentialLoader icl = loader.forIdentity(dirContextFactory, this.identity.getDistinguishedName());

                    Credential credential = icl.getCredential(credentialName, Credential.class);
                    if (credential != null) {
                        return credential;
                    }
                }
            }

            return null;
        }

        private boolean persistCredential(String credentialName, Credential credential) throws RealmUnavailableException {
            for (CredentialPersister persister : credentialPersisters) {
                IdentityCredentialPersister icp = persister.forIdentity(dirContextFactory, this.identity.getDistinguishedName());
                if (icp.getCredentialPersistSupport(credentialName)) {
                    icp.persistCredential(credentialName, credential);
                    return true;
                }
            }
            return false;
        }

        @Override
        public void setCredential(String credentialName, Credential credential) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialName", credentialName);
            Assert.checkNotNullParam("credential", credential);

            if (!exists()) {
                throw log.ldapRealmIdentityNotExists(name);
            }

            if ( ! persistCredential(credentialName, credential)) {
                throw log.ldapRealmsPersisterNotSupportCredentialName(credentialName);
            }
        }

        @Override
        public void deleteCredential(String credentialName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialName", credentialName);

            if (!exists()) {
                throw log.ldapRealmIdentityNotExists(name);
            }

            throw Assert.unsupported(); // TODO
        }

        @Override
        public void setCredentials(Map<String, Credential> credentials) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentials", credentials);

            if (!exists()) {
                throw log.ldapRealmIdentityNotExists(name);
            }

            for (CredentialPersister persister : credentialPersisters) {
                IdentityCredentialPersister icp = persister.forIdentity(dirContextFactory, this.identity.getDistinguishedName());
                icp.clearCredentials();
            }

            for (Map.Entry<String, Credential> credentialEntry : credentials.entrySet()) {
                if ( ! persistCredential(credentialEntry.getKey(), credentialEntry.getValue())) {
                    throw log.ldapRealmsPersisterNotSupportCredentialName(credentialEntry.getKey());
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
        public SupportLevel getEvidenceVerifySupport(String credentialName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialName", credentialName);
            if (!exists()) {
                return null;
            }

            if (LdapSecurityRealm.this.getEvidenceVerifySupport(credentialName) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return SupportLevel.UNSUPPORTED;
            }

            SupportLevel support = SupportLevel.UNSUPPORTED;

            for (EvidenceVerifier verifier : evidenceVerifiers) {
                if (verifier.getEvidenceVerifySupport(dirContextFactory, credentialName).mayBeSupported()) {
                    IdentityEvidenceVerifier iev = verifier.forIdentity(dirContextFactory, identity.getDistinguishedName());

                    SupportLevel temp = iev.getEvidenceVerifySupport(credentialName);
                    if (temp != null && temp.isDefinitelySupported()) {
                        // As soon as one claims definite support we know it is supported.
                        return temp;
                    }

                    if (temp != null && support.compareTo(temp) < 0) {
                        support = temp;
                    }
                }
            }

            return support;
        }

        @Override
        public boolean verifyEvidence(final String credentialName, final Evidence evidence) throws RealmUnavailableException {


            Assert.checkNotNullParam("credentialName", credentialName);
            if (!exists()) {
                return false;
            }

            if (LdapSecurityRealm.this.getEvidenceVerifySupport(credentialName) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return false;
            }

            for (EvidenceVerifier verifier : evidenceVerifiers) {
                if (verifier.getEvidenceVerifySupport(dirContextFactory, credentialName).mayBeSupported()) {
                    IdentityEvidenceVerifier iev = verifier.forIdentity(dirContextFactory, this.identity.getDistinguishedName());

                    if (iev.verifyEvidence(dirContextFactory, credentialName, evidence)) {
                        return true;
                    }
                }
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

                String searchDn = identityMapping.searchDn;
                String name = principalName;

                if (principalName.startsWith(identityMapping.rdnIdentifier)) {
                    LdapName ldapName = new LdapName(principalName);
                    int rdnIdentifierPosition = ldapName.size() - 1;
                    Rdn rdnIdentifier = ldapName.getRdn(rdnIdentifierPosition);

                    name = rdnIdentifier.getValue().toString();
                    ldapName.remove(rdnIdentifierPosition);
                    searchDn = ldapName.toString();
                }

                final DirContext finalContext = context;

                LdapSearch ldapSearch = new LdapSearch(searchDn, String.format("(%s={0})", identityMapping.rdnIdentifier), name);

                ldapSearch.setReturningAttributes(
                        identityMapping.attributes.stream()
                                .map(Attribute::getLdapName)
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
                    searchDn = identityMapping.searchDn;
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
                            javax.naming.directory.Attribute ldapAttribute = entryAttributes.get(attribute.getLdapName());
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
                NamingEnumeration<? extends javax.naming.directory.Attribute> attributesEnum = returnedAttributes.getAll();
                Collection<String> values = new ArrayList<>();

                try {
                    while (attributesEnum.hasMore()) {
                        javax.naming.directory.Attribute ldapAttribute = attributesEnum.next();

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

            searchControls.setSearchScope(identityMapping.searchRecursive ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE);
            searchControls.setTimeLimit(identityMapping.searchTimeLimit);
            searchControls.setReturningAttributes(returningAttributes);

            return searchControls;
        }

        private Map<String, Collection<String>> extractAttributes(Predicate<Attribute> filter, Function<Attribute, Collection<String>> valueFunction) {
            return identityMapping.attributes.stream()
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

    static class IdentityMapping {

        // NOTE: This class is not a general purpose holder for all possible realm configuration, the purpose is to cover
        // configuration related to locating the identity and loading it's attributes.

        private final String searchDn;
        private final boolean searchRecursive;
        private final String rdnIdentifier;
        private final List<Attribute> attributes;
        public final int searchTimeLimit;

        public IdentityMapping(String searchDn, boolean searchRecursive, int searchTimeLimit, String rdnIdentifier, List<Attribute> attributes) {
            Assert.checkNotNullParam("rdnIdentifier", rdnIdentifier);
            this.searchDn = searchDn;
            this.searchRecursive = searchRecursive;
            this.searchTimeLimit = searchTimeLimit;
            this.rdnIdentifier = rdnIdentifier;
            this.attributes = attributes;
        }
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
         * same name of the context defined in {@link org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder.IdentityMappingBuilder#setSearchDn(String)}.
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
