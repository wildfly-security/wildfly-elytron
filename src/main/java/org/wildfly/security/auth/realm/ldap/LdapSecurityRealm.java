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

package org.wildfly.security.auth.realm.ldap;

import static org.wildfly.security._private.ElytronMessages.log;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.PagedResultsControl;
import javax.naming.ldap.PagedResultsResponseControl;
import javax.naming.ldap.Rdn;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.server.CloseableIterator;
import org.wildfly.security.auth.server.IdentityLocator;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.AlgorithmCredential;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.AlgorithmEvidence;
import org.wildfly.security.evidence.Evidence;

/**
 * Security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class LdapSecurityRealm implements ModifiableSecurityRealm {

    private final DirContextFactory dirContextFactory;
    private final NameRewriter nameRewriter;
    private final IdentityMapping identityMapping;
    private final int pageSize;

    private final List<CredentialLoader> credentialLoaders;
    private final List<CredentialPersister> credentialPersisters;
    private final List<EvidenceVerifier> evidenceVerifiers;

    LdapSecurityRealm(final DirContextFactory dirContextFactory, final NameRewriter nameRewriter,
                      final IdentityMapping identityMapping,
                      final List<CredentialLoader> credentialLoaders,
                      final List<CredentialPersister> credentialPersisters,
                      final List<EvidenceVerifier> evidenceVerifiers,
                      final int pageSize) {

        this.dirContextFactory = dirContextFactory;
        this.nameRewriter = nameRewriter;
        this.identityMapping = identityMapping;
        this.pageSize = pageSize;

        this.credentialLoaders = credentialLoaders;
        this.credentialPersisters = credentialPersisters;
        this.evidenceVerifiers = evidenceVerifiers;
    }

    @Override
    public RealmIdentity getRealmIdentity(final IdentityLocator locator) throws RealmUnavailableException {
        // todo: read/write locking
        return getRealmIdentityForUpdate(locator);
    }

    @Override
    public ModifiableRealmIdentity getRealmIdentityForUpdate(final IdentityLocator locator) {
        if (! locator.hasName()) {
            return ModifiableRealmIdentity.NON_EXISTENT;
        }
        String name = nameRewriter.rewriteName(locator.getName());
        if (name == null) {
            throw log.invalidName();
        }

        return new LdapRealmIdentity(name);
    }

    @Override
    public CloseableIterator<ModifiableRealmIdentity> getRealmIdentityIterator() throws RealmUnavailableException {
        if (identityMapping.iteratorFilter == null) {
            throw log.ldapRealmNotConfiguredToSupportIteratingOverIdentities();
        }

        return new CloseableIterator<ModifiableRealmIdentity>() {

            private List<ModifiableRealmIdentity> list = new LinkedList<>();
            private byte[] cookie = null;
            private boolean end = false;

            private void loadNextPage(LdapContext context) throws NamingException, IOException {
                context.setRequestControls(new Control[]{
                        new PagedResultsControl(pageSize, cookie, Control.CRITICAL)
                });

                NamingEnumeration<SearchResult> result = context.search(identityMapping.searchDn, identityMapping.iteratorFilter,
                        identityMapping.iteratorFilterArgs, createSearchControls(identityMapping.rdnIdentifier));
                try {
                    while (result.hasMore()) {
                        SearchResult entry = result.next();
                        String name = (String) entry.getAttributes().get(identityMapping.rdnIdentifier).get();
                        list.add(getRealmIdentityForUpdate(IdentityLocator.fromName(name)));
                    }
                } finally {
                    result.close();
                }

                Control[] controls = context.getResponseControls();
                if (controls != null) {
                    for (int k = 0; k < controls.length; k++) {
                        if (controls[k] instanceof PagedResultsResponseControl) {
                            PagedResultsResponseControl control = (PagedResultsResponseControl) controls[k];
                            cookie = control.getCookie();
                            if (cookie == null) end = true;
                            return;
                        }
                    }
                }
                throw log.ldapRealmPagedControlNotProvidedByLdapContext();
            }

            private void loadCompleteResult(DirContext context) throws NamingException {
                end = true;
                NamingEnumeration<SearchResult> result = context.search(identityMapping.searchDn, identityMapping.iteratorFilter,
                        identityMapping.iteratorFilterArgs, createSearchControls(identityMapping.rdnIdentifier));
                try {
                    while (result.hasMore()) {
                        SearchResult entry = result.next();
                        String name = (String) entry.getAttributes().get(identityMapping.rdnIdentifier).get();
                        list.add(getRealmIdentityForUpdate(IdentityLocator.fromName(name)));
                    }
                } finally {
                    result.close();
                }
            }

            private void loadNextPageOrCompleteResult() {
                log.debug("Iterating over identities");
                DirContext context = null;
                list.clear();

                try {
                    context = dirContextFactory.obtainDirContext(null);
                } catch (NamingException e) {
                    throw log.ldapRealmIdentitySearchFailed(e);
                }
                try {

                    if (context instanceof LdapContext) {
                        try {
                            loadNextPage((LdapContext) context);
                            return; // page loaded successfully
                        } catch (NamingException | IOException e) {
                            log.debug("Iterating with pagination failed", e);
                        } finally {
                            ((LdapContext) context).setRequestControls(null);
                        }
                    }

                    log.debug("Iterating without pagination");
                    loadCompleteResult(context);
                } catch (NamingException e) {
                    throw log.ldapRealmIdentitySearchFailed(e);
                } finally {
                    dirContextFactory.returnContext(context);
                }
            }

            @Override
            public boolean hasNext() {
                return ! list.isEmpty() || ! end;
            }

            @Override
            public ModifiableRealmIdentity next() {
                if (list.isEmpty()) {
                    if (end) {
                        throw new NoSuchElementException();
                    } else {
                        loadNextPageOrCompleteResult();
                    }
                }
                ModifiableRealmIdentity identity = list.get(0);
                list.remove(0);
                return identity;
            }
        };
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        SupportLevel response = SupportLevel.UNSUPPORTED;

        for (CredentialLoader loader : credentialLoaders) {
            SupportLevel support = loader.getCredentialAcquireSupport(dirContextFactory, credentialType, algorithmName);
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
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("evidenceType", evidenceType);
        SupportLevel response = SupportLevel.UNSUPPORTED;

        for (EvidenceVerifier verifier : evidenceVerifiers) {
            SupportLevel support = verifier.getEvidenceVerifySupport(dirContextFactory, evidenceType, algorithmName);
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

    private SearchControls createSearchControls(String... returningAttributes) {
        SearchControls searchControls = new SearchControls();

        searchControls.setSearchScope(identityMapping.searchRecursive ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE);
        searchControls.setTimeLimit(identityMapping.searchTimeLimit);
        searchControls.setReturningAttributes(returningAttributes);

        return searchControls;
    }

    private class LdapRealmIdentity implements ModifiableRealmIdentity {

        private final String name;
        private LdapIdentity identity;

        LdapRealmIdentity(final String name) {
            this.name = name;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            if (!exists()) {
                return null;
            }

            if (LdapSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return SupportLevel.UNSUPPORTED;
            }

            SupportLevel support = SupportLevel.UNSUPPORTED;

            for (CredentialLoader loader : credentialLoaders) {
                if (loader.getCredentialAcquireSupport(dirContextFactory, credentialType, algorithmName).mayBeSupported()) {
                    IdentityCredentialLoader icl = loader.forIdentity(dirContextFactory, identity.getDistinguishedName());

                    SupportLevel temp = icl.getCredentialAcquireSupport(credentialType, algorithmName);
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
        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            return getCredential(credentialType, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            if (!exists()) {
                return null;
            }

            if (LdapSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return null;
            }

            for (CredentialLoader loader : credentialLoaders) {
                if (loader.getCredentialAcquireSupport(dirContextFactory, credentialType, algorithmName).mayBeSupported()) {
                    IdentityCredentialLoader icl = loader.forIdentity(dirContextFactory, this.identity.getDistinguishedName());

                    Credential credential = icl.getCredential(credentialType, algorithmName);
                    if (credentialType.isInstance(credential)) {
                        return credentialType.cast(credential);
                    }
                }
            }

            return null;
        }

        @Override
        public void setCredentials(final Collection<? extends Credential> credentials) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentials", credentials);

            if (!exists()) {
                throw log.ldapRealmIdentityNotExists(name);
            }

            // verify support
            for (Credential credential : credentials) {
                final Class<? extends Credential> credentialType = credential.getClass();
                final String algorithmName = credential instanceof AlgorithmCredential ? ((AlgorithmCredential) credential).getAlgorithm() : null;
                boolean supported = false;
                for (CredentialPersister persister : credentialPersisters) {
                    IdentityCredentialPersister icp = persister.forIdentity(dirContextFactory, this.identity.getDistinguishedName());
                    if (icp.getCredentialPersistSupport(credentialType, algorithmName)) {
                        supported = true;
                    }
                }
                if (! supported) {
                    throw log.ldapRealmsPersisterNotSupported();
                }
            }

            // clear
            for (CredentialPersister persister : credentialPersisters) {
                IdentityCredentialPersister icp = persister.forIdentity(dirContextFactory, this.identity.getDistinguishedName());
                icp.clearCredentials();
            }

            // set
            for (Credential credential : credentials) {
                final Class<? extends Credential> credentialType = credential.getClass();
                final String algorithmName = credential instanceof AlgorithmCredential ? ((AlgorithmCredential) credential).getAlgorithm() : null;
                for (CredentialPersister persister : credentialPersisters) {
                    IdentityCredentialPersister icp = persister.forIdentity(dirContextFactory, this.identity.getDistinguishedName());
                    if (icp.getCredentialPersistSupport(credentialType, algorithmName)) {
                        icp.persistCredential(credential);
                        // next credential
                        break;
                    }
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
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);
            if (!exists()) {
                return SupportLevel.UNSUPPORTED;
            }

            SupportLevel response = SupportLevel.UNSUPPORTED;

            for (EvidenceVerifier verifier : evidenceVerifiers) {
                if (verifier.getEvidenceVerifySupport(dirContextFactory, evidenceType, algorithmName).mayBeSupported()) {
                    final IdentityEvidenceVerifier iev = verifier.forIdentity(dirContextFactory, this.identity.getDistinguishedName());

                    final SupportLevel support = iev.getEvidenceVerifySupport(evidenceType, algorithmName);
                    if (support != null && support.isDefinitelySupported()) {
                        // As soon as one claims definite support we know it is supported.
                        return support;
                    }

                    if (support != null && support.compareTo(support) < 0) {
                        response = support;
                    }
                }
            }
            return response;
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);
            if (!exists()) {
                return false;
            }

            final Class<? extends Evidence> evidenceType = evidence.getClass();
            final String algorithmName = evidence instanceof AlgorithmEvidence ? ((AlgorithmEvidence) evidence).getAlgorithm() : null;

            if (LdapSecurityRealm.this.getEvidenceVerifySupport(evidenceType, algorithmName) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return false;
            }

            for (EvidenceVerifier verifier : evidenceVerifiers) {
                if (verifier.getEvidenceVerifySupport(dirContextFactory, evidenceType, algorithmName).mayBeSupported()) {
                    IdentityEvidenceVerifier iev = verifier.forIdentity(dirContextFactory, this.identity.getDistinguishedName());

                    if (iev.verifyEvidence(evidence)) {
                        return true;
                    }
                }
            }

            return false;
        }

        @Override
        public boolean exists() throws RealmUnavailableException {
            if (this.identity == null) {
                this.identity = getIdentity();
            }

            boolean exists = this.identity != null;

            if (!exists) {
                log.debugf("Principal [%s] does not exists.", this.name);
            }

            return exists;
        }

        private LdapIdentity getIdentity() throws RealmUnavailableException {
            log.debugf("Trying to create identity for principal [%s].", this.name);
            DirContext context = null;

            try {
                context = dirContextFactory.obtainDirContext(null);
            } catch (NamingException e) {
                throw log.ldapRealmFailedObtainIdentityFromServer(this.name, e);
            }
            try {
                String searchDn = identityMapping.searchDn;
                String name = this.name;

                if (this.name.startsWith(identityMapping.rdnIdentifier)) { // getting identity by DN
                    LdapName ldapName = new LdapName(this.name);
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
                                .map(AttributeMapping::getLdapName)
                                .toArray(String[]::new));

                try (
                    Stream<LdapIdentity> identityStream = ldapSearch.search(context)
                            .map(result -> {
                                MapAttributes identityAttributes = new MapAttributes();

                                identityAttributes.addAll(extractSingleAttributes(result));
                                identityAttributes.addAll(extractFilteredAttributes(result, finalContext));

                                return new LdapIdentity(result.getNameInNamespace(), identityAttributes.asReadOnly());
                            })
                ) {
                    Optional<LdapIdentity> optional = identityStream.findFirst();

                    if (optional.isPresent()) {
                        LdapIdentity identity = optional.get();

                        if (log.isDebugEnabled()) {
                            log.debugf("Successfully created identity for principal [%s].", this.name);

                            if (identity.attributes.isEmpty()) {
                                log.debugf("Identity [%s] does not have any attributes.", this.name);
                            } else {
                                log.debugf("Identity [%s] attributes are:", this.name);
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
                throw log.ldapRealmFailedObtainIdentityFromServer(this.name, e);
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
                    Stream<SearchResult> searchResult = search.search(context)
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

        private Map<String, Collection<String>> extractAttributes(Predicate<AttributeMapping> filter, Function<AttributeMapping, Collection<String>> valueFunction) {
            return identityMapping.attributes.stream()
                    .filter(filter)
                    .collect(Collectors.toMap(AttributeMapping::getName, valueFunction, (m1, m2) -> {
                        List<String> merged = new ArrayList<>(m1);

                        merged.addAll(m2);

                        return merged;
                    }));
        }

        @Override public void delete() throws RealmUnavailableException {
            if (identity == null) {
                identity = getIdentity();
            }

            if (identity == null) {
                throw log.noSuchIdentity();
            }

            DirContext context = null;
            try {
                context = dirContextFactory.obtainDirContext(null);
            } catch (NamingException e) {
                throw log.ldapRealmFailedDeleteIdentityFromServer(e);
            }
            try {
                log.debugf("Removing identity [%s] with DN [%s] from LDAP", name, identity.getDistinguishedName());
                context.destroySubcontext(new LdapName(identity.getDistinguishedName()));
            } catch (NamingException e) {
                throw log.ldapRealmFailedDeleteIdentityFromServer(e);
            } finally {
                dirContextFactory.returnContext(context);
            }
        }

        @Override public void create() throws RealmUnavailableException {
            if (identityMapping.newIdentityParent == null || identityMapping.newIdentityAttributes == null) {
                throw log.ldapRealmNotConfiguredToSupportCreatingIdentities();
            }

            DirContext context = null;
            try {
                context = dirContextFactory.obtainDirContext(null);
            } catch (NamingException e) {
                throw log.ldapRealmFailedCreateIdentityOnServer(e);
            }
            try {
                LdapName distinguishName = (LdapName) identityMapping.newIdentityParent.clone();
                distinguishName.add(new Rdn(identityMapping.rdnIdentifier, name));

                log.debugf("Creating identity [%s] with DN [%s] in LDAP", name, distinguishName.toString());
                context.createSubcontext((Name) distinguishName, identityMapping.newIdentityAttributes);

            } catch (NamingException e) {
                throw log.ldapRealmFailedCreateIdentityOnServer(e);
            } finally {
                dirContextFactory.returnContext(context);
            }
        }

        @Override public void setAttributes(org.wildfly.security.authz.Attributes attributes) throws RealmUnavailableException {
            log.debugf("Trying to set attributes for principal [%s].", this.name);

            if (identity == null) {
                identity = getIdentity();
            }

            if (identity == null) {
                throw log.noSuchIdentity();
            }

            DirContext context = null;
            try {
                context = dirContextFactory.obtainDirContext(null);
            } catch (Exception e) {
                throw log.ldapRealmAttributesSettingFailed(this.name, e);
            }
            try {
                List<ModificationItem> modItems = new LinkedList<>();
                LdapName identityLdapName = new LdapName(identity.getDistinguishedName());
                String renameTo = null;

                for(AttributeMapping mapping : identityMapping.attributes) {
                    if (mapping.getFilter() != null || mapping.getRdn() != null) { // filtered attributes
                        if (attributes.size(mapping.getName()) != 0) { // or just ignore it and allow set what was getted?
                            log.ldapRealmDoesNotSupportSettingFilteredAttribute(mapping.getName(), this.name);
                        }
                    } else if (identityMapping.rdnIdentifier.equalsIgnoreCase(mapping.getLdapName())) { // rdn
                        if (attributes.size(mapping.getName()) == 1) {
                            renameTo = attributes.get(mapping.getName(), 0);
                        } else {
                            throw log.ldapRealmRequiresExactlyOneRdnAttribute(mapping.getName(), this.name);
                        }
                    } else { // standard ldap attributes
                        if (attributes.size(mapping.getName()) == 0) {
                            BasicAttribute attribute = new BasicAttribute(mapping.getLdapName());
                            modItems.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, attribute));
                        } else {
                            BasicAttribute attribute = new BasicAttribute(mapping.getLdapName());
                            attributes.get(mapping.getName()).forEach(entryItem -> {
                                attribute.add(entryItem);
                            });
                            modItems.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, attribute));
                        }
                    }
                }

                for(org.wildfly.security.authz.Attributes.Entry entry : attributes.entries()) {
                    if (identityMapping.attributes.stream().filter(mp -> mp.getName().equals(entry.getKey())).count() == 0) {
                        throw log.ldapRealmCannotSetAttributeWithoutMapping(entry.getKey(), this.name);
                    }
                }

                ModificationItem[] modItemsArray = modItems.toArray(new ModificationItem[modItems.size()]);
                context.modifyAttributes(identityLdapName, modItemsArray);

                if (renameTo != null && ! renameTo.equals((String) identityLdapName.getRdn(identityLdapName.size()-1).getValue())) {
                    LdapName newLdapName = new LdapName(identityLdapName.getRdns().subList(0, identityLdapName.size()-1));
                    newLdapName.add(new Rdn(identityMapping.rdnIdentifier, renameTo));
                    context.rename(identityLdapName, newLdapName);
                }

            } catch (Exception e) {
                throw log.ldapRealmAttributesSettingFailed(this.name, e);
            } finally {
                dirContextFactory.returnContext(context);
            }
        }

        @Override
        public org.wildfly.security.authz.Attributes getAttributes() throws RealmUnavailableException {
            if (identity == null) {
                identity = getIdentity();
            }
            if (identity == null) {
                throw log.noSuchIdentity();
            }
            return identity.getAttributes().asReadOnly();
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

            org.wildfly.security.authz.Attributes getAttributes() {
                return this.attributes;
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
                                throw log.ldapRealmErrorWhileConsumingResultsFromSearch(searchDn, filter, Arrays.toString(filterArgs), e);
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
                } catch (Exception e) {
                    throw log.ldapRealmIdentitySearchFailed(e);
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
        private final List<AttributeMapping> attributes;
        public final int searchTimeLimit;
        private final LdapName newIdentityParent;
        private final Attributes newIdentityAttributes;
        private final String iteratorFilter;
        private final Object[] iteratorFilterArgs;

        public IdentityMapping(String searchDn, boolean searchRecursive, int searchTimeLimit, String rdnIdentifier, List<AttributeMapping> attributes, LdapName newIdentityParent, Attributes newIdentityAttributes, String iteratorFilter, Object[] iteratorFilterArgs) {
            Assert.checkNotNullParam("rdnIdentifier", rdnIdentifier);
            this.searchDn = searchDn;
            this.searchRecursive = searchRecursive;
            this.searchTimeLimit = searchTimeLimit;
            this.rdnIdentifier = rdnIdentifier;
            this.attributes = attributes;
            this.newIdentityParent = newIdentityParent;
            this.newIdentityAttributes = newIdentityAttributes;
            this.iteratorFilter = iteratorFilter;
            this.iteratorFilterArgs = iteratorFilterArgs;
        }
    }
}
