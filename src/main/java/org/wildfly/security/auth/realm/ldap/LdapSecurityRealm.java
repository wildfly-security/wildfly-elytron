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
import java.security.Principal;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import javax.naming.Binding;
import javax.naming.InvalidNameException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ReferralException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.event.EventContext;
import javax.naming.event.NamespaceChangeListener;
import javax.naming.event.NamingEvent;
import javax.naming.event.NamingExceptionEvent;
import javax.naming.event.ObjectChangeListener;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.PagedResultsControl;
import javax.naming.ldap.PagedResultsResponseControl;
import javax.naming.ldap.Rdn;

import org.wildfly.common.Assert;
import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.CacheableSecurityRealm;
import org.wildfly.security.auth.realm.IdentitySharedExclusiveLock;
import org.wildfly.security.auth.realm.IdentitySharedExclusiveLock.IdentityLock;
import org.wildfly.security.auth.server.CloseableIterator;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.NameRewriter;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.SupportLevel;
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
class LdapSecurityRealm implements ModifiableSecurityRealm, CacheableSecurityRealm {

    private final Supplier<Provider[]> providers;
    private final ExceptionSupplier<DirContext, NamingException> dirContextSupplier;
    private final NameRewriter nameRewriter;
    private final IdentityMapping identityMapping;
    private final int pageSize;

    private final List<CredentialLoader> credentialLoaders;
    private final List<CredentialPersister> credentialPersisters;
    private final List<EvidenceVerifier> evidenceVerifiers;

    private final ConcurrentHashMap<String, IdentitySharedExclusiveLock> realmIdentityLocks = new ConcurrentHashMap<>();

    LdapSecurityRealm(final Supplier<Provider[]> providers, final ExceptionSupplier<DirContext, NamingException> dirContextSupplier,
                      final NameRewriter nameRewriter,
                      final IdentityMapping identityMapping,
                      final List<CredentialLoader> credentialLoaders,
                      final List<CredentialPersister> credentialPersisters,
                      final List<EvidenceVerifier> evidenceVerifiers,
                      final int pageSize) {

        this.providers = providers;
        this.dirContextSupplier = dirContextSupplier;
        this.nameRewriter = nameRewriter;
        this.identityMapping = identityMapping;
        this.pageSize = pageSize;

        this.credentialLoaders = credentialLoaders;
        this.credentialPersisters = credentialPersisters;
        this.evidenceVerifiers = evidenceVerifiers;
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal) {
        return getRealmIdentity(principal, false);
    }

    @Override
    public ModifiableRealmIdentity getRealmIdentityForUpdate(final Principal principal) {
        return getRealmIdentity(principal, true);
    }

    @Override
    public void registerIdentityChangeListener(Consumer<Principal> listener) {
        DirContext dirContext = null;
        try {
            dirContext = obtainContext();
            EventContext eventContext = (EventContext) dirContext.lookup("");
            eventContext.addNamingListener("", EventContext.SUBTREE_SCOPE, new ServerNotificationListener(listener));
        } catch (Exception cause) {
            throw log.ldapRealmFailedRegisterListener(cause);
        } finally {
            if (dirContext != null) {
                closeContext(dirContext);
            }
        }
    }

    private ModifiableRealmIdentity getRealmIdentity(final Principal principal, final boolean exclusive) {
        if (! (principal instanceof NamePrincipal)) {
            return ModifiableRealmIdentity.NON_EXISTENT;
        }
        String name = nameRewriter.rewriteName(principal.getName());
        if (name == null) {
            throw log.invalidName();
        }

        // Acquire the appropriate lock for the realm identity
        IdentitySharedExclusiveLock realmIdentityLock = getRealmIdentityLockForName(name);
        IdentityLock lock;
        if (exclusive) {
            lock = realmIdentityLock.lockExclusive();
        } else {
            lock = realmIdentityLock.lockShared();
        }
        return new LdapRealmIdentity(name, lock);
    }

    private DirContext obtainContext() throws RealmUnavailableException {
        try {
            return dirContextSupplier.get();
        } catch (NamingException e) {
            throw log.ldapRealmFailedToObtainContext(e);
        }
    }

    private void closeContext(DirContext dirContext) {
        try {
            dirContext.close();
        } catch (NamingException e) {
            log.debug("LdapSecurityRealm failed to close DirContext", e);
        }
    }

    @Override
    public CloseableIterator<ModifiableRealmIdentity> getRealmIdentityIterator() throws RealmUnavailableException {
        if (identityMapping.iteratorFilter == null) {
            throw log.ldapRealmNotConfiguredToSupportIteratingOverIdentities();
        }

        final DirContext dirContext;
        final Stream<SearchResult> resultStream;
        final LdapSearch ldapSearch = new LdapSearch(identityMapping.searchDn, identityMapping.searchRecursive, pageSize, identityMapping.iteratorFilter);
        ldapSearch.setReturningAttributes(identityMapping.rdnIdentifier);
        try {
            dirContext = dirContextSupplier.get();
            resultStream = ldapSearch.search(dirContext);
        } catch (NamingException e) {
            throw log.ldapRealmIdentitySearchFailed(e);
        }
        Iterator<SearchResult> iterator = resultStream.iterator();

        return new CloseableIterator<ModifiableRealmIdentity>() {

            @Override
            public boolean hasNext() {
                return iterator.hasNext();
            }

            @Override
            public ModifiableRealmIdentity next() {
                SearchResult entry = iterator.next();
                // because referrals support cannot be identity obtained by DN
                try {
                    String name = (String) entry.getAttributes().get(identityMapping.rdnIdentifier).get();
                    return getRealmIdentityForUpdate(new NamePrincipal(name));
                } catch (NamingException e) {
                    throw log.ldapRealmIdentitySearchFailed(e);
                }
            }

            @Override
            public void close() throws IOException {
                resultStream.close();
                closeContext(dirContext);
            }
        };
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        SupportLevel response = SupportLevel.UNSUPPORTED;

        for (CredentialLoader loader : credentialLoaders) {
            SupportLevel support = loader.getCredentialAcquireSupport(credentialType, algorithmName);
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

        DirContext dirContext = obtainContext();
        try {
            for (EvidenceVerifier verifier : evidenceVerifiers) {
                SupportLevel support = verifier.getEvidenceVerifySupport(dirContext, evidenceType, algorithmName);
                if (support.isDefinitelySupported()) {
                    // One claiming it is definitely supported is enough!
                    return support;
                }
                if (response.compareTo(support) < 0) {
                    response = support;
                }
            }
        } finally {
            closeContext(dirContext);
        }
        return response;
    }

    private IdentitySharedExclusiveLock getRealmIdentityLockForName(final String name) {
        IdentitySharedExclusiveLock realmIdentityLock = realmIdentityLocks.get(name);
        if (realmIdentityLock == null) {
            final IdentitySharedExclusiveLock newRealmIdentityLock = new IdentitySharedExclusiveLock();
            realmIdentityLock = realmIdentityLocks.putIfAbsent(name, newRealmIdentityLock);
            if (realmIdentityLock == null) {
                realmIdentityLock = newRealmIdentityLock;
            }
        }
        return realmIdentityLock;
    }

    private class LdapRealmIdentity implements ModifiableRealmIdentity {

        private final String name;
        private LdapIdentity identity;
        private IdentityLock lock;

        LdapRealmIdentity(final String name, final IdentityLock lock) {
            this.name = name;
            this.lock = lock;
        }

        public Principal getRealmIdentityPrincipal() {
            return new NamePrincipal(name);
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            if (!exists()) {
                return SupportLevel.UNSUPPORTED;
            }

            if (LdapSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return SupportLevel.UNSUPPORTED;
            }

            SupportLevel support = SupportLevel.UNSUPPORTED;

            DirContext dirContext = obtainContext();
            try {
                for (CredentialLoader loader : credentialLoaders) {
                    if (loader.getCredentialAcquireSupport(credentialType, algorithmName).mayBeSupported()) {
                        IdentityCredentialLoader icl = loader.forIdentity(dirContext, identity.getDistinguishedName());

                        SupportLevel temp = icl.getCredentialAcquireSupport(credentialType, algorithmName, providers);
                        if (temp != null && temp.isDefinitelySupported()) {
                            // As soon as one claims definite support we know it is supported.
                            return temp;
                        }

                        if (temp != null && support.compareTo(temp) < 0) {
                            support = temp;
                        }
                    }
                }
            } finally {
                closeContext(dirContext);
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

            DirContext dirContext = obtainContext();
            try {
                for (CredentialLoader loader : credentialLoaders) {
                    if (loader.getCredentialAcquireSupport(credentialType, algorithmName).mayBeSupported()) {
                        IdentityCredentialLoader icl = loader.forIdentity(dirContext, this.identity.getDistinguishedName());

                        Credential credential = icl.getCredential(credentialType, algorithmName, providers);
                        if (credentialType.isInstance(credential)) {
                            return credentialType.cast(credential);
                        }
                    }
                }
            } finally {
                closeContext(dirContext);
            }
            return null;
        }

        @Override
        public void setCredentials(final Collection<? extends Credential> credentials) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentials", credentials);

            if (!exists()) {
                throw log.ldapRealmIdentityNotExists(name);
            }

            DirContext dirContext = obtainContext();
            try {

                // verify support
                for (Credential credential : credentials) {
                    final Class<? extends Credential> credentialType = credential.getClass();
                    final String algorithmName = credential instanceof AlgorithmCredential ? ((AlgorithmCredential) credential).getAlgorithm() : null;
                    boolean supported = false;
                    for (CredentialPersister persister : credentialPersisters) {
                        IdentityCredentialPersister icp = persister.forIdentity(dirContext, this.identity.getDistinguishedName());
                        if (icp.getCredentialPersistSupport(credentialType, algorithmName)) {
                            supported = true;
                        }
                    }
                    if (!supported) {
                        throw log.ldapRealmsPersisterNotSupported();
                    }
                }

                // clear
                for (CredentialPersister persister : credentialPersisters) {
                    IdentityCredentialPersister icp = persister.forIdentity(dirContext, this.identity.getDistinguishedName());
                    icp.clearCredentials();
                }

                // set
                for (Credential credential : credentials) {
                    final Class<? extends Credential> credentialType = credential.getClass();
                    final String algorithmName = credential instanceof AlgorithmCredential ? ((AlgorithmCredential) credential).getAlgorithm() : null;
                    for (CredentialPersister persister : credentialPersisters) {
                        IdentityCredentialPersister icp = persister.forIdentity(dirContext, this.identity.getDistinguishedName());
                        if (icp.getCredentialPersistSupport(credentialType, algorithmName)) {
                            icp.persistCredential(credential);
                            // next credential
                            break;
                        }
                    }
                }

            } finally {
                closeContext(dirContext);
            }
        }

        @Override
        public void dispose() {
            // Release the lock for this realm identity
            IdentityLock identityLock = lock;
            lock = null;
            if (identityLock != null) {
                identityLock.release();
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

            DirContext dirContext = obtainContext();
            try {
                for (EvidenceVerifier verifier : evidenceVerifiers) {
                    if (verifier.getEvidenceVerifySupport(dirContext, evidenceType, algorithmName).mayBeSupported()) {
                        final IdentityEvidenceVerifier iev = verifier.forIdentity(dirContext, this.identity.getDistinguishedName());

                        final SupportLevel support = iev.getEvidenceVerifySupport(evidenceType, algorithmName, providers);
                        if (support != null && support.isDefinitelySupported()) {
                            // As soon as one claims definite support we know it is supported.
                            return support;
                        }

                        if (support != null && support.compareTo(response) > 0) {
                            response = support;
                        }
                    }
                }
            } finally {
                closeContext(dirContext);
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

            DirContext dirContext = obtainContext();
            try {
                for (EvidenceVerifier verifier : evidenceVerifiers) {
                    if (verifier.getEvidenceVerifySupport(dirContext, evidenceType, algorithmName).mayBeSupported()) {
                        IdentityEvidenceVerifier iev = verifier.forIdentity(dirContext, this.identity.getDistinguishedName());

                        if (iev.verifyEvidence(evidence, providers)) {
                            return true;
                        }
                    }
                }
            } finally {
                closeContext(dirContext);
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

        private LdapSearch searchIdentityByDn() {
            if ( ! name.regionMatches(true, 0, identityMapping.rdnIdentifier, 0, identityMapping.rdnIdentifier.length())) {
                return null;
            } // equal sign not checked here as whitespaces can be between yet
            try {
                LdapName ldapName = new LdapName(name);
                int rdnPosition = ldapName.size() - 1;
                Rdn rdnIdentifier = ldapName.getRdn(rdnPosition);
                if ( ! rdnIdentifier.getType().equalsIgnoreCase(identityMapping.rdnIdentifier)) { // uid=...
                    log.tracef("Getting identity [%s] by DN skipped - RDN does not match [%s]", name, identityMapping.rdnIdentifier);
                    return null;
                }
                if (identityMapping.searchDn != null && ! ldapName.startsWith(new LdapName(identityMapping.searchDn).getRdns())) { // ...,search-dn
                    log.tracef("Getting identity [%s] by DN skipped - DN not in search-dn [%s]", name, identityMapping.searchDn);
                    return null;
                }
                return new LdapSearch(ldapName.toString(), SearchControls.OBJECT_SCOPE, 0, identityMapping.filterName, rdnIdentifier.getValue().toString());

            } catch (InvalidNameException e) {
                log.tracef(e, "Getting identity [%s] by DN failed - will continue by name", name);
            }
            return null;
        }

        private LdapIdentity getIdentity() throws RealmUnavailableException {
            log.debugf("Trying to create identity for principal [%s].", this.name);
            DirContext context;

            try {
                context = dirContextSupplier.get();
            } catch (NamingException e) {
                throw log.ldapRealmFailedObtainIdentityFromServer(this.name, e);
            }
            try {
                LdapSearch ldapSearch = searchIdentityByDn();
                if (ldapSearch == null) { // not found by DN, search by name
                    ldapSearch = new LdapSearch(identityMapping.searchDn, identityMapping.searchRecursive, 0, identityMapping.filterName, name);
                }

                ldapSearch.setReturningAttributes(
                        identityMapping.attributes.stream()
                                .filter(mapping -> !mapping.isFiltered())
                                .map(AttributeMapping::getLdapName)
                                .toArray(String[]::new));

                try (
                    Stream<LdapIdentity> identityStream = ldapSearch.search(context)
                            .map(result -> {
                                MapAttributes identityAttributes = new MapAttributes();

                                identityAttributes.addAll(extractSingleAttributes(result));
                                identityAttributes.addAll(extractFilteredAttributes(result, context));

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
            } finally {
                closeContext(context);
            }
        }

        private String valueFromDn(AttributeMapping mapping, final String dn) {
            String valueRdn = mapping.getRdn();
            try {
                for (Rdn rdn : new LdapName(dn).getRdns()) {
                    if (rdn.getType().equalsIgnoreCase(valueRdn)) {
                        return rdn.getValue().toString();
                    }
                }
            } catch (Exception cause) {
                throw log.ldapRealmInvalidRdnForAttribute(mapping.getName(), dn, valueRdn, cause);
            }
            return null;
        }

        private void valuesFromAttribute(SearchResult entry, AttributeMapping mapping, Collection<String> identityAttributeValues) throws NamingException {
            if (mapping.getLdapName() == null) {
                String value = entry.getNameInNamespace();
                if (mapping.getRdn() != null) {
                    value = valueFromDn(mapping, value);
                }
                identityAttributeValues.add(value);
            } else {
                Attributes entryAttributes = entry.getAttributes();
                javax.naming.directory.Attribute ldapAttribute = entryAttributes.get(mapping.getLdapName());
                if (ldapAttribute == null) return;
                NamingEnumeration<?> attributesEnum = null;
                try {
                    attributesEnum = ldapAttribute.getAll();
                    Stream<String> values = Collections.list(attributesEnum).stream().map(Object::toString);
                    if (mapping.getRdn() != null) {
                        values = values.map(val -> valueFromDn(mapping, val)).filter(val -> val != null);
                    }
                    values.forEach(identityAttributeValues::add);
                } finally {
                    if (attributesEnum != null) {
                        try {
                            attributesEnum.close();
                        } catch (NamingException ignore) {
                        }
                    }
                }
            }
        }

        private Map<String, Collection<String>> extractFilteredAttributes(SearchResult identityEntry, DirContext context) {
            return extractAttributes(AttributeMapping::isFiltered, mapping -> {
                Collection<String> identityAttributeValues = new ArrayList<>();
                extractFilteredAttributesRecursion(identityEntry, mapping, context, 0, identityAttributeValues);
                return identityAttributeValues;
            });
        }

        private void extractFilteredAttributesRecursion(SearchResult referencedEntry, AttributeMapping mapping, DirContext context, int depth, Collection<String> identityAttributeValues) {
            String referencedDn = referencedEntry.getNameInNamespace();
            String searchDn = mapping.getSearchDn() != null ? mapping.getSearchDn() : identityMapping.searchDn;
            LdapSearch search = new LdapSearch(searchDn, mapping.getRecursiveSearch(), 0, mapping.getFilter(), referencedDn);
            search.setReturningAttributes(mapping.getLdapName());

            try (Stream<SearchResult> entries = search.search(context)) {
                entries.forEach(entry -> {
                    try {
                        valuesFromAttribute(entry, mapping, identityAttributeValues);
                    } catch (Exception cause) {
                        throw ElytronMessages.log.ldapRealmFailedObtainAttributes(referencedDn, cause);
                    }
                    if (mapping.getRecursiveDepth() > depth) {
                        extractFilteredAttributesRecursion(entry, mapping, context, depth+1, identityAttributeValues);
                    }
                });
            } catch (Exception cause) {
                throw ElytronMessages.log.ldapRealmFailedObtainAttributes(referencedDn, cause);
            }
        }

        private Map<String, Collection<String>> extractSingleAttributes(SearchResult identityEntry) {
            String principalDn = identityEntry.getNameInNamespace();

            return extractAttributes(mapping -> !mapping.isFiltered(), mapping -> {
                Collection<String> identityAttributeValues = new ArrayList<>();
                try {
                    valuesFromAttribute(identityEntry, mapping, identityAttributeValues);
                } catch (Exception cause) {
                    throw ElytronMessages.log.ldapRealmFailedObtainAttributes(principalDn, cause);
                }
                return identityAttributeValues;
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

            DirContext context;
            try {
                context = dirContextSupplier.get();
            } catch (NamingException e) {
                throw log.ldapRealmFailedDeleteIdentityFromServer(e);
            }
            try {
                log.debugf("Removing identity [%s] with DN [%s] from LDAP", name, identity.getDistinguishedName());
                context.destroySubcontext(new LdapName(identity.getDistinguishedName()));
                identity = null; // force reload
            } catch (NamingException e) {
                throw log.ldapRealmFailedDeleteIdentityFromServer(e);
            } finally {
                closeContext(context);
            }
        }

        @Override public void create() throws RealmUnavailableException {
            if (identityMapping.newIdentityParent == null || identityMapping.newIdentityAttributes == null) {
                throw log.ldapRealmNotConfiguredToSupportCreatingIdentities();
            }

            DirContext context = null;
            try {
                context = dirContextSupplier.get();
            } catch (NamingException e) {
                throw log.ldapRealmFailedCreateIdentityOnServer(e);
            }
            try {
                LdapName distinguishName = (LdapName) identityMapping.newIdentityParent.clone();
                distinguishName.add(new Rdn(identityMapping.rdnIdentifier, name));

                log.debugf("Creating identity [%s] with DN [%s] in LDAP", name, distinguishName.toString());
                context.createSubcontext(distinguishName, identityMapping.newIdentityAttributes);

            } catch (NamingException e) {
                throw log.ldapRealmFailedCreateIdentityOnServer(e);
            } finally {
                closeContext(context);
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
                context = dirContextSupplier.get();
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
                closeContext(context);
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
    }

    private class LdapSearch {

        private final String searchDn;
        private final int searchScope;
        private final int pageSize;
        private final String filter;
        private final String[] filterArgs;
        private String[] returningAttributes;
        private DirContext context;
        private NamingEnumeration<SearchResult> result;
        private byte[] cookie = null;

        public LdapSearch(String searchDn, boolean searchRecursive, int pageSize, String filter, String... filterArgs) {
            this(searchDn, searchRecursive ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE, pageSize, filter, filterArgs);
        }

        public LdapSearch(String searchDn, int searchScope, int pageSize, String filter, String... filterArgs) {
            this.searchDn = searchDn;
            this.searchScope = searchScope;
            this.pageSize = pageSize;
            this.filter = filter;
            this.filterArgs = filterArgs;
        }

        public Stream<SearchResult> search(DirContext ctx) throws RealmUnavailableException {
            log.debugf("Executing search [%s] in context [%s] with arguments [%s]. Returning attributes are [%s]", this.filter, this.searchDn, this.filterArgs, this.returningAttributes);
            context = ctx;
            try {
                result = searchWithPagination();
                return StreamSupport.stream(new Spliterators.AbstractSpliterator<SearchResult>(Long.MAX_VALUE, Spliterator.NONNULL) {
                    @Override
                    public boolean tryAdvance(Consumer<? super SearchResult> action) {
                        try {
                            while (true) {
                                try {
                                    if ( ! result.hasMore()) { // end of page
                                        if ( ! (pageSize != 0 && context instanceof LdapContext) ) {
                                            log.trace("Identity iterating - pagination not supported - end of list");
                                            return false;
                                        }
                                        Control[] controls = ((LdapContext) context).getResponseControls();
                                        if (controls != null) {
                                            for (Control control : controls) {
                                                if (control instanceof PagedResultsResponseControl) {
                                                    cookie = ((PagedResultsResponseControl) control).getCookie();
                                                    if (cookie == null) {
                                                        log.trace("Identity iterating - no more pages - end of list");
                                                        return false; // no more pages
                                                    }
                                                }
                                            }
                                        }
                                        result.close();

                                        result = searchWithPagination();
                                        if ( ! result.hasMore()) {
                                            log.trace("Identity iterating - even after page loading no results - end of list");
                                            return false;
                                        }
                                    }
                                    SearchResult entry = result.next();
                                    log.debugf("Found entry [%s].", entry.getNameInNamespace());
                                    action.accept(entry);
                                    return true;
                                } catch (ReferralException e) {
                                    log.debug("Next referral following in identity iterating...");
                                    context = ((DelegatingLdapContext) context).wrapReferralContextObtaining(e);
                                    result = searchWithPagination();
                                }
                            }
                        } catch (NamingException | IOException e) {
                            try {
                                result.close();
                            } catch (NamingException ex) {
                                log.trace(ex);
                            }
                            throw log.ldapRealmErrorWhileConsumingResultsFromSearch(searchDn, filter, Arrays.toString(filterArgs), e);
                        }
                    }
                }, false).onClose(() -> {
                    if (result != null) {
                        try {
                            result.close();
                        } catch (NamingException e) {
                            log.trace(e);
                        }
                    }
                });
            } catch (NameNotFoundException e) {
                log.trace(e);
                return Stream.empty();
            } catch (Exception e) {
                throw log.ldapRealmIdentitySearchFailed(e);
            }
        }

        private NamingEnumeration<SearchResult> searchWithPagination() throws NamingException, IOException {
            Control[] controlsBackup = null;
            if (pageSize != 0 && context instanceof LdapContext) {
                controlsBackup = ((LdapContext)context).getRequestControls();
                ((LdapContext)context).setRequestControls(new Control[]{
                        new PagedResultsControl(pageSize, cookie, Control.CRITICAL)
                });
            }
            NamingEnumeration<SearchResult> results = context.search(searchDn, filter, filterArgs, createSearchControls(searchScope, returningAttributes));
            if (pageSize != 0 && context instanceof LdapContext) {
                ((LdapContext)context).setRequestControls(controlsBackup);
            }
            return results;
        }

        public void setReturningAttributes(String... returningAttributes) {
            this.returningAttributes = returningAttributes;
        }

        private SearchControls createSearchControls(int searchScope, String... returningAttributes) {
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(searchScope);
            searchControls.setTimeLimit(identityMapping.searchTimeLimit);
            searchControls.setReturningAttributes(returningAttributes);
            return searchControls;
        }
    }

    static class IdentityMapping {

        // NOTE: This class is not a general purpose holder for all possible realm configuration, the purpose is to cover
        // configuration related to locating the identity and loading it's attributes.

        private final String searchDn;
        private final boolean searchRecursive;
        public final int searchTimeLimit;
        private final String rdnIdentifier;
        private final List<AttributeMapping> attributes;
        private final LdapName newIdentityParent;
        private final Attributes newIdentityAttributes;
        private final String filterName;
        private final String iteratorFilter;

        public IdentityMapping(String searchDn, boolean searchRecursive, int searchTimeLimit, String rdnIdentifier, List<AttributeMapping> attributes, LdapName newIdentityParent, Attributes newIdentityAttributes, String filterName, String iteratorFilter) {
            Assert.checkNotNullParam("rdnIdentifier", rdnIdentifier);
            this.searchDn = searchDn;
            this.searchRecursive = searchRecursive;
            this.searchTimeLimit = searchTimeLimit;
            this.rdnIdentifier = rdnIdentifier;
            this.attributes = attributes;
            this.newIdentityParent = newIdentityParent;
            this.newIdentityAttributes = newIdentityAttributes;
            this.filterName = filterName;
            this.iteratorFilter = iteratorFilter;
        }
    }

    private class ServerNotificationListener implements ObjectChangeListener, NamespaceChangeListener {

        private final Consumer<Principal> listener;

        ServerNotificationListener(Consumer<Principal> listener) {
            this.listener = listener;
        }

        @Override
        public void objectAdded(NamingEvent evt) {

        }

        @Override
        public void objectRemoved(NamingEvent evt) {
            invokeCacheUpdateListener(evt);
        }

        @Override
        public void objectRenamed(NamingEvent evt) {
            invokeCacheUpdateListener(evt);
        }

        @Override
        public void objectChanged(NamingEvent evt) {
            invokeCacheUpdateListener(evt);
        }

        @Override
        public void namingExceptionThrown(NamingExceptionEvent evt) {

        }

        private void invokeCacheUpdateListener(NamingEvent evt) {
            Binding oldBinding = evt.getOldBinding();
            LdapName ldapName;
            try {
                ldapName = new LdapName(oldBinding.getName());
            } catch (InvalidNameException e) {
                throw log.ldapInvalidLdapName(oldBinding.getName(), e);
            }
            ldapName.getRdns().stream()
                    .filter(rdn -> rdn.getType().equals(identityMapping.rdnIdentifier))
                    .map(rdn -> new NamePrincipal(rdn.getValue().toString()))
                    .findFirst()
                    .ifPresent(listener::accept);
        }
    }
}
