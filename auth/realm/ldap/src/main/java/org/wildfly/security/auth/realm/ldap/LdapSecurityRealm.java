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

import static org.wildfly.security.auth.realm.ldap.ElytronMessages.log;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
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
import javax.naming.directory.Attribute;
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
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.CacheableSecurityRealm;
import org.wildfly.security.auth.realm.IdentitySharedExclusiveLock;
import org.wildfly.security.auth.realm.IdentitySharedExclusiveLock.IdentityLock;
import org.wildfly.security.auth.server.ModifiableRealmIdentityIterator;
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
import org.wildfly.security.password.spec.Encoding;

/**
 * Security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
class LdapSecurityRealm implements ModifiableSecurityRealm, CacheableSecurityRealm {

    private final String ENV_BINARY_ATTRIBUTES = "java.naming.ldap.attributes.binary";

    private final Supplier<Provider[]> providers;
    private final ExceptionSupplier<DirContext, NamingException> dirContextSupplier;
    private final NameRewriter nameRewriter;
    private final IdentityMapping identityMapping;
    private final int pageSize;
    private final Charset hashCharset;
    private final Encoding hashEncoding;

    private final List<CredentialLoader> credentialLoaders;
    private final List<CredentialPersister> credentialPersisters;
    private final List<EvidenceVerifier> evidenceVerifiers;

    private final ConcurrentHashMap<String, IdentitySharedExclusiveLock> realmIdentityLocks = new ConcurrentHashMap<>();

    private Set<Consumer<Principal>> listenersPendingRegistration = new LinkedHashSet<Consumer<Principal>>();

    LdapSecurityRealm(final Supplier<Provider[]> providers,
                      final ExceptionSupplier<DirContext, NamingException> dirContextSupplier,
                      final NameRewriter nameRewriter,
                      final IdentityMapping identityMapping,
                      final List<CredentialLoader> credentialLoaders,
                      final List<CredentialPersister> credentialPersisters,
                      final List<EvidenceVerifier> evidenceVerifiers,
                      final int pageSize,
                      final Charset hashCharset,
                      final Encoding hashEncoding) {

        this.providers = providers;
        this.dirContextSupplier = dirContextSupplier;
        this.nameRewriter = nameRewriter;
        this.identityMapping = identityMapping;
        this.pageSize = pageSize;
        this.hashCharset = hashCharset != null ? hashCharset : StandardCharsets.UTF_8;
        this.hashEncoding = hashEncoding != null ? hashEncoding : Encoding.BASE64;

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
        synchronized (this.listenersPendingRegistration) {
            DirContext dirContext = null;
            try {
                dirContext = obtainContext();
                registerIdentityChangeListener(dirContext, listener);
            } catch (Exception cause) {
                // either connection died or realm not available during boot
                // we need to wait, lets store
                listenersPendingRegistration.add(listener);

                log.ldapRealmDeferRegistration();
                if (log.isDebugEnabled()) {
                    log.debug("Listener registration failure: ", cause);
                }
            } finally {
                if (dirContext != null) {
                    closeContext(dirContext);
                }
            }
        }
    }

    private void registerIdentityChangeListener(final DirContext dirContext, final Consumer<Principal> listener) throws NamingException {
        EventContext eventContext = (EventContext) dirContext.lookup("");
        eventContext.addNamingListener("", EventContext.SUBTREE_SCOPE, new ServerNotificationListener(listener));
    }

    private ModifiableRealmIdentity getRealmIdentity(final Principal principal, final boolean exclusive) {
        if (! NamePrincipal.isConvertibleTo(principal)) {
            return ModifiableRealmIdentity.NON_EXISTENT;
        }
        String name = nameRewriter.rewriteName(principal.getName());
        if (name == null) {
            throw log.invalidName();
        }

        // Acquire the appropriate lock for the realm identity
        log.debugf("Obtaining lock for identity [%s]...", name);
        IdentitySharedExclusiveLock realmIdentityLock = getRealmIdentityLockForName(name);
        IdentityLock lock;
        if (exclusive) {
            lock = realmIdentityLock.lockExclusive();
        } else {
            lock = realmIdentityLock.lockShared();
        }
        log.debugf("Obtained lock for identity [%s].", name);
        return new LdapRealmIdentity(name, lock, hashCharset, hashEncoding);
    }

    private DirContext obtainContext() throws RealmUnavailableException {
        try {
            DirContext ctx = dirContextSupplier.get();
            synchronized (this.listenersPendingRegistration) {
                // we got ctx, this means connection is up
                // add & remove in case we are ok, take into account network failure.
                final Iterator<Consumer<Principal>> it = this.listenersPendingRegistration.iterator();
                while(it.hasNext()) {
                    registerIdentityChangeListener(ctx, it.next());
                    it.remove();
                }
                return ctx;
            }
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
    public ModifiableRealmIdentityIterator getRealmIdentityIterator() throws RealmUnavailableException {
        if (identityMapping.iteratorFilter == null) {
            throw log.ldapRealmNotConfiguredToSupportIteratingOverIdentities();
        }

        final DirContext dirContext = obtainContext();
        final Stream<SearchResult> resultStream;
        final LdapSearch ldapSearch = new LdapSearch(identityMapping.searchDn, identityMapping.searchRecursive, pageSize, identityMapping.iteratorFilter);
        ldapSearch.setReturningAttributes(Collections.singleton(identityMapping.rdnIdentifier));

        resultStream = ldapSearch.search(dirContext);

        Iterator<String> iterator = resultStream.map(entry -> {
            try {
                return (String) entry.getAttributes().get(identityMapping.rdnIdentifier).get();
            } catch (NamingException e) {
                throw new RuntimeException(log.ldapRealmIdentitySearchFailed(e));
            }
        }).distinct().iterator(); // distinct to prevent deadlock on identity locking when one identity found twice

        return new ModifiableRealmIdentityIterator() {

            @Override
            public boolean hasNext() {
                return iterator.hasNext();
            }

            @Override
            public ModifiableRealmIdentity next() {
                String name = iterator.next();
                return getRealmIdentityForUpdate(new NamePrincipal(name));
            }

            @Override
            public void close() throws RealmUnavailableException {
                resultStream.close();
                closeContext(dirContext);
            }
        };
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        SupportLevel response = SupportLevel.UNSUPPORTED;

        for (CredentialLoader loader : credentialLoaders) {
            SupportLevel support = loader.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
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
            SupportLevel support = verifier.getEvidenceVerifySupport(evidenceType, algorithmName);
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
        private IdentityLock lock;
        private final Charset hashCharset;
        private final Encoding hashEncoding;

        LdapRealmIdentity(final String name, final IdentityLock lock, final Charset hashCharset, final Encoding hashEncoding) {
            this.name = name;
            this.lock = lock;
            this.hashCharset = hashCharset;
            this.hashEncoding = hashEncoding;
        }

        public Principal getRealmIdentityPrincipal() {
            return new NamePrincipal(name);
        }

        public Charset getHashCharset() {
            return this.hashCharset;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);

            if (LdapSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return SupportLevel.UNSUPPORTED;
            }

            DirContext dirContext = obtainContext();
            try {
                Set<String> attributes = new HashSet<>();
                Set<String> binaryAttributes = new HashSet<>();
                for (CredentialLoader loader : credentialLoaders) {
                    loader.addRequiredIdentityAttributes(attributes);
                    loader.addBinaryIdentityAttributes(binaryAttributes);
                }

                LdapIdentity identity = getIdentity(dirContext, attributes, binaryAttributes);
                if (identity == null) {
                    return SupportLevel.UNSUPPORTED;
                }
                SupportLevel support = SupportLevel.UNSUPPORTED;
                for (CredentialLoader loader : credentialLoaders) {
                    if (loader.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec).mayBeSupported()) {
                        IdentityCredentialLoader icl = loader.forIdentity(identity.getDirContext(), identity.getDistinguishedName(), identity.getEntry().getAttributes(), hashEncoding);

                        SupportLevel temp = icl.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec, providers);
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
            } finally {
                closeContext(dirContext);
            }
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType) throws RealmUnavailableException {
            return getCredential(credentialType, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) throws RealmUnavailableException {
            return getCredential(credentialType, algorithmName, null);
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);

            if (LdapSecurityRealm.this.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return null;
            }

            DirContext dirContext = obtainContext();
            try {
                Set<String> attributes = new HashSet<>();
                Set<String> binaryAttributes = new HashSet<>();
                for (CredentialLoader loader : credentialLoaders) {
                    loader.addRequiredIdentityAttributes(attributes);
                    loader.addBinaryIdentityAttributes(binaryAttributes);
                }

                LdapIdentity identity = getIdentity(dirContext, attributes, binaryAttributes);
                if (identity == null) {
                    return null;
                }
                for (CredentialLoader loader : credentialLoaders) {
                    if (loader.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec).mayBeSupported()) {
                        IdentityCredentialLoader icl = loader.forIdentity(identity.getDirContext(), identity.getDistinguishedName(), identity.getEntry().getAttributes(), hashEncoding);

                        Credential credential = icl.getCredential(credentialType, algorithmName, parameterSpec, providers);
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

            DirContext dirContext = obtainContext();
            try {
                Set<String> attributes = new HashSet<>();
                Set<String> binaryAttributes = new HashSet<>();
                for (CredentialPersister persister : credentialPersisters) {
                    persister.addRequiredIdentityAttributes(attributes);
                    persister.addBinaryIdentityAttributes(binaryAttributes);
                }

                LdapIdentity identity = getIdentity(dirContext, attributes, binaryAttributes);
                if (identity == null) {
                    throw log.ldapRealmIdentityNotExists(name);
                }

                // verify support
                for (Credential credential : credentials) {
                    final Class<? extends Credential> credentialType = credential.getClass();
                    final String algorithmName = credential instanceof AlgorithmCredential ? ((AlgorithmCredential) credential).getAlgorithm() : null;
                    final AlgorithmParameterSpec parameterSpec = credential instanceof AlgorithmCredential ? ((AlgorithmCredential) credential).getParameters() : null;
                    boolean supported = false;
                    for (CredentialPersister persister : credentialPersisters) {
                        IdentityCredentialPersister icp = persister.forIdentity(identity.getDirContext(), identity.getDistinguishedName(), identity.getEntry().getAttributes());
                        if (icp.getCredentialPersistSupport(credentialType, algorithmName, parameterSpec)) {
                            supported = true;
                        }
                    }
                    if (!supported) {
                        throw log.ldapRealmsPersisterNotSupported();
                    }
                }

                // clear
                for (CredentialPersister persister : credentialPersisters) {
                    IdentityCredentialPersister icp = persister.forIdentity(identity.getDirContext(), identity.getDistinguishedName(), identity.getEntry().getAttributes());
                    icp.clearCredentials();
                }

                // set
                for (Credential credential : credentials) {
                    final Class<? extends Credential> credentialType = credential.getClass();
                    final String algorithmName = credential instanceof AlgorithmCredential ? ((AlgorithmCredential) credential).getAlgorithm() : null;
                    final AlgorithmParameterSpec parameterSpec = credential instanceof AlgorithmCredential ? ((AlgorithmCredential) credential).getParameters() : null;
                    for (CredentialPersister persister : credentialPersisters) {
                        IdentityCredentialPersister icp = persister.forIdentity(identity.getDirContext(), identity.getDistinguishedName(), identity.getEntry().getAttributes());
                        if (icp.getCredentialPersistSupport(credentialType, algorithmName, parameterSpec)) {
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
            return AuthorizationIdentity.basicIdentity(getAttributes());
        }

        @Override
        public org.wildfly.security.authz.Attributes getAttributes() throws RealmUnavailableException {
            DirContext context = obtainContext();
            try {
                LdapIdentity identity = getIdentity(context,
                        identityMapping.attributes.stream()
                        .map(AttributeMapping::getIdentityLdapName)
                        .filter(Objects::nonNull)
                        .collect(Collectors.toSet()),
                        null);

                SearchResult entry = identity != null ? identity.getEntry() : null;
                DirContext identityContext = identity != null ? identity.getDirContext() : null;

                MapAttributes attributes = new MapAttributes();
                attributes.addAll(extractSimpleAttributes(entry));
                attributes.addAll(extractFilteredAttributes(entry, context, identityContext));

                if (log.isDebugEnabled()) {
                    log.debugf("Obtaining authorization identity attributes for principal [%s]:", name);

                    if (attributes.isEmpty()) {
                        log.debugf("Identity [%s] does not have any attributes.", name);
                    } else {
                        log.debugf("Identity [%s] attributes are:", name);
                        attributes.keySet().forEach(key -> {
                            org.wildfly.security.authz.Attributes.Entry values = attributes.get(key);
                            values.forEach(value -> log.debugf("    Attribute [%s] value [%s].", key, value));
                        });
                    }
                }

                return attributes.asReadOnly();
            } finally {
                closeContext(context);
            }
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);

            DirContext dirContext = obtainContext();
            try {

                Set<String> attributes = new HashSet<>();
                Set<String> binaryAttributes = new HashSet<>();
                for (EvidenceVerifier verifier : evidenceVerifiers) {
                    verifier.addRequiredIdentityAttributes(attributes);
                    verifier.addBinaryIdentityAttributes(binaryAttributes);
                }

                LdapIdentity identity = getIdentity(dirContext, attributes, binaryAttributes);
                if (identity == null) {
                    return SupportLevel.UNSUPPORTED;
                }

                SupportLevel response = SupportLevel.UNSUPPORTED;
                for (EvidenceVerifier verifier : evidenceVerifiers) {
                    if (verifier.getEvidenceVerifySupport(evidenceType, algorithmName).mayBeSupported()) {
                        final IdentityEvidenceVerifier iev = verifier.forIdentity(identity.getDirContext(), identity.getDistinguishedName(), identity.getUrl(), identity.getEntry().getAttributes(), hashEncoding);

                        final SupportLevel support = iev.getEvidenceVerifySupport(evidenceType, algorithmName, providers);
                        if (support != null && support.isDefinitelySupported()) {
                            // As soon as one claims definite support we know it is supported.
                            return support;
                        }

                        if (support != null && response.compareTo(support) < 0) {
                            response = support;
                        }
                    }
                }
                return response;
            } finally {
                closeContext(dirContext);
            }
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);

            final Class<? extends Evidence> evidenceType = evidence.getClass();
            final String algorithmName = evidence instanceof AlgorithmEvidence ? ((AlgorithmEvidence) evidence).getAlgorithm() : null;

            if (LdapSecurityRealm.this.getEvidenceVerifySupport(evidenceType, algorithmName) == SupportLevel.UNSUPPORTED) {
                // If not supported in general then definitely not supported for a specific principal.
                return false;
            }

            DirContext dirContext = obtainContext();
            try {
                Set<String> attributes = new HashSet<>();
                Set<String> binaryAttributes = new HashSet<>();
                for (EvidenceVerifier verifier : evidenceVerifiers) {
                    verifier.addRequiredIdentityAttributes(attributes);
                    verifier.addBinaryIdentityAttributes(binaryAttributes);
                }

                LdapIdentity identity = getIdentity(dirContext, attributes, binaryAttributes);
                if (identity == null) {
                    return false;
                }

                for (EvidenceVerifier verifier : evidenceVerifiers) {
                    if (verifier.getEvidenceVerifySupport(evidenceType, algorithmName).mayBeSupported()) {
                        IdentityEvidenceVerifier iev = verifier.forIdentity(identity.getDirContext(), identity.getDistinguishedName(), identity.getUrl(), identity.getEntry().getAttributes(), hashEncoding);

                        if (iev.verifyEvidence(evidence, providers, hashCharset)) {
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
            DirContext dirContext = obtainContext();
            try {
                LdapIdentity identity = getIdentity(dirContext);
                boolean exists = identity != null;

                if (!exists) {
                    log.debugf("Principal [%s] does not exists.", name);
                }

                return exists;
            } finally {
                closeContext(dirContext);
            }
        }

        private LdapSearch createLdapSearchByDn() {
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
                if (identityMapping.searchDn != null) {
                    List<Rdn> expectedStart = new LdapName(identityMapping.searchDn).getRdns();
                    if ( ! ldapName.startsWith(expectedStart)) { // ...,search-dn
                        log.tracef("Getting identity [%s] by DN skipped - DN not in search-dn [%s]", name, identityMapping.searchDn);
                        return null;
                    }
                    if ( ! identityMapping.searchRecursive && ldapName.size() != expectedStart.size() + 1) {
                        log.tracef("Getting identity [%s] by DN skipped - DN not directly in search-dn and recursive search not enabled [%s]", name, identityMapping.searchDn);
                        return null;
                    }
                }
                return new LdapSearch(ldapName.toString(), SearchControls.OBJECT_SCOPE, 0, identityMapping.filterName, rdnIdentifier.getValue().toString());

            } catch (InvalidNameException e) {
                log.tracef(e, "Getting identity [%s] by DN failed - will continue by name", name);
            }
            return null;
        }

        private LdapIdentity getIdentity(DirContext dirContext) throws RealmUnavailableException {
            return getIdentity(dirContext, null, null);
        }

        private LdapIdentity getIdentity(DirContext dirContext, Collection<String> returningAttributes, Collection<String> binaryAttributes) throws RealmUnavailableException {
            log.debugf("Trying to create identity for principal [%s].", name);
            LdapSearch ldapSearch = createLdapSearchByDn();
            if (ldapSearch == null) { // name is not a valid DN, search by name
                if (identityMapping.searchDn != null) {
                    ldapSearch = new LdapSearch(identityMapping.searchDn, identityMapping.searchRecursive, 0, identityMapping.filterName, name);
                } else {
                    log.debugf("Identity for principal [%s] not found. The name is not a valid DN and the search base DN is null", name);
                    return null;
                }
            }

            ldapSearch.setReturningAttributes(returningAttributes);
            ldapSearch.setBinaryAttributes(binaryAttributes);

            final LdapSearch ldapSearchFinal = ldapSearch;
            try (Stream<SearchResult> resultsStream = ldapSearch.search(dirContext)) {
                SearchResult result = resultsStream.findFirst().orElse(null);
                if (result != null) {
                    LdapIdentity identity = new LdapIdentity(name, ldapSearchFinal.getContext(), result.getNameInNamespace(), result.isRelative() ? null : result.getName(), result);
                    log.debugf("Identity for principal [%s] found at [%s].", name, identity.getDistinguishedName());
                    return identity;
                } else {
                    log.debugf("Identity for principal [%s] not found.", name);
                    return null;
                }
            }
        }

        private String extractRdn(AttributeMapping mapping, final String dn) {
            String valueRdn = mapping.getRdn();
            try {
                LdapName dnName = new LdapName(dn);
                // loop RDNs in reverse order, left to right, to return the leftmost one that matches
                for (int i = dnName.size() - 1; i >= 0; i--) {
                    Rdn rdn = dnName.getRdn(i);
                    if (rdn.getType().equalsIgnoreCase(valueRdn)) {
                        return rdn.getValue().toString();
                    }
                }
            } catch (Exception cause) {
                throw log.ldapRealmInvalidRdnForAttribute(mapping.getName(), dn, valueRdn, cause);
            }
            return null;
        }

        /**
         * Obtains attribute value by mapping from given entry and put it into given collection.
         *
         * @param entry LDAP entry, from which should be values obtained
         * @param mapping attribute mapping defining attribute, whose values should be obtained
         * @param outputCollection output collection for obtained values
         * @return {@code true} if {@code outputCollection} was changed.
         */
        private boolean valuesFromAttribute(SearchResult entry, AttributeMapping mapping, Collection<String> outputCollection) throws NamingException {
            if (mapping.getLdapName() == null) {
                String value = entry.getNameInNamespace();
                if (mapping.getRdn() != null) {
                    value = extractRdn(mapping, value);
                }
                return outputCollection.add(value);
            } else {
                Attributes entryAttributes = entry.getAttributes();
                javax.naming.directory.Attribute ldapAttribute = entryAttributes.get(mapping.getLdapName());
                if (ldapAttribute == null) return false;
                NamingEnumeration<?> attributesEnum = null;
                try {
                    attributesEnum = ldapAttribute.getAll();
                    Stream<String> values = Collections.list(attributesEnum).stream().map(Object::toString);
                    if (mapping.getRdn() != null) {
                        values = values.map(val -> extractRdn(mapping, val)).filter(Objects::nonNull);
                    }
                    return values.map(outputCollection::add).filter(changed -> changed).count() != 0;
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

        private Map<String, Collection<String>> extractFilteredAttributes(SearchResult identityEntry, DirContext context, DirContext identityContext) {
            return extractAttributes(AttributeMapping::isFilteredOrReference, mapping -> {
                Collection<String> values = mapping.getRoleRecursionDepth() == 0 ? new ArrayList<>() : new HashSet<>();
                final String searchDn = mapping.getSearchDn() != null ? mapping.getSearchDn() : identityMapping.searchDn;

                List<SearchResult> toSearch = new LinkedList<>();
                toSearch.add(identityEntry);

                for (int depth = 0; depth <= mapping.getRoleRecursionDepth() && ! toSearch.isEmpty(); depth++) {
                    List<SearchResult> toSearchInNextLevel = new LinkedList<>();
                    for(SearchResult entry : toSearch) {
                        final String entryDn = entry != null ? entry.getNameInNamespace() : null;
                        if (mapping.getReference() != null && entry != null) { // reference
                            forEachAttributeValue(entry, mapping.getReference(), value -> {
                                LdapSearch search = new LdapSearch(value);
                                extractFilteredAttributesFromSearch(search, entry, mapping, context, identityContext, values, toSearchInNextLevel);
                            });
                        } else if (mapping.getReference() == null) { // filter
                            if (depth == 0) { // roles of identity
                                LdapSearch search = new LdapSearch(searchDn, mapping.getRecursiveSearch(), 0, mapping.getFilter(), name, entryDn);
                                extractFilteredAttributesFromSearch(search, entry, mapping, context, identityContext, values, toSearchInNextLevel);
                            } else if (entry != null) { // roles of role
                                forEachAttributeValue(entry, mapping.getRoleRecursionName(), roleName -> {
                                    LdapSearch search = new LdapSearch(searchDn, mapping.getRecursiveSearch(), 0, mapping.getFilter(), roleName, entryDn);
                                    extractFilteredAttributesFromSearch(search, entry, mapping, context, identityContext, values, toSearchInNextLevel);
                                });
                            }
                        }
                    }
                    toSearch = toSearchInNextLevel;
                }
                return values;
            });
        }

        private void extractFilteredAttributesFromSearch(LdapSearch search, SearchResult referencedEntry, AttributeMapping mapping, DirContext context, DirContext identityContext, Collection<String> identityAttributeValues, Collection<SearchResult> toSearchInNextLevel) {
            String referencedDn = referencedEntry != null ? referencedEntry.getNameInNamespace() : null;

            Set<String> attributes = new HashSet<>();
            attributes.add(mapping.getLdapName());
            attributes.add(mapping.getReference());
            attributes.add(mapping.getRoleRecursionName());
            search.setReturningAttributes(attributes);

            try (Stream<SearchResult> entries = search.search(mapping.searchInIdentityContext() ? identityContext : context)) {
                entries.forEach(entry -> {
                    try {
                        if (valuesFromAttribute(entry, mapping, identityAttributeValues)) {
                            toSearchInNextLevel.add(entry);
                        }
                    } catch (Exception cause) {
                        throw ElytronMessages.log.ldapRealmFailedObtainAttributes(referencedDn, cause);
                    }
                });
            } catch (Exception cause) {
                throw ElytronMessages.log.ldapRealmFailedObtainAttributes(referencedDn, cause);
            }
        }

        private Map<String, Collection<String>> extractSimpleAttributes(SearchResult identityEntry) {
            if (identityEntry == null) return Collections.emptyMap();
            return extractAttributes(mapping -> !mapping.isFilteredOrReference(), mapping -> {
                Collection<String> identityAttributeValues = new ArrayList<>();
                try {
                    valuesFromAttribute(identityEntry, mapping, identityAttributeValues);
                } catch (Exception cause) {
                    throw ElytronMessages.log.ldapRealmFailedObtainAttributes(identityEntry.getNameInNamespace(), cause);
                }
                return identityAttributeValues;
            });
        }

        private Map<String, Collection<String>> extractAttributes(Predicate<AttributeMapping> filter, Function<AttributeMapping, Collection<String>> valueFunction) {
            return identityMapping.attributes.stream()
                    .filter(filter)
                    .collect(Collectors.toMap(AttributeMapping::getName, valueFunction, (values1, values2) -> {
                        List<String> merged = new ArrayList<>(values1);
                        merged.addAll(values2);
                        return merged;
                    }));
        }

        private void forEachAttributeValue(SearchResult entry, String attrId, Consumer<String> action) {
            NamingEnumeration<?> attributesEnum = null;
            try {
                Attribute attribute = entry.getAttributes().get(attrId);
                if (attribute == null) return;
                attributesEnum = attribute.getAll();
                Collections.list(attributesEnum).stream().map(Object::toString).forEach(action);
            } catch (NamingException e) {
                throw ElytronMessages.log.ldapRealmFailedObtainAttributes(entry.getNameInNamespace(), e);
            } finally {
                if (attributesEnum != null) {
                    try {
                        attributesEnum.close();
                    } catch (NamingException e) {
                        log.trace("Unable to close attributesEnum", e);
                    }
                }
            }
        }

        @Override
        public void delete() throws RealmUnavailableException {
            DirContext context = obtainContext();
            try {
                LdapIdentity identity = getIdentity(context);
                if (identity == null) {
                    throw log.noSuchIdentity();
                }
                log.debugf("Removing identity [%s] with DN [%s] from LDAP", name, identity.getDistinguishedName());
                identity.getDirContext().destroySubcontext(new LdapName(identity.getDistinguishedName()));
            } catch (NamingException e) {
                throw log.ldapRealmFailedDeleteIdentityFromServer(e);
            } finally {
                closeContext(context);
            }
        }

        @Override
        public void create() throws RealmUnavailableException {
            if (identityMapping.newIdentityParent == null || identityMapping.newIdentityAttributes == null) {
                throw log.ldapRealmNotConfiguredToSupportCreatingIdentities();
            }

            DirContext context = obtainContext();
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
            log.debugf("Trying to set attributes for principal [%s].", name);
            DirContext context = obtainContext();
            try {
                LdapIdentity identity = getIdentity(context);
                if (identity == null) {
                    throw log.noSuchIdentity();
                }

                List<ModificationItem> modItems = new LinkedList<>();
                LdapName identityLdapName = new LdapName(identity.getDistinguishedName());
                String renameTo = null;

                for(AttributeMapping mapping : identityMapping.attributes) {
                    if (mapping.getFilter() != null || mapping.getReference() != null || mapping.getRdn() != null) { // read-only mapping
                        if (attributes.size(mapping.getName()) != 0) {
                            log.ldapRealmDoesNotSupportSettingFilteredAttribute(mapping.getName(), name);
                        }
                    } else if (identityMapping.rdnIdentifier.equalsIgnoreCase(mapping.getLdapName())) { // entry rename
                        if (attributes.size(mapping.getName()) == 1) {
                            renameTo = attributes.get(mapping.getName(), 0);
                        } else {
                            throw log.ldapRealmRequiresExactlyOneRdnAttribute(mapping.getName(), name);
                        }
                    } else { // standard ldap attributes
                        if (attributes.size(mapping.getName()) == 0) {
                            BasicAttribute attribute = new BasicAttribute(mapping.getLdapName());
                            modItems.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, attribute));
                        } else {
                            BasicAttribute attribute = new BasicAttribute(mapping.getLdapName());
                            attributes.get(mapping.getName()).forEach(attribute::add);
                            modItems.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, attribute));
                        }
                    }
                }

                for(org.wildfly.security.authz.Attributes.Entry entry : attributes.entries()) {
                    if (identityMapping.attributes.stream().filter(mp -> mp.getName().equals(entry.getKey())).count() == 0) {
                        throw log.ldapRealmCannotSetAttributeWithoutMapping(entry.getKey(), name);
                    }
                }

                ModificationItem[] modItemsArray = modItems.toArray(new ModificationItem[modItems.size()]);
                identity.getDirContext().modifyAttributes(identityLdapName, modItemsArray);

                if (renameTo != null && ! renameTo.equals(identityLdapName.getRdn(identityLdapName.size()-1).getValue())) {
                    LdapName newLdapName = new LdapName(identityLdapName.getRdns().subList(0, identityLdapName.size()-1));
                    newLdapName.add(new Rdn(identityMapping.rdnIdentifier, renameTo));
                    identity.getDirContext().rename(identityLdapName, newLdapName);
                }

            } catch (Exception e) {
                throw log.ldapRealmAttributesSettingFailed(name, e);
            } finally {
                closeContext(context);
            }
        }

        private class LdapIdentity {

            private final String name;
            private final DirContext dirContext;
            private final String distinguishedName;
            private final String url;
            private final SearchResult entry;

            LdapIdentity(String name, DirContext dirContext, String distinguishedName, String url, SearchResult entry) {
                this.name = name;
                this.dirContext = dirContext;
                this.distinguishedName = distinguishedName;
                this.url = url;
                this.entry = entry;
            }

            String getName() {
                return this.name;
            }

            DirContext getDirContext() {
                return this.dirContext;
            }

            String getDistinguishedName() {
                return this.distinguishedName;
            }

            String getUrl() {
                return this.url;
            }

            SearchResult getEntry() {
                return this.entry;
            }
        }
    }

    private class LdapSearch {

        private final String NO_FILTER = "(objectclass=*)";

        private final String searchDn;
        private final int searchScope;
        private final int pageSize;
        private final String filter;
        private final String[] filterArgs;
        private Collection<String> returningAttributes;
        private Collection<String> binaryAttributes;
        private DirContext context;
        private NamingEnumeration<SearchResult> result;
        private byte[] cookie;
        private ReferralException referralException;

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

        public LdapSearch(String searchDn) {
            this.searchDn = searchDn;
            this.searchScope = SearchControls.OBJECT_SCOPE;
            this.pageSize = 0;
            this.filter = NO_FILTER;
            this.filterArgs = null;
        }

        public Stream<SearchResult> search(DirContext ctx) throws RealmUnavailableException {
            if (log.isDebugEnabled()) {
                log.debugf("Executing search [%s] in context [%s] with arguments [%s]. Returning attributes are [%s]. Binary attributes are [%s].",
                        filter, searchDn,
                        filterArgs == null ? null : String.join(", ", filterArgs),
                        returningAttributes == null ? null : String.join(", ", returningAttributes),
                        binaryAttributes == null ? null : String.join(", ", binaryAttributes)
                );
            }
            context = ctx;
            cookie = null;
            try {
                try {
                    result = searchWithPagination();
                } catch (ReferralException e) {
                    referralException = e;
                }
                return StreamSupport.stream(new Spliterators.AbstractSpliterator<SearchResult>(Long.MAX_VALUE, Spliterator.NONNULL) {

                    boolean finished = false;
                    Set<Object> followedReferrals = new HashSet<>();
                    boolean exceptionWasFollowed = false;
                    boolean execute = false;

                    @Override
                    public boolean tryAdvance(Consumer<? super SearchResult> action) {

                        if (finished) return false;

                        try {
                            while (true) {
                                try {
                                    if(execute) {
                                        execute = false;
                                        result = searchWithPagination();
                                    }

                                    if(referralException != null && !exceptionWasFollowed) {
                                        exceptionWasFollowed = true;
                                        throw referralException;
                                    }

                                    if ( ! result.hasMore()) { // end of page
                                        if ( ! (pageSize != 0 && context instanceof LdapContext) ) {
                                            log.trace("Identity iterating - pagination not supported - end of list");
                                            finished = true;
                                            return false;
                                        }
                                        Control[] controls = ((LdapContext) context).getResponseControls();
                                        if (controls != null) {
                                            for (Control control : controls) {
                                                if (control instanceof PagedResultsResponseControl) {
                                                    cookie = ((PagedResultsResponseControl) control).getCookie();
                                                    if (cookie == null) {
                                                        log.trace("Identity iterating - no more pages - end of list");
                                                        finished = true;
                                                        return false; // no more pages
                                                    }
                                                }
                                            }
                                        }
                                        result.close();

                                        result = searchWithPagination();
                                        if ( ! result.hasMore()) {
                                            log.trace("Identity iterating - even after page loading no results - end of list");
                                            finished = true;
                                            return false; // no more elements
                                        }
                                    }
                                    SearchResult entry = result.next();
                                    log.debugf("Found entry [%s].", entry.getNameInNamespace());
                                    action.accept(entry);
                                    return true;
                                } catch (ReferralException e) {
                                    if (followedReferrals.add(e.getReferralInfo())) { // follow
                                        log.debugf("Next referral following in identity iterating: [%s]", e.getReferralInfo());
                                        context = ((DelegatingLdapContext) context).wrapReferralContextObtaining(e);
                                        execute = true;
                                    } else { // already searched - skip
                                        if (e.skipReferral()) {
                                            log.debugf("Referral skipped, continue: [%s]", e.getReferralInfo());
                                            context = ((DelegatingLdapContext) context).wrapReferralContextObtaining(e);
                                            execute = true;
                                        } else {
                                            log.debugf("Referral skipped and no more elements: [%s]", e.getReferralInfo());
                                            finished = true;
                                            return false; // no more elements
                                        }
                                    }
                                }
                            }
                        } catch (NamingException | IOException e) {
                            try {
                                if(result != null){
                                    result.close();
                                }
                            } catch (NamingException ex) {
                                log.trace("Unable to close result", ex);
                            }
                            throw log.ldapRealmErrorWhileConsumingResultsFromSearch(searchDn, filter, Arrays.toString(filterArgs), e);
                        }
                    }
                }, false).onClose(() -> {
                    if (result != null) {
                        try {
                            result.close();
                        } catch (NamingException e) {
                            log.trace("Unable to close result", e);
                        }
                    }
                });
            } catch (NameNotFoundException e) {
                log.trace("Error searching", e);
                return Stream.empty();
            } catch (Exception e) {
                throw log.ldapRealmIdentitySearchFailed(e);
            }
        }

        private NamingEnumeration<SearchResult> searchWithPagination() throws NamingException, IOException {
            Control[] controlsBackup = null;
            Object binaryAttributesBackup = null;

            // backup and set environment
            if (pageSize != 0 && context instanceof LdapContext) {
                controlsBackup = ((LdapContext)context).getRequestControls();
                ((LdapContext)context).setRequestControls(new Control[]{
                        new PagedResultsControl(pageSize, cookie, Control.CRITICAL)
                });
            }
            if (binaryAttributes != null && binaryAttributes.size() != 0) { // set attributes which should be returned in binary form
                binaryAttributesBackup = context.getEnvironment().get(ENV_BINARY_ATTRIBUTES);
                context.addToEnvironment(ENV_BINARY_ATTRIBUTES, String.join(" ", binaryAttributes));
            }

            NamingEnumeration<SearchResult> results = context.search(new LdapName(searchDn), filter, filterArgs, createSearchControls());

            // revert environment change
            if (binaryAttributes != null && binaryAttributes.size() != 0) {
                if (binaryAttributesBackup == null) {
                    context.removeFromEnvironment(ENV_BINARY_ATTRIBUTES);
                } else {
                    context.addToEnvironment(ENV_BINARY_ATTRIBUTES, binaryAttributesBackup);
                }
            }
            if (pageSize != 0 && context instanceof LdapContext) {
                ((LdapContext)context).setRequestControls(controlsBackup);
            }
            return results;
        }

        private void setReturningAttributes(Collection<String> returningAttributes) {
            this.returningAttributes = returningAttributes;
        }

        private void setBinaryAttributes(Collection<String> binaryAttributes) {
            this.binaryAttributes = binaryAttributes;
        }

        private SearchControls createSearchControls() {
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(searchScope);
            searchControls.setTimeLimit(identityMapping.searchTimeLimit);
            if (returningAttributes == null) {
                searchControls.setReturningAttributes(new String[]{});
            } else {
                searchControls.setReturningAttributes(returningAttributes.toArray(new String[returningAttributes.size()]));
            }
            return searchControls;
        }

        /**
         * Get context, where the last obtained entry was found
         */
        private DirContext getContext() {
            return context;
        }
    }

    static class IdentityMapping {

        // NOTE: This class is not a general purpose holder for all possible realm configuration, the purpose is to cover
        // configuration related to locating the identity and loading it's attributes.

        private final String searchDn;
        private final boolean searchRecursive;
        private final int searchTimeLimit;
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
