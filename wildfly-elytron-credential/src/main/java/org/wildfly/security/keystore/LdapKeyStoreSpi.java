/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.keystore;

import static org.wildfly.security.credential._private.ElytronMessages.log;

import org.wildfly.common.function.ExceptionSupplier;
import org.wildfly.security.util.LdapUtil;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

/**
 * A LDAP backed {@link KeyStore} implementation.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
class LdapKeyStoreSpi extends KeyStoreSpi {

    private final String ENV_BINARY_ATTRIBUTES = "java.naming.ldap.attributes.binary";
    private final String CREATE_TIMESTAMP_ATTRIBUTE = "createTimestamp"; // RFC4512
    private final String MODIFY_TIMESTAMP_ATTRIBUTE = "modifyTimestamp"; // RFC4512


    private final ExceptionSupplier<DirContext, NamingException> dirContextSupplier;
    private final String searchPath;
    private final int searchScope;
    private final int searchTimeLimit;
    private final String filterAlias;
    private final String filterCertificate;
    private final String filterIterate;
    private final LdapName createPath;
    private final String createRdn;
    private final Attributes createAttributes;
    private final String aliasAttribute;
    private final String certificateAttribute;
    private final String certificateType;
    private final String certificateChainAttribute;
    private final String certificateChainEncoding;
    private final String keyAttribute;
    private final String keyType;

    LdapKeyStoreSpi(ExceptionSupplier<DirContext, NamingException> dirContextSupplier, String searchPath, int searchScope, int searchTimeLimit,
                    String filterAlias, String filterCertificate, String filterIterate,
                    LdapName createPath, String createRdn, Attributes createAttributes,
                    String aliasAttribute,
                    String certificateAttribute, String certificateType,
                    String certificateChainAttribute, String certificateChainEncoding,
                    String keyAttribute, String keyType) {
        this.dirContextSupplier = dirContextSupplier;
        this.searchPath = searchPath;
        this.searchScope = searchScope;
        this.searchTimeLimit = searchTimeLimit;
        this.filterAlias = filterAlias;
        this.filterCertificate = filterCertificate;
        this.filterIterate = filterIterate;
        this.createPath = createPath;
        this.createRdn = createRdn;
        this.createAttributes = createAttributes;
        this.aliasAttribute = aliasAttribute;
        this.certificateAttribute = certificateAttribute;
        this.certificateType = certificateType;
        this.certificateChainAttribute = certificateChainAttribute;
        this.certificateChainEncoding = certificateChainEncoding;
        this.keyAttribute = keyAttribute;
        this.keyType = keyType;
    }

    private Object binaryAttributesBackup;

    private DirContext obtainDirContext() {
        try {
            DirContext context = dirContextSupplier.get();
            binaryAttributesBackup = context.getEnvironment().get(ENV_BINARY_ATTRIBUTES);
            context.addToEnvironment(ENV_BINARY_ATTRIBUTES, String.join(" ",
                    certificateAttribute, certificateChainAttribute, keyAttribute));
            return context;
        } catch (NamingException e) {
            throw log.failedToObtainDirContext(e);
        }
    }

    private void returnDirContext(DirContext context) {
        try {
            if (binaryAttributesBackup == null) {
                context.removeFromEnvironment(ENV_BINARY_ATTRIBUTES);
            } else {
                context.addToEnvironment(ENV_BINARY_ATTRIBUTES, binaryAttributesBackup);
            }
            context.close();
        } catch (NamingException e) {
            throw log.failedToReturnDirContext(e);
        }
    }

    private SearchControls createSearchControl(String[] returningAttributes) {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(searchScope);
        controls.setTimeLimit(searchTimeLimit);
        controls.setReturningAttributes(returningAttributes);
        return controls;
    }

    private SearchResult searchAlias(DirContext dirContext, String alias, byte[] cert, String[] returningAttributes) throws NamingException {
        SearchControls ctls = createSearchControl(returningAttributes);
        NamingEnumeration<SearchResult> results = (cert == null) ?
                dirContext.search(searchPath, filterAlias, new String[]{alias}, ctls) :
                dirContext.search(searchPath, filterCertificate, new Object[]{cert}, ctls);

        if (!results.hasMore()) {
            log.debugf("Alias [%s] not found in LdapKeyStore", alias);
            return null;
        }
        return results.next();
    }

    private Attributes obtainAliasOrCertificateAttributes(String alias, byte[] cert, String[] attributes) {
        DirContext context = obtainDirContext();
        if (context == null) {
            log.trace("Unable to obtain DirContext");
            return null;
        }
        try {
            SearchResult result = searchAlias(context, alias, cert, attributes);
            if (result == null) return null;
            return result.getAttributes();
        } catch (NamingException e) {
            throw log.ldapKeyStoreFailedToObtainAlias(alias, e);
        } finally {
            returnDirContext(context);
        }
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        Attributes attributes = obtainAliasOrCertificateAttributes(alias, null, new String[]{certificateAttribute});
        if (attributes == null) {
            log.tracef("Alias [%s] does not exist", alias);
            return null;
        }
        try {
            Attribute attribute = LdapUtil.getBinaryAttribute(attributes, certificateAttribute);
            if (attribute == null) return null;
            byte[] bytes = (byte[]) attribute.get();
            if (bytes == null) return null;
            InputStream is = new ByteArrayInputStream(bytes);
            CertificateFactory certFactory = CertificateFactory.getInstance(certificateType);
            return certFactory.generateCertificate(is);
        } catch (CertificateException | NamingException e) {
            throw log.ldapKeyStoreFailedToObtainCertificate(alias, e);
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        Attributes attributes = obtainAliasOrCertificateAttributes(alias, null, new String[]{certificateChainAttribute});
        if (attributes == null) {
            log.tracef("Alias [%s] does not exist", alias);
            return null;
        }
        try {
            Attribute attribute = LdapUtil.getBinaryAttribute(attributes, certificateChainAttribute);
            if (attribute == null) return null;
            byte[] bytes = (byte[]) attribute.get();
            if (bytes == null) return null;
            InputStream is = new ByteArrayInputStream(bytes);
            CertificateFactory certFactory = CertificateFactory.getInstance(certificateType);
            Collection<? extends Certificate> chain = certFactory.generateCertificates(is);
            return chain.toArray(new Certificate[chain.size()]);
        } catch (CertificateException | NamingException e) {
            throw log.ldapKeyStoreFailedToObtainCertificateChain(alias, e);
        }
    }

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        Attributes attributes = obtainAliasOrCertificateAttributes(alias, null, new String[]{keyAttribute});
        if (attributes == null) {
            log.tracef("Alias [%s] does not exist", alias);
            return null;
        }
        try {
            Attribute attribute = LdapUtil.getBinaryAttribute(attributes, keyAttribute);
            if (attribute == null) return null; // alias does not identify a key-related entry
            byte[] bytes = (byte[]) attribute.get();
            if (bytes == null) return null; // alias does not identify a key-related entry
            InputStream is = new ByteArrayInputStream(bytes);
            KeyStore keystore = KeyStore.getInstance(keyType);
            keystore.load(is, password);
            String firstAlias = keystore.aliases().nextElement();
            return keystore.getKey(firstAlias, password);
        } catch (KeyStoreException | CertificateException | IOException | NamingException e) {
            throw log.ldapKeyStoreFailedToRecoverKey(alias, e);
        }
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        Attributes attributes = obtainAliasOrCertificateAttributes(alias, null, new String[]{CREATE_TIMESTAMP_ATTRIBUTE, MODIFY_TIMESTAMP_ATTRIBUTE});
        if (attributes == null) {
            log.tracef("Alias [%s] does not exist", alias);
            return null;
        }
        try {
            Attribute creationAttribute = attributes.get(CREATE_TIMESTAMP_ATTRIBUTE);
            Attribute modificationAttribute = attributes.get(MODIFY_TIMESTAMP_ATTRIBUTE);
            if (modificationAttribute != null && modificationAttribute.get() != null) {
                return LdapGeneralizedTimeUtil.generalizedTimeToDate((String) modificationAttribute.get());
            } else if (creationAttribute != null && creationAttribute.get() != null) {
                return LdapGeneralizedTimeUtil.generalizedTimeToDate((String) creationAttribute.get());
            } else {
                log.tracef("LDAP entry of alias [%s] does not have create nor modify timestamp attributes", alias);
                return null;
            }
        } catch (ParseException | NamingException e) {
            throw log.ldapKeyStoreFailedToObtainCreationDate(alias, e);
        }
    }

    private void storeAttributes(String alias, List<ModificationItem> items) throws KeyStoreException {
        DirContext context = obtainDirContext();
        try {
            SearchResult result = searchAlias(context, alias, null, new String[]{});
            LdapName distinguishName;

            if (result == null) { // alias not exists yet - create
                if (createPath == null || createAttributes == null || createRdn == null)
                    throw log.creationNotConfigured(alias);

                distinguishName = (LdapName) createPath.clone();
                distinguishName.add(new Rdn(createRdn, alias));

                log.debugf("Creating keystore alias [%s] with DN [%s] in LDAP", alias, distinguishName.toString());
                context.createSubcontext(distinguishName, createAttributes);

                items.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(aliasAttribute, alias)));
            } else {
                distinguishName = new LdapName(result.getNameInNamespace());
            }

            context.modifyAttributes(distinguishName, items.toArray(new ModificationItem[items.size()]));
        } catch (NamingException e) {
            throw log.ldapKeyStoreFailedToStore(alias, e);
        } finally {
            returnDirContext(context);
        }
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        List<ModificationItem> items = new LinkedList<>();
        try {
            BasicAttribute attribute = new BasicAttribute(certificateAttribute);
            attribute.add(cert.getEncoded());
            items.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, attribute));
        } catch (CertificateEncodingException e) {
            throw log.ldapKeyStoreFailedToSerializeCertificate(alias, e);
        }
        storeAttributes(alias, items);
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
        try {
            // pack key into keystore and protect it using password
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            KeyStore keystore = KeyStore.getInstance(keyType);
            keystore.load(null, password);
            keystore.setKeyEntry(alias, key, password, chain);
            keystore.store(os, password);
            byte[] keystoreBytes = os.toByteArray();

            engineSetKeyEntry(alias, keystoreBytes, chain);
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            throw log.ldapKeyStoreFailedToSerializeKey(alias, e);
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] keystoreBytes, Certificate[] chain) throws KeyStoreException {
        try {
            List<ModificationItem> items = new LinkedList<>();

            items.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(keyAttribute, keystoreBytes)));

            CertificateFactory certFactory = CertificateFactory.getInstance(certificateType);
            CertPath certPath = certFactory.generateCertPath(Arrays.asList(chain));
            BasicAttribute chainAttr = new BasicAttribute(certificateChainAttribute, certPath.getEncoded(certificateChainEncoding));
            items.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, chainAttr));

            BasicAttribute certificateAttr = new BasicAttribute(certificateAttribute, chain[0].getEncoded());
            items.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, certificateAttr));

            storeAttributes(alias, items);
        } catch (CertificateException e) {
            throw log.ldapKeyStoreFailedToSerializeCertificate(alias, e);
        }
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        DirContext context = obtainDirContext();
        try {
            SearchResult result = searchAlias(context, alias, null, new String[]{});
            if (result == null) {
                throw log.ldapKeyStoreFailedToDeleteNonExisting(alias);
            }
            context.destroySubcontext(result.getNameInNamespace());
        } catch (NamingException e) {
            throw log.ldapKeyStoreFailedToDelete(alias, e);
        } finally {
            returnDirContext(context);
        }
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        DirContext context = obtainDirContext();
        if (context == null) {
            log.trace("Unable to obtain DirContext");
            return false;
        }
        try {
            NamingEnumeration<SearchResult> results = context.search(searchPath, filterAlias, new String[]{alias}, createSearchControl(new String[]{aliasAttribute}));
            boolean found = results.hasMore();
            results.close();
            return found;
        } catch (NamingException e) {
            throw log.ldapKeyStoreFailedToTestAliasExistence(alias, e);
        } finally {
            returnDirContext(context);
        }
    }

    @Override
    public Enumeration<String> engineAliases() {
        DirContext context = obtainDirContext();
        if (context == null) {
            log.trace("Unable to obtain DirContext");
            return null;
        }
        try {
            NamingEnumeration<SearchResult> results = context.search(searchPath, filterIterate, null, createSearchControl(new String[]{aliasAttribute})); // TODO pagination
            List<String> aliases = new LinkedList<>();
            while (results.hasMore()) {
                Attribute attribute = results.next().getAttributes().get(aliasAttribute);
                if (attribute != null) aliases.add((String) attribute.get());
            }
            return Collections.enumeration(aliases);
        } catch (NamingException e) {
            throw log.ldapKeyStoreFailedToIterateAliases(e);
        } finally {
            returnDirContext(context);
        }
    }

    @Override
    public int engineSize() {
        DirContext context = obtainDirContext();
        if (context == null) {
            log.trace("Unable to obtain DirContext");
            return 0;
        }
        try {
            NamingEnumeration<SearchResult> results = context.search(searchPath, filterIterate, null, createSearchControl(new String[]{aliasAttribute}));
            int count = 0;
            while (results.hasMore()) {
                results.next();
                count++;
            }
            return count;
        } catch (NamingException e) {
            throw log.ldapKeyStoreFailedToIterateAliases(e);
        } finally {
            returnDirContext(context);
        }
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        Attributes attributes = obtainAliasOrCertificateAttributes(alias, null, new String[]{keyAttribute});
        Attribute attribute = attributes == null ? null : LdapUtil.getBinaryAttribute(attributes, keyAttribute);
        if (attribute == null) {
            log.tracef("Alias [%s] is not key entry", alias);
            return false;
        }
        try {
            byte[] bytes = (byte[]) attribute.get();
            return bytes != null;
        } catch (NamingException e) {
            throw log.ldapKeyStoreFailedToObtainKey(alias, e);
        }
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        Attributes attributes = obtainAliasOrCertificateAttributes(alias, null, new String[]{certificateAttribute});
        if (attributes == null) return false;
        Attribute attribute = LdapUtil.getBinaryAttribute(attributes, certificateAttribute);
        if (attribute == null) return false;
        try {
            byte[] bytes = (byte[]) attribute.get();
            return bytes != null;
        } catch (NamingException e) {
            throw log.ldapKeyStoreFailedToObtainKey(alias, e);
        }
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        try {
            byte[] certBytes = cert.getEncoded();
            Attributes attributes = obtainAliasOrCertificateAttributes(null, certBytes, new String[]{aliasAttribute});
            Attribute attribute = attributes == null ? null : attributes.get(aliasAttribute);
            if (attribute == null) {
                log.tracef("Certificate not found in LDAP: [%s]", cert);
                return null;
            }
            return (String) attribute.get();
        } catch (CertificateException | NamingException e) {
            throw log.ldapKeyStoreFailedToObtainAliasByCertificate(e);
        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        // NO-OP
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        // NO-OP
    }

}
