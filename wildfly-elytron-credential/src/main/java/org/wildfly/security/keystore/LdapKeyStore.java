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

import org.wildfly.common.Assert;
import org.wildfly.common.function.ExceptionSupplier;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapName;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.Provider;

/**
 * A LDAP backed {@link KeyStore} implementation.
 *
 * To create the new instances the {@link LdapKeyStore.Builder} should be used.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class LdapKeyStore extends KeyStore {

    protected LdapKeyStore(KeyStoreSpi keyStoreSpi, Provider provider, String type) {
        super(keyStoreSpi, provider, type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private static final int DEFAULT_SEARCH_TIME_LIMIT = 10000;

        private ExceptionSupplier<DirContext, NamingException> dirContextSupplier;
        private String searchPath;
        private int searchScope = SearchControls.SUBTREE_SCOPE;
        private int searchTimeLimit = DEFAULT_SEARCH_TIME_LIMIT;

        private String filterAlias;
        private String filterCertificate;
        private String filterIterate;

        private LdapName createPath;
        private String createRdn = "cn";
        private Attributes createAttributes;

        private String aliasAttribute = "cn";
        private String certificateAttribute = "usercertificate";
        private String certificateType = "X.509";
        private String certificateChainAttribute = "userSMIMECertificate";
        private String certificateChainEncoding = "PKCS7";
        private String keyAttribute = "userPKCS12";
        private String keyType = "PKCS12";

        private Builder() {
        }

        /**
         * Build a LDAP keystore.
         *
         * @return the LDAP keystore
         */
        public LdapKeyStore build() {
            Assert.checkNotNullParam("dirContextSupplier", dirContextSupplier);
            Assert.checkNotNullParam("searchPath", searchPath);
            Assert.checkNotNullParam("searchScope", searchScope);
            Assert.checkNotNullParam("searchTimeLimit", searchTimeLimit);

            Assert.checkNotNullParam("aliasAttribute", aliasAttribute);
            Assert.checkNotNullParam("certificateAttribute", certificateAttribute);
            Assert.checkNotNullParam("certificateType", certificateType);
            Assert.checkNotNullParam("certificateChainAttribute", certificateChainAttribute);
            Assert.checkNotNullParam("certificateChainEncoding", certificateChainEncoding);
            Assert.checkNotNullParam("keyAttribute", keyAttribute);
            Assert.checkNotNullParam("keyType", keyType);

            if (filterAlias == null) filterAlias = "(" + aliasAttribute + "={0})";
            if (filterCertificate == null) filterCertificate = "(" + certificateAttribute + "={0})";
            if (filterIterate == null) filterIterate = "(" + aliasAttribute + "=*)";

            LdapKeyStoreSpi spi = new LdapKeyStoreSpi(dirContextSupplier, searchPath, searchScope, searchTimeLimit,
                    filterAlias, filterCertificate, filterIterate, createPath, createRdn, createAttributes, aliasAttribute,
                    certificateAttribute, certificateType, certificateChainAttribute, certificateChainEncoding,
                    keyAttribute, keyType);
            return new LdapKeyStore(spi, EmptyProvider.getInstance(), "LdapKeyStore");
        }

        /**
         * Set the {@link DirContext} supplier, which will be used to obtain DirContext to perform
         * operation over {@link KeyStore}.
         *
         * @param dirContextSupplier
         * @return this builder
         */
        public Builder setDirContextSupplier(ExceptionSupplier<DirContext, NamingException> dirContextSupplier) {
            this.dirContextSupplier = dirContextSupplier;
            return this;
        }

        /**
         * Set the name of the context (DN, distinguish name) to be used when executing queries.
         *
         * @param searchPath the name of the context to search
         * @return this builder
         */
        public Builder setSearchPath(String searchPath) {
            this.searchPath = searchPath;
            return this;
        }

        /**
         * Set if queries are searching the entire subtree (true) or only one level search is used (false).
         * Default value: SUBTREE_SCOPE
         *
         * @return this builder
         */
        public Builder setSearchScope(int searchScope) {
            this.searchScope = searchScope;
            return this;
        }

        /**
         * Set if queries are searching the entire subtree (true) or only one level search is used (false).
         * Default value: true
         *
         * @return this builder
         */
        public Builder setSearchRecursive(boolean recursive) {
            this.searchScope = recursive ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE;
            return this;
        }

        /**
         * Set the time limit of LDAP search in milliseconds.
         *
         * @param searchTimeLimit the limit in milliseconds. Defaults to {@value #DEFAULT_SEARCH_TIME_LIMIT} milliseconds.
         * @return this builder
         */
        public Builder setSearchTimeLimit(int searchTimeLimit) {
            this.searchTimeLimit = searchTimeLimit;
            return this;
        }

        /**
         * Set the LDAP filter used to search keystore item by alias.
         * If not specified "(alias-attribute={0})" is used.
         *
         * @param filterAlias the LDAP filter, substring "{0}" will by replaced by searched alias
         * @return this builder
         */
        public Builder setFilterAlias(String filterAlias) {
            this.filterAlias = filterAlias;
            return this;
        }

        /**
         * Set the LDAP filter used to search keystore item by certificate.
         * If not specified "(certificate-attribute={0})" is used.
         *
         * @param filterCertificate the LDAP filter, substring "{0}" will by replaced by encoded searched certificate
         * @return this builder
         */
        public Builder setFilterCertificate(String filterCertificate) {
            this.filterCertificate = filterCertificate;
            return this;
        }

        /**
         * Set the LDAP filter used to search all keystore items.
         * If not specified "(alias-attribute=*)" is used.
         *
         * @param filterIterate the LDAP filter
         * @return this builder
         */
        public Builder setFilterIterate(String filterIterate) {
            this.filterIterate = filterIterate;
            return this;
        }

        /**
         * Set the name of the context (DN, distinguish name), where will be LDAP entries of new keystore items created.
         *
         * @param createPath the name of the context, where to create
         * @return this builder
         */
        public Builder setCreatePath(LdapName createPath) {
            this.createPath = createPath;
            return this;
        }

        /**
         * Set the name of the attribute in LDAP, that will be used as RDN - last part of path of new entries.
         * This attribute can be different from aliasAttribute, but its value will be alias too for
         * newly created entries.
         *
         * @param createRdn the name of attribute which will be used as RDN
         * @return this builder
         */
        public Builder setCreateRdn(String createRdn) {
            this.createRdn = createRdn;
            return this;
        }

        /**
         * Set the attributes of newly created LDAP entries and their values.
         *
         * @param createAttributes the attributes and their initial values
         * @return this builder
         */
        public Builder setCreateAttributes(Attributes createAttributes) {
            this.createAttributes = createAttributes;
            return this;
        }

        /**
         * Set the name of the attribute in LDAP that holds the alias of keystore item.
         *
         * @param aliasAttribute the name of attribute that holds the alias
         * @return this builder
         */
        public Builder setAliasAttribute(String aliasAttribute) {
            this.aliasAttribute = aliasAttribute;
            return this;
        }

        /**
         * Set the name of the attribute in LDAP that holds the encoded certificate.
         *
         * @param certificateAttribute the name of attribute that holds the encoded certificate
         * @return this builder
         */
        public Builder setCertificateAttribute(String certificateAttribute) {
            this.certificateAttribute = certificateAttribute;
            return this;
        }

        /**
         * Set the type of certificate, which is stored in certificateAttribute and certificateChainAttribute.
         * This type is used for decoding certificate and certificate chain from LDAP attribute value.
         *
         * @see java.security.cert.CertificateFactory#getInstance(String)
         *
         * @param certificateType the name of attribute that holds the encoded certificate
         * @return this builder
         */
        public Builder setCertificateType(String certificateType) {
            this.certificateType = certificateType;
            return this;
        }

        /**
         * Set the name of the attribute in LDAP that holds the encoded certificate chain.
         *
         * @param certificateChainAttribute the name of attribute that holds the encoded certificate chain
         * @return this builder
         */
        public Builder setCertificateChainAttribute(String certificateChainAttribute) {
            this.certificateChainAttribute = certificateChainAttribute;
            return this;
        }

        /**
         * Set the encoding of certificate chain, which is stored in certificateChainAttribute.
         * This encoding is used for encoding certificate chain into the LDAP attribute value.
         *
         * @see java.security.cert.CertPath#getEncoded(String)
         *
         * @param certificateChainEncoding the name of the encoding to use
         * @return this builder
         */
        public Builder setCertificateChainEncoding(String certificateChainEncoding) {
            this.certificateChainEncoding = certificateChainEncoding;
            return this;
        }

        /**
         * Set the name of the attribute in LDAP that holds the private key.
         * Private key is stored encased in KeyStore, encrypted by password of keystore item.
         *
         * @param keyAttribute the name of attribute that holds the private key
         * @return this builder
         */
        public Builder setKeyAttribute(String keyAttribute) {
            this.keyAttribute = keyAttribute;
            return this;
        }

        /**
         * Set type of keystores, into which is encased every private key before storing into keyAttribute.
         *
         * @see KeyStore#getInstance(String)
         *
         * @param keyType the type of keystore
         * @return this builder
         */
        public Builder setKeyType(String keyType) {
            this.keyType = keyType;
            return this;
        }
    }

}
