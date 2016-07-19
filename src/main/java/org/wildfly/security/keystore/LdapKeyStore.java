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
import javax.naming.ldap.LdapName;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.Provider;

/**
 * A LDAP backed {@link KeyStore} implementation.
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

        private ExceptionSupplier<DirContext, NamingException> dirContextSupplier;
        private String searchPath;
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
        private String certificateChainType = "X.509";
        private String certificateChainEncoding = "PKCS7";
        private String keyAttribute = "userPKCS12";
        private String keyType = "PKCS12";

        private Builder() {
        }

        public LdapKeyStore build() {
            Assert.assertNotNull(dirContextSupplier);
            Assert.assertNotNull(searchPath);
            Assert.assertNotNull(filterAlias);
            Assert.assertNotNull(filterCertificate);
            Assert.assertNotNull(filterIterate);
            Assert.assertNotNull(aliasAttribute);
            Assert.assertNotNull(certificateAttribute);
            Assert.assertNotNull(certificateType);
            Assert.assertNotNull(certificateChainAttribute);
            Assert.assertNotNull(certificateChainType);
            Assert.assertNotNull(certificateChainEncoding);
            Assert.assertNotNull(keyAttribute);
            Assert.assertNotNull(keyType);

            LdapKeyStoreSpi spi = new LdapKeyStoreSpi(dirContextSupplier, searchPath, filterAlias, filterCertificate,
                    filterIterate, createPath, createRdn, createAttributes, aliasAttribute, certificateAttribute,
                    certificateType, certificateChainAttribute, certificateChainType, certificateChainEncoding,
                    keyAttribute, keyType);
            return new LdapKeyStore(spi, null, null);
        }

        public Builder setDirContextSupplier(ExceptionSupplier<DirContext, NamingException> dirContextSupplier) {
            this.dirContextSupplier = dirContextSupplier;
            return this;
        }

        public Builder setSearchPath(String searchPath) {
            this.searchPath = searchPath;
            return this;
        }

        public Builder setFilterAlias(String filterAlias) {
            this.filterAlias = filterAlias;
            return this;
        }

        public Builder setFilterCertificate(String filterCertificate) {
            this.filterCertificate = filterCertificate;
            return this;
        }

        public Builder setFilterIterate(String filterIterate) {
            this.filterIterate = filterIterate;
            return this;
        }

        public Builder setCreatePath(LdapName createPath) {
            this.createPath = createPath;
            return this;
        }

        public Builder setCreateRdn(String createRdn) {
            this.createRdn = createRdn;
            return this;
        }

        public Builder setCreateAttributes(Attributes createAttributes) {
            this.createAttributes = createAttributes;
            return this;
        }

        public Builder setAliasAttribute(String aliasAttribute) {
            this.aliasAttribute = aliasAttribute;
            return this;
        }

        public Builder setCertificateAttribute(String certificateAttribute) {
            this.certificateAttribute = certificateAttribute;
            return this;
        }

        public Builder setCertificateType(String certificateType) {
            this.certificateType = certificateType;
            return this;
        }

        public Builder setCertificateChainAttribute(String certificateChainAttribute) {
            this.certificateChainAttribute = certificateChainAttribute;
            return this;
        }

        public Builder setCertificateChainType(String certificateChainType) {
            this.certificateChainType = certificateChainType;
            return this;
        }

        public Builder setCertificateChainEncoding(String certificateChainEncoding) {
            this.certificateChainEncoding = certificateChainEncoding;
            return this;
        }

        public Builder setKeyAttribute(String keyAttribute) {
            this.keyAttribute = keyAttribute;
            return this;
        }

        public Builder setKeyType(String keyType) {
            this.keyType = keyType;
            return this;
        }
    }

}
