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

import org.wildfly.security.auth.provider.ldap.LdapSecurityRealm.Attribute;
import org.wildfly.security.auth.provider.ldap.LdapSecurityRealm.IdentityMapping;

import static org.wildfly.security._private.ElytronMessages.log;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.NameRewriter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builder for the security realm implementation backed by LDAP.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class LdapSecurityRealmBuilder {

    /*
     *  The LDAP security realm constructed by this builder expects no further modifications to the
     *  Collections it is passed.
     *
     *  This is the reason this builder and all child builders are implemented to prevent subsequent
     *  modification after the build is complete.
     */

    private boolean built = false;
    private DirContextFactory dirContextFactory;
    private NameRewriter nameRewriter = NameRewriter.IDENTITY_REWRITER;
    private List<CredentialLoader> credentialLoaders = new ArrayList<>();
    private List<CredentialPersister> credentialPersisters = new ArrayList<>();
    private List<EvidenceVerifier> evidenceVerifiers = new ArrayList<>();
    private IdentityMapping identityMapping;

    private LdapSecurityRealmBuilder() {
    }

    /**
     * Construct a new instance.
     *
     * @return the new builder instance
     */
    public static LdapSecurityRealmBuilder builder() {
        return new LdapSecurityRealmBuilder();
    }

    /**
     * Set the directory context factory.
     *
     * @param dirContextFactory the directory context factory
     * @return this builder
     */
    public LdapSecurityRealmBuilder setDirContextFactory(final DirContextFactory dirContextFactory) {
        assertNotBuilt();

        this.dirContextFactory = dirContextFactory;

        return this;
    }

    /**
     * Add a name rewriter to this builder.
     *
     * @param nameRewriter the name rewriter
     * @return this builder
     */
    public LdapSecurityRealmBuilder setNameRewriter(final NameRewriter nameRewriter) {
        Assert.checkNotNullParam("nameRewriter", nameRewriter);
        assertNotBuilt();

        this.nameRewriter = nameRewriter;

        return this;
    }

    public IdentityMappingBuilder identityMapping() {
        assertNotBuilt();

        return new IdentityMappingBuilder();
    }

    /**
     * Add a principal mapping to this builder.
     *
     * @return the builder for the principal mapping
     */
    LdapSecurityRealmBuilder setIdentityMapping(IdentityMapping principalMapping) {
        this.identityMapping = principalMapping;

        return this;
    }

    public UserPasswordCredentialLoaderBuilder userPasswordCredentialLoader() {
        assertNotBuilt();

        return new UserPasswordCredentialLoaderBuilder();
    }

    public OtpCredentialLoaderBuilder otpCredentialLoader() {
        assertNotBuilt();

        return new OtpCredentialLoaderBuilder();
    }

    LdapSecurityRealmBuilder addCredentialLoader(CredentialLoader credentialLoader) {
        credentialLoaders.add(credentialLoader);

        return this;
    }

    LdapSecurityRealmBuilder addCredentialPersister(CredentialPersister credentialPersister) {
        credentialPersisters.add(credentialPersister);

        return this;
    }

    LdapSecurityRealmBuilder addEvidenceVerifier(EvidenceVerifier evidenceVerifier) {
        evidenceVerifiers.add(evidenceVerifier);

        return this;
    }

    public LdapSecurityRealmBuilder addDirectEvidenceVerification(String... credentialNames) {
        assertNotBuilt();

        return addEvidenceVerifier(new DirectEvidenceVerifier(new HashSet<>(Arrays.asList(credentialNames))));
    }

    /**
     * Build this realm.
     *
     * @return the built realm
     */
    public LdapSecurityRealm build() {
        assertNotBuilt();
        if (dirContextFactory == null) {
            throw log.noDirContextFactorySet();
        }
        if (identityMapping == null) {
            throw log.noPrincipalMappingDefinition();
        }

        built = true;
        return new LdapSecurityRealm(dirContextFactory, nameRewriter, identityMapping, credentialLoaders, credentialPersisters, evidenceVerifiers);
    }

    private void assertNotBuilt() {
        if (built) {
            throw log.builderAlreadyBuilt();
        }
    }

    /**
     * A builder for a principal mapping.
     */
    public class IdentityMappingBuilder {

        private boolean built = false;

        private String searchDn = null;
        private boolean searchRecursive = false;
        private String nameAttribute;
        private int searchTimeLimit = 10000;
        private List<Attribute> attributes = new ArrayList<>();

        /**
         * <p>Set the name of the context to be used when executing queries.
         *
         * <p>This option is specially useful when authenticating users based on names that don't use a X.500 format such as <em>plainUser</em>.
         * In this case, you must also provide {@link #setRdnIdentifier(String)} with the attribute name that contains the user name.</p>
         *
         * <p>If the names used to authenticate users are based on the X.500 format, this configuration can be suppressed.
         *
         * <p>Please note that by using this option the realm is able to authenticate users based on their simple or X.500 names.
         *
         * @param searchDn the name of the context to search
         * @return this builder
         */
        public IdentityMappingBuilder setSearchDn(final String searchDn) {
            assertNotBuilt();

            this.searchDn = searchDn;
            return this;
        }

        /**
         * Indicate if queries are searchRecursive, searching the entire subtree rooted at the name specified in {@link #setSearchDn(String)}.
         * Otherwise search one level of the named context.
         *
         * @return this builder
         */
        public IdentityMappingBuilder searchRecursive() {
            assertNotBuilt();

            this.searchRecursive = true;
            return this;
        }

        /**
         * Sets the time limit of the SearchControls in milliseconds.
         *
         * @param limit the limit in milliseconds. Defaults to 5000 milliseconds.
         * @return this builder
         */
        public IdentityMappingBuilder setSearchTimeLimit(int limit) {
            assertNotBuilt();

            this.searchTimeLimit = limit;
            return this;
        }

        /**
         * Set the name of the attribute in LDAP that holds the user name.
         *
         * @param nameAttribute the name attribute
         * @return this builder
         */
        public IdentityMappingBuilder setRdnIdentifier(final String nameAttribute) {
            assertNotBuilt();

            this.nameAttribute = nameAttribute;
            return this;
        }

        /**
         * Define an attribute mapping configuration.
         *
         * @param attributes one or more {@link org.wildfly.security.auth.provider.ldap.LdapSecurityRealmBuilder.IdentityMappingBuilder.Attribute} configuration
         * @return this builder
         */
        public IdentityMappingBuilder map(Attribute... attributes) {
            assertNotBuilt();

            this.attributes.addAll(Arrays.asList(attributes));
            return this;
        }

        public LdapSecurityRealmBuilder build() {
            assertNotBuilt();
            built = true;

            return LdapSecurityRealmBuilder.this.setIdentityMapping(new IdentityMapping(
                    searchDn, searchRecursive, searchTimeLimit, nameAttribute, attributes));
        }

        private void assertNotBuilt() {
            if (built) {
                throw log.builderAlreadyBuilt();
            }

            LdapSecurityRealmBuilder.this.assertNotBuilt();
        }

    }

    public class UserPasswordCredentialLoaderBuilder {

        private boolean built = false;

        private String userPasswordAttribute = UserPasswordCredentialLoader.DEFAULT_USER_PASSWORD_ATTRIBUTE_NAME;
        private Map<String, Set<String>> credentialNameToAlgorithms = new HashMap<>();
        private boolean enablePersistence = false;
        private boolean enableVerification = true;

        /**
         * Set the name of the attribute within the LDAP entry that should be queries to load the credential.
         *
         * @param userPasswordAttribute the name of the attribute within the LDAP entry that should be queries to load the credential.
         * @return the {@link UserPasswordCredentialLoaderBuilder} to allow chaining of calls.
         */
        public UserPasswordCredentialLoaderBuilder setUserPasswordAttribute(final String userPasswordAttribute) {
            assertNotBuilt();
            this.userPasswordAttribute = userPasswordAttribute;

            return this;
        }

        /**
         * Set a credential name to be supported along with a list of algorithms to be suppoered with this credential name, if
         * no algorithms are specified then all algorithms are considered supported.
         *
         * @param credentialName the supported credential name
         * @param supportedAlgorithms the algorithms to be supported with this credential name
         * @return the {@link UserPasswordCredentialLoaderBuilder} to allow chaining of calls.
         */
        public UserPasswordCredentialLoaderBuilder addSupportedCredential(final String credentialName, final String... supportedAlgorithms) {
            assertNotBuilt();
            credentialNameToAlgorithms.put(credentialName,  new HashSet<>(Arrays.asList(supportedAlgorithms)));

            return this;
        }

        /**
         * Enable persistence for the {@link UserPasswordCredentialLoader} being defined.
         *
         * @return the {@link UserPasswordCredentialLoaderBuilder} to allow chaining of calls.
         */
        public UserPasswordCredentialLoaderBuilder enablePersistence() {
            assertNotBuilt();
            enablePersistence = true;

            return this;
        }

        /**
         * By default if we can obtain a credential we support verification against it, this disables it.
         *
         * @return the {@link UserPasswordCredentialLoaderBuilder} to allow chaining of calls.
         */
        public UserPasswordCredentialLoaderBuilder disableVerification() {
            assertNotBuilt();
            enableVerification = false;

            return this;
        }

        public LdapSecurityRealmBuilder build() {
            assertNotBuilt();
            built = true;

            UserPasswordCredentialLoader upcl = new UserPasswordCredentialLoader(userPasswordAttribute, false, credentialNameToAlgorithms);
            LdapSecurityRealmBuilder.this.addCredentialLoader(upcl);
            if (enablePersistence) LdapSecurityRealmBuilder.this.addCredentialPersister(upcl);
            if (enableVerification) LdapSecurityRealmBuilder.this.addEvidenceVerifier(upcl.toEvidenceVerifier());

            return LdapSecurityRealmBuilder.this;
        }


        private void assertNotBuilt() {
            if (built) {
                throw log.builderAlreadyBuilt();
            }

            LdapSecurityRealmBuilder.this.assertNotBuilt();
        }
    }

    public class OtpCredentialLoaderBuilder {

        private boolean built = false;

        private String credentialName = OtpCredentialLoader.DEFAULT_CREDENTIAL_NAME;
        private String otpAlgorithmAttribute = null;
        private String otpHashAttribute = null;
        private String otpSeedAttribute = null;
        private String otpSequenceAttribute = null;

        public OtpCredentialLoaderBuilder setCredentialName(final String credentialName) {
            assertNotBuilt();
            this.credentialName = credentialName;

            return this;
        }

        public OtpCredentialLoaderBuilder setOtpAlgorithmAttribute(final String otpAlgorithmAttribute) {
            assertNotBuilt();
            this.otpAlgorithmAttribute = otpAlgorithmAttribute;

            return this;
        }

        public OtpCredentialLoaderBuilder setOtpHashAttribute(final String otpHashAttribute) {
            assertNotBuilt();
            this.otpHashAttribute = otpHashAttribute;

            return this;
        }

        public OtpCredentialLoaderBuilder setOtpSeedAttribute(final String otpSeedAttribute) {
            assertNotBuilt();
            this.otpSeedAttribute = otpSeedAttribute;

            return this;
        }

        public OtpCredentialLoaderBuilder setOtpSequenceAttribute(final String otpSequenceAttribute) {
            assertNotBuilt();
            this.otpSequenceAttribute = otpSequenceAttribute;

            return this;
        }

        public LdapSecurityRealmBuilder build() {
            assertNotBuilt();

            OtpCredentialLoader ocl = new OtpCredentialLoader(credentialName, otpAlgorithmAttribute, otpHashAttribute, otpSeedAttribute, otpSequenceAttribute);
            LdapSecurityRealmBuilder.this.addCredentialLoader(ocl);
            LdapSecurityRealmBuilder.this.addCredentialPersister(ocl);

            return LdapSecurityRealmBuilder.this;
        }

        private void assertNotBuilt() {
            if (built) {
                throw log.builderAlreadyBuilt();
            }

            LdapSecurityRealmBuilder.this.assertNotBuilt();
        }
    }
}
