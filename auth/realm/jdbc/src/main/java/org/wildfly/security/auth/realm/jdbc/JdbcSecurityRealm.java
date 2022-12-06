/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.auth.realm.jdbc;

import static org.wildfly.security.auth.realm.jdbc._private.ElytronMessages.log;

import java.nio.charset.Charset;
import java.security.Principal;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import javax.sql.DataSource;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.CacheableSecurityRealm;
import org.wildfly.security.auth.realm.jdbc.mapper.AttributeMapper;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

/**
 * Security realm implementation backed by a database.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JdbcSecurityRealm implements CacheableSecurityRealm {

    private final Supplier<Provider[]> providers;
    private final List<QueryConfiguration> queryConfiguration;
    private final Charset hashCharset;

    public static JdbcSecurityRealmBuilder builder() {
        return new JdbcSecurityRealmBuilder();
    }

    JdbcSecurityRealm(List<QueryConfiguration> queryConfiguration, Supplier<Provider[]> providers, Charset hashCharset) {
        this.queryConfiguration = queryConfiguration;
        this.providers = providers;
        this.hashCharset = hashCharset;
    }

    @Override
    public RealmIdentity getRealmIdentity(final Principal principal) {
        if (! NamePrincipal.isConvertibleTo(principal)) {
            return RealmIdentity.NON_EXISTENT;
        }
        return new JdbcRealmIdentity(principal.getName(), hashCharset);
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        SupportLevel support = SupportLevel.UNSUPPORTED;
        for (QueryConfiguration configuration : queryConfiguration) {
            for (KeyMapper keyMapper : configuration.getColumnMappers(KeyMapper.class)) {
                final SupportLevel mapperSupport = keyMapper.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
                if (support.compareTo(mapperSupport) < 0) {
                    support = mapperSupport;
                }
            }
        }
        return support;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("evidenceType", evidenceType);
        SupportLevel support = SupportLevel.UNSUPPORTED;
        for (QueryConfiguration configuration : queryConfiguration) {
            for (KeyMapper keyMapper : configuration.getColumnMappers(KeyMapper.class)) {
                final SupportLevel mapperSupport = keyMapper.getEvidenceVerifySupport(evidenceType, algorithmName);
                if (support.compareTo(mapperSupport) < 0) {
                    support = mapperSupport;
                }
            }
        }
        return support;
    }

    @Override
    public void registerIdentityChangeListener(Consumer<Principal> listener) {
        // no notifications from this realm about changes on the underlying storage
    }

    private class JdbcRealmIdentity implements RealmIdentity {

        private final String name;
        private boolean loaded = false;
        private JdbcIdentity identity;
        private final Charset hashCharset;

        public JdbcRealmIdentity(String name, Charset hashCharset) {
            this.name = name;
            this.hashCharset = hashCharset;
        }

        public Principal getRealmIdentityPrincipal() {
            return new NamePrincipal(name);
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);

            JdbcIdentity identity = getIdentity();
            if (identity != null) {
                return identity.identityCredentials.getCredentialAcquireSupport(credentialType, algorithmName, parameterSpec);
            }

            return SupportLevel.UNSUPPORTED;
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

            JdbcIdentity identity = getIdentity();
            if (identity != null) {
                return identity.identityCredentials.getCredential(credentialType, algorithmName);
            }

            return null;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);

            JdbcIdentity identity = getIdentity();
            if (identity != null) {
                return identity.identityCredentials.canVerify(evidenceType, algorithmName) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
            }

            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);

            JdbcIdentity identity = getIdentity();
            if (identity != null) {
                return identity.identityCredentials.verify(providers, evidence, hashCharset);
            }

            return false;
        }

        public boolean exists() throws RealmUnavailableException {
            return getIdentity() != null;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            if (!exists()) {
                return AuthorizationIdentity.EMPTY;
            }

            return AuthorizationIdentity.basicIdentity(this.identity.attributes);
        }

        private JdbcIdentity getIdentity() throws RealmUnavailableException {
            if (!loaded && this.identity == null) {
                MapAttributes attributes = new MapAttributes();
                IdentityCredentials credentials = IdentityCredentials.NONE;
                boolean found = false;

                for (QueryConfiguration configuration : queryConfiguration) {
                    String sql = configuration.getSql();

                    log.tracef("Executing principalQuery %s with value %s", sql, name);

                    try (Connection connection = getConnection(configuration);
                            PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
                        preparedStatement.setString(1, name);

                        try (ResultSet resultSet = preparedStatement.executeQuery()) {
                            List<AttributeMapper> attributeMappers = configuration.getColumnMappers(AttributeMapper.class);
                            List<KeyMapper> keyMappers = configuration.getColumnMappers(KeyMapper.class);
                            while (resultSet.next()) {
                                found = true;

                                for (AttributeMapper attributeMapper : attributeMappers) {
                                    Object value = attributeMapper.map(resultSet, providers);
                                    if (value != null) {
                                        if (attributes.containsKey(attributeMapper.getName())) {
                                            attributes.get(attributeMapper.getName()).add(value.toString());
                                        } else {
                                            attributes.addFirst(attributeMapper.getName(), value.toString());
                                        }
                                    }
                                }

                                for (KeyMapper keyMapper : keyMappers) {
                                    Credential credential = keyMapper.map(resultSet, providers);
                                    if (credential != null) {
                                        credentials = credentials.withCredential(credential);
                                    }
                                }
                            }
                        }
                    } catch (SQLException e) {
                        throw log.couldNotExecuteQuery(sql, e);
                    } catch (Exception e) {
                        throw log.unexpectedErrorWhenProcessingAuthenticationQuery(sql, e);
                    }
                }

                this.identity = found ? new JdbcIdentity(attributes, credentials) : null;
                loaded = true;
            }

            return this.identity;
        }

        private Connection getConnection(QueryConfiguration configuration) throws RealmUnavailableException {
            try {
                DataSource dataSource = configuration.getDataSource();
                return dataSource.getConnection();
            } catch (Exception e) {
                throw log.couldNotOpenConnection(e);
            }
        }

        private class JdbcIdentity {

            private final Attributes attributes;
            private final IdentityCredentials identityCredentials;

            JdbcIdentity(Attributes attributes, IdentityCredentials identityCredentials) {
                this.attributes = attributes;
                this.identityCredentials = identityCredentials;
            }
        }
    }
}
