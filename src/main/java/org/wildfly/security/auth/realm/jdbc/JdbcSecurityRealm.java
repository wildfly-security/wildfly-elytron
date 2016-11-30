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

import org.wildfly.common.Assert;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.realm.jdbc.mapper.AttributeMapper;
import org.wildfly.security.auth.server.IdentityLocator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmIdentityStringKey;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;

import javax.sql.DataSource;

import java.security.Principal;
import java.security.Provider;
import java.sql.Connection;
import java.sql.ParameterMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * Security realm implementation backed by a database.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JdbcSecurityRealm implements SecurityRealm {

    private static final String ATTRIBUTE_IDENTITY_NAME = RealmIdentity.class.getName() + "#NAME";
    private static final String ATTRIBUTE_IDENTITY_KEY = RealmIdentity.class.getName() + "#KEY";

    private final Supplier<Provider[]> providers;
    private final List<QueryConfiguration> queryConfiguration;

    public static JdbcSecurityRealmBuilder builder() {
        return new JdbcSecurityRealmBuilder();
    }

    JdbcSecurityRealm(List<QueryConfiguration> queryConfiguration, Supplier<Provider[]> providers) {
        this.queryConfiguration = queryConfiguration;
        this.providers = providers;
    }

    @Override
    public RealmIdentity getRealmIdentity(final IdentityLocator locator) throws RealmUnavailableException {
        if (locator.hasName() || locator.hasKey()) {
            return new JdbcRealmIdentity(locator.hasKey() ? locator.getKey() : null, locator.hasName() ? locator.getName() : null);
        }
        return RealmIdentity.NON_EXISTENT;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
        Assert.checkNotNullParam("credentialType", credentialType);
        SupportLevel support = SupportLevel.UNSUPPORTED;
        for (QueryConfiguration configuration : queryConfiguration) {
            for (KeyMapper keyMapper : configuration.getColumnMappers(KeyMapper.class)) {
                final SupportLevel mapperSupport = keyMapper.getCredentialAcquireSupport(credentialType, algorithmName);
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

    private class JdbcRealmIdentity implements RealmIdentity {

        private final Key key;
        private final String name;
        private JdbcIdentity identity;

        public JdbcRealmIdentity(Key key, String name) {
            this.key = key;
            this.name = name;
        }

        @Override
        public Key getKey() throws RealmUnavailableException {
            if (!exists()) {
                return Key.EMPTY;
            }
            Key key = getIdentity().getKey();
            return key != null ? key : new RealmIdentityStringKey(name);
        }

        @Override
        public Principal getRealmIdentityPrincipal() throws RealmUnavailableException {
            if (!exists()) {
                return null;
            }
            return new NamePrincipal(getIdentity().getName());
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("credentialType", credentialType);
            SupportLevel support = SupportLevel.UNSUPPORTED;
            for (QueryConfiguration configuration : queryConfiguration) {
                for (KeyMapper keyMapper : configuration.getColumnMappers(KeyMapper.class)) {
                    if (keyMapper.getCredentialAcquireSupport(credentialType, algorithmName).mayBeSupported()) {
                        final SupportLevel mapperSupport = executePrincipalQuery(configuration, r -> keyMapper.getCredentialSupport(r, providers));
                        if (mapperSupport == SupportLevel.SUPPORTED) {
                            return SupportLevel.SUPPORTED;
                        } else if (mapperSupport == SupportLevel.POSSIBLY_SUPPORTED) {
                            support = SupportLevel.POSSIBLY_SUPPORTED;
                        }
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
            for (QueryConfiguration configuration : queryConfiguration) {
                for (KeyMapper keyMapper : configuration.getColumnMappers(KeyMapper.class)) {
                    if (keyMapper.getCredentialAcquireSupport(credentialType, algorithmName).mayBeSupported()) {
                        final Credential credential = executePrincipalQuery(configuration, r -> keyMapper.map(r, providers));
                        if (credentialType.isInstance(credential)) {
                            return credentialType.cast(credential);
                        }
                    }
                }
            }

            return null;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidenceType", evidenceType);
            SupportLevel support = SupportLevel.UNSUPPORTED;
            for (QueryConfiguration configuration : queryConfiguration) {
                for (KeyMapper keyMapper : configuration.getColumnMappers(KeyMapper.class)) {
                    if (keyMapper.getEvidenceVerifySupport(evidenceType, algorithmName).mayBeSupported()) {
                        final SupportLevel mapperSupport = executePrincipalQuery(configuration, r -> keyMapper.getCredentialSupport(r, providers));
                        if (mapperSupport == SupportLevel.SUPPORTED) {
                            return SupportLevel.SUPPORTED;
                        } else if (mapperSupport == SupportLevel.POSSIBLY_SUPPORTED) {
                            support = SupportLevel.POSSIBLY_SUPPORTED;
                        }
                    }
                }
            }

            return support;
        }

        @Override
        public boolean verifyEvidence(final Evidence evidence) throws RealmUnavailableException {
            Assert.checkNotNullParam("evidence", evidence);
            for (QueryConfiguration configuration : queryConfiguration) {
                for (KeyMapper keyMapper : configuration.getColumnMappers(KeyMapper.class)) {
                    Credential credential = executePrincipalQuery(configuration, r -> keyMapper.map(r, providers));
                    if (credential != null) {
                        if (credential.canVerify(evidence)) {
                            return credential.verify(providers, evidence);
                        }
                    }
                }
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

        private JdbcIdentity getIdentity() {
            if (identity == null) {
                identity =  queryConfiguration.stream().map(queryConfiguration -> executePrincipalQuery(queryConfiguration, resultSet -> {
                    if (resultSet.next()) {
                        MapAttributes attributes = new MapAttributes();

                        do {
                            queryConfiguration.getColumnMappers(AttributeMapper.class).forEach(attributeMapper -> {
                                try {
                                    Object value = attributeMapper.map(resultSet, providers);

                                    if (value != null) {
                                        if (attributeMapper.isOfType(AttributeMapper.Type.IDENTIFIER)) {
                                            String identityKey = value.toString();
                                            if (key != null && !key.asString().equals(identityKey)) {
                                                throw new RuntimeException("RealmIdentity key mismatch");
                                            }
                                            attributes.addFirst(ATTRIBUTE_IDENTITY_KEY, identityKey);
                                        } else if (attributeMapper.isOfType(AttributeMapper.Type.IDENTIFIER)) {
                                            String identityName = value.toString();
                                            if (identityName != null) {
                                                if (name != null && !name.equals(identityName)) {
                                                    throw new RuntimeException("RealmIdentity name mismatch");
                                                }
                                            }
                                            attributes.addFirst(ATTRIBUTE_IDENTITY_NAME, identityName);
                                        }
                                        attributes.addFirst(attributeMapper.getName(), value.toString());
                                    }
                                } catch (SQLException cause) {
                                    throw log.ldapRealmFailedObtainAttributes(this.name, cause);
                                }
                            });
                        } while (resultSet.next());

                        return attributes;
                    }

                    return null;
                })).filter(attributes -> attributes != null).collect(Collectors.reducing((lAttribute, rAttribute) -> {
                    MapAttributes attributes = new MapAttributes(lAttribute);
                    for (Attributes.Entry rEntry : rAttribute.entries()) {
                        attributes.get(rEntry.getKey()).addAll(rEntry);
                    }
                    return attributes;
                })).map(attributes -> {
                    String identityKey = attributes.getFirst(ATTRIBUTE_IDENTITY_KEY);
                    String identityName = attributes.getFirst(ATTRIBUTE_IDENTITY_NAME);
                    return new JdbcIdentity(identityKey, identityName, attributes);
                }).orElse(null);
            }

            return identity;
        }

        private Connection getConnection(QueryConfiguration configuration) {
            try {
                DataSource dataSource = configuration.getDataSource();
                return dataSource.getConnection();
            } catch (Exception e) {
                throw log.couldNotOpenConnection(e);
            }
        }

        private <E> E executePrincipalQuery(QueryConfiguration configuration, ResultSetCallback<E> resultSetCallback) {
            String sql = configuration.getSql();

            try (
                    Connection connection = getConnection(configuration);
                    PreparedStatement preparedStatement = connection.prepareStatement(sql)
            ) {
                ParameterMetaData parameterMetaData = preparedStatement.getParameterMetaData();
                int parameterCount = parameterMetaData.getParameterCount();

                if (parameterCount == 1) {
                    preparedStatement.setString(1, name);
                } else if (parameterCount == 2) {
                    if (key != null) {
                        preparedStatement.setString(1, null);
                        preparedStatement.setObject(2, key.getValue());
                    } else {
                        preparedStatement.setString(1, name);
                        preparedStatement.setObject(2, null);
                    }
                } else {
                    throw new RuntimeException("Invalid parameter count.");
                }

                try (
                        ResultSet resultSet = preparedStatement.executeQuery()
                ) {
                    return resultSetCallback.handle(resultSet);
                }
            } catch (SQLException e) {
                throw log.couldNotExecuteQuery(sql, e);
            } catch (Exception e) {
                throw log.unexpectedErrorWhenProcessingAuthenticationQuery(sql, e);
            }
        }

        private class JdbcIdentity {

            private final Attributes attributes;
            private Key key;
            private final String name;

            JdbcIdentity(String key, String name, Attributes attributes) {
                this.key = key != null ? new RealmIdentityStringKey(key) : null;
                this.name = name;
                this.attributes = attributes;
            }

            String getName() {
                return name;
            }

            Key getKey() {
                return key;
            }
        }
    }

    private interface ResultSetCallback<E> {
        E handle(ResultSet resultSet) throws SQLException;
    }
}
