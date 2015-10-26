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
package org.wildfly.security.auth.provider.jdbc;

import org.wildfly.security.auth.provider.jdbc.mapper.AttributeMapper;
import org.wildfly.security.auth.provider.jdbc.mapper.PasswordKeyMapper;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;
import org.wildfly.security.password.PasswordFactory;

import javax.sql.DataSource;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.stream.Collectors;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * Security realm implementation backed by a database.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JdbcSecurityRealm implements SecurityRealm {

    private final List<QueryConfiguration> queryConfiguration;

    public static JdbcSecurityRealmBuilder builder() {
        return new JdbcSecurityRealmBuilder();
    }

    JdbcSecurityRealm(List<QueryConfiguration> queryConfiguration) {
        this.queryConfiguration = queryConfiguration;
    }

    @Override
    public RealmIdentity createRealmIdentity(final String name) throws RealmUnavailableException {
        return new JdbcRealmIdentity(name);
    }

    @Override
    public CredentialSupport getCredentialSupport(String credentialName) throws RealmUnavailableException {
        for (QueryConfiguration configuration : this.queryConfiguration) {
            for (KeyMapper keyMapper : configuration.getColumnMappers(KeyMapper.class)) {
                if (keyMapper.getCredentialName().equals(credentialName)) {
                    // by default, all credential types are supported if they have a corresponding mapper.
                    // however, we don't know if an account or realm identity has a specific credential or not.
                    return CredentialSupport.UNKNOWN;
                }
            }
        }

        return CredentialSupport.UNSUPPORTED;
    }

    private class JdbcRealmIdentity implements RealmIdentity {

        private final String name;
        private JdbcIdentity identity;

        public JdbcRealmIdentity(String name) {
            this.name = name;
        }

        @Override
        public CredentialSupport getCredentialSupport(final String credentialName) throws RealmUnavailableException {
            for (QueryConfiguration configuration : JdbcSecurityRealm.this.queryConfiguration) {
                for (KeyMapper keyMapper : configuration.getColumnMappers(KeyMapper.class)) {
                    if (keyMapper.getCredentialName().equals(credentialName)) {
                        return executePrincipalQuery(configuration, keyMapper::getCredentialSupport);
                    }
                }
            }

            return CredentialSupport.UNSUPPORTED;
        }

        @Override
        public Credential getCredential(final String credentialName) throws RealmUnavailableException {
            for (QueryConfiguration configuration : JdbcSecurityRealm.this.queryConfiguration) {
                for (KeyMapper keyMapper : configuration.getColumnMappers(KeyMapper.class)) {
                    if (keyMapper.getCredentialName().equals(credentialName)) {
                        return executePrincipalQuery(configuration, resultSet -> keyMapper.map(resultSet));
                    }
                }
            }

            return null;
        }

        @Override
        public boolean verifyEvidence(final String credentialName, final Evidence evidence) throws RealmUnavailableException {
            if (evidence != null) {
                for (QueryConfiguration configuration : JdbcSecurityRealm.this.queryConfiguration) {
                    for (PasswordKeyMapper passwordMapper : configuration.getColumnMappers(PasswordKeyMapper.class)) {
                        if (passwordMapper.getCredentialName().equals(credentialName)) {
                            return verifyPassword(configuration, passwordMapper, evidence);
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
            if (this.identity == null) {
                JdbcSecurityRealm.this.queryConfiguration.stream()
                        .map(queryConfiguration -> {
                            return executePrincipalQuery(queryConfiguration, resultSet -> {
                                if (resultSet.next()) {
                                    MapAttributes attributes = new MapAttributes();

                                    do {
                                        queryConfiguration.getColumnMappers(AttributeMapper.class).forEach(attributeMapper -> {
                                            try {
                                                Object value = attributeMapper.map(resultSet);

                                                if (value != null) {
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
                            });
                        }).collect(Collectors.reducing((lAttribute, rAttribute) -> {
                    MapAttributes attributes = new MapAttributes(lAttribute);

                    for (Attributes.Entry rEntry : rAttribute.entries()) {
                        attributes.get(rEntry.getKey()).addAll(rEntry);
                    }

                    return attributes;
                })).ifPresent(attributes -> this.identity = new JdbcIdentity(attributes));
            }

            return this.identity;
        }

        private boolean verifyPassword(QueryConfiguration configuration, PasswordKeyMapper passwordMapper, Evidence evidence) {
            Credential credential = executePrincipalQuery(configuration, passwordMapper::map);
            String algorithm = passwordMapper.getAlgorithm();

            try {
                if (credential instanceof PasswordCredential) {
                    PasswordFactory passwordFactory = getPasswordFactory(algorithm);
                    char[] guessCredentialChars;

                    if (evidence instanceof PasswordGuessEvidence) {
                        guessCredentialChars = ((PasswordGuessEvidence) evidence).getGuess();
                    } else {
                        throw log.passwordBasedCredentialsMustBeCharsOrClearPassword();
                    }

                    return passwordFactory.verify(((PasswordCredential) credential).getPassword(), guessCredentialChars);
                }
            } catch (InvalidKeyException e) {
                throw log.invalidPasswordKeyForAlgorithm(algorithm, e);
            }

            return false;
        }

        private PasswordFactory getPasswordFactory(String algorithm) {
            try {
                return PasswordFactory.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                throw log.couldNotObtainPasswordFactoryForAlgorithm(algorithm, e);
            }
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
                preparedStatement.setString(1, name);

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

            JdbcIdentity(Attributes attributes) {
                this.attributes = attributes;
            }
        }
    }

    private interface ResultSetCallback<E> {
        E handle(ResultSet resultSet) throws SQLException;
    }
}
