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

import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.provider.jdbc.mapper.PasswordKeyMapper;
import org.wildfly.security.auth.spi.AuthorizationIdentity;
import org.wildfly.security.auth.spi.CredentialSupport;
import org.wildfly.security.auth.spi.RealmIdentity;
import org.wildfly.security.auth.spi.RealmUnavailableException;
import org.wildfly.security.auth.spi.SecurityRealm;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;

import javax.sql.DataSource;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

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
    public RealmIdentity createRealmIdentity(Principal principal) throws RealmUnavailableException {
        if (principal instanceof NamePrincipal == false) {
            throw ElytronMessages.log.invalidPrincipalType(NamePrincipal.class, principal == null ? null : principal.getClass());
        }

        return new JdbcRealmIdentity(principal);
    }

    @Override
    public CredentialSupport getCredentialSupport(Class<?> credentialType) throws RealmUnavailableException {
        for (QueryConfiguration configuration : this.queryConfiguration) {
            for (ColumnMapper mapper : configuration.getColumnMappers()) {
                if (KeyMapper.class.isInstance(mapper)) {
                    KeyMapper keyMapper = (KeyMapper) mapper;

                    if (credentialType.equals(keyMapper.getKeyType())) {
                        // by default, all credential types are supported if they have a corresponding mapper.
                        // however, we don't know if an account or realm identity has a specific credential or not.
                        return CredentialSupport.UNKNOWN;
                    }
                }
            }
        }

        return CredentialSupport.UNSUPPORTED;
    }

    private class JdbcRealmIdentity implements RealmIdentity {

        private final Principal principal;

        public JdbcRealmIdentity(Principal name) {
            this.principal = name;
        }

        @Override
        public Principal getPrincipal() throws RealmUnavailableException {
            return this.principal;
        }

        @Override
        public CredentialSupport getCredentialSupport(Class<?> credentialType) throws RealmUnavailableException {
            for (QueryConfiguration configuration : JdbcSecurityRealm.this.queryConfiguration) {
                for (ColumnMapper mapper : configuration.getColumnMappers()) {
                    if (KeyMapper.class.isInstance(mapper)) {
                        KeyMapper keyMapper = (KeyMapper) mapper;

                        if (keyMapper.getKeyType().isAssignableFrom(credentialType)) {
                            return executeAuthenticationQuery(configuration, resultSet -> keyMapper.getCredentialSupport(resultSet));
                        }
                    }
                }
            }

            return CredentialSupport.UNSUPPORTED;
        }

        @Override
        public <C> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
            for (QueryConfiguration configuration : JdbcSecurityRealm.this.queryConfiguration) {
                for (ColumnMapper mapper : configuration.getColumnMappers()) {
                    if (KeyMapper.class.isInstance(mapper)) {
                        KeyMapper keyMapper = (KeyMapper) mapper;

                        if (keyMapper.getKeyType().isAssignableFrom(credentialType)) {
                            return executeAuthenticationQuery(configuration, resultSet -> (C) keyMapper.map(resultSet));
                        }
                    }
                }
            }

            return null;
        }

        @Override
        public boolean verifyCredential(Object credential) throws RealmUnavailableException {
            if (credential == null) {
                return false;
            }

            for (QueryConfiguration configuration : JdbcSecurityRealm.this.queryConfiguration) {
                for (ColumnMapper mapper : configuration.getColumnMappers()) {
                    if (KeyMapper.class.isInstance(mapper)) {
                        KeyMapper credentialMapper = (KeyMapper) mapper;

                        if (Password.class.isAssignableFrom(credentialMapper.getKeyType())) {
                            PasswordKeyMapper passwordMapper = (PasswordKeyMapper) mapper;
                            return verifyPassword(configuration, passwordMapper, credential);
                        }
                    }
                }
            }

            return false;
        }

        @Override
        public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
            return new JdbcAuthorizationIdentity(getPrincipal());
        }

        private boolean verifyPassword(QueryConfiguration configuration, PasswordKeyMapper passwordMapper, Object givenCredential) {
            Object credential = executeAuthenticationQuery(configuration, resultSet -> passwordMapper.map(resultSet));

            String algorithm = passwordMapper.getAlgorithm();

            try {
                if (Password.class.isInstance(credential)) {
                    PasswordFactory passwordFactory = getPasswordFactory(algorithm);
                    char[] guessCredentialChars;

                    if (String.class.equals(givenCredential.getClass())) {
                        guessCredentialChars = givenCredential.toString().toCharArray();
                    } else if (char[].class.equals(givenCredential.getClass())) {
                        guessCredentialChars = (char[]) givenCredential;
                    } else if (ClearPassword.class.isInstance(givenCredential)) {
                        guessCredentialChars = ((ClearPassword) givenCredential).getPassword();
                    } else {
                        throw new RuntimeException("Password-based credentials must be either a String, char[] or ClearPassword.");
                    }

                    return passwordFactory.verify((Password) credential, guessCredentialChars);
                }
            } catch (InvalidKeyException e) {
                throw new RuntimeException("Invalid password key for algorithm [" + algorithm + "].", e);
            }

            return false;
        }

        private PasswordFactory getPasswordFactory(String algorithm) {
            try {
                return PasswordFactory.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Could not obtain PasswordFactory for algorithm [" + algorithm + "].", e);
            }
        }

        private Connection getConnection(QueryConfiguration configuration) {
            Connection connection;
            try {
                DataSource dataSource = configuration.getDataSource();
                connection = dataSource.getConnection();
            } catch (Exception e) {
                throw new RuntimeException("Could not open connection.", e);
            }
            return connection;
        }

        private void safeClose(AutoCloseable closeable) {
            try {
                if (closeable != null) {
                    closeable.close();
                }
            } catch (Exception ignore) {

            }
        }

        private <E> E executeAuthenticationQuery(QueryConfiguration configuration, ResultSetCallback<E> resultSetCallback) {
            String sql = configuration.getSql();
            Connection connection = getConnection(configuration);
            PreparedStatement preparedStatement = null;
            ResultSet resultSet = null;

            try {
                preparedStatement = connection.prepareStatement(sql);
                preparedStatement.setString(1, getPrincipal().getName());
                resultSet = preparedStatement.executeQuery();
                return resultSetCallback.handle(resultSet);
            } catch (SQLException e) {
                throw new RuntimeException("Could not execute query [" + sql + "].", e);
            } catch (RealmUnavailableException e) {
                throw new RuntimeException("Realm is unavailable.", e);
            } catch (Exception e) {
                throw new RuntimeException("Unexpected error when processing authentication query [" + sql + "].", e);
            } finally {
                safeClose(resultSet);
                safeClose(preparedStatement);
                safeClose(connection);
            }
        }

        private class JdbcAuthorizationIdentity implements AuthorizationIdentity {

            private Principal principal;

            public JdbcAuthorizationIdentity(Principal principal) {
                this.principal = principal;
            }

            @Override
            public Principal getPrincipal() {
                return this.principal;
            }

            @Override
            public Set<String> getRoles() {
                return Collections.emptySet();
            }
        }
    }

    private interface ResultSetCallback<E> {
         E handle(ResultSet resultSet);
    }
}
