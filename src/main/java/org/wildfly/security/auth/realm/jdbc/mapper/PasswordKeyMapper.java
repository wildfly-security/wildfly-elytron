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
package org.wildfly.security.auth.realm.jdbc.mapper;

import static org.wildfly.security._private.ElytronMessages.log;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.auth.realm.jdbc.KeyMapper;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.password.spec.HashPasswordSpec;
import org.wildfly.security.password.spec.IteratedHashPasswordSpec;
import org.wildfly.security.password.spec.IteratedSaltedHashPasswordSpec;
import org.wildfly.security.password.spec.PasswordSpec;
import org.wildfly.security.password.spec.SaltedHashPasswordSpec;
import org.wildfly.security.password.util.ModularCrypt;

/**
 * <p>A {@link KeyMapper} that knows how to map columns from a SQL query to attributes of specific {@link org.wildfly.security.password.Password} type
 * as defined by the algorithm.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PasswordKeyMapper implements KeyMapper {

    private final int hashColumn;
    private final int saltColumn;
    private final int iterationCountColumn;
    private final int defaultIterationCount;
    private final int algorithmColumn;
    private final String defaultAlgorithm;

    PasswordKeyMapper(Builder builder) {
        final int hashColumn = builder.hashColumn;
        Assert.checkMinimumParameter("hashColumn", 1, hashColumn);
        this.hashColumn = hashColumn;
        final int saltColumn = builder.saltColumn;
        if (saltColumn != -1) Assert.checkMinimumParameter("saltColumn", 1, saltColumn);
        this.saltColumn = saltColumn;
        final int iterationCountColumn = builder.iterationCountColumn;
        if (iterationCountColumn != -1) Assert.checkMinimumParameter("iterationCountColumn", 1, iterationCountColumn);
        this.iterationCountColumn = iterationCountColumn;
        final int defaultIterationCount = builder.defaultIterationCount;
        if (defaultIterationCount != -1) Assert.checkMinimumParameter("defaultIterationCount", 1, defaultIterationCount);
        this.defaultIterationCount = defaultIterationCount;
        final int algorithmColumn = builder.algorithmColumn;
        if (algorithmColumn != -1) Assert.checkMinimumParameter("algorithmColumn", 1, algorithmColumn);
        this.algorithmColumn = algorithmColumn;
        defaultAlgorithm = builder.defaultAlgorithm;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName, final AlgorithmParameterSpec parameterSpec) {
        return PasswordCredential.class.isAssignableFrom(credentialType) ? SupportLevel.POSSIBLY_SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(final Class<? extends Evidence> evidenceType, final String algorithmName) {
        return PasswordCredential.canVerifyEvidence(evidenceType, algorithmName) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    /**
     * Returns the name of the algorithm being used.
     *
     * @return the algorithm
     */
    public String getDefaultAlgorithm() {
        return this.defaultAlgorithm;
    }

    /**
     * Returns an integer representing the column index from where the password in its clear, hash or encoded form is obtained.
     *
     * @return the column index
     */
    public int getHashColumn() {
        return this.hashColumn;
    }

    /**
     * Returns an integer representing the column index from where the salt (if supported) is obtained.
     *
     * @return the column index
     */
    public int getSaltColumn() {
        return this.saltColumn;
    }

    /**
     * Returns an integer representing the column index from where the iteration count (if supported) is obtained.
     *
     * @return the column index
     */
    public int getIterationCountColumn() {
        return this.iterationCountColumn;
    }

    /**
     * Get the default iteration count.  This count is used if there is no iteration count column but the password
     * algorithm uses an iteration count.
     *
     * @return the default iteration count
     */
    public int getDefaultIterationCount() {
        return defaultIterationCount;
    }

    /**
     * Get the column index of the algorithm name column.
     *
     * @return the column index of the algorithm name column, or -1 if there is no algorithm column defined
     */
    public int getAlgorithmColumn() {
        return algorithmColumn;
    }

    private static byte[] getBinaryColumn(ResultSetMetaData metaData, ResultSet resultSet, int column) throws SQLException {
        if (column == -1) return null;
        final int columnType = metaData.getColumnType(column);
        switch (columnType) {
            case Types.BINARY:
            case Types.VARBINARY:
            case Types.LONGVARBINARY: {
                return resultSet.getBytes(column);
            }
            case Types.CHAR:
            case Types.LONGVARCHAR:
            case Types.LONGNVARCHAR:
            case Types.VARCHAR:
            case Types.NVARCHAR: {
                return CodePointIterator.ofString(resultSet.getString(column)).base64Decode().drain();
            }
            default: {
                final Object object = resultSet.getObject(column);
                if (object instanceof byte[]) {
                    return (byte[]) object;
                } else if (object instanceof String) {
                    return CodePointIterator.ofString(resultSet.getString(column)).base64Decode().drain();
                }
                return null;
            }
        }
    }

    private static String getStringColumn(ResultSetMetaData metaData, ResultSet resultSet, int column) throws SQLException {
        if (column == -1) return null;
        final int columnType = metaData.getColumnType(column);
        switch (columnType) {
            case Types.BINARY:
            case Types.VARBINARY:
            case Types.LONGVARBINARY: {
                return new String(resultSet.getBytes(column), StandardCharsets.UTF_8);
            }
            case Types.CHAR:
            case Types.LONGVARCHAR:
            case Types.LONGNVARCHAR:
            case Types.VARCHAR:
            case Types.NVARCHAR: {
                return resultSet.getString(column);
            }
            default: {
                final Object object = resultSet.getObject(column);
                if (object instanceof byte[]) {
                    return new String((byte[]) object, StandardCharsets.UTF_8);
                } else if (object instanceof String) {
                    return (String) object;
                } else {
                    return null;
                }
            }
        }
    }

    @Override
    public Credential map(ResultSet resultSet, Supplier<Provider[]> providers) throws SQLException {
        byte[] hash = null;
        char[] clear = null;
        byte[] salt = null;
        int iterationCount = -1;
        String algorithmName = getDefaultAlgorithm();

        final int hashColumn = getHashColumn();
        final int saltColumn = getSaltColumn();
        final int iterationCountColumn = getIterationCountColumn();
        final int algorithmColumn = getAlgorithmColumn();
        final int defaultIterationCount = getDefaultIterationCount();

        final ResultSetMetaData metaData = resultSet.getMetaData();

        if (algorithmColumn > 0) {
            algorithmName = resultSet.getString(algorithmColumn);
            if (algorithmName == null) {
                algorithmName = getDefaultAlgorithm();
            }
        }

        if (ClearPassword.ALGORITHM_CLEAR.equals(algorithmName)) {
            final String s = getStringColumn(metaData, resultSet, hashColumn);
            if (s != null) {
                clear = s.toCharArray();
            } else {
                hash = getBinaryColumn(metaData, resultSet, hashColumn);
            }
        } else {
            if (saltColumn == -1 && iterationCountColumn == -1) {
                // try modular crypt
                final String s = getStringColumn(metaData, resultSet, hashColumn);
                if (s != null) {
                    final char[] chars = s.toCharArray();
                    final String identified = ModularCrypt.identifyAlgorithm(chars);
                    if (identified != null) {
                        try {
                            Password modularCryptPassword = ModularCrypt.decode(chars);
                            if (log.isTraceEnabled()) {
                                log.tracef("Key Mapper: Password credential created using Modular Crypt algorithm [%s]", identified);
                            }
                            return new PasswordCredential(modularCryptPassword);
                        } catch (InvalidKeySpecException e) {
                            log.tracef(e, "Key Mapper: Unable to identify Modular Crypt algorithm [%s]", identified);
                        }
                    }
                }
            }
            hash = getBinaryColumn(metaData, resultSet, hashColumn);
        }

        if (saltColumn > 0) {
            salt = getBinaryColumn(metaData, resultSet, saltColumn);
        }

        if (iterationCountColumn > 0) {
            iterationCount = resultSet.getInt(iterationCountColumn);
        } else {
            iterationCount = defaultIterationCount;
        }


        final PasswordFactory passwordFactory;
        try {
            passwordFactory = PasswordFactory.getInstance(algorithmName, providers);
        } catch (NoSuchAlgorithmException e) {
            throw log.couldNotObtainPasswordFactoryForAlgorithm(algorithmName, e);
        }
        PasswordSpec passwordSpec;

        if (hash != null) {
            if (salt != null) {
                if (iterationCount > 0) {
                    passwordSpec = new IteratedSaltedHashPasswordSpec(hash, salt, iterationCount);
                } else {
                    passwordSpec = new SaltedHashPasswordSpec(hash, salt);
                }
            } else {
                if (iterationCount > 0) {
                    passwordSpec = new IteratedHashPasswordSpec(hash, iterationCount);
                } else {
                    passwordSpec = new HashPasswordSpec(hash);
                }
            }
        } else if (clear != null) {
            passwordSpec = new ClearPasswordSpec(clear);
        } else {
            return null;
        }

        try {
            Password password = passwordFactory.generatePassword(passwordSpec);
            if (log.isTraceEnabled()) {
                log.tracef("Key Mapper: Password credential created using algorithm column value [%s]", algorithmName);
            }
            return new PasswordCredential(password);
        } catch (InvalidKeySpecException e) {
            throw log.invalidPasswordKeySpecificationForAlgorithm(algorithmName, e);
        }
    }

    /**
     * Construct a builder for password key mappers.
     *
     * @return the new builder (not {@code null})
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for {@code PasswordKeyMapper} instances.
     */
    public static final class Builder {

        int hashColumn = -1;
        int saltColumn = -1;
        int iterationCountColumn = -1;
        int defaultIterationCount = -1;
        int algorithmColumn = -1;
        String defaultAlgorithm;

        Builder() {
        }

        public int getHashColumn() {
            return hashColumn;
        }

        public Builder setHashColumn(final int hashColumn) {
            this.hashColumn = hashColumn;
            return this;
        }

        public int getSaltColumn() {
            return saltColumn;
        }

        public Builder setSaltColumn(final int saltColumn) {
            this.saltColumn = saltColumn;
            return this;
        }

        public int getIterationCountColumn() {
            return iterationCountColumn;
        }

        public Builder setIterationCountColumn(final int iterationCountColumn) {
            this.iterationCountColumn = iterationCountColumn;
            return this;
        }

        public int getDefaultIterationCount() {
            return defaultIterationCount;
        }

        public Builder setDefaultIterationCount(final int defaultIterationCount) {
            this.defaultIterationCount = defaultIterationCount;
            return this;
        }

        public int getAlgorithmColumn() {
            return algorithmColumn;
        }

        public Builder setAlgorithmColumn(final int algorithmColumn) {
            this.algorithmColumn = algorithmColumn;
            return this;
        }

        public String getDefaultAlgorithm() {
            return defaultAlgorithm;
        }

        public Builder setDefaultAlgorithm(final String defaultAlgorithm) {
            this.defaultAlgorithm = defaultAlgorithm;
            return this;
        }

        public PasswordKeyMapper build() {
            return new PasswordKeyMapper(this);
        }
    }
}
