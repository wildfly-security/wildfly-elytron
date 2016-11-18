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

import java.sql.ResultSet;
import java.sql.SQLException;

import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;

/**
 * A key mapper is responsible to map data from a column in a table to a specific credential type.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface KeyMapper extends ColumnMapper {

    /**
     * Determine whether a credential of the given type and algorithm is definitely obtainable, possibly obtainable (for]
     * some identities), or definitely not obtainable.
     *
     * @param credentialType the exact credential type (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the credential type does
     *  not support algorithm names
     * @return the level of support for this credential
     */
    SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName);

    /**
     * Determine whether a given type of evidence is definitely verifiable, possibly verifiable (for some identities),
     * or definitely not verifiable.
     *
     * @param evidenceType the type of evidence to be verified (must not be {@code null})
     * @param algorithmName the algorithm name, or {@code null} if any algorithm is acceptable or the evidence type does
     *  not support algorithm names
     * @return the level of support for this evidence type
     */
    default SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) {
        if (PasswordGuessEvidence.class.isAssignableFrom(evidenceType)) {
            return getCredentialAcquireSupport(PasswordCredential.class, null);
        }
        return SupportLevel.UNSUPPORTED;
    }

    /**
     * Determine whether a given credential is definitely obtainable, possibly obtainable (for some identities), or definitely not
     * obtainable based on the given {@link ResultSet}.
     *
     * <p>In this case the support is defined based on the query result, usually related with a specific account.
     *
     * @param resultSet the result set
     * @return the level of support for a credential based on the given result set
     */
    SupportLevel getCredentialSupport(ResultSet resultSet);

    Credential map(ResultSet resultSet) throws SQLException;
}
