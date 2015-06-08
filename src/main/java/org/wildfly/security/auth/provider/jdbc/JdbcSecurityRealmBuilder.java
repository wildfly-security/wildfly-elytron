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

import org.wildfly.security.auth.spi.RealmIdentity;

import java.util.ArrayList;
import java.util.List;

/**
 * A builder class to that creates {@link JdbcSecurityRealm} instances.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JdbcSecurityRealmBuilder {

    private List<QueryBuilder> queries = new ArrayList<>();

    JdbcSecurityRealmBuilder() {

    }

    /**
     * Builds a new {@link JdbcSecurityRealm} instance based on configuration defined for this {@link JdbcSecurityRealmBuilder} instance.
     *
     * @return the built realm
     */
    public JdbcSecurityRealm build() {
        List<QueryConfiguration> configuration = new ArrayList<>();

        for (QueryBuilder query : this.queries) {
            configuration.add(query.buildQuery());
        }

        return new JdbcSecurityRealm(configuration);
    }

    /**
     * <p>A SQL SELECT statement that will be used to return data from a database based on the {@link RealmIdentity#getPrincipal()}.
     *
     * <p>When authenticating, validating or obtaining credentials for a {@link org.wildfly.security.auth.spi.RealmIdentity},
     * this query will be used. You must provide a SELECT with a single query parameter as follows:
     *
     * <pre>
     *     JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder().authenticationQuery("SELECT password FROM user_bcrypt_password where name = ?")
     * </pre>
     *
     * <p>Where the query parameter value would be the {@link RealmIdentity#getPrincipal()} name.
     *
     * @param sql the authentication query
     * @return this builder
     */
    public QueryBuilder authenticationQuery(String sql) {
        QueryBuilder builder = new QueryBuilder(sql, this);

        this.queries.add(builder);

        return builder;
    }
}
