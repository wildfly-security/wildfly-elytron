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

import static org.wildfly.security.provider.util.ProviderUtil.INSTALLED_PROVIDERS;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.RealmIdentity;

/**
 * A builder class to that creates {@link JdbcSecurityRealm} instances.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JdbcSecurityRealmBuilder {

    private Supplier<Provider[]> providers = INSTALLED_PROVIDERS;
    private List<QueryBuilder> queries = new ArrayList<>();
    private Charset hashCharset;

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

        if (hashCharset == null) {
            hashCharset = StandardCharsets.UTF_8;
        }
        return new JdbcSecurityRealm(configuration, providers, hashCharset);
    }

    /**
     * Set the providers to be used by the realm.
     *
     * @param providers the providers to be used by the realm.
     * @return this builder.
     */
    public JdbcSecurityRealmBuilder setProviders(Supplier<Provider[]> providers) {
        Assert.checkNotNullParam("providers", providers);
        this.providers = providers;

        return this;
    }

    /**
     * Set the character set to use when converting the password string to a byte array.
     * Uses UTF-8 by default.
     * @param hashCharset the name of the character set (must not be {@code null})
     * @return this builder
     */
    public JdbcSecurityRealmBuilder setHashCharset(Charset hashCharset) {
        Assert.checkNotNullParam("hashCharset", hashCharset);
        this.hashCharset = hashCharset;

        return this;
    }

    /**
     * <p>A SQL SELECT statement that will be used to return data from a database based on the principal's name.
     *
     * <p>When authenticating, validating or obtaining credentials for a {@link RealmIdentity},
     * this query will be used. You must provide a SELECT with a single query parameter as follows:
     *
     * <pre>
     *     JdbcSecurityRealm securityRealm = JdbcSecurityRealm.builder().principalQuery("SELECT password FROM user_bcrypt_password where name = ?")
     * </pre>
     *
     * <p>Where the query parameter value would be the principal's name.
     *
     * @param sql the authentication query
     * @return this builder
     */
    public QueryBuilder principalQuery(String sql) {
        QueryBuilder builder = new QueryBuilder(sql, this);

        this.queries.add(builder);

        return builder;
    }
}
