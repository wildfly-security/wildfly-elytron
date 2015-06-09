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

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A builder class with different configuration options to configure queries.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class QueryBuilder extends JdbcSecurityRealmBuilder {

    private final String sql;
    private final JdbcSecurityRealmBuilder parent;
    private List<ColumnMapper> mappers = new ArrayList<>();
    private DataSource dataSource;

    QueryBuilder(String sql, JdbcSecurityRealmBuilder parent) {
        this.sql = sql;
        this.parent = parent;
    }

    /**
     * Defines a mapper that will be applied to the query in order to map the returned columns to some internal representation.
     *
     * @param mapper the column mapper instance
     * @return this builder
     */
    public QueryBuilder withMapper(ColumnMapper... mapper) {
        this.mappers.addAll(Arrays.asList(mapper));
        return this;
    }

    /**
     * Defines the {@link DataSource} from where connections are obtained.
     *
     * @param dataSource the data source.
     * @return this builder
     */
    public QueryBuilder from(DataSource dataSource) {
        this.dataSource = dataSource;
        return this;
    }


    @Override
    public QueryBuilder authenticationQuery(String sql) {
        return this.parent.authenticationQuery(sql);
    }

    @Override
    public JdbcSecurityRealm build() {
        return this.parent.build();
    }

    QueryConfiguration buildQuery() {
        return new QueryConfiguration(this.sql, this.dataSource, this.mappers);
    }

}
