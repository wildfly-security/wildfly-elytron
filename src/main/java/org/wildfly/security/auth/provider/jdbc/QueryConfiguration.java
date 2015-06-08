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
import java.util.Collections;
import java.util.List;

/**
 * Holds the configuration for a specific query.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class QueryConfiguration {

    private final DataSource dataSource;
    private String sql;
    private List<ColumnMapper> keys = new ArrayList<>();

    QueryConfiguration(String sql, DataSource dataSource, List<ColumnMapper> configuration) {
        this.sql = sql;
        this.dataSource = dataSource;
        this.keys = configuration;
    }

    /**
     * Returns the SQL used by this query.
     *
     * @return
     */
    public String getSql() {
        return this.sql;
    }

    /**
     * Returns the {@link DataSource} from where connections are obtained.
     *
     * @return
     */
    public DataSource getDataSource() {
        return this.dataSource;
    }

    /**
     * Returns all {@link ColumnMapper} instances associated with this query.
     *
     * @return
     */
    public List<ColumnMapper> getColumnMappers() {
        return Collections.unmodifiableList(this.keys);
    }
}
