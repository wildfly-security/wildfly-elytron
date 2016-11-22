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

import java.security.Provider;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.function.Supplier;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.realm.jdbc.ColumnMapper;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AttributeMapper implements ColumnMapper {

    private final int index;
    private final String name;

    public AttributeMapper(int index, String name) {
        Assert.checkMinimumParameter("index", 1, index);
        this.index = index;
        this.name = name;
    }

    @Override
    public Object map(ResultSet resultSet, Supplier<Provider[]> providers) throws SQLException {
        return resultSet.getString(this.index);
    }

    public String getName() {
        return this.name;
    }
}
