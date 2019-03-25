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

import org.hsqldb.jdbc.JDBCDataSource;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;

import javax.sql.DataSource;
import java.security.Provider;
import java.security.Security;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DataSourceRule implements TestRule {

    private static final Provider provider = WildFlyElytronPasswordProvider.getInstance();
    private JDBCDataSource dataSource;

    @Override
    public Statement apply(Statement current, Description description) {
        return new Statement() {

            @Override
            public void evaluate() throws Throwable {
                Security.addProvider(provider);

                dataSource = new JDBCDataSource();

                dataSource.setDatabase("mem:elytron-jdbc-realm-test");
                dataSource.setUser("sa");

                try {
                    current.evaluate();
                } catch (Exception e) {
                    throw e;
                } finally {
                    Security.removeProvider(provider.getName());
                }
            }
        };
    }

    public DataSource getDataSource() {
        return dataSource;
    }
}
