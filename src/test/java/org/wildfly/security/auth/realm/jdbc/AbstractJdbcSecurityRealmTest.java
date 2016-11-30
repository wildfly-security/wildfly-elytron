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

import org.junit.ClassRule;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class AbstractJdbcSecurityRealmTest {

    @ClassRule
    public static DataSourceRule dataSourceRule = new DataSourceRule();

    protected void createUserTable() throws Exception {
        try (
                Connection connection = getDataSource().getConnection();
                Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS role_mapping_table");
            statement.executeUpdate("DROP TABLE IF EXISTS user_table");
            statement.executeUpdate("CREATE TABLE user_table (id INT, name VARCHAR(100) UNIQUE, password VARCHAR(50), firstName VARCHAR(50), lastName VARCHAR(50), email VARCHAR(50), PRIMARY KEY (id))");
        }
    }

    protected DataSource getDataSource() {
        return dataSourceRule.getDataSource();
    }

    protected void createRoleTable() throws Exception {
        try (
                Connection connection = getDataSource().getConnection();
                Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS role_table");
            statement.executeUpdate("CREATE TABLE role_table (name VARCHAR(100), PRIMARY KEY (name))");
        }
    }

    protected void createRoleMappingTable() throws Exception {
        try (
                Connection connection = getDataSource().getConnection();
                Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DROP TABLE IF EXISTS role_mapping_table");
            statement.executeUpdate("CREATE TABLE role_mapping_table (role_name VARCHAR(100), user_name VARCHAR(100), FOREIGN KEY (role_name) REFERENCES role_table(name) ON DELETE CASCADE, FOREIGN KEY (user_name) REFERENCES user_table(name))");
        }
    }

    protected void insertUser(int id, String userName, String password, String firstName, String lastName, String email) throws SQLException {
        try (
                Connection connection = getDataSource().getConnection();
                Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("INSERT INTO user_table (id, name, password, firstName, lastName, email) VALUES (" + id + ", '" + userName + "','" + password + "','" + firstName + "','" + lastName + "','" + email + "')");
        }
    }

    protected void insertUserRole(String userName, String roleName) throws SQLException {
        try (
                Connection connection = getDataSource().getConnection();
                Statement statement = connection.createStatement();
        ) {
            statement.executeUpdate("DELETE FROM role_table WHERE name = '" + roleName + "'");
            statement.executeUpdate("INSERT INTO role_table (name) VALUES ('" + roleName + "')");
            statement.executeUpdate("INSERT INTO role_mapping_table (role_name, user_name) VALUES ('" + roleName + "','" + userName + "')");
        }
    }
}
