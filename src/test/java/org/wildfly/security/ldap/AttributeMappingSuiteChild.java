/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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

package org.wildfly.security.ldap;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.wildfly.security.auth.realm.ldap.AttributeMapping;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AttributeMappingSuiteChild extends AbstractAttributeMappingSuiteChild {

    @Test
    public void testSingleAttributeToSpecifiedName() throws Exception {
        assertAttributes("userWithAttributes", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get("firstName"), "My First Name");
        }, AttributeMapping.fromIdentity().from("cn").to("firstName").build());
    }

    @Test
    public void testSingleAttributeToLdapName() throws Exception {
        assertAttributes("userWithAttributes", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get("CN"), "My First Name");
        }, AttributeMapping.fromIdentity().from("cn").build());
    }

    @Test
    public void testMultipleAttributeMapping() throws Exception {
        assertAttributes("userWithAttributes", attributes -> {
            assertEquals("Expected two attributes.", 2, attributes.size());
            assertAttributeValue(attributes.get("CN"), "My First Name");
            assertAttributeValue(attributes.get("lastName"), "My Last Name");
        }, AttributeMapping.fromIdentity().from("cn").build(), AttributeMapping.fromIdentity().from("sn").to("lastName").build());
    }

    @Test
    public void testAttributeFromDifferentMappings() throws Exception {
        assertAttributes("userWithAttributes", attributes -> {
            assertEquals("Expected one attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get("CN"), "My First Name", "My Last Name");
        }, AttributeMapping.fromIdentity().from("cn").build(), AttributeMapping.fromIdentity().from("sn").to("CN").build());
    }

    @Test
    public void testAttributeFilterRdn() throws Exception {
        assertAttributes("userWithRdnAttribute", attributes -> {
            assertEquals("Expected one attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get("businessArea"), "Finance", "cn=Manager,ou=Sales,dc=elytron,dc=wildfly,dc=org");
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").searchDn("ou=Finance,dc=elytron,dc=wildfly,dc=org").extractRdn("OU").to("businessArea").build()
         , AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").searchDn("ou=Sales,dc=elytron,dc=wildfly,dc=org").to("businessArea").build());
    }

    @Test
    public void testAttributeFilterAttribute() throws Exception {
        assertAttributes("userWithRdnAttribute", attributes -> {
            assertEquals("Expected one attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get("roles"), "Manager", "Manager");
            assertEquals("Expected two roles.", 2, attributes.get("roles").size());
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").from("cn").searchDn("ou=Finance,dc=elytron,dc=wildfly,dc=org").to("roles").build()
         , AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").from("cn").searchDn("ou=Sales,dc=elytron,dc=wildfly,dc=org").to("roles").build());
    }

    @Test
    public void testDnToSpecifiedAttribute() throws Exception {
        assertAttributes("userWithAttributes", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get("myDn"), "uid=userWithAttributes,dc=elytron,dc=wildfly,dc=org");
        }, AttributeMapping.fromIdentity().to("myDn").build());
    }

    @Test
    public void testRecursiveRoles() throws Exception {
        assertAttributes("jduke", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get("roles"), "R1", "R2");
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfNames)(member={1}))").from("cn").roleRecursion(1).to("roles").build());
    }
}
