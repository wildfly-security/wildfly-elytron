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
        }, AttributeMapping.from("cn").to("firstName"));
    }

    @Test
    public void testSingleAttributeToLdapName() throws Exception {
        assertAttributes("userWithAttributes", attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get("CN"), "My First Name");
        }, AttributeMapping.from("cn"));
    }

    @Test
    public void testMultipleAttributeMapping() throws Exception {
        assertAttributes("userWithAttributes", attributes -> {
            assertEquals("Expected two attributes.", 2, attributes.size());
            assertAttributeValue(attributes.get("CN"), "My First Name");
            assertAttributeValue(attributes.get("lastName"), "My Last Name");
        }, AttributeMapping.from("cn"), AttributeMapping.from("sn").to("lastName"));
    }

    @Test
    public void testAttributeFromDifferentMappings() throws Exception {
        assertAttributes("userWithAttributes", attributes -> {
            assertEquals("Expected two attributes.", 1, attributes.size());
            assertAttributeValue(attributes.get("CN"), "My First Name", "My Last Name");
        }, AttributeMapping.from("cn"), AttributeMapping.from("sn").to("CN"));
    }

    @Test
    public void testAttributeFromRDN() throws Exception {
        assertAttributes("userWithRdnAttribute", attributes -> {
            assertEquals("Expected two attributes.", 1, attributes.size());
            assertAttributeValue(attributes.get("businessArea"), "Finance", "Sales");
        }, AttributeMapping.fromFilter("ou=Finance,dc=elytron,dc=wildfly,dc=org", "(&(objectClass=groupOfNames)(member={0}))", "CN").asRdn("OU").to("businessArea")
         , AttributeMapping.fromFilter("ou=Sales,dc=elytron,dc=wildfly,dc=org", "(&(objectClass=groupOfNames)(member={0}))", "CN").asRdn("OU").to("businessArea"));
    }
}
