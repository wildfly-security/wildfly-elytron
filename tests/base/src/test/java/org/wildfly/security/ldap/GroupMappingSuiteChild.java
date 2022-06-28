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
public class GroupMappingSuiteChild extends AbstractAttributeMappingSuiteChild {

    @Test
    public void testMultipleGroupsWithUniqueMember() throws Exception {
        assertAttributes(attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get("Groups"), "GroupOne", "GroupTwo", "GroupThree", "GroupOneInGroupThree");
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfUniqueNames)(uniqueMember={1}))").from("CN").to("Groups").build());
    }

    @Test
    public void testMultipleGroupsWithUniqueMemberExtractRdn() throws Exception {
        assertAttributes(attributes -> {
            assertEquals("Expected a single attribute.", 1, attributes.size());
            assertAttributeValue(attributes.get("Groups"), "GroupOne", "GroupTwo", "GroupThree", "GroupOneInGroupThree");
        }, AttributeMapping.fromFilter("(&(objectClass=groupOfUniqueNames)(uniqueMember={1}))").to("Groups").extractRdn("CN").build());
    }
}
