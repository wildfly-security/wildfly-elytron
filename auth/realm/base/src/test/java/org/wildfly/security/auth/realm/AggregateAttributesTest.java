/*
 * Copyright 2019 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.realm;

import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.wildfly.security.authz.AggregateAttributes;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.Attributes.Entry;
import org.wildfly.security.authz.MapAttributes;

/**
 * Test case testing the {@link AggregateAttributes} implementation.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class AggregateAttributesTest {

    @Test
    public void testTwoNoOverlap() {
        Attributes firstAttributes = new MapAttributes();
        firstAttributes.add("team", 0, "WildFly");

        Attributes secondAttributes = new MapAttributes();
        secondAttributes.add("e-mail", 0, "second@wildfly.org");
        secondAttributes.add("group", 0, "Three");
        secondAttributes.add("group", 1, "Four");

        Attributes combinedAttributes = AggregateAttributes.aggregateOf(firstAttributes, secondAttributes);
        assertEquals("Expected attribute count.", 3, combinedAttributes.size());
        assertEquals("Expected e-mail", "second@wildfly.org", combinedAttributes.get("e-mail", 0));
        Entry group = combinedAttributes.get("group");
        assertEquals("Expected Groups", 2, group.size());
        assertEquals("Expected Group", "Three", group.get(0));
        assertEquals("Expected Group", "Four", group.get(1));

        assertEquals("Expected Team", "WildFly", combinedAttributes.get("team", 0));
    }

    @Test
    public void testTwoOverlap() {
        Attributes firstAttributes = new MapAttributes();
        firstAttributes.add("e-mail", 0, "first@wildfly.org");
        firstAttributes.add("group", 0, "One");
        firstAttributes.add("group", 1, "Two");

        Attributes secondAttributes = new MapAttributes();
        secondAttributes.add("e-mail", 0, "second@wildfly.org");
        secondAttributes.add("group", 0, "Three");
        secondAttributes.add("group", 1, "Four");
        secondAttributes.add("team", 0, "WildFly");

        Attributes combinedAttributes = AggregateAttributes.aggregateOf(firstAttributes, secondAttributes);
        assertEquals("Expected attribute count.", 3, combinedAttributes.size());
        assertEquals("Expected e-mail", "first@wildfly.org", combinedAttributes.get("e-mail", 0));
        Entry group = combinedAttributes.get("group");
        assertEquals("Expected Groups", 2, group.size());
        assertEquals("Expected Group", "One", group.get(0));
        assertEquals("Expected Group", "Two", group.get(1));
        assertEquals("Expected Team", "WildFly", combinedAttributes.get("team", 0));
    }

    @Test
    public void testThreeNoOverlap() {
        Attributes firstAttributes = new MapAttributes();
        firstAttributes.add("e-mail", 0, "first@wildfly.org");

        Attributes secondAttributes = new MapAttributes();
        secondAttributes.add("team", 0, "WildFly");

        Attributes thirdAttributes = new MapAttributes();
        thirdAttributes.add("group", 0, "Three");
        thirdAttributes.add("group", 1, "Four");
        thirdAttributes.add("country", 0, "UK");

        Attributes combinedAttributes = AggregateAttributes.aggregateOf(firstAttributes, secondAttributes, thirdAttributes);
        assertEquals("Expected attribute count.", 4, combinedAttributes.size());
        assertEquals("Expected e-mail", "first@wildfly.org", combinedAttributes.get("e-mail", 0));
        Entry group = combinedAttributes.get("group");
        assertEquals("Expected Groups", 2, group.size());
        assertEquals("Expected Group", "Three", group.get(0));
        assertEquals("Expected Group", "Four", group.get(1));
        assertEquals("Expected Team", "WildFly", combinedAttributes.get("team", 0));
        assertEquals("Expected Country", "UK", combinedAttributes.get("country", 0));
    }

    @Test
    public void testThreeSecondOverlap() {
        Attributes firstAttributes = new MapAttributes();
        firstAttributes.add("e-mail", 0, "first@wildfly.org");
        firstAttributes.add("group", 0, "One");
        firstAttributes.add("group", 1, "Two");

        Attributes secondAttributes = new MapAttributes();
        secondAttributes.add("e-mail", 0, "second@wildfly.org");
        secondAttributes.add("group", 0, "Three");
        secondAttributes.add("group", 1, "Four");
        secondAttributes.add("team", 0, "WildFly");

        Attributes thirdAttributes = new MapAttributes();
        thirdAttributes.add("country", 0, "UK");

        Attributes combinedAttributes = AggregateAttributes.aggregateOf(firstAttributes, secondAttributes, thirdAttributes);
        assertEquals("Expected attribute count.", 4, combinedAttributes.size());
        assertEquals("Expected e-mail", "first@wildfly.org", combinedAttributes.get("e-mail", 0));
        Entry group = combinedAttributes.get("group");
        assertEquals("Expected Groups", 2, group.size());
        assertEquals("Expected Group", "One", group.get(0));
        assertEquals("Expected Group", "Two", group.get(1));
        assertEquals("Expected Team", "WildFly", combinedAttributes.get("team", 0));
        assertEquals("Expected Country", "UK", combinedAttributes.get("country", 0));
    }

    @Test
    public void testThreeThirdOverlap() {
        Attributes firstAttributes = new MapAttributes();
        firstAttributes.add("e-mail", 0, "first@wildfly.org");
        firstAttributes.add("group", 0, "One");
        firstAttributes.add("group", 1, "Two");

        Attributes secondAttributes = new MapAttributes();
        secondAttributes.add("team", 0, "WildFly");

        Attributes thirdAttributes = new MapAttributes();
        thirdAttributes.add("e-mail", 0, "second@wildfly.org");
        thirdAttributes.add("group", 0, "Three");
        thirdAttributes.add("group", 1, "Four");
        thirdAttributes.add("country", 0, "UK");

        Attributes combinedAttributes = AggregateAttributes.aggregateOf(firstAttributes, secondAttributes, thirdAttributes);
        assertEquals("Expected attribute count.", 4, combinedAttributes.size());
        assertEquals("Expected e-mail", "first@wildfly.org", combinedAttributes.get("e-mail", 0));
        Entry group = combinedAttributes.get("group");
        assertEquals("Expected Groups", 2, group.size());
        assertEquals("Expected Group", "One", group.get(0));
        assertEquals("Expected Group", "Two", group.get(1));
        assertEquals("Expected Team", "WildFly", combinedAttributes.get("team", 0));
        assertEquals("Expected Country", "UK", combinedAttributes.get("country", 0));
    }

}
