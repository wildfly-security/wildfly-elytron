/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.util;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ServerFactoryHelpersTest {

    @Test
    public void testBasicRealmEncoding(){

        String encoded = LegacyRealmListSaslServerFactory.arrayToRealmListProperty(new String[]{"aaa", "bbb", "ccc"});
        assertEquals("aaa bbb ccc", encoded);

        String[] decoded = AvailableRealmsSaslServerFactory.realmListPropertyToArray("aaa bbb ccc");
        assertEquals(3, decoded.length);
        assertEquals("aaa", decoded[0]);
        assertEquals("bbb", decoded[1]);
        assertEquals("ccc", decoded[2]);

    }

    @Test
    public void testRealmEncodingWithDelimiters(){

        String encoded = LegacyRealmListSaslServerFactory.arrayToRealmListProperty(new String[]{"aa a", "b  bb "});
        assertEquals("aa\\ a b\\ \\ bb\\ ", encoded);

        String[] decoded = AvailableRealmsSaslServerFactory.realmListPropertyToArray("aa\\ a b\\ \\ bb\\ ");
        assertEquals(2, decoded.length);
        assertEquals("aa a", decoded[0]);
        assertEquals("b  bb ", decoded[1]);

    }

    @Test
    public void testRealmEncodingWithEscapeCharacters(){

        String encoded = LegacyRealmListSaslServerFactory.arrayToRealmListProperty(new String[]{"aa\\ a", "bbb\\"});
        assertEquals("aa\\\\\\ a bbb\\\\", encoded);

        String[] decoded = AvailableRealmsSaslServerFactory.realmListPropertyToArray("aa\\\\\\ a bbb\\\\");
        assertEquals(2, decoded.length);
        assertEquals("aa\\ a", decoded[0]);
        assertEquals("bbb\\", decoded[1]);

    }

    @Test
    public void testRealmEncodingWithNonstandardCharacters(){

        String encoded = LegacyRealmListSaslServerFactory.arrayToRealmListProperty(new String[]{"a@\n\t", "bb\u0438\u4F60\uD83C\uDCA1b\\"});
        assertEquals("a@\n\t bb\u0438\u4F60\uD83C\uDCA1b\\\\", encoded);

        String[] decoded = AvailableRealmsSaslServerFactory.realmListPropertyToArray("a@\n\t bb\u0438\u4F60\uD83C\uDCA1b\\\\");
        assertEquals(2, decoded.length);
        assertEquals("a@\n\t", decoded[0]);
        assertEquals("bb\u0438\u4F60\uD83C\uDCA1b\\", decoded[1]);

    }

    @Test
    public void testRealmEncodingWithGivenDelimitersAndEscapeCharacters(){
        String encoded = LegacyRealmListSaslServerFactory.arrayToRealmListProperty(new String[]{"aa\\ a", "bbb\\", "c\\c\\cc\\"}, '\\', ',', ' ');
        assertEquals("aa\\\\\\ a, bbb\\\\, c\\\\c\\\\cc\\\\", encoded);

        String[] decoded = AvailableRealmsSaslServerFactory.realmListPropertyToArray("aa\\\\\\ a, bbb\\\\, c\\\\c\\\\cc\\\\", '\\', ',', ' ');
        assertEquals(3, decoded.length);
        assertEquals("aa\\ a", decoded[0]);
        assertEquals("bbb\\", decoded[1]);
        assertEquals("c\\c\\cc\\", decoded[2]);
    }

}
