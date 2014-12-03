package org.wildfly.security.sasl.md5digest;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ServerFactoryHelpersTest {

    @Test
    public void testBasicRealmEncoding(){

        String encoded = MD5DigestServerFactory.realmsArrayToProperty(new String[]{"aaa", "bbb", "ccc"});
        assertEquals("aaa bbb ccc", encoded);

        String[] decoded = MD5DigestServerFactory.realmsPropertyToArray("aaa bbb ccc");
        assertEquals(3, decoded.length);
        assertEquals("aaa", decoded[0]);
        assertEquals("bbb", decoded[1]);
        assertEquals("ccc", decoded[2]);

    }

    @Test
    public void testRealmEncodingWithDelimiters(){

        String encoded = MD5DigestServerFactory.realmsArrayToProperty(new String[]{"aa a", "b  bb "});
        assertEquals("aa\\ a b\\ \\ bb\\ ", encoded);

        String[] decoded = MD5DigestServerFactory.realmsPropertyToArray("aa\\ a b\\ \\ bb\\ ");
        assertEquals(2, decoded.length);
        assertEquals("aa a", decoded[0]);
        assertEquals("b  bb ", decoded[1]);

    }

    @Test
    public void testRealmEncodingWithEscapeCharacters(){

        String encoded = MD5DigestServerFactory.realmsArrayToProperty(new String[]{"aa\\ a", "bbb\\"});
        assertEquals("aa\\\\\\ a bbb\\\\", encoded);

        String[] decoded = MD5DigestServerFactory.realmsPropertyToArray("aa\\\\\\ a bbb\\\\");
        assertEquals(2, decoded.length);
        assertEquals("aa\\ a", decoded[0]);
        assertEquals("bbb\\", decoded[1]);

    }

    @Test
    public void testRealmEncodingWithNonstandardCharacters(){

        String encoded = MD5DigestServerFactory.realmsArrayToProperty(new String[]{"a@\n\t", "bb\u0438\u4F60\uD83C\uDCA1b\\"});
        assertEquals("a@\n\t bb\u0438\u4F60\uD83C\uDCA1b\\\\", encoded);

        String[] decoded = MD5DigestServerFactory.realmsPropertyToArray("a@\n\t bb\u0438\u4F60\uD83C\uDCA1b\\\\");
        assertEquals(2, decoded.length);
        assertEquals("a@\n\t", decoded[0]);
        assertEquals("bb\u0438\u4F60\uD83C\uDCA1b\\", decoded[1]);

    }

}