/*
 * JBoss, Home of Professional Open Source.
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
package org.wildfly.security.sasl.test;

import static org.junit.Assert.*;
import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.sasl.util.Charsets;

/**
 * Tests of org.wildfly.security.sasl.util.Charsets
 * <p>
 * Reference output by:
 * <li> http://www.ltg.ed.ac.uk/~richard/utf-8.html
 * <li> http://www.russellcottrell.com/greek/utilities/SurrogatePairCalculator.htm
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class CharsetsTest {

	@Test
	public void testConstants() throws Exception {
		assertEquals("UTF-8", Charsets.UTF_8.name());
		assertEquals("ISO-8859-1", Charsets.LATIN_1.name());
	}

	@Test
	public void testIndexOf() throws Exception {
		byte[] array = { 0x10, 0x15, (byte)0x81, 0x00, 0x15, (byte)0xab };

		assertEquals(0, Charsets.indexOf(array, 0x10));
		assertEquals(2, Charsets.indexOf(array, 0x81));
		assertEquals(3, Charsets.indexOf(array, 0x00));
		assertEquals(5, Charsets.indexOf(array, 0xab));
		assertEquals(-1, Charsets.indexOf(array, 0x16));

		assertEquals(1, Charsets.indexOf(array, 0x15));
		assertEquals(1, Charsets.indexOf(array, 0x15, 0));
		assertEquals(4, Charsets.indexOf(array, 0x15, 2));
		assertEquals(4, Charsets.indexOf(array, 0x15, 4));
		assertEquals(-1, Charsets.indexOf(array, 0x15, 5));
		assertEquals(-1, Charsets.indexOf(array, 0x10, 1));

		assertEquals(4, Charsets.indexOf(array, 0x15, 3, 5));
		assertEquals(4, Charsets.indexOf(array, 0x15, 2, 4));
		assertEquals(4, Charsets.indexOf(array, 0x15, 4, 5));
		assertEquals(1, Charsets.indexOf(array, 0x15, 0, 5));
		assertEquals(-1, Charsets.indexOf(array, 0xff, 1, 4));
	}

	@Test
	public void testEncodedLengthOf() throws Exception {
		assertEquals(0, Charsets.encodedLengthOf(""));
		assertEquals(1, Charsets.encodedLengthOf("a"));
		assertEquals(2, Charsets.encodedLengthOf("и"));
		assertEquals(3, Charsets.encodedLengthOf("你"));
		assertEquals(11, Charsets.encodedLengthOf("Hello world"));
		assertEquals(20, Charsets.encodedLengthOf("Привет, мир"));
		assertEquals(12, Charsets.encodedLengthOf("你好世界"));
		assertEquals(1, Charsets.encodedLengthOf("\n"));
		assertEquals(2, Charsets.encodedLengthOf("\0")); // two-byte form of NULL character
	}

	@Test
	public void testEncodingOf1byteChar() throws Exception {
		byte[] dest = new byte[1];
		Charsets.encodeTo("a", dest, 0);
		Assert.assertArrayEquals(new byte[]{(byte)0x61}, dest);
	}

	@Test
	public void testEncodingOf2bytesChar() throws Exception {
		byte[] dest = new byte[2];
		Charsets.encodeTo("\u0438", dest, 0);
		Assert.assertArrayEquals(new byte[]{(byte)0xD0,(byte)0xB8}, dest);
	}

	@Test
	public void testEncodingOf3bytesChar() throws Exception {
		byte[] dest = new byte[3];
		Charsets.encodeTo("\u4F60", dest, 0);
		Assert.assertArrayEquals(new byte[]{(byte)0xE4,(byte)0xBD,(byte)0xA0}, dest);
	}

	@Test
	public void testEncodingOf4bytesChar() throws Exception {
		byte[] dest = new byte[4];
		Charsets.encodeTo("\uD83C\uDCA1", dest, 0);
		Assert.assertArrayEquals(new byte[]{(byte)0xF0,(byte)0x9F,(byte)0x82,(byte)0xA1}, dest);
	}

	@Test
	public void testEncodingOfNullChar() throws Exception {
		byte[] dest = new byte[2];
		Charsets.encodeTo("\0", dest, 0);
		Assert.assertArrayEquals(new byte[]{(byte)0xC0,(byte)0x80}, dest); // two-byte form of NULL character
	}

	@Test
	public void testEncodingOfNewline() throws Exception {
		byte[] dest = new byte[1];
		Charsets.encodeTo("\n", dest, 0);
		Assert.assertArrayEquals(new byte[]{(byte)0x0A}, dest);
	}

	@Test
	public void testEncodingOfMoreCharacters() throws Exception {
		byte[] dest = new byte[10];
		Charsets.encodeTo("a\u0438\u4F60\uD83C\uDCA1", dest, 0);
		Assert.assertArrayEquals(new byte[]{(byte)0x61,(byte)0xD0,(byte)0xB8,(byte)0xE4,(byte)0xBD,(byte)0xA0,(byte)0xF0,(byte)0x9F,(byte)0x82,(byte)0xA1}, dest);
	}

	@Test
	public void testEncodingWithOffset() throws Exception {
		byte[] dest = new byte[13];
		Charsets.encodeTo("a\u0438\u4F60\uD83C\uDCA1", dest, 2);
		Assert.assertArrayEquals(new byte[]{0x00,0x00,(byte)0x61,(byte)0xD0,(byte)0xB8,(byte)0xE4,(byte)0xBD,(byte)0xA0,(byte)0xF0,(byte)0x9F,(byte)0x82,(byte)0xA1,0x00}, dest);
	}

	@Test
	public void testTooShortDestinationOfEncoding() throws Exception {
		byte[] dest = new byte[2];
		assertFalse(Charsets.encodeTo("a\u0438\u4F60\uD83C\uDCA1", dest, 0));
		Assert.assertArrayEquals(new byte[]{(byte)0x61,(byte)0xD0}, dest);
	}

}