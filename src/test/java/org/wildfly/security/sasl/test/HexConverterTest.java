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
import org.wildfly.security.sasl.util.HexConverter;

/**
 * Tests of org.wildfly.security.sasl.util.HexConverter
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class HexConverterTest {

	@Test
	public void testConvertToHexString(){
		assertEquals("",HexConverter.convertToHexString(new byte[]{}));
		assertEquals("00",HexConverter.convertToHexString(new byte[]{(byte)0x00}));
		assertEquals("ff",HexConverter.convertToHexString(new byte[]{(byte)0xFF}));
		assertEquals("1234af",HexConverter.convertToHexString(new byte[]{(byte)0x12,(byte)0x34,(byte)0xAF}));
	}

	@Test
	public void testConvertToHexBytes(){
		Assert.assertArrayEquals(new byte[]{},HexConverter.convertToHexBytes(new byte[]{}));
		Assert.assertArrayEquals(new byte[]{(byte)'0',(byte)'0'},HexConverter.convertToHexBytes(new byte[]{(byte)0x00}));
		Assert.assertArrayEquals(new byte[]{(byte)'f',(byte)'f'},HexConverter.convertToHexBytes(new byte[]{(byte)0xFF}));
		Assert.assertArrayEquals(new byte[]{(byte)'1',(byte)'2',(byte)'3',(byte)'4',(byte)'a',(byte)'f'},HexConverter.convertToHexBytes(new byte[]{(byte)0x12,(byte)0x34,(byte)0xAF}));
	}

	@Test
	public void testConvertFromHexString(){
		Assert.assertArrayEquals(new byte[]{},HexConverter.convertFromHex(""));
		Assert.assertArrayEquals(new byte[]{(byte)0x1F,(byte)0x0E},HexConverter.convertFromHex("1f0e"));
		Assert.assertArrayEquals(new byte[]{(byte)0x1F,(byte)0x0E},HexConverter.convertFromHex("1f0E"));
		Assert.assertArrayEquals(new byte[]{(byte)0x1F,(byte)0x0E},HexConverter.convertFromHex("1F0E"));
	}

	@Test
	public void testConvertFromHexChars(){
		Assert.assertArrayEquals(new byte[]{},HexConverter.convertFromHex(new char[]{}));
		Assert.assertArrayEquals(new byte[]{(byte)0x1F,(byte)0x0E},HexConverter.convertFromHex(new char[]{'1','f','0','e'}));
		Assert.assertArrayEquals(new byte[]{(byte)0xAF,(byte)0x0E},HexConverter.convertFromHex(new char[]{'A','f','0','E'}));
	}

	@Test
    public void testConvertFromBadCountOfHexChars() throws Exception {
	    try{
	        HexConverter.convertFromHex(new char[]{'1','F','A'});
            fail("Not throwed IllegalArgumentException!");
        }
        catch(IllegalArgumentException e){}
	}

	@Test
	public void testConvertFromUnvalidHexChars() throws Exception {
	    try{
            HexConverter.convertFromHex(new char[]{'B','Z'});
            fail("Not throwed IllegalArgumentException!");
        }
        catch(IllegalArgumentException e){}
    }

	@Test
	public void testConvertAllCombinations(){

		byte[] toConvert = new byte[256];
		for(int i = 0; i < 256; i++){
			toConvert[i] = (byte) i;
		}

		String convertedToHex = HexConverter.convertToHexString(toConvert);

		assertEquals("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", convertedToHex);

		byte[] convertedBackToBytes = HexConverter.convertFromHex(convertedToHex);

		assertEquals(256, convertedBackToBytes.length);
		for(int i = 0; i < 256; i++){
			assertEquals((byte)i, convertedBackToBytes[i]);
		}

    }

}
