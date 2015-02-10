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

package org.wildfly.security.sasl.digest._private;

import static org.junit.Assert.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.crypto.Mac;

import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.sasl.digest.Digest;
import org.wildfly.security.sasl.util.HexConverter;

import static org.wildfly.security.sasl.digest._private.DigestUtil.*;

/**
 * Digest SASL utilities tests
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class DigestUtilTest {

    MessageDigest md;

    @Before
    public void init() throws Exception {
        md = MessageDigest.getInstance(messageDigestAlgorithm(Digest.DIGEST_MD5));
    }

    @Test
    public void testH_A1() throws Exception {

        assertEquals("a2549853149b0536f01f0b850c643c57", HexConverter.convertToHexString(
                H_A1(md, "chris", "elwood.innosoft.com", "secret".toCharArray(),
                "OA6MG9tEQGm2hh".getBytes(), "OA6MHXh6VqTrRk".getBytes(), null, StandardCharsets.UTF_8)));

        assertEquals("7f94ea5b1eb1b0573cca321e2b517b63", HexConverter.convertToHexString(
                H_A1(md, "chris", "elwood.innosoft.com", "secret".toCharArray(),
                "OA9BSXrbuRhWay".getBytes(), "OA9BSuZWMSpW8m".getBytes(), "chris", StandardCharsets.UTF_8)));

    }

    @Test
    public void testDigestResponse() throws Exception {

        assertEquals("d388dad90d4bbd760a152321f2143af7", new String(
                digestResponse(md, HexConverter.convertFromHex("a2549853149b0536f01f0b850c643c57"),
                "OA6MG9tEQGm2hh".getBytes(), 1, "OA6MHXh6VqTrRk".getBytes(), null, "auth", "imap/elwood.innosoft.com", true)));

        assertEquals("ea40f60335c427b5527b84dbabcdfffd", new String(
                digestResponse(md, HexConverter.convertFromHex("a2549853149b0536f01f0b850c643c57"),
                "OA6MG9tEQGm2hh".getBytes(), 1, "OA6MHXh6VqTrRk".getBytes(), null, "auth", "imap/elwood.innosoft.com", false)));

        assertEquals("aa4e81f1c6656350f7bce05d436665de", new String(
                digestResponse(md, HexConverter.convertFromHex("7f94ea5b1eb1b0573cca321e2b517b63"),
                "OA9BSXrbuRhWay".getBytes(), 1, "OA9BSuZWMSpW8m".getBytes(), "chris", "auth", "acap/elwood.innosoft.com", true)));

        assertEquals("af3ca83a805d4cfa00675a17315475c4", new String(
                digestResponse(md, HexConverter.convertFromHex("7f94ea5b1eb1b0573cca321e2b517b63"),
                "OA9BSXrbuRhWay".getBytes(), 1, "OA9BSuZWMSpW8m".getBytes(), "chris", "auth", "acap/elwood.innosoft.com", false)));

    }

    @Test
    /* LHEX = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "a" | "b" | "c" | "d" | "e" | "f" */
    public void testConvertToHexBytesWithLeftPadding() throws Exception {
        assertEquals("00000001", new String(convertToHexBytesWithLeftPadding(1, 8)));
        assertEquals("0000002", new String(convertToHexBytesWithLeftPadding(2, 7)));
        assertEquals("000a", new String(convertToHexBytesWithLeftPadding(10, 4)));
        assertEquals("abc", new String(convertToHexBytesWithLeftPadding(0xABC, 3)));
    }

    @Test
    public void testCreate3desSubKey() throws Exception {
        byte[] input1 = HexConverter.convertFromHex("FFFFFFFFFFFFFF");
        byte[] output1 = create3desSubKey(input1, 0, 7);
        assertEquals("FEFEFEFEFEFEFEFE".toLowerCase(), HexConverter.convertToHexString(output1));

        byte[] input2 = HexConverter.convertFromHex("d7c920cf2564cec39c570490f7ea");
        byte[] output2 = create3desSubKey(input2, 0, 7);
        assertEquals("D6E54919F22A929D".toLowerCase(), HexConverter.convertToHexString(output2));

        byte[] input3 = HexConverter.convertFromHex("d7c920cf2564cec39c570490f7ea");
        byte[] output3 = create3desSubKey(input3, 7, 7);
        assertEquals("C2CE15E04986DFD5".toLowerCase(), HexConverter.convertToHexString(output3));
    }

    @Test
    public void testComputeHmac() throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        byte[] message = HexConverter.convertFromHex("11223344");
        byte[] kc = HexConverter.convertFromHex("9fdbff3d48c87e74bd89460e2462c73a");
        byte[] output = computeHMAC(kc, 0, mac, message, 0, message.length);
        assertEquals("EF3E40D7B5A64C1DAE6B".toLowerCase(), HexConverter.convertToHexString(output));
    }

    @Test
    public void testIntegerByteOrdered() throws Exception {
        byte[] output0 = new byte[4];
        integerByteOrdered(0x0, output0, 0, 4);
        assertEquals("00000000".toLowerCase(), HexConverter.convertToHexString(output0));

        byte[] output1 = new byte[4];
        integerByteOrdered(0x1, output1, 0, 4);
        assertEquals("00000001".toLowerCase(), HexConverter.convertToHexString(output1));

        byte[] output1234 = new byte[6];
        integerByteOrdered(0x1234, output1234, 1, 4);
        assertEquals("000000123400".toLowerCase(), HexConverter.convertToHexString(output1234));

        byte[] outputFFFFFFFF = new byte[4];
        integerByteOrdered(0xFFFFFFFF, outputFFFFFFFF, 0, 4);
        assertEquals("FFFFFFFF".toLowerCase(), HexConverter.convertToHexString(outputFFFFFFFF));
    }

    @Test
    public void testDecodeByteOrderedInteger() throws Exception {
        byte[] input0 = HexConverter.convertFromHex("00000000");
        assertEquals(0x0, decodeByteOrderedInteger(input0, 0, 4));

        byte[] input1 = HexConverter.convertFromHex("00000001");
        assertEquals(0x1, decodeByteOrderedInteger(input1, 0, 4));

        byte[] input1234 = HexConverter.convertFromHex("000000123400");
        assertEquals(0x1234, decodeByteOrderedInteger(input1234, 1, 4));

        byte[] input1234b = HexConverter.convertFromHex("000000123400");
        assertEquals(0x1234, decodeByteOrderedInteger(input1234b, 3, 2));

        byte[] inputFFFFFFFF = HexConverter.convertFromHex("FFFFFFFF");
        assertEquals(0xFFFFFFFF, decodeByteOrderedInteger(inputFFFFFFFF, 0, 4));
    }

}