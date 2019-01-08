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
import static org.wildfly.security.mechanism.digest.DigestUtil.userRealmPasswordDigest;
import static org.wildfly.security.sasl.digest._private.DigestUtil.H_A1;
import static org.wildfly.security.sasl.digest._private.DigestUtil.computeHMAC;
import static org.wildfly.security.sasl.digest._private.DigestUtil.convertToHexBytesWithLeftPadding;
import static org.wildfly.security.sasl.digest._private.DigestUtil.create3desSubKey;
import static org.wildfly.security.sasl.digest._private.DigestUtil.decodeByteOrderedInteger;
import static org.wildfly.security.sasl.digest._private.DigestUtil.digestResponse;
import static org.wildfly.security.sasl.digest._private.DigestUtil.integerByteOrdered;
import static org.wildfly.security.sasl.digest._private.DigestUtil.messageDigestAlgorithm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

import javax.crypto.Mac;

import org.junit.Before;
import org.junit.Test;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.sasl.util.SaslMechanismInformation;

/**
 * Digest SASL utilities tests
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class DigestUtilTest {

    MessageDigest md;

    @Before
    public void init() throws Exception {
        md = MessageDigest.getInstance(messageDigestAlgorithm(SaslMechanismInformation.Names.DIGEST_MD5));
    }

    @Test
    public void testH_A1() throws Exception {
        assertEquals("a2549853149b0536f01f0b850c643c57", ByteIterator.ofBytes(
                H_A1(md, userRealmPasswordDigest(md, "chris", "elwood.innosoft.com", "secret".toCharArray()),
                "OA6MG9tEQGm2hh".getBytes(StandardCharsets.UTF_8), "OA6MHXh6VqTrRk".getBytes(StandardCharsets.UTF_8), null, StandardCharsets.UTF_8)).hexEncode().drainToString());

        assertEquals("7f94ea5b1eb1b0573cca321e2b517b63", ByteIterator.ofBytes(
                H_A1(md, userRealmPasswordDigest(md, "chris", "elwood.innosoft.com", "secret".toCharArray()),
                "OA9BSXrbuRhWay".getBytes(StandardCharsets.UTF_8), "OA9BSuZWMSpW8m".getBytes(StandardCharsets.UTF_8), "chris", StandardCharsets.UTF_8)).hexEncode().drainToString());

        assertEquals("4e863a809aa7f7cc191be93705967394", ByteIterator.ofBytes(
                H_A1(md, userRealmPasswordDigest(md, "\u0438\u4F60\uD83C\uDCA1", "realm.\u0438\u4F60\uD83C\uDCA1.com", "\u0438\u4F60\uD83C\uDCA1".toCharArray()),
                "sn\u0438\u4F60\uD83C\uDCA1".getBytes(StandardCharsets.UTF_8), "cn\u0438\u4F60\uD83C\uDCA1".getBytes(StandardCharsets.UTF_8), null,
                StandardCharsets.UTF_8)).hexEncode().drainToString());

    }

    @Test
    public void testDigestResponse() throws Exception {

        assertEquals("d388dad90d4bbd760a152321f2143af7", new String(
                digestResponse(md, CodePointIterator.ofString("a2549853149b0536f01f0b850c643c57").hexDecode().drain(),
                "OA6MG9tEQGm2hh".getBytes(StandardCharsets.UTF_8), 1, "OA6MHXh6VqTrRk".getBytes(StandardCharsets.UTF_8), null, "auth", "imap/elwood.innosoft.com", true), StandardCharsets.UTF_8));

        assertEquals("ea40f60335c427b5527b84dbabcdfffd", new String(
                digestResponse(md, CodePointIterator.ofString("a2549853149b0536f01f0b850c643c57").hexDecode().drain(),
                "OA6MG9tEQGm2hh".getBytes(StandardCharsets.UTF_8), 1, "OA6MHXh6VqTrRk".getBytes(StandardCharsets.UTF_8), null, "auth", "imap/elwood.innosoft.com", false), StandardCharsets.UTF_8));

        assertEquals("aa4e81f1c6656350f7bce05d436665de", new String(
                digestResponse(md, CodePointIterator.ofString("7f94ea5b1eb1b0573cca321e2b517b63").hexDecode().drain(),
                "OA9BSXrbuRhWay".getBytes(StandardCharsets.UTF_8), 1, "OA9BSuZWMSpW8m".getBytes(StandardCharsets.UTF_8), "chris", "auth", "acap/elwood.innosoft.com", true), StandardCharsets.UTF_8));

        assertEquals("af3ca83a805d4cfa00675a17315475c4", new String(
                digestResponse(md, CodePointIterator.ofString("7f94ea5b1eb1b0573cca321e2b517b63").hexDecode().drain(),
                "OA9BSXrbuRhWay".getBytes(StandardCharsets.UTF_8), 1, "OA9BSuZWMSpW8m".getBytes(StandardCharsets.UTF_8), "chris", "auth", "acap/elwood.innosoft.com", false), StandardCharsets.UTF_8));

    }

    @Test
    /* LHEX = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "a" | "b" | "c" | "d" | "e" | "f" */
    public void testConvertToHexBytesWithLeftPadding() throws Exception {
        assertEquals("00000001", new String(convertToHexBytesWithLeftPadding(1, 8), StandardCharsets.UTF_8));
        assertEquals("0000002", new String(convertToHexBytesWithLeftPadding(2, 7), StandardCharsets.UTF_8));
        assertEquals("000a", new String(convertToHexBytesWithLeftPadding(10, 4), StandardCharsets.UTF_8));
        assertEquals("abc", new String(convertToHexBytesWithLeftPadding(0xABC, 3), StandardCharsets.UTF_8));
    }

    @Test
    public void testCreate3desSubKey() throws Exception {
        byte[] input1 = CodePointIterator.ofString("FFFFFFFFFFFFFF").hexDecode().drain();
        byte[] output1 = create3desSubKey(input1, 0);
        assertEquals("FEFEFEFEFEFEFEFE".toLowerCase(Locale.ROOT), ByteIterator.ofBytes(output1).hexEncode().drainToString());

        byte[] input2 = CodePointIterator.ofString("d7c920cf2564cec39c570490f7ea").hexDecode().drain();
        byte[] output2 = create3desSubKey(input2, 0);
        assertEquals("D6E54919F22A929D".toLowerCase(Locale.ROOT), ByteIterator.ofBytes(output2).hexEncode().drainToString());

        byte[] input3 = CodePointIterator.ofString("d7c920cf2564cec39c570490f7ea").hexDecode().drain();
        byte[] output3 = create3desSubKey(input3, 7);
        assertEquals("C2CE15E04986DFD5".toLowerCase(Locale.ROOT), ByteIterator.ofBytes(output3).hexEncode().drainToString());
    }

    @Test
    public void testComputeHmac() throws Exception {
        Mac mac = Mac.getInstance("HmacMD5");
        byte[] message = CodePointIterator.ofString("11223344").hexDecode().drain();
        byte[] kc = CodePointIterator.ofString("9fdbff3d48c87e74bd89460e2462c73a").hexDecode().drain();
        byte[] output = computeHMAC(kc, 0, mac, message, 0, message.length);
        assertEquals("EF3E40D7B5A64C1DAE6B".toLowerCase(Locale.ROOT), ByteIterator.ofBytes(output).hexEncode().drainToString());
    }

    @Test
    public void testIntegerByteOrdered() throws Exception {
        byte[] output0 = new byte[4];
        integerByteOrdered(0x0, output0, 0, 4);
        assertEquals("00000000".toLowerCase(Locale.ROOT), ByteIterator.ofBytes(output0).hexEncode().drainToString());

        byte[] output1 = new byte[4];
        integerByteOrdered(0x1, output1, 0, 4);
        assertEquals("00000001".toLowerCase(Locale.ROOT), ByteIterator.ofBytes(output1).hexEncode().drainToString());

        byte[] output1234 = new byte[6];
        integerByteOrdered(0x1234, output1234, 1, 4);
        assertEquals("000000123400".toLowerCase(Locale.ROOT), ByteIterator.ofBytes(output1234).hexEncode().drainToString());

        byte[] outputFFFFFFFF = new byte[4];
        integerByteOrdered(0xFFFFFFFF, outputFFFFFFFF, 0, 4);
        assertEquals("FFFFFFFF".toLowerCase(Locale.ROOT), ByteIterator.ofBytes(outputFFFFFFFF).hexEncode().drainToString());
    }

    @Test
    public void testDecodeByteOrderedInteger() throws Exception {
        byte[] input0 = CodePointIterator.ofString("00000000").hexDecode().drain();
        assertEquals(0x0, decodeByteOrderedInteger(input0, 0, 4));

        byte[] input1 = CodePointIterator.ofString("00000001").hexDecode().drain();
        assertEquals(0x1, decodeByteOrderedInteger(input1, 0, 4));

        byte[] input1234 = CodePointIterator.ofString("000000123400").hexDecode().drain();
        assertEquals(0x1234, decodeByteOrderedInteger(input1234, 1, 4));

        byte[] input1234b = CodePointIterator.ofString("000000123400").hexDecode().drain();
        assertEquals(0x1234, decodeByteOrderedInteger(input1234b, 3, 2));

        byte[] inputFFFFFFFF = CodePointIterator.ofString("FFFFFFFF").hexDecode().drain();
        assertEquals(0xFFFFFFFF, decodeByteOrderedInteger(inputFFFFFFFF, 0, 4));

        byte[] inputFF = CodePointIterator.ofString("000000FF").hexDecode().drain();
        assertEquals(0xFF, decodeByteOrderedInteger(inputFF, 0, 4));

    }

}