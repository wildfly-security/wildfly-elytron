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

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.wildfly.security.sasl.util.StringPrep;
import org.wildfly.security.util.ByteStringBuilder;

/**
 * Tests of org.wildfly.security.sasl.util.StringPrep by RFC 3454
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class StringPrepTest {

    @Test
    public void testEncoding() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("", b, 0);
        Assert.assertArrayEquals(new byte[]{}, b.toArray());
        StringPrep.encode("abc", b, 0);
        Assert.assertArrayEquals(new byte[]{'a', 'b', 'c'}, b.toArray());
    }

    @Test
    public void testEncodingOf1byteChar() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("a", b, 0);
        Assert.assertArrayEquals(new byte[]{(byte) 0x61}, b.toArray());
    }

    @Test
    public void testEncodingOf2bytesChar() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("\u0438", b, 0);
        Assert.assertArrayEquals(new byte[]{(byte) 0xD0, (byte) 0xB8}, b.toArray());
    }

    @Test
    public void testEncodingOf3bytesChar() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("\u4F60", b, 0);
        Assert.assertArrayEquals(new byte[]{(byte) 0xE4, (byte) 0xBD, (byte) 0xA0}, b.toArray());
    }

    @Test
    public void testEncodingOf4bytesChar() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("\uD83C\uDCA1", b, 0); // 0x1F0A1
        Assert.assertArrayEquals(new byte[]{(byte) 0xF0, (byte) 0x9F, (byte) 0x82, (byte) 0xA1}, b.toArray());
    }

    @Test
    public void testEncodingOfMaxCodepointChar() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("\uDBFF\uDFFF", b, 0); // 0x10FFFF
        Assert.assertArrayEquals(new byte[]{(byte) 0xF4, (byte) 0x8F, (byte) 0xBF, (byte) 0xBF}, b.toArray());
    }

    @Test
    public void testEncodingStringWithSurrogates() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("a\uD83C\uDCA1b", b, 0);
        Assert.assertArrayEquals(new byte[]{(byte) 0x61, (byte) 0xF0, (byte) 0x9F, (byte) 0x82, (byte) 0xA1, (byte) 0x62}, b.toArray());
    }

    @Test
    public void testEncodingOfHighSurrogateWithoutLow() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        try {
            StringPrep.encode("\uD83C", b, 0); // only high surrogate
            throw new Exception("Not throwed Invalid surrogate pair");
        } catch (IllegalArgumentException e) {}
    }

    @Test
    public void testEncodingOfLowSurrogateWithoutHigh() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        try {
            StringPrep.encode("\uDC00", b, 0); // only low surrogate
            throw new Exception("Not throwed Invalid surrogate pair");
        } catch (IllegalArgumentException e) {}
    }

    @Test
    public void testEncodingOfTwoHighSurrogates() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        try {
            StringPrep.encode("\uD83C\uD83C", b, 0); // two high surrogates
            throw new Exception("Not throwed Invalid surrogate pair");
        } catch (IllegalArgumentException e) {}
    }

    @Test
    public void testEncodingOfWrongOrderedSurrogates() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        try {
            StringPrep.encode("\uDCA1\uD83C", b, 0); // wrong order of surrogates
            throw new Exception("Not throwed Invalid surrogate pair");
        } catch (IllegalArgumentException e) {}
    }

    @Test
    public void testRightString() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("\u05BE", b, 0);
        Assert.assertArrayEquals(new byte[]{(byte) 0xD6, (byte) 0xBE}, b.toArray());
    }

    @Test
    public void testRightStringWithNeutralChars() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("\u05BE - \uFBA8", b, 0);
        Assert.assertArrayEquals(new byte[]{(byte) 0xD6, (byte) 0xBE, (byte) 0x20, (byte) 0x2D, (byte) 0x20, (byte) 0xEF, (byte) 0xAE, (byte) 0xA8}, b.toArray()); // D6 BE 20 2D 20 EF AE A8
    }

    /**
     * RFC 3454: If a string contains any RandALCat character, the string MUST NOT contain any LCat character.
     */
    @Test
    public void testLeftInRightString() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        try {
            StringPrep.encode("\u05BE\uFBA8a\u05BE\uFBA8", b, 0); // <right><right><left><right><right>
            throw new Exception("Not throwed directionality exception");
        } catch (IllegalArgumentException e) {}
    }

    /**
     * RFC 3454: requirement 3 prohibits strings such as <U+0627><U+0031>
     */
    @Test
    public void testRightWithoutTrailing() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        try {
            StringPrep.encode("\u0627\u0031", b, 0); // <right><neutral>
            throw new Exception("Not throwed directionality exception");
        } catch (IllegalArgumentException e) {}
    }

    /**
     * RFC 3454: requirement 3 ... allows strings such as <U+0627><U+0031><U+0628>
     */
    @Test
    public void testRightWithTrailing() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("\u0627\u0031\u0628", b, 0); // <right><neutral><right>
    }

    @Test
    public void testRightWithoutLeading() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        try {
            StringPrep.encode("\u0031\u0627", b, 0); // <neutral><right>
            throw new Exception("Not throwed directionality exception");
        } catch (IllegalArgumentException e) {}
    }

    @Test
    public void testRightWithoutLeadingAndTrailing() throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        try {
            StringPrep.encode("\u0031\u0627\u0032", b, 0); // <neutral><right><neutral>
            throw new Exception("Not throwed directionality exception");
        } catch (IllegalArgumentException e) {}
    }

    /**
     * RFC 3454 3.1 Commonly mapped to nothing / Table B.1
     */
    @Test
    public void testMappingToNothing() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("a\u00AD\u1806\u200B\u2060\uFEFF\u034F\u180B\u180C\u180D\u200C\u200D\uFE00\uFE01\uFE02\uFE03\uFE04\uFE05\uFE06\uFE07\uFE08\uFE09\uFE0A\uFE0B\uFE0C\uFE0D\uFE0E\uFE0Fa", b, StringPrep.MAP_TO_NOTHING);
        Assert.assertArrayEquals(new byte[]{'a', 'a'}, b.toArray());
    }

    /**
     * RFC 3454 5.1 Space characters / Table C.1.2
     */
    @Test
    public void testMappingNonAsciiSpaceToSpace() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("a\u00A0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u200B\u202F\u205F\u3000a", b, StringPrep.MAP_TO_SPACE);
        Assert.assertArrayEquals(new byte[]{'a', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 'a'}, b.toArray());
    }

    /**
     * RFC 5802 5.1. SCRAM Attributes - characters ',' or '=' in usernames
     */
    @Test
    public void testMappingScramLoginChars() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("a,b=c", b, StringPrep.MAP_SCRAM_LOGIN_CHARS);
        Assert.assertArrayEquals(new byte[]{'a', '=', '2', 'C', 'b', '=', '3', 'D', 'c'}, b.toArray());
    }

    /**
     * RFC 3454 4. Normalization (sanity check)
     */
    @Test
    public void testNFKCSanity() {
        assertEquals("a\u00C5b", Normalizer.normalize("a\u0041\u030Ab", Normalizer.Form.NFKC));
    }

    /**
     * RFC 3454 4. Normalization
     */
    @Test
    public void testNFKC() {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode("a\u0041\u030Ab", b, StringPrep.NORMALIZE_KC);
        assertEquals("a\u00C5b", new String(b.toArray(), StandardCharsets.UTF_8));
    }

    /**
     * Mapping for case-folding used together with NFKC / Table B.2
     */
    @Test
    @Ignore("Case folding is not implemented yet, test mentioned in ELY-47")
    public void testCaseFoldingWithNFKC() {
        ByteStringBuilder b = new ByteStringBuilder();

        String before = "\u0041\u0042\u0043\u0044\u0045\u0046\u0047\u0048\u0049\u004A\u004B\u004C\u004D\u004E\u004F\u0050\u0051\u0052\u0053\u0054\u0055\u0056\u0057\u0058\u0059\u005A\u00B5\u00C0\u00C1\u00C2\u00C3\u00C4\u00C5\u00C6\u00C7\u00C8\u00C9\u00CA\u00CB\u00CC\u00CD\u00CE\u00CF\u00D0\u00D1\u00D2\u00D3\u00D4\u00D5\u00D6\u00D8\u00D9\u00DA\u00DB\u00DC\u00DD\u00DE\u00DF\u0100\u0102\u0104\u0106\u0108\u010A\u010C\u010E\u0110\u0112\u0114\u0116\u0118\u011A\u011C\u011E\u0120\u0122\u0124\u0126\u0128\u012A\u012C\u012E\u0130\u0132\u0134\u0136\u0139\u013B\u013D\u013F\u0141\u0143\u0145\u0147\u0149\u014A\u014C\u014E\u0150\u0152\u0154\u0156\u0158\u015A\u015C\u015E\u0160\u0162\u0164\u0166\u0168\u016A\u016C\u016E\u0170\u0172\u0174\u0176\u0178\u0179\u017B\u017D\u017F\u0181\u0182\u0184\u0186\u0187\u0189\u018A\u018B\u018E\u018F\u0190\u0191\u0193\u0194\u0196\u0197\u0198\u019C\u019D\u019F\u01A0\u01A2\u01A4\u01A6\u01A7\u01A9\u01AC\u01AE\u01AF\u01B1\u01B2\u01B3\u01B5\u01B7\u01B8\u01BC\u01C4\u01C5\u01C7\u01C8\u01CA\u01CB\u01CD\u01CF\u01D1\u01D3\u01D5\u01D7\u01D9\u01DB\u01DE\u01E0\u01E2\u01E4\u01E6\u01E8\u01EA\u01EC\u01EE\u01F0\u01F1\u01F2\u01F4\u01F6\u01F7\u01F8\u01FA\u01FC\u01FE\u0200\u0202\u0204\u0206\u0208\u020A\u020C\u020E\u0210\u0212\u0214\u0216\u0218\u021A\u021C\u021E\u0220\u0222\u0224\u0226\u0228\u022A\u022C\u022E\u0230\u0232\u0345\u037A\u0386\u0388\u0389\u038A\u038C\u038E\u038F\u0390\u0391\u0392\u0393\u0394\u0395\u0396\u0397\u0398\u0399\u039A\u039B\u039C\u039D\u039E\u039F\u03A0\u03A1\u03A3\u03A4\u03A5\u03A6\u03A7\u03A8\u03A9\u03AA\u03AB\u03B0\u03C2\u03D0\u03D1\u03D2\u03D3\u03D4\u03D5\u03D6\u03D8\u03DA\u03DC\u03DE\u03E0\u03E2\u03E4\u03E6\u03E8\u03EA\u03EC\u03EE\u03F0\u03F1\u03F2\u03F4\u03F5\u0400\u0401\u0402\u0403\u0404\u0405\u0406\u0407\u0408\u0409\u040A\u040B\u040C\u040D\u040E\u040F\u0410\u0411\u0412\u0413\u0414\u0415\u0416\u0417\u0418\u0419\u041A\u041B\u041C\u041D\u041E\u041F\u0420\u0421\u0422\u0423\u0424\u0425\u0426\u0427\u0428\u0429\u042A\u042B\u042C\u042D\u042E\u042F\u0460\u0462\u0464\u0466\u0468\u046A\u046C\u046E\u0470\u0472\u0474\u0476\u0478\u047A\u047C\u047E\u0480\u048A\u048C\u048E\u0490\u0492\u0494\u0496\u0498\u049A\u049C\u049E\u04A0\u04A2\u04A4\u04A6\u04A8\u04AA\u04AC\u04AE\u04B0\u04B2\u04B4\u04B6\u04B8\u04BA\u04BC\u04BE\u04C1\u04C3\u04C5\u04C7\u04C9\u04CB\u04CD\u04D0\u04D2\u04D4\u04D6\u04D8\u04DA\u04DC\u04DE\u04E0\u04E2\u04E4\u04E6\u04E8\u04EA\u04EC\u04EE\u04F0\u04F2\u04F4\u04F8\u0500\u0502\u0504\u0506\u0508\u050A\u050C\u050E\u0531\u0532\u0533\u0534\u0535\u0536\u0537\u0538\u0539\u053A\u053B\u053C\u053D\u053E\u053F\u0540\u0541\u0542\u0543\u0544\u0545\u0546\u0547\u0548\u0549\u054A\u054B\u054C\u054D\u054E\u054F\u0550\u0551\u0552\u0553\u0554\u0555\u0556\u0587\u1E00\u1E02\u1E04\u1E06\u1E08\u1E0A\u1E0C\u1E0E\u1E10\u1E12\u1E14\u1E16\u1E18\u1E1A\u1E1C\u1E1E\u1E20\u1E22\u1E24\u1E26\u1E28\u1E2A\u1E2C\u1E2E\u1E30\u1E32\u1E34\u1E36\u1E38\u1E3A\u1E3C\u1E3E\u1E40\u1E42\u1E44\u1E46\u1E48\u1E4A\u1E4C\u1E4E\u1E50\u1E52\u1E54\u1E56\u1E58\u1E5A\u1E5C\u1E5E\u1E60\u1E62\u1E64\u1E66\u1E68\u1E6A\u1E6C\u1E6E\u1E70\u1E72\u1E74\u1E76\u1E78\u1E7A\u1E7C\u1E7E\u1E80\u1E82\u1E84\u1E86\u1E88\u1E8A\u1E8C\u1E8E\u1E90\u1E92\u1E94\u1E96\u1E97\u1E98\u1E99\u1E9A\u1E9B\u1EA0\u1EA2\u1EA4\u1EA6\u1EA8\u1EAA\u1EAC\u1EAE\u1EB0\u1EB2\u1EB4\u1EB6\u1EB8\u1EBA\u1EBC\u1EBE\u1EC0\u1EC2\u1EC4\u1EC6\u1EC8\u1ECA\u1ECC\u1ECE\u1ED0\u1ED2\u1ED4\u1ED6\u1ED8\u1EDA\u1EDC\u1EDE\u1EE0\u1EE2\u1EE4\u1EE6\u1EE8\u1EEA\u1EEC\u1EEE\u1EF0\u1EF2\u1EF4\u1EF6\u1EF8\u1F08\u1F09\u1F0A\u1F0B\u1F0C\u1F0D\u1F0E\u1F0F\u1F18\u1F19\u1F1A\u1F1B\u1F1C\u1F1D\u1F28\u1F29\u1F2A\u1F2B\u1F2C\u1F2D\u1F2E\u1F2F\u1F38\u1F39\u1F3A\u1F3B\u1F3C\u1F3D\u1F3E\u1F3F\u1F48\u1F49\u1F4A\u1F4B\u1F4C\u1F4D\u1F50\u1F52\u1F54\u1F56\u1F59\u1F5B\u1F5D\u1F5F\u1F68\u1F69\u1F6A\u1F6B\u1F6C\u1F6D\u1F6E\u1F6F\u1F80\u1F81\u1F82\u1F83\u1F84\u1F85\u1F86\u1F87\u1F88\u1F89\u1F8A\u1F8B\u1F8C\u1F8D\u1F8E\u1F8F\u1F90\u1F91\u1F92\u1F93\u1F94\u1F95\u1F96\u1F97\u1F98\u1F99\u1F9A\u1F9B\u1F9C\u1F9D\u1F9E\u1F9F\u1FA0\u1FA1\u1FA2\u1FA3\u1FA4\u1FA5\u1FA6\u1FA7\u1FA8\u1FA9\u1FAA\u1FAB\u1FAC\u1FAD\u1FAE\u1FAF\u1FB2\u1FB3\u1FB4\u1FB6\u1FB7\u1FB8\u1FB9\u1FBA\u1FBB\u1FBC\u1FBE\u1FC2\u1FC3\u1FC4\u1FC6\u1FC7\u1FC8\u1FC9\u1FCA\u1FCB\u1FCC\u1FD2\u1FD3\u1FD6\u1FD7\u1FD8\u1FD9\u1FDA\u1FDB\u1FE2\u1FE3\u1FE4\u1FE6\u1FE7\u1FE8\u1FE9\u1FEA\u1FEB\u1FEC\u1FF2\u1FF3\u1FF4\u1FF6\u1FF7\u1FF8\u1FF9\u1FFA\u1FFB\u1FFC\u20A8\u2102\u2103\u2107\u2109\u210B\u210C\u210D\u2110\u2111\u2112\u2115\u2116\u2119\u211A\u211B\u211C\u211D\u2120\u2121\u2122\u2124\u2126\u2128\u212A\u212B\u212C\u212D\u2130\u2131\u2133\u213E\u213F\u2145\u2160\u2161\u2162\u2163\u2164\u2165\u2166\u2167\u2168\u2169\u216A\u216B\u216C\u216D\u216E\u216F\u24B6\u24B7\u24B8\u24B9\u24BA\u24BB\u24BC\u24BD\u24BE\u24BF\u24C0\u24C1\u24C2\u24C3\u24C4\u24C5\u24C6\u24C7\u24C8\u24C9\u24CA\u24CB\u24CC\u24CD\u24CE\u24CF\u3371\u3373\u3375\u3380\u3381\u3382\u3383\u3384\u3385\u3386\u3387\u338A\u338B\u338C\u3390\u3391\u3392\u3393\u3394\u33A9\u33AA\u33AB\u33AC\u33B4\u33B5\u33B6\u33B7\u33B8\u33B9\u33BA\u33BB\u33BC\u33BD\u33BE\u33BF\u33C0\u33C1\u33C3\u33C6\u33C7\u33C8\u33C9\u33CB\u33CD\u33CE\u33D7\u33D9\u33DA\u33DC\u33DD\uFB00\uFB01\uFB02\uFB03\uFB04\uFB05\uFB06\uFB13\uFB14\uFB15\uFB16\uFB17\uFF21\uFF22\uFF23\uFF24\uFF25\uFF26\uFF27\uFF28\uFF29\uFF2A\uFF2B\uFF2C\uFF2D\uFF2E\uFF2F\uFF30\uFF31\uFF32\uFF33\uFF34\uFF35\uFF36\uFF37\uFF38\uFF39\uFF3A\u10400\u10401\u10402\u10403\u10404\u10405\u10406\u10407\u10408\u10409\u1040A\u1040B\u1040C\u1040D\u1040E\u1040F\u10410\u10411\u10412\u10413\u10414\u10415\u10416\u10417\u10418\u10419\u1041A\u1041B\u1041C\u1041D\u1041E\u1041F\u10420\u10421\u10422\u10423\u10424\u10425\u1D400\u1D401\u1D402\u1D403\u1D404\u1D405\u1D406\u1D407\u1D408\u1D409\u1D40A\u1D40B\u1D40C\u1D40D\u1D40E\u1D40F\u1D410\u1D411\u1D412\u1D413\u1D414\u1D415\u1D416\u1D417\u1D418\u1D419\u1D434\u1D435\u1D436\u1D437\u1D438\u1D439\u1D43A\u1D43B\u1D43C\u1D43D\u1D43E\u1D43F\u1D440\u1D441\u1D442\u1D443\u1D444\u1D445\u1D446\u1D447\u1D448\u1D449\u1D44A\u1D44B\u1D44C\u1D44D\u1D468\u1D469\u1D46A\u1D46B\u1D46C\u1D46D\u1D46E\u1D46F\u1D470\u1D471\u1D472\u1D473\u1D474\u1D475\u1D476\u1D477\u1D478\u1D479\u1D47A\u1D47B\u1D47C\u1D47D\u1D47E\u1D47F\u1D480\u1D481\u1D49C\u1D49E\u1D49F\u1D4A2\u1D4A5\u1D4A6\u1D4A9\u1D4AA\u1D4AB\u1D4AC\u1D4AE\u1D4AF\u1D4B0\u1D4B1\u1D4B2\u1D4B3\u1D4B4\u1D4B5\u1D4D0\u1D4D1\u1D4D2\u1D4D3\u1D4D4\u1D4D5\u1D4D6\u1D4D7\u1D4D8\u1D4D9\u1D4DA\u1D4DB\u1D4DC\u1D4DD\u1D4DE\u1D4DF\u1D4E0\u1D4E1\u1D4E2\u1D4E3\u1D4E4\u1D4E5\u1D4E6\u1D4E7\u1D4E8\u1D4E9\u1D504\u1D505\u1D507\u1D508\u1D509\u1D50A\u1D50D\u1D50E\u1D50F\u1D510\u1D511\u1D512\u1D513\u1D514\u1D516\u1D517\u1D518\u1D519\u1D51A\u1D51B\u1D51C\u1D538\u1D539\u1D53B\u1D53C\u1D53D\u1D53E\u1D540\u1D541\u1D542\u1D543\u1D544\u1D546\u1D54A\u1D54B\u1D54C\u1D54D\u1D54E\u1D54F\u1D550\u1D56C\u1D56D\u1D56E\u1D56F\u1D570\u1D571\u1D572\u1D573\u1D574\u1D575\u1D576\u1D577\u1D578\u1D579\u1D57A\u1D57B\u1D57C\u1D57D\u1D57E\u1D57F\u1D580\u1D581\u1D582\u1D583\u1D584\u1D585\u1D5A0\u1D5A1\u1D5A2\u1D5A3\u1D5A4\u1D5A5\u1D5A6\u1D5A7\u1D5A8\u1D5A9\u1D5AA\u1D5AB\u1D5AC\u1D5AD\u1D5AE\u1D5AF\u1D5B0\u1D5B1\u1D5B2\u1D5B3\u1D5B4\u1D5B5\u1D5B6\u1D5B7\u1D5B8\u1D5B9\u1D5D4\u1D5D5\u1D5D6\u1D5D7\u1D5D8\u1D5D9\u1D5DA\u1D5DB\u1D5DC\u1D5DD\u1D5DE\u1D5DF\u1D5E0\u1D5E1\u1D5E2\u1D5E3\u1D5E4\u1D5E5\u1D5E6\u1D5E7\u1D5E8\u1D5E9\u1D5EA\u1D5EB\u1D5EC\u1D5ED\u1D608\u1D609\u1D60A\u1D60B\u1D60C\u1D60D\u1D60E\u1D60F\u1D610\u1D611\u1D612\u1D613\u1D614\u1D615\u1D616\u1D617\u1D618\u1D619\u1D61A\u1D61B\u1D61C\u1D61D\u1D61E\u1D61F\u1D620\u1D621\u1D63C\u1D63D\u1D63E\u1D63F\u1D640\u1D641\u1D642\u1D643\u1D644\u1D645\u1D646\u1D647\u1D648\u1D649\u1D64A\u1D64B\u1D64C\u1D64D\u1D64E\u1D64F\u1D650\u1D651\u1D652\u1D653\u1D654\u1D655\u1D670\u1D671\u1D672\u1D673\u1D674\u1D675\u1D676\u1D677\u1D678\u1D679\u1D67A\u1D67B\u1D67C\u1D67D\u1D67E\u1D67F\u1D680\u1D681\u1D682\u1D683\u1D684\u1D685\u1D686\u1D687\u1D688\u1D689\u1D6A8\u1D6A9\u1D6AA\u1D6AB\u1D6AC\u1D6AD\u1D6AE\u1D6AF\u1D6B0\u1D6B1\u1D6B2\u1D6B3\u1D6B4\u1D6B5\u1D6B6\u1D6B7\u1D6B8\u1D6B9\u1D6BA\u1D6BB\u1D6BC\u1D6BD\u1D6BE\u1D6BF\u1D6C0\u1D6D3\u1D6E2\u1D6E3\u1D6E4\u1D6E5\u1D6E6\u1D6E7\u1D6E8\u1D6E9\u1D6EA\u1D6EB\u1D6EC\u1D6ED\u1D6EE\u1D6EF\u1D6F0\u1D6F1\u1D6F2\u1D6F3\u1D6F4\u1D6F5\u1D6F6\u1D6F7\u1D6F8\u1D6F9\u1D6FA\u1D70D\u1D71C\u1D71D\u1D71E\u1D71F\u1D720\u1D721\u1D722\u1D723\u1D724\u1D725\u1D726\u1D727\u1D728\u1D729\u1D72A\u1D72B\u1D72C\u1D72D\u1D72E\u1D72F\u1D730\u1D731\u1D732\u1D733\u1D734\u1D747\u1D756\u1D757\u1D758\u1D759\u1D75A\u1D75B\u1D75C\u1D75D\u1D75E\u1D75F\u1D760\u1D761\u1D762\u1D763\u1D764\u1D765\u1D766\u1D767\u1D768\u1D769\u1D76A\u1D76B\u1D76C\u1D76D\u1D76E\u1D781\u1D790\u1D791\u1D792\u1D793\u1D794\u1D795\u1D796\u1D797\u1D798\u1D799\u1D79A\u1D79B\u1D79C\u1D79D\u1D79E\u1D79F\u1D7A0\u1D7A1\u1D7A2\u1D7A3\u1D7A4\u1D7A5\u1D7A6\u1D7A7\u1D7A8\u1D7BB";
        String after = "\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u03BC\u00E0\u00E1\u00E2\u00E3\u00E4\u00E5\u00E6\u00E7\u00E8\u00E9\u00EA\u00EB\u00EC\u00ED\u00EE\u00EF\u00F0\u00F1\u00F2\u00F3\u00F4\u00F5\u00F6\u00F8\u00F9\u00FA\u00FB\u00FC\u00FD\u00FE\u00730073\u0101\u0103\u0105\u0107\u0109\u010B\u010D\u010F\u0111\u0113\u0115\u0117\u0119\u011B\u011D\u011F\u0121\u0123\u0125\u0127\u0129\u012B\u012D\u012F\u00690307\u0133\u0135\u0137\u013A\u013C\u013E\u0140\u0142\u0144\u0146\u0148\u02BC006E\u014B\u014D\u014F\u0151\u0153\u0155\u0157\u0159\u015B\u015D\u015F\u0161\u0163\u0165\u0167\u0169\u016B\u016D\u016F\u0171\u0173\u0175\u0177\u00FF\u017A\u017C\u017E\u0073\u0253\u0183\u0185\u0254\u0188\u0256\u0257\u018C\u01DD\u0259\u025B\u0192\u0260\u0263\u0269\u0268\u0199\u026F\u0272\u0275\u01A1\u01A3\u01A5\u0280\u01A8\u0283\u01AD\u0288\u01B0\u028A\u028B\u01B4\u01B6\u0292\u01B9\u01BD\u01C6\u01C6\u01C9\u01C9\u01CC\u01CC\u01CE\u01D0\u01D2\u01D4\u01D6\u01D8\u01DA\u01DC\u01DF\u01E1\u01E3\u01E5\u01E7\u01E9\u01EB\u01ED\u01EF\u006A030C\u01F3\u01F3\u01F5\u0195\u01BF\u01F9\u01FB\u01FD\u01FF\u0201\u0203\u0205\u0207\u0209\u020B\u020D\u020F\u0211\u0213\u0215\u0217\u0219\u021B\u021D\u021F\u019E\u0223\u0225\u0227\u0229\u022B\u022D\u022F\u0231\u0233\u03B9\u002003B9\u03AC\u03AD\u03AE\u03AF\u03CC\u03CD\u03CE\u03B903080301\u03B1\u03B2\u03B3\u03B4\u03B5\u03B6\u03B7\u03B8\u03B9\u03BA\u03BB\u03BC\u03BD\u03BE\u03BF\u03C0\u03C1\u03C3\u03C4\u03C5\u03C6\u03C7\u03C8\u03C9\u03CA\u03CB\u03C503080301\u03C3\u03B2\u03B8\u03C5\u03CD\u03CB\u03C6\u03C0\u03D9\u03DB\u03DD\u03DF\u03E1\u03E3\u03E5\u03E7\u03E9\u03EB\u03ED\u03EF\u03BA\u03C1\u03C3\u03B8\u03B5\u0450\u0451\u0452\u0453\u0454\u0455\u0456\u0457\u0458\u0459\u045A\u045B\u045C\u045D\u045E\u045F\u0430\u0431\u0432\u0433\u0434\u0435\u0436\u0437\u0438\u0439\u043A\u043B\u043C\u043D\u043E\u043F\u0440\u0441\u0442\u0443\u0444\u0445\u0446\u0447\u0448\u0449\u044A\u044B\u044C\u044D\u044E\u044F\u0461\u0463\u0465\u0467\u0469\u046B\u046D\u046F\u0471\u0473\u0475\u0477\u0479\u047B\u047D\u047F\u0481\u048B\u048D\u048F\u0491\u0493\u0495\u0497\u0499\u049B\u049D\u049F\u04A1\u04A3\u04A5\u04A7\u04A9\u04AB\u04AD\u04AF\u04B1\u04B3\u04B5\u04B7\u04B9\u04BB\u04BD\u04BF\u04C2\u04C4\u04C6\u04C8\u04CA\u04CC\u04CE\u04D1\u04D3\u04D5\u04D7\u04D9\u04DB\u04DD\u04DF\u04E1\u04E3\u04E5\u04E7\u04E9\u04EB\u04ED\u04EF\u04F1\u04F3\u04F5\u04F9\u0501\u0503\u0505\u0507\u0509\u050B\u050D\u050F\u0561\u0562\u0563\u0564\u0565\u0566\u0567\u0568\u0569\u056A\u056B\u056C\u056D\u056E\u056F\u0570\u0571\u0572\u0573\u0574\u0575\u0576\u0577\u0578\u0579\u057A\u057B\u057C\u057D\u057E\u057F\u0580\u0581\u0582\u0583\u0584\u0585\u0586\u05650582\u1E01\u1E03\u1E05\u1E07\u1E09\u1E0B\u1E0D\u1E0F\u1E11\u1E13\u1E15\u1E17\u1E19\u1E1B\u1E1D\u1E1F\u1E21\u1E23\u1E25\u1E27\u1E29\u1E2B\u1E2D\u1E2F\u1E31\u1E33\u1E35\u1E37\u1E39\u1E3B\u1E3D\u1E3F\u1E41\u1E43\u1E45\u1E47\u1E49\u1E4B\u1E4D\u1E4F\u1E51\u1E53\u1E55\u1E57\u1E59\u1E5B\u1E5D\u1E5F\u1E61\u1E63\u1E65\u1E67\u1E69\u1E6B\u1E6D\u1E6F\u1E71\u1E73\u1E75\u1E77\u1E79\u1E7B\u1E7D\u1E7F\u1E81\u1E83\u1E85\u1E87\u1E89\u1E8B\u1E8D\u1E8F\u1E91\u1E93\u1E95\u00680331\u00740308\u0077030A\u0079030A\u006102BE\u1E61\u1EA1\u1EA3\u1EA5\u1EA7\u1EA9\u1EAB\u1EAD\u1EAF\u1EB1\u1EB3\u1EB5\u1EB7\u1EB9\u1EBB\u1EBD\u1EBF\u1EC1\u1EC3\u1EC5\u1EC7\u1EC9\u1ECB\u1ECD\u1ECF\u1ED1\u1ED3\u1ED5\u1ED7\u1ED9\u1EDB\u1EDD\u1EDF\u1EE1\u1EE3\u1EE5\u1EE7\u1EE9\u1EEB\u1EED\u1EEF\u1EF1\u1EF3\u1EF5\u1EF7\u1EF9\u1F00\u1F01\u1F02\u1F03\u1F04\u1F05\u1F06\u1F07\u1F10\u1F11\u1F12\u1F13\u1F14\u1F15\u1F20\u1F21\u1F22\u1F23\u1F24\u1F25\u1F26\u1F27\u1F30\u1F31\u1F32\u1F33\u1F34\u1F35\u1F36\u1F37\u1F40\u1F41\u1F42\u1F43\u1F44\u1F45\u03C50313\u03C503130300\u03C503130301\u03C503130342\u1F51\u1F53\u1F55\u1F57\u1F60\u1F61\u1F62\u1F63\u1F64\u1F65\u1F66\u1F67\u1F0003B9\u1F0103B9\u1F0203B9\u1F0303B9\u1F0403B9\u1F0503B9\u1F0603B9\u1F0703B9\u1F0003B9\u1F0103B9\u1F0203B9\u1F0303B9\u1F0403B9\u1F0503B9\u1F0603B9\u1F0703B9\u1F2003B9\u1F2103B9\u1F2203B9\u1F2303B9\u1F2403B9\u1F2503B9\u1F2603B9\u1F2703B9\u1F2003B9\u1F2103B9\u1F2203B9\u1F2303B9\u1F2403B9\u1F2503B9\u1F2603B9\u1F2703B9\u1F6003B9\u1F6103B9\u1F6203B9\u1F6303B9\u1F6403B9\u1F6503B9\u1F6603B9\u1F6703B9\u1F6003B9\u1F6103B9\u1F6203B9\u1F6303B9\u1F6403B9\u1F6503B9\u1F6603B9\u1F6703B9\u1F7003B9\u03B103B9\u03AC03B9\u03B10342\u03B1034203B9\u1FB0\u1FB1\u1F70\u1F71\u03B103B9\u03B9\u1F7403B9\u03B703B9\u03AE03B9\u03B70342\u03B7034203B9\u1F72\u1F73\u1F74\u1F75\u03B703B9\u03B903080300\u03B903080301\u03B90342\u03B903080342\u1FD0\u1FD1\u1F76\u1F77\u03C503080300\u03C503080301\u03C10313\u03C50342\u03C503080342\u1FE0\u1FE1\u1F7A\u1F7B\u1FE5\u1F7C03B9\u03C903B9\u03CE03B9\u03C90342\u03C9034203B9\u1F78\u1F79\u1F7C\u1F7D\u03C903B9\u00720073\u0063\u00B00063\u025B\u00B00066\u0068\u0068\u0068\u0069\u0069\u006C\u006E\u006E006F\u0070\u0071\u0072\u0072\u0072\u0073006D\u00740065006C\u0074006D\u007A\u03C9\u007A\u006B\u00E5\u0062\u0063\u0065\u0066\u006D\u03B3\u03C0\u0064\u2170\u2171\u2172\u2173\u2174\u2175\u2176\u2177\u2178\u2179\u217A\u217B\u217C\u217D\u217E\u217F\u24D0\u24D1\u24D2\u24D3\u24D4\u24D5\u24D6\u24D7\u24D8\u24D9\u24DA\u24DB\u24DC\u24DD\u24DE\u24DF\u24E0\u24E1\u24E2\u24E3\u24E4\u24E5\u24E6\u24E7\u24E8\u24E9\u006800700061\u00610075\u006F0076\u00700061\u006E0061\u03BC0061\u006D0061\u006B0061\u006B0062\u006D0062\u00670062\u00700066\u006E0066\u03BC0066\u0068007A\u006B0068007A\u006D0068007A\u00670068007A\u00740068007A\u00700061\u006B00700061\u006D00700061\u006700700061\u00700076\u006E0076\u03BC0076\u006D0076\u006B0076\u006D0076\u00700077\u006E0077\u03BC0077\u006D0077\u006B0077\u006D0077\u006B03C9\u006D03C9\u00620071\u00632215006B0067\u0063006F002E\u00640062\u00670079\u00680070\u006B006B\u006B006D\u00700068\u00700070006D\u00700072\u00730076\u00770062\u00660066\u00660069\u0066006C\u006600660069\u00660066006C\u00730074\u00730074\u05740576\u05740565\u0574056B\u057E0576\u0574056D\uFF41\uFF42\uFF43\uFF44\uFF45\uFF46\uFF47\uFF48\uFF49\uFF4A\uFF4B\uFF4C\uFF4D\uFF4E\uFF4F\uFF50\uFF51\uFF52\uFF53\uFF54\uFF55\uFF56\uFF57\uFF58\uFF59\uFF5A\u10428\u10429\u1042A\u1042B\u1042C\u1042D\u1042E\u1042F\u10430\u10431\u10432\u10433\u10434\u10435\u10436\u10437\u10438\u10439\u1043A\u1043B\u1043C\u1043D\u1043E\u1043F\u10440\u10441\u10442\u10443\u10444\u10445\u10446\u10447\u10448\u10449\u1044A\u1044B\u1044C\u1044D\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u0061\u0063\u0064\u0067\u006A\u006B\u006E\u006F\u0070\u0071\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u0061\u0062\u0064\u0065\u0066\u0067\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u0061\u0062\u0064\u0065\u0066\u0067\u0069\u006A\u006B\u006C\u006D\u006F\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u0061\u0062\u0063\u0064\u0065\u0066\u0067\u0068\u0069\u006A\u006B\u006C\u006D\u006E\u006F\u0070\u0071\u0072\u0073\u0074\u0075\u0076\u0077\u0078\u0079\u007A\u03B1\u03B2\u03B3\u03B4\u03B5\u03B6\u03B7\u03B8\u03B9\u03BA\u03BB\u03BC\u03BD\u03BE\u03BF\u03C0\u03C1\u03B8\u03C3\u03C4\u03C5\u03C6\u03C7\u03C8\u03C9\u03C3\u03B1\u03B2\u03B3\u03B4\u03B5\u03B6\u03B7\u03B8\u03B9\u03BA\u03BB\u03BC\u03BD\u03BE\u03BF\u03C0\u03C1\u03B8\u03C3\u03C4\u03C5\u03C6\u03C7\u03C8\u03C9\u03C3\u03B1\u03B2\u03B3\u03B4\u03B5\u03B6\u03B7\u03B8\u03B9\u03BA\u03BB\u03BC\u03BD\u03BE\u03BF\u03C0\u03C1\u03B8\u03C3\u03C4\u03C5\u03C6\u03C7\u03C8\u03C9\u03C3\u03B1\u03B2\u03B3\u03B4\u03B5\u03B6\u03B7\u03B8\u03B9\u03BA\u03BB\u03BC\u03BD\u03BE\u03BF\u03C0\u03C1\u03B8\u03C3\u03C4\u03C5\u03C6\u03C7\u03C8\u03C9\u03C3\u03B1\u03B2\u03B3\u03B4\u03B5\u03B6\u03B7\u03B8\u03B9\u03BA\u03BB\u03BC\u03BD\u03BE\u03BF\u03C0\u03C1\u03B8\u03C3\u03C4\u03C5\u03C6\u03C7\u03C8\u03C9\u03C3";

        StringPrep.encode(before, b, StringPrep.NORMALIZE_KC);
        assertEquals(after, new String(b.toArray(), StandardCharsets.UTF_8));
    }

    @Test
    public void testForbidNonAsciiSpaces() throws Exception {
        testAllowChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x0000, 0x009F);
        testForbidChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x00A0);
        testAllowChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x00A1, 0x167F);
        testForbidChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x1680);
        testAllowChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x1681, 0x1FFF);
        testForbidChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x2000, 0x200B);
        testAllowChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x200C, 0x202E);
        testForbidChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x202F);
        testAllowChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x2030, 0x205E);
        testForbidChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x205F);
        testAllowChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x2060, 0x2FFF);
        testForbidChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x3000);
        testAllowChars(StringPrep.FORBID_NON_ASCII_SPACES, 0x3001, 0xD7FF);
        testForbidChars(StringPrep.FORBID_NON_ASCII_SPACES, 0xD800, 0xDFFF); // separated surrogates
        testAllowChars(StringPrep.FORBID_NON_ASCII_SPACES, 0xE000, 0x10FFFF);
    }

    @Test
    public void testForbidAsciiControl() throws Exception {
        testForbidChars(StringPrep.FORBID_ASCII_CONTROL, 0x0000, 0x001F);
        testAllowChars(StringPrep.FORBID_ASCII_CONTROL, 0x0020, 0x007E);
        testForbidChars(StringPrep.FORBID_ASCII_CONTROL, 0x007F);
        testAllowChars(StringPrep.FORBID_ASCII_CONTROL, 0x0080, 0xD7FF);
        testForbidChars(StringPrep.FORBID_ASCII_CONTROL, 0xD800, 0xDFFF); // separated surrogates
        testAllowChars(StringPrep.FORBID_NON_ASCII_SPACES, 0xE000, 0x10FFFF);
    }

    @Test
    public void testForbidNonAsciiControl() throws Exception {
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x0000, 0x007F);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x0080, 0x009F);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x00A0, 0x06DC);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x06DD);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x06DE, 0x070E);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x070F);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x0710, 0x180D);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x180E);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x180F, 0x200B);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x200C, 0x200D);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x200E, 0x2027);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x2028, 0x2029);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x202A, 0x205F);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x2060, 0x2063);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x2064, 0x2069);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x206A, 0x206F);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x2070, 0xD7FF);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0xD800, 0xDFFF); // separated surrogates
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0xE000, 0xFEFE);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0xFEFF);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0xFF00, 0xFFF8);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0xFFF9, 0xFFFC);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0xFFFD, 0x1D172);
        testForbidChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x1D173, 0x1D17A);
        testAllowChars(StringPrep.FORBID_NON_ASCII_CONTROL, 0x1D17B, 0x10FFFF);
    }

    @Test
    public void testForbidPrivateUse() throws Exception {
        testAllowChars(StringPrep.FORBID_PRIVATE_USE, 0x0000, 0xD7FF);
        testForbidChars(StringPrep.FORBID_PRIVATE_USE, 0xD800, 0xDFFF); // separated surrogates
        testForbidChars(StringPrep.FORBID_PRIVATE_USE, 0xE000, 0xF8FF);
        testAllowChars(StringPrep.FORBID_PRIVATE_USE, 0xF900, 0xEFFFF);
        testForbidChars(StringPrep.FORBID_PRIVATE_USE, 0xF0000, 0xFFFFD);
        testAllowChars(StringPrep.FORBID_PRIVATE_USE, 0xFFFFE, 0xFFFFF);
        testForbidChars(StringPrep.FORBID_PRIVATE_USE, 0x100000, 0x10FFFD);
        testAllowChars(StringPrep.FORBID_PRIVATE_USE, 0x10FFFE, 0x10FFFF);
    }

    /**
     * 5.4 Non-character code points
     */
    @Test
    public void testForbidNonCharacter() throws Exception {
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x0000, 0xD7FF);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0xD800, 0xDFFF); // separated surrogates
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0xE000, 0xFDCF);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0xFDD0, 0xFDEF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0xFDF0, 0xFFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0xFFFE, 0xFFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x10000, 0x1FFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0x1FFFE, 0x1FFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x20000, 0x2FFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0x2FFFE, 0x2FFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x30000, 0x3FFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0x3FFFE, 0x3FFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x40000, 0x4FFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0x4FFFE, 0x4FFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x50000, 0x5FFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0x5FFFE, 0x5FFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x60000, 0x6FFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0x6FFFE, 0x6FFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x70000, 0x7FFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0x7FFFE, 0x7FFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x80000, 0x8FFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0x8FFFE, 0x8FFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x90000, 0x9FFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0x9FFFE, 0x9FFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0xA0000, 0xAFFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0xAFFFE, 0xAFFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0xB0000, 0xBFFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0xBFFFE, 0xBFFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0xC0000, 0xCFFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0xCFFFE, 0xCFFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0xD0000, 0xDFFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0xDFFFE, 0xDFFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0xE0000, 0xEFFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0xEFFFE, 0xEFFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0xF0000, 0xFFFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0xFFFFE, 0xFFFFF);
        testAllowChars(StringPrep.FORBID_NON_CHARACTER, 0x100000, 0x10FFFD);
        testForbidChars(StringPrep.FORBID_NON_CHARACTER, 0x10FFFE, 0x10FFFF);
    }

    /**
     * 5.5 Surrogate codes
     */
    @Test
    public void testForbidSurrogate() throws Exception {
        testAllowChars(StringPrep.FORBID_SURROGATE, 0x0000, 0xD7FF);
        testForbidChars(StringPrep.FORBID_SURROGATE, 0xD800, 0xDFFF);
        testAllowChars(StringPrep.FORBID_SURROGATE, 0xE000, 0x10FFFF);
    }

    /**
     * 5.6 Inappropriate for plain text
     */
    @Test
    public void testForbidInappropriateForPlainText() throws Exception {
        testAllowChars(StringPrep.FORBID_INAPPROPRIATE_FOR_PLAIN_TEXT, 0x0000, 0xD7FF);
        testForbidChars(StringPrep.FORBID_INAPPROPRIATE_FOR_PLAIN_TEXT, 0xD800, 0xDFFF); // separated surrogates
        testAllowChars(StringPrep.FORBID_INAPPROPRIATE_FOR_PLAIN_TEXT, 0xE000, 0xFFF8);
        testForbidChars(StringPrep.FORBID_INAPPROPRIATE_FOR_PLAIN_TEXT, 0xFFF9, 0xFFFD);
        testAllowChars(StringPrep.FORBID_INAPPROPRIATE_FOR_PLAIN_TEXT, 0xFFFE, 0x10FFFF);
    }

    /**
     * 5.7 Inappropriate for canonical representation
     */
    @Test
    public void testForbidInappropriateForCanonicalRepresentation() throws Exception {
        testAllowChars(StringPrep.FORBID_INAPPROPRIATE_FOR_CANON_REP, 0x0000, 0x2FEF);
        testForbidChars(StringPrep.FORBID_INAPPROPRIATE_FOR_CANON_REP, 0x2FF0, 0x2FFB);
        testAllowChars(StringPrep.FORBID_INAPPROPRIATE_FOR_CANON_REP, 0x2FFC, 0xD7FF);
        testForbidChars(StringPrep.FORBID_INAPPROPRIATE_FOR_CANON_REP, 0xD800, 0xDFFF); // separated surrogates
        testAllowChars(StringPrep.FORBID_INAPPROPRIATE_FOR_CANON_REP, 0xE000, 0x10FFFF);
    }

    /**
     * 5.8 Change display properties or are deprecated
     */
    @Test
    public void testForbidChangeDisplayAndDeprecated() throws Exception {
        testAllowChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0x0000, 0x033F);
        testForbidChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0x0340, 0x0341);
        testAllowChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0x0342, 0x200D);
        testForbidChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0x200E, 0x200F);
        testAllowChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0x2010, 0x2029);
        testForbidChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0x202A, 0x202E);
        testAllowChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0x202F, 0x2069);
        testForbidChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0x206A, 0x206F);
        testAllowChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0x2070, 0xD7FF);
        testForbidChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0xD800, 0xDFFF); // separated surrogates
        testAllowChars(StringPrep.FORBID_CHANGE_DISPLAY_AND_DEPRECATED, 0xE000, 0x10FFFF);
    }

    /**
     * 5.9 Tagging characters
     */
    @Test
    public void testForbidTagging() throws Exception {
        testAllowChars(StringPrep.FORBID_TAGGING, 0x0000, 0xD7FF);
        testForbidChars(StringPrep.FORBID_TAGGING, 0xD800, 0xDFFF); // separated surrogates
        testAllowChars(StringPrep.FORBID_TAGGING, 0xE000, 0xE0000);
        testForbidChars(StringPrep.FORBID_TAGGING, 0xE0001);
        testAllowChars(StringPrep.FORBID_TAGGING, 0xE0002, 0xE001F);
        testForbidChars(StringPrep.FORBID_TAGGING, 0xE0020, 0xE007F);
    }

    /**
     * A.1 Unassigned code points in Unicode 3.2
     */
    @Test
    @Ignore("This implementation use newer Unicode then RFC of StringPrep (which use Unicode 3.2), see ELY-48")
    public void testForbidUnassigned() throws Exception {
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0221);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0234, 0x024F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x02AE, 0x02AF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x02EF, 0x02FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0350, 0x035F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0370, 0x0373);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0376, 0x0379);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x037B, 0x037D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x037F, 0x0383);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x038B);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x038D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x03A2);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x03CF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x03F7, 0x03FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0487);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x04CF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x04F6, 0x04F7);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x04FA, 0x04FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0510, 0x0530);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0557, 0x0558);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0560);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0588);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x058B, 0x0590);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x05A2);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x05BA);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x05C5, 0x05CF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x05EB, 0x05EF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x05F5, 0x060B);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x060D, 0x061A);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x061C, 0x061E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0620);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x063B, 0x063F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0656, 0x065F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x06EE, 0x06EF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x06FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x070E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x072D, 0x072F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x074B, 0x077F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x07B2, 0x0900);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0904);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x093A, 0x093B);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x094E, 0x094F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0955, 0x0957);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0971, 0x0980);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0984);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x098D, 0x098E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0991, 0x0992);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09A9);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09B1);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09B3, 0x09B5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09BA, 0x09BB);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09BD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09C5, 0x09C6);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09C9, 0x09CA);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09CE, 0x09D6);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09D8, 0x09DB);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09DE);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09E4, 0x09E5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x09FB, 0x0A01);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A03, 0x0A04);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A0B, 0x0A0E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A11, 0x0A12);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A29);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A31);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A34);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A37);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A3A, 0x0A3B);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A3D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A43, 0x0A46);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A49, 0x0A4A);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A4E, 0x0A58);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A5D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A5F, 0x0A65);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A75, 0x0A80);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A84);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A8C);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A8E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0A92);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0AA9);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0AB1);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0AB4);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0ABA, 0x0ABB);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0AC6);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0ACA);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0ACE, 0x0ACF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0AD1, 0x0ADF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0AE1, 0x0AE5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0AF0, 0x0B00);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B04);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B0D, 0x0B0E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B11, 0x0B12);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B29);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B31);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B34, 0x0B35);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B3A, 0x0B3B);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B44, 0x0B46);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B49, 0x0B4A);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B4E, 0x0B55);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B58, 0x0B5B);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B5E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B62, 0x0B65);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B71, 0x0B81);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B84);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B8B, 0x0B8D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B91);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B96, 0x0B98);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B9B);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0B9D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0BA0, 0x0BA2);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0BA5, 0x0BA7);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0BAB, 0x0BAD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0BB6);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0BBA, 0x0BBD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0BC3, 0x0BC5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0BC9);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0BCE, 0x0BD6);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0BD8, 0x0BE6);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0BF3, 0x0C00);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C04);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C0D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C11);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C29);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C34);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C3A, 0x0C3D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C45);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C49);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C4E, 0x0C54);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C57, 0x0C5F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C62, 0x0C65);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C70, 0x0C81);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C84);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C8D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0C91);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0CA9);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0CB4);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0CBA, 0x0CBD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0CC5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0CC9);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0CCE, 0x0CD4);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0CD7, 0x0CDD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0CDF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0CE2, 0x0CE5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0CF0, 0x0D01);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D04);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D0D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D11);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D29);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D3A, 0x0D3D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D44, 0x0D45);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D49);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D4E, 0x0D56);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D58, 0x0D5F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D62, 0x0D65);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D70, 0x0D81);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D84);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0D97, 0x0D99);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0DB2);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0DBC);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0DBE, 0x0DBF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0DC7, 0x0DC9);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0DCB, 0x0DCE);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0DD5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0DD7);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0DE0, 0x0DF1);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0DF5, 0x0E00);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0E3B, 0x0E3E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0E5C, 0x0E80);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0E83);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0E85, 0x0E86);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0E89);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0E8B, 0x0E8C);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0E8E, 0x0E93);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0E98);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EA0);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EA4);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EA6);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EA8, 0x0EA9);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EAC);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EBA);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EBE, 0x0EBF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EC5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EC7);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0ECE, 0x0ECF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EDA, 0x0EDB);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0EDE, 0x0EFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0F48);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0F6B, 0x0F70);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0F8C, 0x0F8F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0F98);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0FBD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0FCD, 0x0FCE);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x0FD0, 0x0FFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1022);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1028);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x102B);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1033, 0x1035);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x103A, 0x103F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x105A, 0x109F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x10C6, 0x10CF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x10F9, 0x10FA);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x10FC, 0x10FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x115A, 0x115E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x11A3, 0x11A7);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x11FA, 0x11FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1207);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1247);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1249);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x124E, 0x124F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1257);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1259);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x125E, 0x125F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1287);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1289);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x128E, 0x128F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x12AF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x12B1);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x12B6, 0x12B7);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x12BF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x12C1);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x12C6, 0x12C7);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x12CF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x12D7);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x12EF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x130F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1311);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1316, 0x1317);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x131F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1347);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x135B, 0x1360);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x137D, 0x139F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x13F5, 0x1400);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1677, 0x167F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x169D, 0x169F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x16F1, 0x16FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x170D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1715, 0x171F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1737, 0x173F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1754, 0x175F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x176D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1771);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1774, 0x177F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x17DD, 0x17DF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x17EA, 0x17FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x180F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x181A, 0x181F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1878, 0x187F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x18AA, 0x1DFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1E9C, 0x1E9F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1EFA, 0x1EFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1F16, 0x1F17);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1F1E, 0x1F1F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1F46, 0x1F47);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1F4E, 0x1F4F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1F58);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1F5A);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1F5C);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1F5E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1F7E, 0x1F7F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1FB5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1FC5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1FD4, 0x1FD5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1FDC);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1FF0, 0x1FF1);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1FF5);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1FFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2053, 0x2056);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2058, 0x205E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2064, 0x2069);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2072, 0x2073);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x208F, 0x209F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x20B2, 0x20CF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x20EB, 0x20FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x213B, 0x213C);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x214C, 0x2152);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2184, 0x218F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x23CF, 0x23FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2427, 0x243F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x244B, 0x245F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x24FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2614, 0x2615);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2618);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x267E, 0x267F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x268A, 0x2700);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2705);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x270A, 0x270B);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2728);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x274C);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x274E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2753, 0x2755);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2757);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x275F, 0x2760);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2795, 0x2797);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x27B0);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x27BF, 0x27CF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x27EC, 0x27EF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2B00, 0x2E7F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2E9A);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2EF4, 0x2EFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2FD6, 0x2FEF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2FFC, 0x2FFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x3040);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x3097, 0x3098);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x3100, 0x3104);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x312D, 0x3130);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x318F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x31B8, 0x31EF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x321D, 0x321F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x3244, 0x3250);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x327C, 0x327E);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x32CC, 0x32CF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x32FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x3377, 0x337A);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x33DE, 0x33DF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x33FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x4DB6, 0x4DFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x9FA6, 0x9FFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xA48D, 0xA48F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xA4C7, 0xABFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xD7A4, 0xD7FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFA2E, 0xFA2F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFA6B, 0xFAFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFB07, 0xFB12);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFB18, 0xFB1C);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFB37);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFB3D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFB3F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFB42);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFB45);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFBB2, 0xFBD2);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFD40, 0xFD4F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFD90, 0xFD91);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFDC8, 0xFDCF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFDFD, 0xFDFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFE10, 0xFE1F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFE24, 0xFE2F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFE47, 0xFE48);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFE53);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFE67);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFE6C, 0xFE6F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFE75);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFEFD, 0xFEFE);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFF00);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFFBF, 0xFFC1);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFFC8, 0xFFC9);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFFD0, 0xFFD1);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFFD8, 0xFFD9);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFFDD, 0xFFDF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFFE7);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xFFEF, 0xFFF8);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x10000, 0x102FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1031F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x10324, 0x1032F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1034B, 0x103FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x10426, 0x10427);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1044E, 0x1CFFF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D0F6, 0x1D0FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D127, 0x1D129);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D1DE, 0x1D3FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D455);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D49D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D4A0, 0x1D4A1);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D4A3, 0x1D4A4);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D4A7, 0x1D4A8);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D4AD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D4BA);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D4BC);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D4C1);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D4C4);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D506);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D50B, 0x1D50C);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D515);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D51D);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D53A);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D53F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D545);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D547, 0x1D549);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D551);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D6A4, 0x1D6A7);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D7CA, 0x1D7CD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x1D800, 0x1FFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2A6D7, 0x2F7FF);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x2FA1E, 0x2FFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x30000, 0x3FFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x40000, 0x4FFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x50000, 0x5FFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x60000, 0x6FFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x70000, 0x7FFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x80000, 0x8FFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0x90000, 0x9FFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xA0000, 0xAFFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xB0000, 0xBFFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xC0000, 0xCFFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xD0000, 0xDFFFD);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xE0000);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xE0002, 0xE001F);
        testForbidChars(StringPrep.FORBID_UNASSIGNED, 0xE0080, 0xEFFFD);
    }

    // ---------------------- helpers ----------------------

    private String codePointToString(int codePoint) {
        if (codePoint <= 0xFFFF) {
            return new String(new char[]{(char) codePoint}); // allow separated surrogates, but only 2-bytes codepoints
        } else {
            ByteStringBuilder b = new ByteStringBuilder();
            b.appendUtf8Raw(codePoint);
            return new String(b.toArray(), StandardCharsets.UTF_8); // String(byte[]) not permit separated surrogates
        }
    }

    private void testForbidChars(long profile, int codePoint) throws Exception {
        try {
            ByteStringBuilder b = new ByteStringBuilder();
            StringPrep.encode(codePointToString(codePoint), b, profile);
            fail("Not throwed IllegalArgumentException for " + Integer.toHexString(codePoint) + "!");
        } catch (IllegalArgumentException e) {}
    }

    private void testAllowChars(long profile, int codePoint) throws Exception {
        ByteStringBuilder b = new ByteStringBuilder();
        StringPrep.encode(codePointToString(codePoint), b, profile);
    }

    private void testForbidChars(long profile, int from, int to) throws Exception {
        for (int i = from; i <= to; i++) {
            testForbidChars(profile, i);
        }
    }

    private void testAllowChars(long profile, int from, int to) throws Exception {
        for (int i = from; i <= to; i++) {
            testAllowChars(profile, i);
        }
    }

    @Test
    public void testHelpersCodePointToStringConversion() throws Exception {
        assertArrayEquals(new char[]{(char)0xD800}, codePointToString(0xD800).toCharArray());
        assertEquals("\uD800", codePointToString(0xD800));
        assertEquals("\uDBB6\uDC00", codePointToString(0xFD800));
        assertEquals("\uDBFF\uDFFF", codePointToString(0x10FFFF));
    }

}
