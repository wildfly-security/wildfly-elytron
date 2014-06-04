/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.wildfly.sasl.util;

/**
 * A utility class for mapping between byte arrays and their hex representation and back again.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class HexConverter {

    private static final char[] HEX_CHARS = new char[]
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    private static final byte[] HEX_BYTES = new byte[]
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /**
     * Take the supplied byte array and convert it to a hex encoded String.
     *
     * @param toBeConverted - the bytes to be converted.
     * @return the hex encoded String.
     */
    public static String convertToHexString(byte[] toBeConverted) {
        if (toBeConverted == null) {
            throw new NullPointerException("Parameter to be converted can not be null");
        }

        char[] converted = new char[toBeConverted.length * 2];
        for (int i = 0; i < toBeConverted.length; i++) {
            byte b = toBeConverted[i];
            converted[i * 2] = HEX_CHARS[b >> 4 & 0x0F];
            converted[i * 2 + 1] = HEX_CHARS[b & 0x0F];
        }

        return String.valueOf(converted);
    }

    /**
     * Take the supplied byte array and convert it to to a byte array of the encoded
     * hex values.
     * <p/>
     * Each byte on the incoming array will be converted to two bytes on the return
     * array.
     *
     * @param toBeConverted - the bytes to be encoded.
     * @return the encoded byte array.
     */
    public static byte[] convertToHexBytes(byte[] toBeConverted) {
        if (toBeConverted == null) {
            throw new NullPointerException("Parameter to be converted can not be null");
        }

        byte[] converted = new byte[toBeConverted.length * 2];
        for (int i = 0; i < toBeConverted.length; i++) {
            byte b = toBeConverted[i];
            converted[i * 2] = HEX_BYTES[b >> 4 & 0x0F];
            converted[i * 2 + 1] = HEX_BYTES[b & 0x0F];
        }

        return converted;
    }

    /**
     * Take the incoming character of hex encoded data and convert to the raw byte values.
     * <p/>
     * The characters in the incoming array are processed in pairs with two chars of a pair
     * being converted to a single byte.
     *
     * @param toConvert - the hex encoded String to convert.
     * @return the raw byte array.
     */
    public static byte[] convertFromHex(final char[] toConvert) {
        if (toConvert.length % 2 != 0) {
            throw new IllegalArgumentException("The supplied character array must contain an even number of hex chars.");
        }

        byte[] response = new byte[toConvert.length / 2];

        for (int i = 0; i < response.length; i++) {
            int posOne = i * 2;
            response[i] =   (byte)(toByte(toConvert, posOne) << 4 | toByte(toConvert, posOne+1));
        }

        return response;
    }

    private static byte toByte(final char[] toConvert, final int pos) {
        int response = Character.digit(toConvert[pos], 16);
        if (response < 0 || response > 15) {
            throw new IllegalArgumentException("Non-hex character '" + toConvert[pos] + "' at index=" + pos);
        }

        return (byte) response;
    }

    /**
     * Take the incoming String of hex encoded data and convert to the raw byte values.
     * <p/>
     * The characters in the incoming String are processed in pairs with two chars of a pair
     * being converted to a single byte.
     *
     * @param toConvert - the hex encoded String to convert.
     * @return the raw byte array.
     */
    public static byte[] convertFromHex(final String toConvert) {
        return convertFromHex(toConvert.toCharArray());
    }

    public static void main(String[] args) {
        byte[] toConvert = new byte[256];
        for (int i = 0; i < toConvert.length; i++) {
            toConvert[i] = (byte) i;
        }

        String hexValue = convertToHexString(toConvert);

        System.out.println("Converted - " + hexValue);

        byte[] convertedBack = convertFromHex(hexValue);

        StringBuffer sb = new StringBuffer();
        for (byte current : convertedBack) {
            sb.append((int)current).append(" ");
        }
        System.out.println("Converted Back " + sb.toString());
    }

}
