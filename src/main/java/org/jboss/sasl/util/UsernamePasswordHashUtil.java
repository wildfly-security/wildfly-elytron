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
package org.jboss.sasl.util;

import static org.jboss.sasl.util.Charsets.LATIN_1;
import static org.jboss.sasl.util.Charsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A utility class for generating both the {user-name : realm-value : passwd } hash
 * and the hex encoded version of the hash.
 * <p/>
 * This class makes use of the MessageDigest by single calls to the .digest(byte[]) method,
 * however beyond that there is no synchronisation so this should not be considered thread safe.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class UsernamePasswordHashUtil {

    private static final String MD5 = "MD5";

    private static final byte COLON = ':';

    private final MessageDigest digest;

    /**
     * The default constructor for UsernamePasswordHashUtil, when instantiated
     * using this constructor a local MD5 MessageDigest will be used for the
     * generated hashes.
     *
     * @throws NoSuchAlgorithmException - If the MD5 MessageDigest fails to be created.
     */
    public UsernamePasswordHashUtil() throws NoSuchAlgorithmException {
        digest = MessageDigest.getInstance(MD5);
    }

    /**
     * Constructor to allow a pre-instantiated MessageDigest to be supplied.
     * <p/>
     * The supplied MessageDigest will be used for the hash generation requests,
     *
     * @param digest The MessageDigest to use for hash generation requests.
     */
    public UsernamePasswordHashUtil(final MessageDigest digest) {
        this.digest = digest;
    }

    /**
     * An interpretation of the stringToByte_8859_1 method previously from DigestMD5Base.
     * <p/>
     * Converts the supplied String to a byte array using 8859_1 encoding, however if any of the
     * characters in the String are outside of the range for 8859_1 and if allowUTF8 is true the
     * String will be converted to UTF-8.
     *
     * @param toConvert the raw String to convert.
     * @param allowUTF8 should the conversion use UTF-8 if non 8859_1 chars are found.
     * @return the resulting byte[]
     */
    private byte[] stringToByte(final String toConvert, final boolean allowUTF8) {
        // If UTF-8 encoding is not allowed at all there is no point checking
        // for non 8859_1 characters.
        if (allowUTF8) {
            char[] theChars = toConvert.toCharArray();

            for (char c : theChars) {
                if (c > '\u00FF') {
                    return toConvert.getBytes(UTF_8);
                }
            }
        }

        return toConvert.getBytes(LATIN_1);
    }

    /**
     * A version of stringToByte that takes in a char[]
     *
     * @param toConvert the character array to convert.
     * @param allowUTF8 should the conversion use UTF-8 if non 8859_1 chars are found.
     * @return the resulting byte[]
     */
    private byte[] stringToByte(final char[] toConvert, final boolean allowUTF8) {
        if (allowUTF8) {

            for (char c : toConvert) {
                if (c > '\u00FF') {
                    // TODO - Is there a quicker conversion without going to String before to byte[]
                    return String.valueOf(toConvert).getBytes(UTF_8);
                }
            }
        }

        return String.valueOf(toConvert).getBytes(LATIN_1);
    }

    /**
     * Takes the supplied username, realm and password and generates the digested { username ':' realm ':' password}
     *
     * @param userName             The username to use in the generated hash.
     * @param realm                The realm to use in the generated hash.
     * @param password             The password to use in the generated hash.
     * @param utf8StringConversion Should a conversion to UTF-8 be allowed if non 8859_1 chars are encountered.
     * @return The generated hash.
     */
    public byte[] generateHashedURP(final String userName, final String realm, final char[] password,
                                    final boolean utf8StringConversion) {
        byte[] userNameArray = stringToByte(userName, utf8StringConversion);
        byte[] realmArray = stringToByte(realm, utf8StringConversion);
        byte[] passwordArray = stringToByte(password, utf8StringConversion);

        int requiredSize = userNameArray.length + realmArray.length + passwordArray.length + 2;

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(requiredSize);
            baos.write(userNameArray);
            baos.write(COLON);
            baos.write(realmArray);
            baos.write(COLON);
            baos.write(passwordArray);

            return digest.digest(baos.toByteArray());
        } catch (IOException e) {
            throw new IllegalStateException("The ByteArrayOutputStream should not be throwing this IOException", e);
        }
    }

    public byte[] generateHashedURP(final String userName, final String realm, final char[] password) {
        return generateHashedURP(userName, realm, password, true);
    }

    public String generateHashedHexURP(final String userName, final String realm, final char[] password,
                                       final boolean utf8StringConversion) {
        byte[] hashedURP = generateHashedURP(userName, realm, password, utf8StringConversion);

        return HexConverter.convertToHexString(hashedURP);
    }

    public String generateHashedHexURP(final String userName, final String realm, final char[] password) {
        return generateHashedHexURP(userName, realm, password, true);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String userName;
        String realm;
        char[] password;

        if (args.length == 2) {
            userName = args[0];
            realm = "";
            password = args[1].toCharArray();
        } else if (args.length == 3) {
            userName = args[0];
            realm = args[1];
            password = args[2].toCharArray();
        } else {
            System.out.println("Usage : UsernamePasswordHashUtil UserName [Realm] Password");
            return;
        }

        UsernamePasswordHashUtil util = new UsernamePasswordHashUtil();

        System.out.println(userName + "=" + util.generateHashedHexURP(userName, realm, password));
    }

}
