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

package org.wildfly.security.password.impl;

import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.UnixSHACryptPassword;
import org.wildfly.security.password.spec.UnixSHACryptPasswordSpec;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Implements the Unix SHA Crypt standard, as specified by
 * <a href="http://ftp.arlut.utexas.edu/pub/java_hashes/SHA-crypt.txt">http://ftp.arlut.utexas.edu/pub/java_hashes/SHA-crypt.txt</a>
 *
 * @author <a href="mailto:jpkroehling.javadoc@redhat.com">Juraci Paixão Kröhling</a>
 * @see <a href="http://ftp.arlut.utexas.edu/pub/java_hashes/SHA-crypt.txt">http://ftp.arlut.utexas.edu/pub/java_hashes/SHA-crypt.txt</a>
 */
final class UnixSHACryptPasswordUtil {

    private byte[] salt;
    private int iterationCount;
    private char id;
    private byte[] password;
    private int inputSize = -1;
    private boolean omitIterationCount = true;
    private Charset charset;

    /**
     * Hashes the given password based on the specifications. The output is a byte[] with the complete representation
     * of the password+specifications. Example: $5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA
     *
     * @param spec    the Key Specification to generate the password for.
     * @return a {@link UnixSHACryptPassword} with the results
     */
    public static UnixSHACryptPassword encode(UnixSHACryptPasswordSpec spec) throws NoSuchAlgorithmException {
        byte[] encoded = encode(spec.getId(), spec.getSalt(), spec.getIterationCount(), spec.getHashBytes());
        return new UnixSHACryptPasswordImpl(spec.getSalt(), spec.getIterationCount(), spec.getId(), encoded);
    }

    public static boolean verify(final Password password, final char[] guess) throws NoSuchAlgorithmException {
        UnixSHACryptPassword p = ((UnixSHACryptPassword) password);
        ByteBuffer guessAsBuffer = p.getCharset().encode(CharBuffer.wrap(guess));
        byte[] guessAsBytes = new byte[guessAsBuffer.remaining()];
        guessAsBuffer.get(guessAsBytes);

        byte[] encodedGuess = UnixSHACryptPasswordUtil.encode(p.getId(), p.getSalt(), p.getIterationCount(), guessAsBytes);
        return Arrays.equals(password.getEncoded(), encodedGuess);
    }

    /**
     * Hashes the given password based on the specifications. The output is a byte[] with the complete representation
     * of the password+specifications. Example: $5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA
     *
     * @param id                the id, with the possible values being 5 or 6
     * @param salt              the salt, with at most 16 bytes. If an array bigger than 16 is provided,
     *                          only the first 16 bytes are used.
     * @param iterationCount    an iteration count, between 1,000 and 999,999,999. Values outside of the boundaries fall
     *                          back to the closest boundary (less than 1,000 becomes 1,000, bigger than 999,999,999
     *                          becomes 999,999,999)
     * @param password          the password to be digested
     * @param charset           the charset to use when building the output. Useful if the charset of the original password
     *                          was not UTF-8.
     * @return the resulting hash
     * @throws IllegalArgumentException if the ID is not '5' nor '6'
     * @throws NoSuchAlgorithmException if the current runtime cannot provide a message digester for SHA256 or SHA512
     */
    public static byte[] encode(char id, byte[] salt, int iterationCount, byte[] password, Charset charset) throws IllegalArgumentException, NoSuchAlgorithmException {
        return new UnixSHACryptPasswordUtil(id, salt, iterationCount, password, charset, false).doEncode();
    }

    /**
     * Hashes the given password based on the specifications. Similar to {@link #encode(char, byte[], int, byte[], java.nio.charset.Charset)},
     * with a default charset of UTF-8.
     *
     * @param id                the id, with the possible values being 5 or 6
     * @param salt              the salt, with at most 16 bytes. If an array bigger than 16 is provided,
     *                          only the first 16 bytes are used.
     * @param iterationCount    an iteration count, between 1,000 and 999,999,999. Values outside of the boundaries fall
     *                          back to the closest boundary (less than 1,000 becomes 1,000, bigger than 999,999,999
     *                          becomes 999,999,999)
     * @param password          the password to be digested
     * @return the resulting hash
     * @throws IllegalArgumentException if the ID is not '5' nor '6'
     * @throws NoSuchAlgorithmException if the current runtime cannot provide a message digester for SHA256 or SHA512
     * @see {@link #encode(char, byte[], int, byte[], java.nio.charset.Charset)}
     */
    public static byte[] encode(char id, byte[] salt, int iterationCount, byte[] password) throws IllegalArgumentException, NoSuchAlgorithmException {
        return encode(id, salt, iterationCount, password, Charset.forName("UTF-8"));
    }

    /**
     * Hashes the given password based on the specifications from a formatted string. Examples for the specification are:
     *
     * - $6$saltstring
     * - $6$rounds=10000$saltstringsaltstring
     *
     * If the rounds part is not specified, it defaults to 5,000.
     * If the salt is bigger than 16, it's truncated at the 16th character.
     *
     * Anything added after the salt part is discarded.

     * @param formatted    the formatted string
     * @param charset      the charset to use
     * @param password     the password to be digested
     * @return  a byte[] with the hashed password
     * @throws IllegalArgumentException if the formatted string is invalid or if the ID is not '5' nor '6'
     * @throws NoSuchAlgorithmException if the current runtime cannot provide a message digester for SHA256 or SHA512
     */
    public static byte[] encode(String formatted, Charset charset, byte[] password) throws IllegalArgumentException, NoSuchAlgorithmException {
        String[] parts = formatted.split("\\$");

        if (parts.length < 3) {
            throw new IllegalArgumentException("The format specification should have at least two parts: an ID and a salt");
        }

        char[] idPart = parts[1].toCharArray();

        if (idPart.length > 1) {
            throw new IllegalArgumentException("Invalid ID. Received " + parts[1] + ", but valid values are only '5' and '6'");
        }

        char id = idPart[0];

        boolean omitIterationCount = true;
        int iterationCount;
        byte[] salt;

        if (parts[2].startsWith("rounds=")) {
            omitIterationCount = false;
            iterationCount = Integer.parseInt(parts[2].substring("rounds=".length(), parts[2].length()));
            salt = parts[3].getBytes(charset);
        } else {
            iterationCount = 5000;
            salt = parts[2].getBytes(charset);
        }

        return new UnixSHACryptPasswordUtil(id, salt, iterationCount, password, charset, omitIterationCount).doEncode();
    }

    /**
     * Similar to the {@link #encode(String, java.nio.charset.Charset, byte[])}, with a default Charset of UTF-8
     *
     * @param formatted    the formatted string
     * @param password     the password to be digested
     * @return  a byte[] with the hashed password
     * @throws IllegalArgumentException
     * @throws NoSuchAlgorithmException
     * @see {@link #encode(String, java.nio.charset.Charset, byte[])}
     */
    public static byte[] encode(String formatted, byte[] password) throws IllegalArgumentException, NoSuchAlgorithmException {
        return encode(formatted, Charset.forName("UTF-8"), password);
    }

    /**
     * Prepares a new password implementation for the Unix SHA Crypt.
     *
     * @param id                the id, with the possible values being 5 or 6
     * @param salt              a random salt
     * @param iterationCount    an iteration count, between 1,000 and 999,999,999. Values outside of the boundaries fall
     *                          back to the closest boundary (less than 1,000 becomes 1,000, bigger than 999,999,999
     *                          becomes 999,999,999)
     * @param password          the password to be digested
     * @throws IllegalArgumentException if the ID is not 5 nor 6
     */
    private UnixSHACryptPasswordUtil(char id, byte[] salt, int iterationCount, byte[] password, Charset charset, boolean omitIterationCount) throws IllegalArgumentException {
        if (id != '5' && id != '6') {
            throw new IllegalArgumentException("Invalid ID. Received " + id + ", but valid values are only '5' and '6'");
        }

        if (null == charset) {
            charset = Charset.forName("UTF-8");
        }

        if (salt.length > 16) {
            salt = Arrays.copyOfRange(salt, 0, 16);
        }

        this.id = id;
        this.salt = salt;
        this.iterationCount = Math.min(999999999, Math.max(1000, iterationCount));
        this.password = password;
        this.charset = charset;
        this.omitIterationCount = omitIterationCount;
    }

    /**
     * Internal method, responsible for hashing the password based on the parameters provided when creating this.
     * The state of the instance property {@code encoded} is altered on this method.
     *
     * @throws NoSuchAlgorithmException
     */
    private byte[] doEncode() throws NoSuchAlgorithmException {
        // see ftp://ftp.arlut.utexas.edu/pub/java_hashes/SHA-crypt.txt
        // most of the comments from this point and on are copy/paste from the url above, to make it easier
        // to correlate the code with the steps.

        // implementation note: we use "digestAC" here, because we don't need to duplicate digestA into digestAC,
        // as at the time the "digestAC" is "C", then "A" is not needed anymore.
        byte[] digestAC = getDigestA(); // at this point, digestAC is "A"
        byte[] sequenceP = getSequenceP();
        byte[] sequenceS = getSequenceS(digestAC);
        for (int i = 0 ; i < iterationCount ; i++) {
            // 21. repeat a loop according to the number specified in the rounds=<N>
            // specification in the salt (or the default value if none is
            // present).  Each round is numbered, starting with 0 and up to N-1.
            //
            //     The loop uses a digest as input.  In the first round it is the
            // digest produced in step 12.  In the latter steps it is the digest
            // produced in step 21.h.  The following text uses the notation
            // "digest A/C" to desribe this behavior.
            digestAC = getDigestC(digestAC, sequenceP, sequenceS, i);
            // implementation note: at this point, digestAC is "C"
        }

        return getEncodedForFinalDigest(digestAC);
    }

    /**
     * Returns the final output based on the digestAC, including the prefixes.
     *
     * @param digestAC    the digest A/C
     * @return the byte[] representing the final output
     */
    private byte[] getEncodedForFinalDigest(byte[] digestAC) {
        // TODO: evaluate if we couldn't use a ByteBuffer instead, as both the output and most of the input is byte[]

        // 22. Produce the output string.  This is an ASCII string of the maximum size specified above, consisting of multiple pieces:
        StringBuilder output = new StringBuilder(getMaximumOutputSize());

        // a) the salt prefix, $5$ or $6$ respectively
        output.append("$").append(this.id).append("$");

        //     b) the rounds=<N> specification, if one was present in the input
        // salt string.  A trailing '$' is added in this case to separate
        // the rounds specification from the following text.
        if (!omitIterationCount) {
            output.append("rounds=").append(iterationCount).append("$");
        }

        //     c) the salt string truncated to 16 characters
        output.append(new String(salt));

        //     d) a '$' character
        output.append("$");

        //     e) the base-64 encoded final C digest.  The encoding used is as follows
        // Note: look at the url mentioned at the beginning of this method, as this part is big
        produceOutput(digestAC, output);

        return output.toString().getBytes(charset);
    }

    /**
     * Calculates the "digest C", derived from the sequenceP, sequenceS, digestAC and the iteration round
     *
     * @param digestAC     the digest A/C
     * @param sequenceP    the sequence P
     * @param sequenceS    the sequence S
     * @param round        the iteration round
     * @return             the resulting digest C
     * @throws NoSuchAlgorithmException
     */
    private byte[] getDigestC(byte[] digestAC, byte[] sequenceP, byte[] sequenceS, int round) throws NoSuchAlgorithmException {
        // a) start digest C
        MessageDigest digestC = getMessageDigest();

        // b) for odd round numbers add the byte sequense P to digest C
        // c) for even round numbers add digest A/C
        if (round % 2 != 0) {
            digestC.update(sequenceP, 0, sequenceP.length);
        } else {
            digestC.update(digestAC, 0, digestAC.length);
        }

        // d) for all round numbers not divisible by 3 add the byte sequence S
        if (round % 3 != 0) {
            digestC.update(sequenceS, 0, sequenceS.length);
        }

        // e) for all round numbers not divisible by 7 add the byte sequence P
        if (round % 7 != 0) {
            digestC.update(sequenceP, 0, sequenceP.length);
        }

        // f) for odd round numbers add digest A/C
        // g) for even round numbers add the byte sequence P
        if (round % 2 != 0) {
            digestC.update(digestAC, 0, digestAC.length);
        } else {
            digestC.update(sequenceP, 0, sequenceP.length);
        }

        // h) finish digest C.
        // from the javadoc: After digest has been called, the MessageDigest object is reset to its initialized state.
        return digestC.digest();
    }

    /**
     * Calculates the "sequence S", based on a given "digest A"
     *
     * @param digestA    the digest A
     * @return           the sequence S
     * @throws NoSuchAlgorithmException
     */
    private byte[] getSequenceS(byte[] digestA) throws NoSuchAlgorithmException {
        // 20. produce byte sequence S of the same length as the salt string where
        //
        // a) for each block of 32 or 64 bytes of length of the salt string
        // the entire digest DS is used
        //
        // b) for the remaining N (up to  31 or 63) bytes use the first N
        // bytes of digest DS
        byte[] sequenceS = new byte[salt.length];
        byte[] digestDSResult = getDigestDS(digestA);
        ByteBuffer bufferSequenceS = ByteBuffer.wrap(sequenceS);
        int numberOfBlocksSalt = salt.length / getInputSize();
        int remainingBytesSizeSalt = salt.length % getInputSize();

        for (int i = 0 ; i < numberOfBlocksSalt ; i++ ) {
            bufferSequenceS.put(Arrays.copyOfRange(digestDSResult, 0, getInputSize()));
        }
        bufferSequenceS.put(Arrays.copyOfRange(digestDSResult, 0, remainingBytesSizeSalt));
        return sequenceS;
    }

    /**
     * Calculates the "digest DS", derived from the salt and on the "digest A"
     *
     * @param digestA    the digest A
     * @return           the digest DS
     * @throws NoSuchAlgorithmException
     */
    private byte[] getDigestDS(byte[] digestA) throws NoSuchAlgorithmException {
        // 17. start digest DS
        MessageDigest digestDS = getMessageDigest();

        // 18. repeast the following 16+A[0] times, where A[0] represents the first
        // byte in digest A interpreted as an 8-bit unsigned value
        //
        // add the salt to digest DS
        int repeatTimes = 16 + (digestA[0] & 0xFF); // this binary-and converts the byte into "8-bit unsigned" value
        for (int i = 0 ; i < repeatTimes ; i++) {
            digestDS.update(salt, 0, salt.length);
        }

        // 19. finish digest DS
        return digestDS.digest();
    }

    /**
     * Calculates the "sequence P", derived from the password
     *
     * @return the sequence P
     * @throws NoSuchAlgorithmException
     */
    private byte[] getSequenceP() throws NoSuchAlgorithmException {
        // 16. produce byte sequence P of the same length as the password where
        //
        // a) for each block of 32 or 64 bytes of length of the password string
        // the entire digest DP is used
        //
        // b) for the remaining N (up to  31 or 63) bytes use the first N
        // bytes of digest DP
        byte[] digestDPResult = getDigestDP();
        byte[] sequenceP = new byte[password.length];
        ByteBuffer bufferSequenceP = ByteBuffer.wrap(sequenceP);

        int numberOfBlocksPassword = password.length / getInputSize();
        for (int i = 0 ; i < numberOfBlocksPassword ; i++ ) {
            bufferSequenceP.put(Arrays.copyOfRange(digestDPResult, 0, getInputSize()));
        }

        int remainingBytesSizePassword = password.length % getInputSize();
        bufferSequenceP.put(Arrays.copyOfRange(digestDPResult, 0, remainingBytesSizePassword));

        return sequenceP;
    }

    /**
     * Calculates the "digest A", derived from the password and salt.
     * @return the digest A
     * @throws NoSuchAlgorithmException
     */
    private byte[] getDigestA() throws NoSuchAlgorithmException {
        byte[] digestBResult = getDigestB();
        // 1.  start digest A
        MessageDigest digestA = getMessageDigest();

        // 2.  the password string is added to digest A
        digestA.update(password, 0, password.length);

        // 3.  the salt string is added to digest A.
        digestA.update(salt, 0, salt.length);

        // 9.  For each block of 32 or 64 bytes in the password string, add digest B to digest A
        int numberOfBlocksPassword = password.length / getInputSize();
        for (int i = 0 ; i < numberOfBlocksPassword ; i++ ) {
            digestA.update(digestBResult, 0, getInputSize());
        }

        // 10. For the remaining N bytes of the password string add the first N bytes of digest B to digest A
        int remainingBytesSizePassword = password.length % getInputSize();
        digestA.update(digestBResult, 0, remainingBytesSizePassword);

        // 11. For each bit of the binary representation of the length of the
        // password string up to and including the highest 1-digit, starting
        // from to lowest bit position (numeric value 1):
        //
        // a) for a 1-digit add digest B to digest A
        //
        // b) for a 0-digit add the password string
        for (int i = password.length ; i > 0 ; i >>= 1) {
            if (i % 2 != 0) {
                digestA.update(digestBResult, 0, getInputSize());
            } else {
                digestA.update(password, 0, password.length);
            }
        }

        // 12. finish digest A
        return digestA.digest();
    }

    /**
     * Returns the "digest B", derived from the password and salt
     *
     * @return the digest B
     * @throws NoSuchAlgorithmException
     */
    private byte[] getDigestB() throws NoSuchAlgorithmException {
        // 4.  start digest B
        MessageDigest digestB = getMessageDigest();

        // 5.  add the password to digest B
        digestB.update(password, 0, password.length);

        // 6.  add the salt string to digest B
        digestB.update(salt, 0, salt.length);

        // 7.  add the password again to digest B
        digestB.update(password, 0, password.length);

        // 8.  finish digest B
        return digestB.digest();
    }

    /**
     * Calculates the "digest DP", derived from the password
     * @return
     * @throws NoSuchAlgorithmException
     */
    private byte[] getDigestDP() throws NoSuchAlgorithmException {
        // 13. start digest DP
        MessageDigest digestDP = getMessageDigest();

        // 14. for every byte in the password add the password to digest DP
        for (byte ignored : password) {
            digestDP.update(password, 0, password.length);
        }

        // 15. finish digest DP
        return digestDP.digest();
    }

    private void produceOutput(byte[] finalDigest, StringBuilder output) {
        switch (id) {
            case '5': produceOutput256(finalDigest, output); break;
            case '6': produceOutput512(finalDigest, output); break;
            default: throw new IllegalStateException("Couldn't determine the digest algorithm. Expected the ID to be 5 (SHA256) or 6 (SHA512), but was " + id);
        }
    }

    private MessageDigest getMessageDigest() throws NoSuchAlgorithmException {
        switch (id) {
            case '5': return MessageDigest.getInstance("SHA-256");
            case '6': return MessageDigest.getInstance("SHA-512");
            default: throw new IllegalStateException("Couldn't determine the digest algorithm. Expected the ID to be 5 (SHA256) or 6 (SHA512), but was " + id);
        }
    }

    private int getInputSize() {
        // For MD5 the digest is 16 bytes, for SHA-256 it is 32 bytes, and for SHA-512 it is 64 bytes.
        if (inputSize == -1) {
            switch (id) {
                case '5': inputSize = 32; break;
                case '6': inputSize = 64; break;
                default: throw new IllegalStateException("Couldn't determine the digest algorithm. Expected the ID to be 5 (SHA256) or 6 (SHA512), but was " + id);
            }
        }

        return inputSize;
    }

    private int getMaximumOutputSize() {
        // The output consists of the base64-encoded digest.  The maximum length
        // of a password string is therefore (excluding final NUL byte in the C
        // representation):
        //
        // SHA-256     80 characters
        // SHA-512     123 characters

        switch (id) {
            case '5': return 80;
            case '6': return 123;
            default: throw new IllegalStateException("Couldn't determine the digest algorithm. Expected the ID to be 5 (SHA256) or 6 (SHA512), but was " + id);
        }
    }

    private void produceOutput512(byte[] finalDigest, StringBuilder output) {
        //TODO: this is mainly a translation from the code in the spec, can probably be optimized
        output.append(produceCharsFromBytes(finalDigest[0], finalDigest[21], finalDigest[42], 4));
        output.append(produceCharsFromBytes(finalDigest[22], finalDigest[43], finalDigest[1], 4));
        output.append(produceCharsFromBytes(finalDigest[44], finalDigest[2], finalDigest[23], 4));
        output.append(produceCharsFromBytes(finalDigest[3], finalDigest[24], finalDigest[45], 4));
        output.append(produceCharsFromBytes(finalDigest[25], finalDigest[46], finalDigest[4], 4));
        output.append(produceCharsFromBytes(finalDigest[47], finalDigest[5], finalDigest[26], 4));
        output.append(produceCharsFromBytes(finalDigest[6], finalDigest[27], finalDigest[48], 4));
        output.append(produceCharsFromBytes(finalDigest[28], finalDigest[49], finalDigest[7], 4));
        output.append(produceCharsFromBytes(finalDigest[50], finalDigest[8], finalDigest[29], 4));
        output.append(produceCharsFromBytes(finalDigest[9], finalDigest[30], finalDigest[51], 4));
        output.append(produceCharsFromBytes(finalDigest[31], finalDigest[52], finalDigest[10], 4));
        output.append(produceCharsFromBytes(finalDigest[53], finalDigest[11], finalDigest[32], 4));
        output.append(produceCharsFromBytes(finalDigest[12], finalDigest[33], finalDigest[54], 4));
        output.append(produceCharsFromBytes(finalDigest[34], finalDigest[55], finalDigest[13], 4));
        output.append(produceCharsFromBytes(finalDigest[56], finalDigest[14], finalDigest[35], 4));
        output.append(produceCharsFromBytes(finalDigest[15], finalDigest[36], finalDigest[57], 4));
        output.append(produceCharsFromBytes(finalDigest[37], finalDigest[58], finalDigest[16], 4));
        output.append(produceCharsFromBytes(finalDigest[59], finalDigest[17], finalDigest[38], 4));
        output.append(produceCharsFromBytes(finalDigest[18], finalDigest[39], finalDigest[60], 4));
        output.append(produceCharsFromBytes(finalDigest[40], finalDigest[61], finalDigest[19], 4));
        output.append(produceCharsFromBytes(finalDigest[62], finalDigest[20], finalDigest[41], 4));

        // For the last group there are not enough bytes left in the digest and the value zero is used in its place.
        output.append(produceCharsFromBytes((byte) '0', (byte) '0', finalDigest[63], 2));
    }

    private void produceOutput256(byte[] finalDigest, StringBuilder output) {
        //TODO: this is mainly a translation from the code in the spec, can probably be optimized
        output.append(produceCharsFromBytes(finalDigest[0], finalDigest[10], finalDigest[20], 4));
        output.append(produceCharsFromBytes(finalDigest[21], finalDigest[1], finalDigest[11], 4));
        output.append(produceCharsFromBytes(finalDigest[12], finalDigest[22], finalDigest[2], 4));
        output.append(produceCharsFromBytes(finalDigest[3], finalDigest[13], finalDigest[23], 4));
        output.append(produceCharsFromBytes(finalDigest[24], finalDigest[4], finalDigest[14], 4));
        output.append(produceCharsFromBytes(finalDigest[15], finalDigest[25], finalDigest[5], 4));
        output.append(produceCharsFromBytes(finalDigest[6], finalDigest[16], finalDigest[26], 4));
        output.append(produceCharsFromBytes(finalDigest[27], finalDigest[7], finalDigest[17], 4));
        output.append(produceCharsFromBytes(finalDigest[18], finalDigest[28], finalDigest[8], 4));
        output.append(produceCharsFromBytes(finalDigest[9], finalDigest[19], finalDigest[29], 4));

        // For the last group there are not enough bytes left in the digest and the value zero is used in its place.
        output.append(produceCharsFromBytes((byte) '0', finalDigest[31], finalDigest[30], 3));
    }

    private char[] produceCharsFromBytes(byte first, byte second, byte third, int numOfChars) {
        //TODO: this is mainly a translation from the code in the spec, can probably be optimized
        String map = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        // note that the original C uses "unsigned char", and we use byte (because of MessageDigest), so, we need to
        // get a 8-bit unsigned char by using a binary-and
        int offset = ((first & 0xFF) << 16) | ((second & 0xFF) << 8) | (third & 0xFF);

        char[] output = new char[numOfChars];
        for (int i = 0 ; i < numOfChars ; i++) {
            output[i] = map.charAt(offset & 0x3F);
            offset >>= 6;
        }

        return output;
    }
}
