/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.digest;

import org.wildfly.common.Assert;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.ByteIterator;

import java.security.MessageDigestSpi;

/**
 * SHA-512/256 hashing implementation as defined in FIPS PUB 180-4 Secure Hash Standard
 */
public class SHA512_256MessageDigest extends MessageDigestSpi {

    private static final long[] K = {
            0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
            0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
            0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
            0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
            0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
            0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
            0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
            0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
            0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
            0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
            0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
            0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
            0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
            0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
            0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
            0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
            0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
            0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
            0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
            0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };

    private static final int BLOCK_SIZE = 128;

    private final byte[] tempByte = new byte[1];
    private final long[] H = new long[8];
    private final long[] W = new long[80];
    private final byte[] block = new byte[SHA512_256MessageDigest.BLOCK_SIZE];

    private long messageLength; // total length of the message
    private int bytesLoaded; // amount of used bytes in current block

    public SHA512_256MessageDigest() {
        engineReset();
    }

    @Override
    protected void engineReset() {
        bytesLoaded = 0;
        messageLength = 0;
        resetH(H);
    }

    protected static void resetH(long[] H) {
        H[0] = 0x22312194FC2BF72CL;
        H[1] = 0x9F555FA3C84C64C2L;
        H[2] = 0x2393B86B6F53B151L;
        H[3] = 0x963877195940EABDL;
        H[4] = 0x96283EE2A88EFFE3L;
        H[5] = 0xBE5E1E2553863992L;
        H[6] = 0x2B0199FC2C85B8AAL;
        H[7] = 0x0EB72DDC81C52CA2L;
    }

    protected byte[] resultFromH(long[] H) {
        ByteStringBuilder result = new ByteStringBuilder();
        for (byte i = 0; i < 4; i++) {
            result.appendBE(H[i]);
        }
        return result.toArray();
    }

    @Override
    protected void engineUpdate(byte input) {
        tempByte[0] = input;
        engineUpdate(tempByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        Assert.checkMinimumParameter("offset", 0, offset);
        Assert.checkMinimumParameter("len", 0, len);
        Assert.checkMaximumParameter("offset + len", input.length, offset + len);
        if (len == 0) return;

        messageLength += len;

        while (len > 0) {
            int loadingBytes = Math.min(len, BLOCK_SIZE - bytesLoaded); // amount of bytes from input into current block
            System.arraycopy(input, offset, block, bytesLoaded, loadingBytes);
            bytesLoaded += loadingBytes;
            offset += loadingBytes;
            len -= loadingBytes;

            if (bytesLoaded == BLOCK_SIZE) {
                ByteIterator bi = ByteIterator.ofBytes(block);

                // prepare the message schedule
                for (int i = 0; i < 16; i++) {
                    W[i] = bi.getBE64();
                }
                for(int i = 16; i < 80; i++) {
                    long s0 = rotr(W[i - 15], 1) ^ rotr(W[i - 15], 8) ^ (W[i - 15] >>> 7);
                    long s1 = rotr(W[i - 2], 19) ^ rotr(W[i - 2], 61) ^ (W[i - 2] >>> 6);
                    W[i] = W[i - 16] + s0 + W[i - 7] + s1;
                }

                processBlock();
                bytesLoaded = 0;
            }
        }
    }

    @Override
    protected byte[] engineDigest() {

        int paddingLen = bytesLoaded < 112 ? // SHS: L + 1 + k = 448 mod 512 (bits)
                BLOCK_SIZE - 9 - bytesLoaded : // 9 = "0x80" + 64-bit message length
                BLOCK_SIZE + BLOCK_SIZE - 9 - bytesLoaded;

        ByteStringBuilder postBuilder = new ByteStringBuilder();
        postBuilder.append((byte) 0x80); // terminating "1", zero-padded
        postBuilder.append(new byte[paddingLen]);
        postBuilder.appendBE(messageLength * 8); // bits
        byte[] postfix = postBuilder.toArray();

        engineUpdate(postfix, 0, postfix.length);

        byte[] result = resultFromH(H);
        engineReset();
        return result;
    }

    private void processBlock() {
        // initialize working variables
        long a = H[0];
        long b = H[1];
        long c = H[2];
        long d = H[3];
        long e = H[4];
        long f = H[5];
        long g = H[6];
        long h = H[7];

        for(int t = 0; t < 80; t++) {
            long temp1 = h + sigma1(e) + ch(e, f, g) + K[t] + W[t];
            long temp2 = sigma0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // compute intermediate hash value
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    private static long sigma0(long a) {
        return rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
    }

    private static long sigma1(long e) {
        return rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
    }

    private static long ch(long e, long f, long g) {
        return e & f ^ ~e & g;
    }

    private static long maj(long a, long b, long c) {
        return a & b ^ a & c ^ b & c;
    }

    private static long rotr(long x, int bits) {
        return x >>> bits | x << (64 - bits);
    }
}
