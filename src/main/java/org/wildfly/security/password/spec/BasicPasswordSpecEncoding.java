/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.password.spec;

import static org.wildfly.security.util.ProviderUtil.INSTALLED_PROVIDERS;

import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.function.Supplier;

/**
 * Provide methods for encoding and decoding of {@link PasswordSpec}.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class BasicPasswordSpecEncoding {

    // the value for each identifier must be kept and can not change
    private static final byte CLEAR_PASSWORD_SPEC_ID = 1;
    private static final byte DIGEST_PASSWORD_SPEC_ID = 2;
    private static final byte HASH_PASSWORD_SPEC_ID = 3;
    private static final byte SALTED_HASH_PASSWORD_SPEC_ID = 4;
    private static final byte ITERATED_SALTED_HASH_SPEC_ID = 5;

    private BasicPasswordSpecEncoding() {}

    /**
     * Encode the given {@link PasswordSpec} to a byte array.
     *
     * @param passwordSpec the password spec to encode
     * @return a byte array representing the encoded password or null if no encoder was capable to encode the given password
     */
    public static byte[] encode(PasswordSpec passwordSpec) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (passwordSpec instanceof ClearPasswordSpec) {
            return encodeClearPasswordSpec((ClearPasswordSpec) passwordSpec);
        } else if (passwordSpec instanceof DigestPasswordSpec) {
            return encodeDigestPasswordSpec((DigestPasswordSpec) passwordSpec);
        } else if (passwordSpec instanceof SaltedHashPasswordSpec) {
            return encodeSaltedHashPasswordSpec((SaltedHashPasswordSpec) passwordSpec);
        } else if (passwordSpec instanceof IteratedSaltedHashPasswordSpec) {
            return encodeIteratedSaltedHashSpec((IteratedSaltedHashPasswordSpec) passwordSpec);
        } else if (passwordSpec instanceof HashPasswordSpec) {
            return encodeHashPasswordSpec((HashPasswordSpec) passwordSpec);
        }

        return null;
    }

    /**
     * Encode the given {@link Password} to a byte array.
     *
     * @param password the password to encode
     * @return a byte array representing the encoded password or null if no encoder was capable to encode the given password
     */
    public static byte[] encode(Password password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return encode(password, INSTALLED_PROVIDERS);
    }

    /**
     * Encode the given {@link Password} to a byte array.
     *
     * @param password the password to encode
     * @param providers providers to use with the underlying {@link PasswordFactory}
     * @return a byte array representing the encoded password or null if no encoder was capable to encode the given password
     */
    public static byte[] encode(Password password, Supplier<Provider[]> providers) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(password.getAlgorithm(), providers);

        if (passwordFactory.convertibleToKeySpec(password, ClearPasswordSpec.class)) {
            return encodeClearPasswordSpec(passwordFactory.getKeySpec(password, ClearPasswordSpec.class));
        } else if (passwordFactory.convertibleToKeySpec(password, DigestPasswordSpec.class)) {
            return encodeDigestPasswordSpec(passwordFactory.getKeySpec(password, DigestPasswordSpec.class));
        } else if (passwordFactory.convertibleToKeySpec(password, SaltedHashPasswordSpec.class)) {
            return encodeSaltedHashPasswordSpec(passwordFactory.getKeySpec(password, SaltedHashPasswordSpec.class));
        } else if (passwordFactory.convertibleToKeySpec(password, IteratedSaltedHashPasswordSpec.class)) {
            return encodeIteratedSaltedHashSpec(passwordFactory.getKeySpec(password, IteratedSaltedHashPasswordSpec.class));
        } else if (passwordFactory.convertibleToKeySpec(password, HashPasswordSpec.class)) {
            return encodeHashPasswordSpec(passwordFactory.getKeySpec(password, HashPasswordSpec.class));
        }

        return null;
    }

    /**
     * Decode the given byte array and create a {@link PasswordSpec} from it.
     *
     * @param encoded the byte array representing the encoded password
     * @return a {@link PasswordSpec} instance created from the encoded password or null if no decoder was capable to decode the given format.
     */
    public static PasswordSpec decode(byte[] encoded) {
        ByteIterator iterator = ByteIterator.ofBytes(encoded);

        int identifier;

        try {
            identifier = iterator.next();
        } catch (Exception e) {
            throw ElytronMessages.log.couldNotObtainKeySpecEncodingIdentifier();
        }

        switch (identifier) {
            case CLEAR_PASSWORD_SPEC_ID:
                return decodeClearPasswordSpec(iterator);
            case DIGEST_PASSWORD_SPEC_ID:
                return decodeDigestPasswordSpec(iterator);
            case HASH_PASSWORD_SPEC_ID:
                return decodeHashPasswordSpec(iterator);
            case SALTED_HASH_PASSWORD_SPEC_ID:
                return decodeSaltedHashPasswordSpec(iterator);
            case ITERATED_SALTED_HASH_SPEC_ID:
                return decodeIteratedSaltedHashPasswordSpec(iterator);
            default:
                return null;
        }
    }

    private static byte[] encodeIteratedSaltedHashSpec(IteratedSaltedHashPasswordSpec keySpec) throws InvalidKeySpecException {
        byte[] salt = keySpec.getSalt();
        return new ByteStringBuilder().append(ITERATED_SALTED_HASH_SPEC_ID)
                .appendPackedUnsignedBE(keySpec.getIterationCount()).appendPackedUnsignedBE(salt.length).append(salt).append(keySpec.getHash()).toArray();
    }

    private static PasswordSpec decodeIteratedSaltedHashPasswordSpec(ByteIterator iterator) {
        int iterationCount = iterator.getPackedBE32();
        byte[] salt = iterator.drain(iterator.getPackedBE32());
        byte[] hash = iterator.drain();
        return new IteratedSaltedHashPasswordSpec(hash, salt, iterationCount);
    }

    private static byte[] encodeSaltedHashPasswordSpec(SaltedHashPasswordSpec keySpec) throws InvalidKeySpecException {
        byte[] salt = keySpec.getSalt();
        return new ByteStringBuilder().append(SALTED_HASH_PASSWORD_SPEC_ID)
                .appendPackedUnsignedBE(salt.length).append(salt).append(keySpec.getHash()).toArray();
    }

    private static PasswordSpec decodeSaltedHashPasswordSpec(ByteIterator iterator) {
        byte[] salt = iterator.drain(iterator.getPackedBE32());
        byte[] hash = iterator.drain();
        return new SaltedHashPasswordSpec(hash, salt);
    }

    private static byte[] encodeHashPasswordSpec(HashPasswordSpec keySpec) throws InvalidKeySpecException {
        return new ByteStringBuilder().append(HASH_PASSWORD_SPEC_ID).append(keySpec.getDigest()).toArray();
    }

    private static PasswordSpec decodeHashPasswordSpec(ByteIterator iterator) {
        return new HashPasswordSpec(iterator.drain());
    }

    private static byte[] encodeDigestPasswordSpec(DigestPasswordSpec keySpec) throws InvalidKeySpecException {
        byte[] u = keySpec.getUsername().getBytes(StandardCharsets.UTF_8);
        byte[] r = keySpec.getRealm().getBytes(StandardCharsets.UTF_8);
        return new ByteStringBuilder().append(DIGEST_PASSWORD_SPEC_ID)
                .appendPackedUnsignedBE(u.length).append(u)
                .appendPackedUnsignedBE(r.length).append(r)
                .append(keySpec.getDigest()).toArray();
    }

    private static PasswordSpec decodeDigestPasswordSpec(ByteIterator iterator) {
        String username = iterator.drainToUtf8(iterator.getPackedBE32());
        String realm = iterator.drainToUtf8(iterator.getPackedBE32());
        byte[] digest = iterator.drain();
        return new DigestPasswordSpec(username, realm, digest);
    }

    private static byte[] encodeClearPasswordSpec(ClearPasswordSpec keySpec) throws InvalidKeySpecException {
        byte[] passwordBytes = CodePointIterator.ofChars(keySpec.getEncodedPassword()).asUtf8().drain();
        return new ByteStringBuilder().append(CLEAR_PASSWORD_SPEC_ID).append(passwordBytes).toArray();
    }

    private static PasswordSpec decodeClearPasswordSpec(ByteIterator iterator) {
        return new ClearPasswordSpec(iterator.asUtf8String().drainToString().toCharArray());
    }
}
