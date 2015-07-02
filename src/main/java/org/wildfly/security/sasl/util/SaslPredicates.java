/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Predicate;

/**
 * A collection of predicates which can be used to filter SASL mechanisms.
 *
 * @see FilterMechanismSaslClientFactory
 * @see FilterMechanismSaslServerFactory
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class SaslPredicates {
    private static final Set<String> MD5_MECHS = new HashSet<>(Arrays.asList(
        "CRAM-MD5",
        "DIGEST-MD5"
    ));

    private static final Set<String> SHA_MECHS = new HashSet<>(Arrays.asList(
        "DIGEST-SHA",
        "SCRAM-SHA-1",
        "SCRAM-SHA-1-PLUS"
    ));

    private static final Set<String> SHA_256_MECHS = new HashSet<>(Arrays.asList(
        "DIGEST-SHA-256",
        "SCRAM-SHA-256",
        "SCRAM-SHA-256-PLUS"
    ));

    private static final Set<String> SHA_384_MECHS = new HashSet<>(Arrays.asList(
        "DIGEST-SHA-384",
        "SCRAM-SHA-384",
        "SCRAM-SHA-384-PLUS"
    ));

    private static final Set<String> SHA_512_MECHS = new HashSet<>(Arrays.asList(
        "DIGEST-SHA-512",
        "SCRAM-SHA-512",
        "SCRAM-SHA-512-PLUS"
    ));

    private static final Set<String> MUTUAL_MECHS = new HashSet<>(Arrays.asList(
        "9798-M-DSA-SHA1",
        "9798-M-ECDSA-SHA1",
        "9798-M-RSA-SHA1-ENC"
    ));

    private static final Set<String> RECOMMENDED_MECHS = new HashSet<>(Arrays.asList(
        "9798-M-DSA-SHA1",
        "9798-M-ECDSA-SHA1",
        "9798-M-RSA-SHA1-ENC",
        "9798-U-DSA-SHA1",
        "9798-U-ECDSA-SHA1",
        "9798-U-RSA-SHA1-ENC",
        "ANONYMOUS",
        "EAP-AES128",
        "EAP-AES128-PLUS",
        "EXTERNAL",
        "OAUTH10A",
        "OAUTHBEARER",
        "OPENID20",
        "OTP",
        "SAML20",
        "SECURID"
    ));

    /**
     * A predicate which is true when the mechanism uses MD5.
     */
    public static final Predicate<String> HASH_MD5 = MD5_MECHS::contains;

    /**
     * A predicate which is true when the mechanism uses SHA.
     */
    public static final Predicate<String> HASH_SHA = SHA_MECHS::contains;

    /**
     * A predicate which is true when the mechanism uses SHA-256.
     */
    public static final Predicate<String> HASH_SHA_256 = SHA_256_MECHS::contains;

    /**
     * A predicate which is true when the mechanism uses SHA-384.
     */
    public static final Predicate<String> HASH_SHA_384 = SHA_384_MECHS::contains;

    /**
     * A predicate which is true when the mechanism uses SHA-512.
     */
    public static final Predicate<String> HASH_SHA_512 = SHA_512_MECHS::contains;

    /**
     * A predicate which is true when a GS2-family mechanism is being used.
     */
    public static final Predicate<String> GS2 = name -> name.startsWith("GS2-");

    /**
     * A predicate which is true when a SCRAM-family mechanism is being used.
     */
    public static final Predicate<String> SCRAM = name -> name.startsWith("SCRAM-");

    /**
     * A predicate which is true when the mechanism supports mutual authentication.
     */
    public static final Predicate<String> MUTUAL = ((Predicate<String>)MUTUAL_MECHS::contains).or(SCRAM).or(GS2);

    /**
     * A predicate which is true when a mechanism which uses channel binding is being used.
     */
    public static final Predicate<String> BINDING = name -> name.endsWith("-PLUS");

    /**
     * A predicate which is true when the name being tested is a recommended mechanism as of the time of this release.
     */
    public static final Predicate<String> RECOMMENDED = ((Predicate<String>)RECOMMENDED_MECHS::contains).or(GS2).or(SCRAM).and(HASH_MD5.negate());
}
