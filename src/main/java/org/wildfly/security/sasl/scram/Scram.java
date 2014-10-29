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

package org.wildfly.security.sasl.scram;

import java.nio.charset.StandardCharsets;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class Scram {

    public static final String SCRAM_SHA_1 = "SCRAM-SHA-1";
    public static final String SCRAM_SHA_1_PLUS = "SCRAM-SHA-1-PLUS";
    public static final String SCRAM_SHA_256 = "SCRAM-SHA-256";
    public static final String SCRAM_SHA_256_PLUS = "SCRAM-SHA-256-PLUS";
    public static final String SCRAM_SHA_384 = "SCRAM-SHA-384";
    public static final String SCRAM_SHA_384_PLUS = "SCRAM-SHA-384-PLUS";
    public static final String SCRAM_SHA_512 = "SCRAM-SHA-512";
    public static final String SCRAM_SHA_512_PLUS = "SCRAM-SHA-512-PLUS";

    static final byte[] CLIENT_KEY_BYTES = "Client Key".getBytes(StandardCharsets.UTF_8);
    static final byte[] SERVER_KEY_BYTES = "Server Key".getBytes(StandardCharsets.UTF_8);
}
