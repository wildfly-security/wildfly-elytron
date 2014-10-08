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

package org.wildfly.security.password.interfaces;

import org.wildfly.security.password.OneWayPassword;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public interface TrivialDigestPassword extends OneWayPassword {
    String ALGORITHM_DIGEST_MD2 = "digest-md2";
    String ALGORITHM_DIGEST_MD5 = "digest-md5";
    String ALGORITHM_DIGEST_SHA_1 = "digest-sha-1";
    String ALGORITHM_DIGEST_SHA_256 = "digest-sha-256";
    String ALGORITHM_DIGEST_SHA_384 = "digest-sha-384";
    String ALGORITHM_DIGEST_SHA_512 = "digest-sha-512";

    byte[] getDigest();
}
