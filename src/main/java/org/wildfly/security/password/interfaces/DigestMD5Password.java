/*
 * JBoss, Home of Professional Open Source
 * Copyright 2013 Red Hat, Inc., and individual contributors
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
 * Digest MD5 (pre-digested) password.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public interface DigestMD5Password extends OneWayPassword {

    String ALGORITHM_DIGEST_MD5 = "digest-md5";

    byte[] getHA1();

    byte[] getNonce();

    int getNonceCount();

    byte[] getCnonce();

    String getAuthzid();

    String getQop();

    String getDigestURI();

    byte[] getDigestResponse();
}
