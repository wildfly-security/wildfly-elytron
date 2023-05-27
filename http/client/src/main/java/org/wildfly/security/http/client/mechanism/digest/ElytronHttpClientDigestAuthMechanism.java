/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.http.client.mechanism.digest;

import org.wildfly.security.http.client.mechanism.digest.util.DigestHttpMechanismUtil;
import org.wildfly.security.http.client.utils.ElytronHttpClientCredentialUtils;
import org.wildfly.security.mechanism.AuthenticationMechanismException;

import java.net.URI;
import java.net.http.HttpRequest;

/**
 * Elytron client for HTTP authentication
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class ElytronHttpClientDigestAuthMechanism {

    private static ElytronHttpClientCredentialUtils elytronHttpClientCredentialProvider = new ElytronHttpClientCredentialUtils();

    public static HttpRequest evaluateMechanism(URI uri, String authHeader) throws AuthenticationMechanismException {
        String userName = elytronHttpClientCredentialProvider.getUserName(uri);
        String password = elytronHttpClientCredentialProvider.getPassword(uri);
        return DigestHttpMechanismUtil.createDigestRequest(uri, userName, password, authHeader);
    }
}
