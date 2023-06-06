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

package org.wildfly.security.http.client.utils;

import javax.net.ssl.SSLContext;
import java.net.URI;

/**
 * Elytron client for HTTP authentication
 *
 * @author <a href="mailto:kekumar@redhat.com">Keshav Kumar</a>
 */
public class ElytronHttpClientCredentialUtils {

    private HttpMechClientConfigUtil httpMechClientConfigUtil = new HttpMechClientConfigUtil();

    public String getUserName(URI uri){
        return httpMechClientConfigUtil.getUsername(uri);
    }

    public String getPassword(URI uri){
        return httpMechClientConfigUtil.getPassword(uri);
    }

    public String getToken(URI uri) {
        return httpMechClientConfigUtil.getToken(uri);
    }

    public SSLContext getSSLContext(URI uri){
        return httpMechClientConfigUtil.getSSLContext(uri);
    }
}
