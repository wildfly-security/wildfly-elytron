/*
 * Copyright 2021 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.http.util;

import org.wildfly.security.http.HttpServerCookie;

/**
 * A simple implementation of {@link HttpServerCookie}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SimpleHttpServerCookie implements HttpServerCookie {

    private final String name;
    private final String value;
    private final String domain;
    private final int maxAge;
    private final String path;
    private final boolean secure;
    private final int version;
    private final boolean httpOnly;

    SimpleHttpServerCookie(String name, String value, String domain, int maxAge, String path, boolean secure, int version, boolean httpOnly) {
        super();
        this.name = name;
        this.value = value;
        this.domain = domain;
        this.maxAge = maxAge;
        this.path = path;
        this.secure = secure;
        this.version = version;
        this.httpOnly = httpOnly;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public String getDomain() {
        return domain;
    }

    @Override
    public int getMaxAge() {
        return maxAge;
    }

    @Override
    public String getPath() {
        return path;
    }

    @Override
    public boolean isSecure() {
        return secure;
    }

    @Override
    public int getVersion() {
        return version;
    }

    @Override
    public boolean isHttpOnly() {
        return httpOnly;
    }

    public static HttpServerCookie newInstance(String name, String value, String domain, int maxAge, String path, boolean secure, int version, boolean httpOnly) {
        return new SimpleHttpServerCookie(name, value, domain, maxAge, path, secure, version, httpOnly);
    }
}
