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

package org.wildfly.security.http.util.sso;

/**
 * The relevent configuration for SingleSignOn.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class SingleSignOnConfiguration {

    private final String cookieName;
    private final String domain;
    private final String path;
    private final boolean httpOnly;
    private final boolean secure;

    public SingleSignOnConfiguration(String cookieName, String domain, String path, boolean httpOnly, boolean secure) {
        this.cookieName = cookieName;
        this.domain = domain;
        this.path = path;
        this.httpOnly = httpOnly;
        this.secure = secure;
    }

    public String getCookieName() {
        return cookieName;
    }

    public String getDomain() {
        return domain;
    }

    public String getPath() {
        return path;
    }

    public boolean isSecure() {
        return secure;
    }

    public boolean isHttpOnly() {
        return httpOnly;
    }

}
