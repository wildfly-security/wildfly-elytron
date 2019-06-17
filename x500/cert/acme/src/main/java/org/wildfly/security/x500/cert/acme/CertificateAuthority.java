/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert.acme;

import org.wildfly.common.Assert;

/**
 * A class that represents an <a href="https://tools.ietf.org/html/draft-ietf-acme-acme-18.txt">Automatic Certificate
 * Management Environment (ACME)</a> certificate authority endpoint.
 *
 * @author <a href="mailto:dvilkola@redhat.com">Diana Vilkolakova</a>
 * @since 1.9.0
 */
public class CertificateAuthority {

    private static final String DIRECTORY = "directory";
    private static final String LETS_ENCRYPT_STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/" + DIRECTORY;
    private static final String LETS_ENCRYPT_URL = "https://acme-v02.api.letsencrypt.org/" + DIRECTORY;
    private String name;
    private String url;
    private String stagingUrl;

    public static final CertificateAuthority LETS_ENCRYPT = new CertificateAuthority("LetsEncrypt", LETS_ENCRYPT_URL, LETS_ENCRYPT_STAGING_URL);

    public CertificateAuthority(String name, String url, String stagingUrl) {
        this.name = name;
        this.url = url;
        this.stagingUrl = stagingUrl;
    }

    /**
     * Get the default certificate authority endpoint.
     *
     * @return LETS_ENCRYPT certificate authority holding Let's Encrypt URLs
     */
    public static CertificateAuthority getDefault() {
        return LETS_ENCRYPT;
    }

    /**
     * Get the name of certificate authority.
     *
     * @return name of the certificate authority
     */
    public String getName() {
        return name;
    }

    /**
     * Get the certificate authority URL
     *
     * @return certificate authority URL
     */
    public String getUrl() {
        return url;
    }

    /**
     * Get the certificate authority staging URL
     *
     * @return certificate authority staging URL
     */
    public String getStagingUrl() {
        return stagingUrl;
    }

    /**
     * Set the name of certificate authority.
     *
     * @param name the name of certificate authority (must not be {@code null})
     */
    public void setName(String name) {
        Assert.checkNotNullParam("name", name);
        this.name = name;
    }

    /**
     * Set the URL of certificate authority.
     *
     * @param url URL of certificate authority (must not be {@code null})
     */
    public void setUrl(String url) {
        Assert.checkNotNullParam("url", url);
        this.url = url;
    }

    /**
     * Set the staging URL of certificate authority.
     *
     * @param stagingUrl staging URL of certificate authority
     */
    public void setStagingUrl(String stagingUrl) {
        this.stagingUrl = stagingUrl;
    }
}
