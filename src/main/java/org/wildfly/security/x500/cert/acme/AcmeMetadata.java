/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.x500.cert.acme;

import org.wildfly.common.Assert;

/**
 * A class that represents the metadata associated with an <a href="https://www.ietf.org/id/draft-ietf-acme-acme-14.txt">Automatic
 * Certificate Management Environment (ACME)</a> server.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @since 1.5.0
 */
public final class AcmeMetadata {

    private final String termsOfServiceUrl;
    private final String websiteUrl;
    private final String[] caaIdentities;
    private final boolean externalAccountRequired;

    private AcmeMetadata(Builder builder) {
        this.termsOfServiceUrl = builder.termsOfServiceUrl;
        this.websiteUrl = builder.websiteUrl;
        this.caaIdentities = builder.caaIdentities;
        this.externalAccountRequired = builder.externalAccountRequired;
    }

    /**
     * Get the terms of service URL.
     *
     * @return the terms of service URL
     */
    public String getTermsOfServiceUrl() {
        return termsOfServiceUrl;
    }

    /**
     * Get the website URL.
     *
     * @return the website URL
     */
    public String getWebsiteUrl() {
        return websiteUrl;
    }

    /**
     * Get the CAA identities.
     *
     * @return the CAA identities
     */
    public String[] getCAAIdentities() {
        return caaIdentities;
    }

    /**
     * Get whether or not an external account is required.
     *
     * @return whether or not an external account is required
     */
    public boolean isExternalAccountRequired() {
        return externalAccountRequired;
    }

    /**
     * Construct a new builder instance.
     *
     * @return the new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private String termsOfServiceUrl;
        private String websiteUrl;
        private String[] caaIdentities;
        private boolean externalAccountRequired;

        /**
         * Construct a new uninitialized instance.
         */
        Builder() {
        }

        /**
         * Set the terms of service URL.
         *
         * @param termsOfServiceUrl the terms of service URL (must not be {@code null})
         * @return this builder instance
         */
        public Builder setTermsOfServiceUrl(final String termsOfServiceUrl) {
            Assert.checkNotNullParam("termsOfServiceUrl", termsOfServiceUrl);
            this.termsOfServiceUrl = termsOfServiceUrl;
            return this;
        }

        /**
         * Set the website URL.
         *
         * @param websiteUrl the website URL (must not be {@code null})
         * @return this builder instance
         */
        public Builder setWebsiteUrl(final String websiteUrl) {
            Assert.checkNotNullParam("websiteUrl", websiteUrl);
            this.websiteUrl = websiteUrl;
            return this;
        }


        /**
         * Set the CAA identities.
         *
         * @param caaIdentities the CAA identities (must not be {@code null})
         * @return this builder instance
         */
        public Builder setCaaIdentities(final String[] caaIdentities) {
            Assert.checkNotNullParam("caaIdentities", caaIdentities);
            this.caaIdentities = caaIdentities;
            return this;
        }

        /**
         * Set whether or not an external account is required.
         *
         * @param externalAccountRequired {@code true} if an external account is required and {@code false} otherwise
         * @return this builder instance
         */
        public Builder setExternalAccountRequired(final boolean externalAccountRequired) {
            this.externalAccountRequired = externalAccountRequired;
            return this;
        }

        /**
         * Create the ACME metadata.
         *
         * @return the newly created ACME metadata
         */
        public AcmeMetadata build() throws IllegalArgumentException {
            return new AcmeMetadata(this);
        }
    }
}
