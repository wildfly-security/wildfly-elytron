/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert.ocsp;

import java.security.cert.CRLReason;

/**
 * The revocation status of a certificate.
 */
final class OcspStatus {
    private final CertStatus status;
    private final CRLReason reason;

    /**
     * Construct the status of the certificate.
     * @param status the status of the certificate
     * @param reason the reason that a certificate is revoked
     */
    OcspStatus(CertStatus status, CRLReason reason) {
        this.status = status;
        this.reason = reason;
    }

    /**
     * Get the status of the certificate.
     *
     * @return the status of the certificate
     */
    CertStatus getStatus() {
        return status;
    }

    /**
     * Get the reason that a certificate is revoked.
     *
     * @return the reason that a certificate is revoked
     */
    CRLReason getReason() {
        return reason;
    }

    @Override
    public String toString() {
        return "OcspStatus{" + status + ", reason=" + reason + '}';
    }

    enum CertStatus {
        GOOD,
        REVOKED,
        UNKNOWN
    }
}
