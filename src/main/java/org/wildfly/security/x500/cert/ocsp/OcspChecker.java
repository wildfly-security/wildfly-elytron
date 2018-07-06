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

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * The object providing OCSP status of a certificate.
 */
public interface OcspChecker {

    /**
     * To obtain revocation status of the certificate.
     *
     * @param certId an OCSP specific identification of the checked certificate
     * @param issuer an issuer certificate of the checked certificate
     * @param responder the responder to check the certificate against
     * @param signatureVerifier a verifier of OCSP responses
     * @return the obtained status of the certificate
     * @throws CertificateException if an OCSP server has not provided appropriate response
     * @throws IOException if communication with OCSP responder has failed
     */
    OcspStatus obtainStatus(CertId certId, X509Certificate issuer, URL responder, OcspSignatureVerifier signatureVerifier)
            throws CertificateException, IOException;

}
