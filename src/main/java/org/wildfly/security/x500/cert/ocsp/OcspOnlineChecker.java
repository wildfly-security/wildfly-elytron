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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.wildfly.security._private.ElytronMessages;

/**
 * A default implementation of OCSP checker which always contact the OCSP responder.
 */
public class OcspOnlineChecker implements OcspChecker {

    private final int timeout;

    /**
     * Construct the OCSP checker.
     *
     * @param timeout the timeout value in milliseconds (zero for infinite timeout)
     */
    public OcspOnlineChecker(int timeout) {
        this.timeout = timeout;
    }

    @Override
    public OcspStatus obtainStatus(CertId certId, X509Certificate issuer, URL responder, OcspSignatureVerifier signatureVerifier)
            throws CertificateException, IOException {
        OcspRequest request = new OcspRequest(Collections.singletonList(certId));
        OcspResponse response = processRequest(responder, request);
        boolean verified = signatureVerifier.check(response, issuer);
        if (! verified) {
            throw ElytronMessages.ocsp.invalidSignatureOfOcspResponse(responder);
        }
        return response.getResults().get(certId);
    }

    /**
     * Send one OCSP request to given OCSP responder and process a response.
     *
     * @param responder the OCSP responder
     * @param request the OCSP request
     * @return the OCSP response
     * @throws IOException if the connection has failed
     * @throws CertificateException if OCSP communication was not successful (untrusted signature, rejected request)
     */
    private OcspResponse processRequest(URL responder, OcspRequest request) throws IOException, CertificateException {
        HttpURLConnection conn = (HttpURLConnection) responder.openConnection();

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/ocsp-request");
        conn.setConnectTimeout(timeout);
        conn.setReadTimeout(timeout);
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(request.getEncoded());
        }

        OcspResponse response = new OcspResponse();
        try (InputStream is = conn.getInputStream()) {
            response.parse(streamToByteArray(is));
            return response;
        }
    }

    private static byte[] streamToByteArray(InputStream is) throws IOException {
        byte[] data = new byte[256];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int i; (i = is.read(data)) != -1; )
            baos.write(data, 0, i);
        return baos.toByteArray();
    }

}
