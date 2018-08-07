/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.asn1.util.ASN1;

public class OcspParsingTest {

    private CertId cert1 = new CertId(ASN1.OID_SHA1,
            CodePointIterator.ofString("056acea8ab97ad48f2a1016653b14f837a9e6773").hexDecode().drain(),
            CodePointIterator.ofString("def06922b82bc769e70683f4766787521a49b0dd").hexDecode().drain(),
            BigInteger.valueOf(2553437807527164539L)
    );

    private CertId cert2 = new CertId(ASN1.OID_SHA1,
            CodePointIterator.ofString("056acea8ab97ad48f2a1016653b14f837a9e6773").hexDecode().drain(),
            CodePointIterator.ofString("def06922b82bc769e70683f4766787521a49b0dd").hexDecode().drain(),
            BigInteger.valueOf(7010134036373951907L)
    );

    @Test
    public void testRequestGenerating() {
        List<CertId> certs = new LinkedList<>();
        certs.add(cert1);
        certs.add(cert2);
        OcspRequest request = new OcspRequest(certs);
        String encoded = ByteIterator.ofBytes(request.getEncoded()).base64Encode().drainToString();
        Assert.assertEquals("MIGRMIGOoAMCAQAwgYYwQTA/MAcGBSsOAwIaBBQFas6oq5etSPKhAWZTsU+Dep5ncwQU3vBpIrgrx2nnBoP0dmeHUhpJsN0CCCNvoihBtXp7MEEwPzAHBgUrDgMCGgQUBWrOqKuXrUjyoQFmU7FPg3qeZ3MEFN7waSK4K8dp5waD9HZnh1IaSbDdAghhSP/DyfHVow==", encoded);
    }

    @Test
    public void testResponseParsing() throws CertificateException {
        String encoded = "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";

        OcspResponse response = new OcspResponse();
        response.parse(CodePointIterator.ofString(encoded).base64Decode().drain());

        Assert.assertEquals("CN=OCSP1, O=xipki, C=DE", response.getCertificates().get(0).getSubjectDN().getName());
        Assert.assertEquals("CN=OCSP1, O=xipki, C=DE", response.getResponderName().toString());

        Assert.assertEquals(OcspStatus.CertStatus.GOOD, response.getResults().get(cert1).getStatus());
        Assert.assertEquals(OcspStatus.CertStatus.REVOKED, response.getResults().get(cert2).getStatus());
    }

}
