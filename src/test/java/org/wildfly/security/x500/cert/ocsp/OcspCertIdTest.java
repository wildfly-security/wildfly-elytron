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

import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.asn1.util.ASN1;

import org.junit.Assert;
import org.junit.Test;

public class OcspCertIdTest {

    private CertId cert1 = new CertId(ASN1.OID_SHA1,
            CodePointIterator.ofString("056acea8ab97ad48f2a1016653b14f837a9e6773").hexDecode().drain(),
            CodePointIterator.ofString("def06922b82bc769e70683f4766787521a49b0dd").hexDecode().drain(),
            BigInteger.valueOf(2553437807527164539L));

    private CertId cert2 = new CertId(ASN1.OID_SHA1,
            CodePointIterator.ofString("056acea8ab97ad48f2a1016653b14f837a9e6773").hexDecode().drain(),
            CodePointIterator.ofString("def06922b82bc769e70683f4766787521a49b0dd").hexDecode().drain(),
            BigInteger.valueOf(7010134036373951907L));

    @Test
    public void testCertIdEquals() {
        Assert.assertTrue(cert1.equals(cert1));
        Assert.assertFalse(cert1.equals(cert2));
    }
}
