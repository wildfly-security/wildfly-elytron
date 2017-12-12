/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.asn1.util;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class OidsUtilTest {

    @Test
    public void testAttributeNameToOid() throws Exception {
        Assert.assertEquals("2.5.4.8", OidsUtil.attributeNameToOid(OidsUtil.Category.RDN, "ST"));
        Assert.assertEquals("2.5.4.8", OidsUtil.attributeNameToOid(OidsUtil.Category.RDN, "s"));
    }

    @Test
    public void testOidToAttributeName() throws Exception {
        Assert.assertEquals("ST", OidsUtil.oidToAttributeName(OidsUtil.Category.RDN, "2.5.4.8"));
    }
}