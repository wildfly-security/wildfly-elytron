/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2015 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.scram;

import static org.junit.Assert.*;

import javax.crypto.Mac;

import org.junit.Test;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.CodePointIterator;

/**
 * Test of SCRAM mechanism utils.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class ScramUtilTest {

    @Test
    public void testCalculateHi() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA1");
        char[] password = "pencil".toCharArray();
        byte[] salt = CodePointIterator.ofString("4125C247E43AB1E93C6DFF76").hexDecode().drain();

        byte[] saltedPassword = ScramUtil.calculateHi(mac, password, salt, 0, salt.length, 4096);

        assertEquals("1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d", ByteIterator.ofBytes(saltedPassword).hexEncode().drainToString());
    }

}
