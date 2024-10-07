/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2024 Red Hat, Inc. and/or its affiliates.
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
package org.wildfly.security.password.impl;

import org.junit.Assert;
import org.junit.Test;

public class PasswordUtilTest {

    @Test
    public void testConvertBytesToInt() {
        Assert.assertEquals(0, PasswordUtil.convertBytesToInt(new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00}));
        Assert.assertEquals(Integer.MAX_VALUE, PasswordUtil.convertBytesToInt(new byte[] {(byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff}));
        Assert.assertEquals(Integer.MIN_VALUE, PasswordUtil.convertBytesToInt(new byte[] {(byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00}));
        Assert.assertEquals(-1, PasswordUtil.convertBytesToInt(new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}));
    }
}
