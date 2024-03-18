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
