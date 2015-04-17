package org.wildfly.security.sasl.scram;

import static org.junit.Assert.*;

import javax.crypto.Mac;

import org.junit.Test;
import org.wildfly.security.sasl.util.HexConverter;

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
        byte[] salt = HexConverter.convertFromHex("4125C247E43AB1E93C6DFF76");

        byte[] saltedPassword = ScramUtil.calculateHi(mac, password, salt, 0, salt.length, 4096);

        assertEquals("1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d", HexConverter.convertToHexString(saltedPassword));
    }

}
