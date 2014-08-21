package org.wildfly.sasl.test;

import static org.junit.Assert.assertEquals;

import java.security.MessageDigest;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.sasl.util.UsernamePasswordHashUtil;

/**
 * Tests of org.wildfly.sasl.util.UsernamePasswordHashUtil
 * 
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class UsernamePasswordHashUtilTest {
	
	@Test
	public void testGeneratingHex() throws Exception {
		UsernamePasswordHashUtil util = new UsernamePasswordHashUtil();
		String hash = util.generateHashedHexURP("admin", "test", "secret".toCharArray());
		assertEquals("d6f18efa527f1bd22b4a67fc621cfbe7",hash);
	}
	
	@Test
	public void testGeneratingBytes() throws Exception {
		UsernamePasswordHashUtil util = new UsernamePasswordHashUtil();
		byte[] hash = util.generateHashedURP("admin", "test", "secret".toCharArray());
		Assert.assertArrayEquals(new byte[]{(byte)0xd6,(byte)0xf1,(byte)0x8e,(byte)0xfa,(byte)0x52,(byte)0x7f,(byte)0x1b,(byte)0xd2,(byte)0x2b,(byte)0x4a,(byte)0x67,(byte)0xfc,(byte)0x62,(byte)0x1c,(byte)0xfb,(byte)0xe7},hash);
	}
	
	@Test
	public void testGeneratingHexWithUtf() throws Exception {
		UsernamePasswordHashUtil util = new UsernamePasswordHashUtil();
		String hash = util.generateHashedHexURP("管理员", "测试", "秘密".toCharArray());
		assertEquals("64a5cd94a3953484a1e473d0ca35d208",hash);
	}
	
	@Test
	public void testGeneratingHexWithAlternativeDigest() throws Exception {
		UsernamePasswordHashUtil util = new UsernamePasswordHashUtil(MessageDigest.getInstance("SHA1"));
		String hash = util.generateHashedHexURP("admin", "test", "secret".toCharArray());
		assertEquals("88b8bf3682564e447713c1ed8b09810df135195a",hash);
	}
	
	@Test
	public void testGeneratingBlank() throws Exception {
		UsernamePasswordHashUtil util = new UsernamePasswordHashUtil();
		String hash = util.generateHashedHexURP("", "", new char[]{});
		assertEquals("4501c091b0366d76ea3218b6cfdd8097",hash);
	}
	
}
