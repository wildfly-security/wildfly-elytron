package org.wildfly.security.auth.provider.ldap;

import java.nio.charset.Charset;
import java.security.MessageDigest;

import org.wildfly.security.auth.provider.CredentialSupport;
import org.wildfly.security.util.Base64;
import org.wildfly.security.util.ByteArrayIterator;
import org.wildfly.security.util.HexConverter;

public class Temp {

    static final Charset UTF_8 = Charset.forName("UTF-8");

    public static void main(String[] args) throws Exception {
        for (CredentialSupport outer : CredentialSupport.values()) {
            for (CredentialSupport inner : CredentialSupport.values()) {
                System.out.println(String.format("%s.compareTo(%s)=%d", outer, inner, outer.compareTo(inner)));
            }
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] response = digest.digest("xxxx".getBytes(UTF_8));

        StringBuilder builder = new StringBuilder();
        Base64.base64EncodeB(builder, new ByteArrayIterator(response));

        System.out.println("{sha512}" + builder.toString());

        byte[] salt = HexConverter.convertFromHex("86b075f45c21ad31".toCharArray());

        digest.update("xxxx".getBytes(UTF_8));
        digest.update(salt);

        response = digest.digest();

        byte[] combined = new byte[response.length + salt.length];
        System.arraycopy(response, 0, combined, 0, response.length);
        System.arraycopy(salt,0,combined, response.length, salt.length);

        builder = new StringBuilder();
        Base64.base64EncodeB(builder, new ByteArrayIterator(combined));

        System.out.println("{ssha512}" + builder.toString());
        System.out.println(String.format("Salt Length = %d, Hash Length = %d", salt.length, response.length));
    }

}
