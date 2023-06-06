package org.wildfly.security.http.client;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.client.ElytronXmlParser;
import org.wildfly.security.auth.client.InvalidAuthenticationConfigurationException;
import org.wildfly.security.http.client.mechanism.cert.ElytronHttpClientCertAuthMechanism;
import org.wildfly.security.http.client.utils.ClientCertSSLTestUtils;
import org.wildfly.security.auth.client.AuthenticationContext;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
//import java.net.http.HttpResponse;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.cert.CertificateException;

import static java.security.AccessController.doPrivileged;

public class ElytronHttpClientCertTest {
    static final String RESOURCES = "./target/keystores/";
    private static SSLServerSocketTestInstance sslServerSocketTestInstancePort10001;

    @BeforeClass
    public static void before() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException {
        ClientCertSSLTestUtils.createKeystores();

        sslServerSocketTestInstancePort10001 = new SSLServerSocketTestInstance(RESOURCES + "server1.keystore.jks", RESOURCES + "server1.truststore.jks", 10001);

        sslServerSocketTestInstancePort10001.run();
    }

    @AfterClass
    public static void after() {
        sslServerSocketTestInstancePort10001.stop();

        ClientCertSSLTestUtils.deleteKeystores();
    }

    @Test
    public void testElytronHttpClientCertAuth(){
        getAuthenticationContext("wildfly-config-http-client-cert.xml").run(() -> {
           try {
               URI uri = new URI("http://localhost:10001");
               ElytronHttpClientCertAuthMechanism.evaluateRequest(uri);
//               System.out.println(httpResponse);
           }catch (Exception e){
                e.printStackTrace();
           }
        });
    }

    private AuthenticationContext getAuthenticationContext(String path) {
        return doPrivileged((PrivilegedAction<AuthenticationContext>) () -> {
            URL config = getClass().getResource(path);
            try {
                return ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI()).create();
            } catch (Exception e) {
                e.printStackTrace();
                Assert.assertEquals("fine", e.getMessage());
                throw new InvalidAuthenticationConfigurationException(e);
            }
        });
    }
}
