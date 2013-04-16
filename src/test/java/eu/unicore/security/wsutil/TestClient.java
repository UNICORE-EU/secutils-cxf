package eu.unicore.security.wsutil;

import org.apache.cxf.configuration.security.ProxyAuthorizationPolicy;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;

import eu.unicore.util.httpclient.HttpClientProperties;

public class TestClient extends AbstractTestBase{

	public void testHttpProxySettings()throws Exception{

		MockSecurityConfig sec = new MockSecurityConfig(true, false, false); 
		sec.getHttpClientProperties().setProperty(HttpClientProperties.HTTP_PROXY_HOST, "http://foo");
		sec.getHttpClientProperties().setProperty(HttpClientProperties.HTTP_PROXY_PORT, "123");
		sec.getHttpClientProperties().setProperty(HttpClientProperties.HTTP_PROXY_USER, "user");
		sec.getHttpClientProperties().setProperty(HttpClientProperties.HTTP_PROXY_PASS, "pass");
		SimpleSecurityService s = makeProxy(sec);
		
		Client xfc=ClientProxy.getClient(s);
		HTTPConduit hc=(HTTPConduit)xfc.getConduit();
		
		ProxyAuthorizationPolicy ap=hc.getProxyAuthorization();
		assertEquals("user",ap.getUserName());
		assertEquals("pass",ap.getPassword());

		assertEquals("http://foo",hc.getClient().getProxyServer());
		assertEquals(123,hc.getClient().getProxyServerPort());
		
	}

}
