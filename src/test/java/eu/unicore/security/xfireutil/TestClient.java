package eu.unicore.security.xfireutil;

import org.apache.cxf.configuration.security.ProxyAuthorizationPolicy;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;

import eu.unicore.util.httpclient.HttpUtils;

public class TestClient extends AbstractTestBase{

	public void testHttpProxySettings()throws Exception{

		MockSecurityConfig sec = new MockSecurityConfig(true, false, false); 
		sec.getExtraSettings().setProperty(HttpUtils.HTTP_PROXY_HOST, "http://foo");
		sec.getExtraSettings().setProperty(HttpUtils.HTTP_PROXY_PORT, "123");
		sec.getExtraSettings().setProperty(HttpUtils.HTTP_PROXY_USER, "user");
		sec.getExtraSettings().setProperty(HttpUtils.HTTP_PROXY_PASS, "pass");
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
