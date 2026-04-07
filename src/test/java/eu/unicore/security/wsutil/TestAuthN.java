package eu.unicore.security.wsutil;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;

import eu.unicore.security.wsutil.client.OAuthBearerTokenOutInterceptor;

public class TestAuthN extends AbstractTestBase
{

	@Test
	public void testHTTPAuth()
	{
		try
		{
			System.out.println("\nTest HTTP\n");
			MockSecurityConfig config = new MockSecurityConfig(true, false, false); 
			SimpleSecurityService s = makeProxy(config);
			
			int n=100;
			for (int i=0; i<n; i++)
			{
				String httpRet = s.TestHTTPCreds();
				String http = MockSecurityConfig.HTTP_USER + "-" + MockSecurityConfig.HTTP_PASSWD;
				assertTrue(http.equals(httpRet));
			}
			
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}


	@Test
	public void testPlainHTTPAuth()
	{
		try
		{
			System.out.println("\nTest plain HTTP\n");
			MockSecurityConfig config = new MockSecurityConfig(true, false, false); 
			SimpleSecurityService s = makePlainProxy(config);
			
			int n=100;
			for (int i=0; i<n; i++)
			{
				String httpRet = s.TestHTTPCreds();
				String http = MockSecurityConfig.HTTP_USER + "-" + MockSecurityConfig.HTTP_PASSWD;
				assertTrue(http.equals(httpRet));
			}
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}
	
	@Test
	public void testBearerToken(){
		try
		{
			String token = "test123";
			System.out.println("\nTest Bearer token\n");
			MockSecurityConfig config = new MockSecurityConfig(false, false, false); 
			config.getExtraSecurityTokens().put(OAuthBearerTokenOutInterceptor.TOKEN_KEY,token);
			
			SimpleSecurityService s = makeProxy(config);
			String ret = s.TestBearerToken();
			assertTrue(ret.contains(token));
			
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

}