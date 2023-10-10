/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.unicore.samly2.SAMLConstants.AuthNClasses;
import eu.unicore.security.consignor.ConsignorAPI;
import eu.unicore.security.consignor.ConsignorAssertion;
import eu.unicore.security.consignor.ConsignorImpl;
import eu.unicore.security.wsutil.client.OAuthBearerTokenOutInterceptor;

public class TestAuthN extends AbstractTestBase
{
	public void testGWConsignorNormal()
	{
		try
		{
			System.out.println("\nTest GW assertion\n");

			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false); 
			SimpleSecurityService s = makeProxy(config);
			
			ConsignorAPI engine = new ConsignorImpl();
			X509Certificate consignor = configWrong.getCredential().getCertificate();
			ConsignorAssertion consignorA = engine.generateConsignorToken(
					MockSecurityConfig.GW_CRED.getSubjectName(),
					new X509Certificate[] {consignor},
					AuthNClasses.TLS, "127.0.0.1");
			Client xfireClient = ClientProxy.getClient(s);
			GwHandler gwH = new GwHandler();
			gwH.reinit(consignorA);
			xfireClient.getOutInterceptors().add(gwH);
			String consignorRet = s.TestConsignor();
			assertTrue(X500NameUtils.equal(consignor.getSubjectX500Principal(), consignorRet));
			String ip = s.TestIP();
			assertEquals("127.0.0.1", ip);
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testGWConsignorProxy()
	{
		try
		{
			System.out.println("\nTest GW assertion - proxy user\n");

			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false); 
			SimpleSecurityService s = makeProxy(config);
			
			ConsignorAPI engine = new ConsignorImpl();
			X509Certificate[] consignor = configWrong.getCredential().getCertificateChain();
			
			ProxyCertificateOptions proxyOpts = new ProxyCertificateOptions(consignor);
			ProxyCertificate proxyC = ProxyGenerator.generate(proxyOpts, 
					configWrong.getCredential().getKey());
			
			
			ConsignorAssertion consignorA = engine.generateConsignorToken(
					MockSecurityConfig.GW_CRED.getSubjectName(),
					proxyC.getCertificateChain(),
					AuthNClasses.TLS, "127.0.0.1");
			Client xfireClient = ClientProxy.getClient(s);
			GwHandler gwH = new GwHandler();
			gwH.reinit(consignorA);
			xfireClient.getOutInterceptors().add(gwH);
			
			String consignorRet = s.TestConsignor();
			assertTrue(X500NameUtils.equal(consignor[0].getSubjectX500Principal(), consignorRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testGWConsignorAnon()
	{
		try
		{
			System.out.println("\nTest GW anon assertion\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			
			SimpleSecurityService s = makeProxy(config);
			
			ConsignorAPI engine = new ConsignorImpl();
			ConsignorAssertion consignorA = engine.generateConsignorToken(
					MockSecurityConfig.GW_CRED.getSubjectName());
			Client xfireClient = ClientProxy.getClient(s);
			GwHandler gwH = new GwHandler();
			gwH.reinit(consignorA);
			xfireClient.getOutInterceptors().add(gwH);
			
			String consignorRet = s.TestConsignor();
			assertTrue(consignorRet == null);
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}
	
	public void testSSLConsignor() throws Exception
	{
		MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
		SimpleSecurityService s = makeProxy(config);

		String consignorRet = s.TestConsignor();
		String consignor = config.getCertDN();
		assertEquals(consignor, consignorRet);
	}

	public void testNoSSLConsignor()
	{
		try
		{
			System.out.println("\nTest no SSL\n");
			MockSecurityConfig config = new MockSecurityConfig(false, false, false); 
			SimpleSecurityService s = makeProxy(config);
			String consignorRet = s.TestConsignor();
			assertTrue(consignorRet == null);
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testInvalidSSLConsignor()
	{
		try
		{
			System.out.println("\nTest invalid SSL\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, 
					MockSecurityConfig.WRONGCLIENT_CRED); 
			SimpleSecurityService s = makeProxy(config);
			
			s.TestConsignor();
			fail("Managed to perform a WS operation with invalid SSL authN data");
		} catch (Exception e)
		{
			Throwable ee = e;
			boolean correctCause = false;
			while (ee != null) 
			{
				ee = ee.getCause();
				if (ee instanceof SSLException)
				{
					correctCause = true;
					break;
				}
			}
			if (!correctCause)
			{
				System.out.println("*** Wrong exception received: " + e);
			}
		}
	}

	public void testChangedSSLConsignor()
	{
		try
		{
			System.out.println("\nTest changing of SSL settings\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			SimpleSecurityService s = makeProxy(config);
			
			String consignorRet = s.TestConsignor();
			String consignor = config.getCertDN();
			assertTrue(consignor.equals(consignorRet));
			
			//now let's change
			config = new MockSecurityConfig(false, true, 
					MockSecurityConfig.WRONGCLIENT_CRED); 
			s = makeProxy(config);
			
			consignorRet = s.TestConsignor();
			fail("Managed to perform a WS operation with invalid SSL authN data");
		} catch (Exception e)
		{
			Throwable ee = e;
			boolean correctCause = false;
			while (ee != null) 
			{
				ee = ee.getCause();
				if (ee instanceof SSLException)
				{
					correctCause = true;
					break;
				}
			}
			if (!correctCause)
			{
				e.printStackTrace();
				System.out.println("*** Wrong exception received?! " + e);
			}
		}
	}

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