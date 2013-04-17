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

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.unicore.bugsreporter.annotation.RegressionTest;
import eu.unicore.samly2.SAMLConstants.AuthNClasses;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.consignor.ConsignorAPI;
import eu.unicore.security.consignor.ConsignorAssertion;

public class TestAuthN extends AbstractTestBase
{
	@RegressionTest(url="https://sourceforge.net/tracker/index.php?func=detail&aid=3418447&group_id=102081&atid=633902",
			description="Among others checks if the Consignor assertion is accepted when also the wss:security element with SAML assertions is present")
	public void testGWConsignorNormal()
	{
		try
		{
			System.out.println("\nTest GW assertion\n");

			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false); 
			X509Credential gwCredential = MockSecurityConfig.getGatewayCredential();
			SimpleSecurityService s = makeProxy(config);
			
			ConsignorAPI engine = UnicoreSecurityFactory.getConsignorAPI();
			X509Certificate consignor = configWrong.getCredential().getCertificate();
			ConsignorAssertion consignorA = engine.generateConsignorToken(
					gwCredential.getCertificate().getSubjectX500Principal().getName(),
					new X509Certificate[] {consignor},
					AuthNClasses.TLS, "127.0.0.1");
			Client xfireClient = ClientProxy.getClient(s);
			GwHandler gwH = new GwHandler();
			gwH.reinit(consignorA);
			xfireClient.getOutInterceptors().add(gwH);
			ExtraSAMLOutHandler samlH = new ExtraSAMLOutHandler();
			xfireClient.getOutInterceptors().add(samlH);
			
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
			X509Credential gwCredential = MockSecurityConfig.getGatewayCredential();
			SimpleSecurityService s = makeProxy(config);
			
			ConsignorAPI engine = UnicoreSecurityFactory.getConsignorAPI();
			X509Certificate[] consignor = configWrong.getCredential().getCertificateChain();
			
			ProxyCertificateOptions proxyOpts = new ProxyCertificateOptions(consignor);
			ProxyCertificate proxyC = ProxyGenerator.generate(proxyOpts, 
					configWrong.getCredential().getKey());
			
			
			ConsignorAssertion consignorA = engine.generateConsignorToken(
					gwCredential.getCertificate().getSubjectX500Principal().getName(),
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
			X509Credential gwCredential = MockSecurityConfig.getGatewayCredential();
			
			SimpleSecurityService s = makeProxy(config);
			
			ConsignorAPI engine = UnicoreSecurityFactory.getConsignorAPI();
			ConsignorAssertion consignorA = engine.generateConsignorToken(
					gwCredential.getCertificate().getSubjectX500Principal().getName());
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
	
	public void testSSLConsignor()
	{
		try
		{
			System.out.println("\nTest SSL\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			SimpleSecurityService s = makeProxy(config);
			
			String consignorRet = s.TestConsignor();
			String consignor = config.getCertDN();
			assertTrue(consignor.equals(consignorRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
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
			MockSecurityConfig config = new MockSecurityConfig(false, true, false); 
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
				e.printStackTrace();
				fail("Wrong exception received: " + e);
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
			config = new MockSecurityConfig(false, true, false); 
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
				fail("Wrong exception received: " + e);
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

}