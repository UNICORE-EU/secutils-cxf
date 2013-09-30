/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;

import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.unicore.security.wsutil.client.ClientDSigUtil;
import eu.unicore.util.httpclient.DefaultClientConfiguration;

/**
 * Tests cooperation with other handler which also inserts elements into 
 * SOAP Security header.
 * @author golbi
 */
public class TestDSig2 extends AbstractTestBase
{
	public void testDSigWithProxy()
	{
		try
		{
			System.out.println("\nTest Good signature\n");
			
			DefaultClientConfiguration config = new DefaultClientConfiguration();
			config.setSslEnabled(true);
			config.setDoSignMessage(true);
			config.setSslAuthn(true);
			config.setValidator(MockSecurityConfig.VALIDATOR);
			config.setUseSecuritySessions(false);

			ProxyCertificateOptions proxyOpts = new ProxyCertificateOptions(MockSecurityConfig.CLIENT1_CRED.getCertificateChain());
			ProxyCertificate pc = ProxyGenerator.generate(proxyOpts, MockSecurityConfig.CLIENT1_CRED.getKey());
			config.setCredential(pc.getCredential());
			System.out.println(config.getCredential().getSubjectName());
			SimpleSecurityService s = makeProxy(config);
			
			ClientDSigUtil.addDSigHandler(s, config.getCredential(), null, null);
			
			Client xfireClient = ClientProxy.getClient(s);
			xfireClient.getOutInterceptors().add(new AdditionalOutHandler());
			
			String sigRet = s.TestSignature2();
			assertTrue("OK".equals(sigRet));
			sigRet = s.TestSignature();
			assertTrue("OK".equals(sigRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}
	
	public void testNormalDSig()
	{
		try
		{
			System.out.println("\nTest Good signature\n");
			MockSecurityConfig config = new MockSecurityConfig(
					false, true, true); 
			SimpleSecurityService s = makeProxy(config);
			
			ClientDSigUtil.addDSigHandler(s, config.getCredential(), null, null);
			
			Client xfireClient = ClientProxy.getClient(s);
			xfireClient.getOutInterceptors().add(new AdditionalOutHandler());
			
			String sigRet = s.TestSignature2();
			assertTrue("OK".equals(sigRet));
			sigRet = s.TestSignature();
			assertTrue("OK".equals(sigRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}
}