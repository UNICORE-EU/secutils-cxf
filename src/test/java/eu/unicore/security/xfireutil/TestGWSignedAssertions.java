/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.interceptor.Interceptor;
import org.apache.cxf.message.Message;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.samly2.SAMLConstants.AuthNClasses;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.consignor.ConsignorAPI;
import eu.unicore.security.consignor.ConsignorAssertion;

public class TestGWSignedAssertions extends AbstractTestBase
{
	public X509Certificate gwCert;
	public PrivateKey gwKey;
	
	@Override
	protected void addHandlers(List<Interceptor<? extends Message>> s)throws Exception{

		X509Credential credential = MockSecurityConfig.getGatewayCredential();
		gwCert = credential.getCertificate();
		gwKey = credential.getKey();

		AuthInHandler authHandler = new AuthInHandler(true, true, true, gwCert);
		ETDInHandler etdHandler = new ETDInHandler(null, new BinaryCertChainValidator(true));
		s.add(authHandler);
		s.add(etdHandler);
	}

	public void testGWConsignorUnsigned()
	{
		try
		{
			System.out.println("\nTest unsigned GW assertion\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false); 
			SimpleSecurityService s = makeProxy(config);
			
			ConsignorAPI engine = UnicoreSecurityFactory.getConsignorAPI();
			X509Certificate consignor = configWrong.getCredential().getCertificate();
			ConsignorAssertion consignorA = engine.generateConsignorToken(
					gwCert.getSubjectX500Principal().getName(),
					new X509Certificate[] {consignor},
					AuthNClasses.TLS, "127.0.0.1");
			org.apache.cxf.endpoint.Client xfireClient = ClientProxy.getClient(s);
			GwHandler gwH = new GwHandler();
			gwH.reinit(consignorA);
			xfireClient.getOutInterceptors().add(gwH);
			
			String consignorRet = s.TestConsignor();
			assertNull("Got: " + consignorRet, consignorRet);
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testGWConsignorOK()
	{
		try
		{
			System.out.println("\nTest signed GW assertion\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true);
			MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false);
			SimpleSecurityService s = makeProxy(config);
			
			ConsignorAPI engine = UnicoreSecurityFactory.getConsignorAPI();
			X509Certificate consignor = configWrong.getCredential().getCertificate();
			ConsignorAssertion consignorA = engine.generateConsignorToken(
					gwCert.getSubjectX500Principal().getName(),
					new X509Certificate[] {consignor},
					gwKey,
					0, 5, AuthNClasses.TLS, "127.0.0.1");
			Client xfireClient = ClientProxy.getClient(s);
			GwHandler gwH = new GwHandler();
			gwH.reinit(consignorA);
			xfireClient.getOutInterceptors().add(gwH);
			
			String consignorRet = s.TestConsignor();
			System.out.println("Expected: "+consignor.getSubjectX500Principal()+" got "+consignorRet);
			assertTrue(X500NameUtils.equal(consignor.getSubjectX500Principal(), consignorRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}
}