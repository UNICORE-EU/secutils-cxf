/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.unicore.security.SignatureStatus;
import eu.unicore.security.UnicoreSecurityFactory;
import eu.unicore.security.etd.ETDApi;
import eu.unicore.security.etd.TrustDelegation;
import eu.unicore.security.wsutil.client.ClientDSigUtil;
import eu.unicore.security.wsutil.client.ClientTrustDelegationUtil;
import eu.unicore.security.wsutil.client.SessionIDProviderImpl;
import eu.unicore.security.wsutil.client.WSClientFactory;
import eu.unicore.util.httpclient.SessionIDProvider;

public class TestETD extends AbstractTestBase
{
	public void testViaSecureClient()
	{
		try
		{

			System.out.println("\nTest ETD via SECURE CLIENT\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true);
			config.getETDSettings().initializeSimple(JettyServer.SERVER_IDENTITY,
					config.getCredential());
			SimpleSecurityService s = makeSecuredProxy(config);

			String userRet = s.TestUser();
			assertNotNull(userRet);
			assertTrue("Got: " + userRet, X500NameUtils.equal(
					config.getCertDN(), userRet));
		} catch (Exception e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testETDWithSig() throws Exception
	{
		System.out.println("\nTest ETD via SECURE CLIENT\n");
		
		for(int i=0; i<200; i++){
			MockSecurityConfig config = new MockSecurityConfig(false, true, true);
			config.getETDSettings().initializeSimple(JettyServer.SERVER_IDENTITY,
					config.getCredential());
			SessionIDProviderImpl.clearAll();
			SimpleSecurityService s = makeSecuredProxy(config);
			ClientDSigUtil.addDSigHandler(s, config.getCredential(), null, null);

			// check ETD
			boolean valid = Boolean.parseBoolean(s.TestETDValid());
			assertTrue("No valid ETD when using DSIG", valid);

			// check signature
			SignatureStatus signed=SimpleSecurityServiceImpl.lastCallTokens.getMessageSignatureStatus();
			assertNotNull(signed);
			assertTrue("No valid signature when using DSIG and ETD, got "+signed, signed.equals(SignatureStatus.OK));
			System.out.print(".");
		}
		System.out.println();
	}

	public void testUser()
	{
		try
		{
			System.out.println("\nTest USER\n");
			MockSecurityConfig config = new MockSecurityConfig(false, false, false); 
			SimpleSecurityService s = makeProxy(config);

			List<TrustDelegation> tds = createTD(true);
			ClientTrustDelegationUtil.addTrustDelegation(s, tds);

			String userRet = s.TestUser();
			String user = config.getCertDN();
			assertTrue(user.equals(userRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testUserUsingProxy()
	{
		try
		{
			System.out.println("\nTest USER using proxy\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			SessionIDProviderImpl.clearAll();
			SimpleSecurityService s = makeSecuredProxy(config);

			List<TrustDelegation> tds = createTDWithProxy();
			ClientTrustDelegationUtil.addTrustDelegation(s, tds);

			MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false); 
			String userRet = s.TestUser();
			String user = configWrong.getCertDN();
			assertEquals(user, userRet);
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testUserPreferences()
	{
		try
		{
			System.out.println("\nTest USER preferences with ETD\n");

			MockSecurityConfig config = new MockSecurityConfig(false, true, true);
			config.getETDSettings().initializeSimple(JettyServer.SERVER_IDENTITY,
					config.getCredential());
			config.getETDSettings().getRequestedUserAttributes2().put("preference", new String [] {"user"});
			SessionIDProviderImpl.clearAll();
			SimpleSecurityService s = makeSecuredProxy(config);

			String prefRet = s.TestPreference();
			assertEquals("preference|user", prefRet);


			System.out.println("\nTest USER preferences without ETD\n");

			MockSecurityConfig config2 = new MockSecurityConfig(false, true, true);
			config2.getETDSettings().setIssuerCertificateChain(config2.getCredential().getCertificateChain());
			config2.getETDSettings().getRequestedUserAttributes2().put("preference", new String [] {"user"});
			SimpleSecurityService s2 = makeSecuredProxy(config2);

			String prefRet2 = s2.TestPreference();
			assertEquals("preference|user", prefRet2);

		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}


	public void testUserAsDN()
	{
		try
		{
			System.out.println("\nTest USER as DN\n");
			MockSecurityConfig config = new MockSecurityConfig(false, false, false);
			MockSecurityConfig configCorrect = new MockSecurityConfig(false, false, true);
			SimpleSecurityService s = makeProxy(config);

			List<TrustDelegation> tds = createTD(true);
			String user = config.getCertDN();

			ClientTrustDelegationUtil.addTrustDelegation(s, tds, user, 
					configCorrect.getCertDN());

			String userRet = s.TestUser();
			assertTrue(user.equals(userRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testTDExtraction()
	{
		try
		{
			System.out.println("\nTest TD extraction\n");
			MockSecurityConfig config = new MockSecurityConfig(false, false, false); 
			MockSecurityConfig configCorrect = new MockSecurityConfig(false, false, true); 
			SimpleSecurityService s = makeProxy(config);

			List<TrustDelegation> tds = createTD(true);
			ClientTrustDelegationUtil.addTrustDelegation(s, tds);

			String issuerRet = s.TestETDIssuer();
			String receiverRet = s.TestETDLastSubject();

			String receiver = configCorrect.getCertDN();
			String issuer = config.getCertDN();
			assertTrue(issuer.equals(issuerRet));
			assertTrue(receiver.equals(receiverRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testTDValidation()
	{
		try
		{
			System.out.println("\nTest TD validation\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false); 
			SimpleSecurityService s = makeProxy(config);

			List<TrustDelegation> tds = createTD(true);
			ClientTrustDelegationUtil.addTrustDelegation(s, tds);

			String effUserRet = s.TestEffectiveUser();
			String consignorRet = s.TestConsignor();

			String receiver = config.getCertDN();
			String issuer = configWrong.getCertDN();

			assertTrue("Got " + effUserRet + " should get " + issuer, 
					issuer.equals(effUserRet));
			assertTrue(receiver.equals(consignorRet));
		} catch (Exception e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testInvalidTDValidation()
	{
		try
		{
			System.out.println("\nTest Invalid TD validation\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false); 
			SimpleSecurityService s = makeProxy(config);

			List<TrustDelegation> tds = createTD(false);
			X509Certificate usercert = configWrong.getCredential().getCertificate();
			ClientTrustDelegationUtil.addTrustDelegation(s, tds, usercert, "cn=test");

			String effUserRet = s.TestEffectiveUser();
			String consignorRet = s.TestConsignor();

			String receiver = config.getCertDN();

			assertTrue(receiver.equals(effUserRet));
			assertTrue(receiver.equals(consignorRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testChangedTDValidation()
	{
		try
		{
			System.out.println("\nTest changed TD validation\n");
			MockSecurityConfig config = new MockSecurityConfig(false, true, true); 
			MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false); 
			SimpleSecurityService s = makeProxy(config);

			List<TrustDelegation> tds = createTD(true);
			ClientTrustDelegationUtil.addTrustDelegation(s, tds);

			String effUserRet = s.TestEffectiveUser();
			String consignorRet = s.TestConsignor();

			String receiver = config.getCertDN();
			String issuer = configWrong.getCertDN();

			assertTrue(issuer.equals(effUserRet));
			assertTrue(receiver.equals(consignorRet));

			//now let's change the settings
			tds = createTD(false);
			X509Certificate usercert = configWrong.getCredential().getCertificate();
			ClientTrustDelegationUtil.addTrustDelegation(s, tds, usercert, "cn=test");
			effUserRet = s.TestEffectiveUser();
			consignorRet = s.TestConsignor();

			assertTrue(receiver.equals(effUserRet));
			assertTrue(receiver.equals(consignorRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}
	
	public void testSessionIDProvider()
	{
		try
		{
			MockSecurityConfig sec = new MockSecurityConfig(false, true, true);
			sec.setUseSecuritySessions(true);
			SimpleSecurityService s = makeSecuredProxy(sec);
			
			String msg = s.TestSessionID();
			System.out.println("reply from service = "+msg);
			SessionIDProvider p = WSClientFactory.getSessionIDProvider(s);
			assertNotNull(p);
			String id=p.getSessionID();
			System.out.println("ID = "+id);
			assertEquals(msg, id);
			
			p.setSessionID(id);
			String msg2 = s.TestSessionID();
			System.out.println("2nd reply from service = "+msg2);
			String id2=p.getSessionID();
			
			// it's still the same session
			assertEquals(id2, id);
			
			// check that the SessionIDProviderImpl tracks everything
			System.out.println("Stored sessionIDs: "+SessionIDProviderImpl.getAll());
			assertEquals(1, SessionIDProviderImpl.getAll().size());
			assertEquals(id2, SessionIDProviderImpl.getAll().values().iterator().next());
			
			
		} catch (Exception e)
		{
			e.printStackTrace();
			fail();
		}
	}

	private List<TrustDelegation> createTD(boolean mode) 
			throws Exception
			{
		MockSecurityConfig configCorrect = new MockSecurityConfig(false, true, true); 
		MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false); 

		List<TrustDelegation> tds = new ArrayList<TrustDelegation>();

		ETDApi etdEngine = UnicoreSecurityFactory.getETDEngine();

		String receiverDN = mode ? configCorrect.getCertDN() : configWrong.getCertDN();

		PrivateKey pk = mode ? configWrong.getCredential().getKey() : 
			configCorrect.getCredential().getKey();
		X509Certificate issuerCert = mode ? configWrong.getCredential().getCertificate() : 
			configCorrect.getCredential().getCertificate();

		TrustDelegation td = etdEngine.generateTD(
				issuerCert.getSubjectX500Principal().getName(), 
				new X509Certificate[] {issuerCert}, 
				pk, receiverDN, null);
		tds.add(td);
		return tds;
			}

	private List<TrustDelegation> createTDWithProxy() throws Exception
	{
		MockSecurityConfig configCorrect = new MockSecurityConfig(false, true, true); 
		MockSecurityConfig configWrong = new MockSecurityConfig(false, true, false); 

		ProxyCertificateOptions proxyOpts = new ProxyCertificateOptions(
				configWrong.getCredential().getCertificateChain());
		ProxyCertificate proxyC = ProxyGenerator.generate(proxyOpts, 
				configWrong.getCredential().getKey());

		List<TrustDelegation> tds = new ArrayList<TrustDelegation>();
		ETDApi etdEngine = UnicoreSecurityFactory.getETDEngine();

		String receiverDN = configCorrect.getCertDN();

		PrivateKey pk = proxyC.getPrivateKey();
		X509Certificate[] issuerCert = proxyC.getCertificateChain();

		TrustDelegation td = etdEngine.generateTD(
				issuerCert[0].getSubjectX500Principal().getName(), 
				issuerCert, 
				pk, receiverDN, null);
		tds.add(td);
		return tds;
	}

}