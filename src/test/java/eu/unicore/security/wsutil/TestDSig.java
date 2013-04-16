/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.util.Set;
import java.util.Vector;

import org.apache.ws.security.WSEncryptionPart;
import org.w3c.dom.Document;

import eu.unicore.security.SignatureStatus;
import eu.unicore.security.wsutil.client.ClientDSigUtil;
import eu.unicore.security.wsutil.client.ToBeSignedDecider;
import eu.unicore.security.wsutil.client.UnicoreWSClientFactory;

public class TestDSig extends AbstractTestBase
{
	private static class MyDecider implements ToBeSignedDecider
	{
		//decide to sign only body content element...
		public Vector<WSEncryptionPart> getElementsToBeSigned(
				Document docToSign)
		{
			WSEncryptionPart part = new WSEncryptionPart(
					"TestSignature",
					"http://xfireutil.security.unicore.eu",  
					"");
			Vector<WSEncryptionPart> ret = new Vector<WSEncryptionPart>();
			ret.add(part);
			return ret;
		}
	}
	
	public void testWrongElementSigned()
	{
		try
		{
			System.out.println("\nTest wrong element signed\n");
			MockSecurityConfig config = new MockSecurityConfig(
					false, true, true);
			SimpleSecurityService s = makeProxy(config);

			ToBeSignedDecider partsDecider = new MyDecider();
			
			ClientDSigUtil.addDSigHandler(s, config.getCredential(), null, partsDecider);
			
			String sigRet = s.TestSignature();
			assertTrue(SignatureStatus.OK_BUT_NOT_IN_POLICY.name().equals(sigRet));
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

			String sigRet = s.TestSignature();
			assertTrue(SignatureStatus.OK.name().equals(sigRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	//as above, but using SecuredXFireClientFactory and with logging
	public void testNormalDSig2()
	{
		try
		{
			System.out.println("\nTest Good signature\n");
			MockSecurityConfig config = new MockSecurityConfig(
					false, true, true);
			SimpleSecurityService s = makeSecuredProxy(config);

			String sigRet = s.TestSignature();
			assertTrue(SignatureStatus.OK.name().equals(sigRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testDSigAnnotations()
	{
		Set<String> toSign = UnicoreWSClientFactory.getOperationsToSign(
				SimpleSecurityService.class);
		assertTrue(toSign.size() == 2);
		assertTrue(toSign.contains("TestSignatureAction"));
		assertTrue(toSign.contains("TestSignature2Action"));
	}
	
	public void testNoDSig()
	{
		try
		{
			System.out.println("\nTest lack of signature\n");
			MockSecurityConfig config = new MockSecurityConfig(
					false, true, true); 
			SimpleSecurityService s = makeProxy(config);
			
			String sigRet = s.TestSignature();
			assertTrue(SignatureStatus.UNSIGNED.name().equals(sigRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

	public void testChangingConfig()
	{
		try
		{
			System.out.println("\nTest changing the configuration signed\n");
			MockSecurityConfig config = new MockSecurityConfig(
					false, true, true);
			SimpleSecurityService s = makeProxy(config);

			ToBeSignedDecider partsDecider = new MyDecider();
			
			ClientDSigUtil.addDSigHandler(s, config.getCredential(), null, partsDecider);
			
			String sigRet = s.TestSignature();
			assertTrue(SignatureStatus.OK_BUT_NOT_IN_POLICY.name().equals(sigRet));
			
			ClientDSigUtil.addDSigHandler(s, config.getCredential(), null, null);
			sigRet = s.TestSignature();
			assertTrue(SignatureStatus.OK.name().equals(sigRet));

		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}

}