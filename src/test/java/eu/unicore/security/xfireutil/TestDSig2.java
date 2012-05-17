/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil;

import org.codehaus.xfire.client.Client;

import eu.unicore.security.xfireutil.client.ClientDSigUtil;
import eu.unicore.security.xfireutil.client.XFireClientFactory;

/**
 * Tests cooperation with other handler which also inserts elements into 
 * SOAP Security header.
 * @author golbi
 */
public class TestDSig2 extends AbstractTestBase
{
	public void testNormalDSig()
	{
		try
		{
			System.out.println("\nTest Good signature\n");
			MockSecurityConfig config = new MockSecurityConfig(
					false, true, true); 
			SimpleSecurityService s = makeProxy(config);
			
			ClientDSigUtil.addDSigHandler(s, config.getCredential(), null, null);
			
			Client xfireClient = XFireClientFactory.getXfireClient(s);
			xfireClient.addOutHandler(new AdditionalOutHandler());
			
			String sigRet = s.TestSignature2();
			assertTrue("OK".equals(sigRet));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		}
	}
}