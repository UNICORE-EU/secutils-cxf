/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;


public class TestAction extends AbstractTestBase
{
	public void testAction()
	{
		try
		{
			MockSecurityConfig config = new MockSecurityConfig(false, true, true);
			config.getETDSettings().initializeSimple(JettyServer.SERVER_IDENTITY,
					config.getCredential());
			config.setMessageLogging(true);
			SimpleSecurityService s = makeSecuredProxy(config);
			
			String userRet = s.TestAction();
			assertNotNull(userRet);
			assertTrue("Got: " + userRet, SimpleSecurityService.test_action.equals(userRet));
		} catch (Exception e)
		{
			e.printStackTrace();
			fail();
		}
	}
	
}