/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import java.util.Calendar;

import eu.unicore.security.wsutil.client.ConditionalGetInHandler;
import eu.unicore.security.wsutil.client.ConditionalGetUtil;


public class TestConditionalGet extends AbstractTestBase
{
	public void testConditionalGet()
	{
		try
		{
			MockSecurityConfig sec = new MockSecurityConfig(false, false, false); 
			SimpleSecurityService s = makeProxy(sec);
			
			// data was last changed a while ago
			SimpleSecurityServiceImpl.lastMod.add(Calendar.MONTH, -2);
			
			String userRet = s.TestConditionalGet();
			assertNotNull(userRet);
			String etag = ConditionalGetUtil.Client.getEtag();
			String lastmod = ConditionalGetUtil.Client.getLastModified();
			System.out.println("etag = "+etag);
			System.out.println("lastModified = "+lastmod);
			
			// now do conditional get
			ConditionalGetUtil.Client.setIfNoneMatch(etag);
			ConditionalGetUtil.Client.setIfModifiedSince(lastmod);
			
			String userRet2 = s.TestConditionalGet();
			assertTrue(ConditionalGetUtil.Client.isNotModified());
			assertEquals("", userRet2);

			// now change the server-side data
			SimpleSecurityServiceImpl.lastMod=Calendar.getInstance();
			String newData="some new data";
			SimpleSecurityServiceImpl.currentRepresentation=newData;
			String userRet3 = s.TestConditionalGet();
			assertFalse(ConditionalGetUtil.Client.isNotModified());
			assertEquals(newData, userRet3);
			etag = ConditionalGetInHandler.getEtag();
			lastmod = ConditionalGetInHandler.getLastModified();
			System.out.println("etag = "+etag);
			System.out.println("lastModified = "+lastmod);
			
		} catch (Exception e)
		{
			e.printStackTrace();
			fail();
		}
	}
	
}