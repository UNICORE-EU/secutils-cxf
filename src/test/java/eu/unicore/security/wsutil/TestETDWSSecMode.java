/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 16, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil;

import eu.unicore.security.wsutil.client.TDOutHandler;

public class TestETDWSSecMode extends TestETD
{

	protected void setUp() throws Exception
	{
		System.setProperty(TDOutHandler.WSSEC_COMPILANT_PROPERTY, "true");
		super.setUp();
	}
}