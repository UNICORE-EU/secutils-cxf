/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 28, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil.client;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.apache.cxf.endpoint.Client;

import eu.unicore.samly2.assertion.Assertion;
import eu.unicore.security.xfireutil.client.XFireClientFactory;



/**
 * This class provides static methods to configure VO push handler 
 * ({@link SAMLAttributePushOutHandler}) for the XFire proxy.  
 * @author K. Benedyczak
 */
public class ClientVOUtil
{
	/**
	 * Sets SAML attribute assertion to be attached to the requests 
	 * produced by the Xfire client. It is assumed that standard
	 * XFireProxy was used (so don't use this method clients obtained with WSRFLite
	 * or other higher level frameworks -- see other methods).  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 *  
	 * @param xfireProxy Object used to make WS calls via XFire.
	 * @param assertion Assertion to be used.
	 * @throws IOException 
	 * @throws JDOMException 
	 */
	public static void addVOAssertion(Object xfireProxy, Assertion assertion) 
		throws IOException
	{
		addVOAssertions(xfireProxy, Collections.singletonList(assertion));
	}
	
	/**
	 * Sets SAML attribute assertion to be attached to the requests 
	 * produced by the Xfire client. This method is for use 
	 * with custom code with manipulates XFire default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 *  
	 * @param xfireClient XFire client underlying XFire proxy.
	 * @param assertion Assertion to be used.
	 * @throws IOException 
	 * @throws JDOMException 
	 */
	public static void addVOAssertion(Client xfireClient, Assertion assertion) 
		throws IOException
	{
		addVOAssertions(xfireClient, Collections.singletonList(assertion));
	}

	
	/**
	 * Sets SAML attribute assertions to be attached to the requests 
	 * produced by the Xfire client.It is assumed that standard
	 * XFireProxy was used (so don't use this method clients obtained with WSRFLite
	 * or other higher level frameworks -- see other methods).  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 *  
	 * @param xfireProxy Object used to make WS calls via XFire.
	 * @param assertions List of assertions to be used.
	 * @throws IOException 
	 * @throws JDOMException 
	 */
	public static void addVOAssertions(Object xfireProxy, List<Assertion> assertions) 
		throws IOException
	{
		Client xfireClient = XFireClientFactory.getXfireClient(xfireProxy);
		addVOAssertions(xfireClient, assertions);
	}
	
	/**
	 * Sets SAML attribute assertions to be attached to the requests 
	 * produced by the Xfire client. This method is for use 
	 * with custom code with manipulates XFire default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 *  
	 * @param xfireClient XFire client underlying XFire proxy.
	 * @param assertions List of assertions to be used.
	 * @throws IOException 
	 * @throws JDOMException 
	 */
	public static void addVOAssertions(Client xfireClient, List<Assertion> assertions) 
		throws IOException
	{
		List<?> outHandlers = xfireClient.getOutInterceptors();
		SAMLAttributePushOutHandler voHandler = null;
		for (Object h: outHandlers)
			if (h instanceof SAMLAttributePushOutHandler)
			{
				voHandler = (SAMLAttributePushOutHandler)h;
				break;
			}
		if (voHandler != null)
			outHandlers.remove(voHandler);

		voHandler = new SAMLAttributePushOutHandler(assertions);
		xfireClient.getOutInterceptors().add(voHandler);
	}

	/**
	 * Removes all vo handlers from the given proxy.
	 * <p>
	 * It is assumed that standard XFireProxy was used (so don't use this 
	 * method clients obtained with WSRFLite or other higher level frameworks
	 *  -- see other method).
	 * @param xfireProxy Object used to make WS calls via XFire.
	 */
	public static void removeVOHandlers(Object xfireProxy)
	{
		Client xfireClient = XFireClientFactory.getXfireClient(xfireProxy);
		removeVOHandlers(xfireClient);
	}
	
	/**
	 * Removes all vo handlers from the given proxy.
	 * <p>
	 * @param xfireClient XFire client underlying XFire proxy.
	 */
	public static void removeVOHandlers(Client xfireClient)
	{
		List<?> outHandlers = xfireClient.getOutInterceptors();
		for (int i=outHandlers.size()-1; i>=0; i--)
		{
			Object h = outHandlers.get(i);
			if (h instanceof SAMLAttributePushOutHandler)
				outHandlers.remove(i);
		}
	}
	
	/**
	 * Returns actually configured list of assertions for the XFire proxy. 
	 *  
	 * @param xfireProxy Object used to make WS calls via XFire.
	 * @return list of configured assertions or null if VO handler is not configured.
	 */
	public static List<Assertion> getConfiguredVOAssertions(Object xfireProxy) 
		throws IOException
	{
		Client xfireClient = XFireClientFactory.getXfireClient(xfireProxy);
		return getConfiguredVOAssertions(xfireClient);
	}

	/**
	 * Returns actually configured list of assertions for the XFire client. 
	 * <p>
	 * @param xfireClient XFire client underlying XFire proxy.
	 * @return list of configured assertions or null if VO handler is not configured.
	 */
	public static List<Assertion> getConfiguredVOAssertions(Client xfireClient)
	{
		List<?> outHandlers = xfireClient.getOutInterceptors();
		for (int i=outHandlers.size()-1; i>=0; i--)
		{
			Object h = outHandlers.get(i);
			if (h instanceof SAMLAttributePushOutHandler)
				return ((SAMLAttributePushOutHandler)h).getOrigList();
		}
		return null;
	}
}





