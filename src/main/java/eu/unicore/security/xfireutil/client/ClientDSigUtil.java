/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 28, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil.client;

import java.util.List;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;

import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.security.xfireutil.DSigDecider;


/**
 * This class provides static methods to configure digital signature out handler 
 * ({@link DSigOutHandler} for the XFire proxy.
 * @author K. Benedyczak
 */
public class ClientDSigUtil
{
	/**
	 * Configures digital signature for the Xfire proxy. It is assumed that standard
	 * XFireProxy was used (so don't use this method clients obtained with WSRFLite
	 * or other higher level frameworks -- see other methods).  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * 
	 * @param xfireProxy Object used to make WS calls via XFire.
 	 * @param securityCfg Mandatory security configuration used to get private key
	 * for making signatures.
	 * @param decider Per message decider saying if it should be signed or not.
	 * Can be null meaning that all messages should be signed.
	 * @param partsDecider Per message decider saying what parts should be signed.
	 * Can be null meaning that only SOAP body should be signed.
	 */
	public static void addDSigHandler(Object xfireProxy, 
			X509Credential securityCfg, 
			DSigDecider decider, ToBeSignedDecider partsDecider)
	{
		Client xfireClient = ClientProxy.getClient(xfireProxy);
		addDSigHandler(xfireClient, securityCfg, decider, partsDecider);
	}
	
	/**
	 * Configures digital signature for the Xfire client. This method is for use 
	 * with custom code with manipulates XFire default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * 
	 * @param xfireClient XFire client underlying XFire proxy.
	 * @param securityCfg Mandatory security configuration used to get private key
	 * for making signatures.
	 * @param decider Per message decider saying if it should be signed or not.
	 * Can be null meaning that all messages should be signed.
	 * @param partsDecider Per message decider saying what parts should be signed.
	 * Can be null meaning that only SOAP body should be signed.
	 */
	public static void addDSigHandler(Client xfireClient, 
			X509Credential securityCfg, 
			DSigDecider decider, ToBeSignedDecider partsDecider)
	{
		List<?> outHandlers = xfireClient.getOutInterceptors();
	
		for (Object h: outHandlers)
			if (h instanceof DSigOutHandler)
			{
				outHandlers.remove(h);
				break;
			}
		
		for (Object h: outHandlers)
			if (h instanceof OnDemandSAAJOutInterceptor)
			{
				outHandlers.remove(h);
				break;
			}
		xfireClient.getOutInterceptors().add(new OnDemandSAAJOutInterceptor(decider));
		xfireClient.getOutInterceptors().add(new DSigOutHandler(securityCfg, decider, partsDecider));
	}

	/**
	 * Removes all digital singature handlers from the given proxy.
	 * <p>
	 * It is assumed that standard XFireProxy was used (so don't use this 
	 * method clients obtained with WSRFLite or other higher level frameworks
	 *  -- see other method).
	 * @param xfireProxy Object used to make WS calls via XFire.
	 */
	public static void removeDSigHandlers(Object xfireProxy)
	{
		Client xfireClient = ClientProxy.getClient(xfireProxy);
		removeDSigHandlers(xfireClient);
	}
	
	/**
	 * Removes all digital signature handlers from the given proxy.
	 * <p>
	 * @param xfireClient XFire client underlying XFire proxy.
	 */
	public static void removeDSigHandlers(Client xfireClient)
	{
		List<?> outHandlers = xfireClient.getOutInterceptors();
		for (int i=outHandlers.size()-1; i>=0; i--)
		{
			Object h = outHandlers.get(i);
			if (h instanceof DSigOutHandler || h instanceof OnDemandSAAJOutInterceptor)
				outHandlers.remove(i);
		}
	}
}





