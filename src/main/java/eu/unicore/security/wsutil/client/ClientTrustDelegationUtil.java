/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 28, 2008
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil.client;

import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;

import eu.unicore.security.etd.TrustDelegation;


/**
 * This class provides static methods to configure trust delegation handler 
 * ({@link TDOutHandler} for the XFire proxy. Note that is also adds User statements,
 * not only trust delegation statements. 
 * @author K. Benedyczak
 */
public class ClientTrustDelegationUtil
{
	/**
	 * Configures trust delegation for the Xfire proxy. It is assumed that standard
	 * XFireProxy was used (so don't use this method clients obtained with WSRFLite
	 * or other higher level frameworks -- see other methods).  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * The assumption here is that 
	 * the issuer of the first trust delegation in the list is the USER (on her 
	 * behalf request shall be executed) and the subject of the last trust delegation
	 * in chain is a CONSIGNOR (so the guy who actually make the request, or to state
	 * it in another way: you).
	 * 
	 * @param xfireProxy Object used to make WS calls via XFire.
	 * @param tdChain list of trust delegations.
	 */
	public static void addTrustDelegation(Object xfireProxy, 
			List<TrustDelegation> tdChain)
	{
		Client xfireClient = ClientProxy.getClient(xfireProxy);
		addTrustDelegation(xfireClient, tdChain);
	}
	
	/**
	 * Configures trust delegation for the Xfire client. This method is for use 
	 * with custom code with manipulates XFire default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * The assumption here is that 
	 * the issuer of the first trust delegation in the list is the USER (on her 
	 * behalf request shall be executed) and the subject of the last trust delegation
	 * in chain is a CONSIGNOR (so the guy who actually make the request, or to state
	 * it in another way: you).
	 * 
	 * @param xfireClient XFire client underlying XFire proxy.
	 * @param tdChain list of trust delegations.
	 */
	public static void addTrustDelegation(Client xfireClient, 
			List<TrustDelegation> tdChain)
	{
		if (tdChain == null || tdChain.size() == 0)
			throw new IllegalArgumentException(
				"Trust delegation chain can't be null/empty");
		
		TrustDelegation td1 = tdChain.get(0);
		TrustDelegation tdLast = tdChain.get(tdChain.size() - 1);
		addTrustDelegation(xfireClient, tdChain, 
				td1.getIssuerFromSignature()[0], tdLast.getSubjectName());
	}
	
	
	/**
	 * Configures trust delegation for the Xfire proxy. It is assumed that standard
	 * XFireProxy was used (so don't use this method clients obtained with WSRFLite
	 * or other higher level frameworks -- see other methods).  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * This version allows for setting trust delegation and manually set the User 
	 * (identified by certificate). 
	 *  
	 * @param xfireProxy Object used to make WS calls via XFire.
	 * @param tdChain list of trust delegations.
	 * @param user certificate of USER or null if User assertion shouldn't be added.
	 * @param callerDN DN of CONSIGNOR or null if User assertion shouldn't be added.
	 */
	public static void addTrustDelegation(Object xfireProxy, 
			List<TrustDelegation> tdChain, X509Certificate user,
			String callerDN)
	{
		Client xfireClient = ClientProxy.getClient(xfireProxy);
		addTrustDelegation(xfireClient, tdChain, user, callerDN);
	}

	/**
	 * Configures trust delegation for the Xfire client. This method is for use 
	 * with custom code with manipulates XFire default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * This version allows for setting trust delegation and the User
	 * (identified by a certificate). 
	 *  
	 * @param xfireClient XFire client underlying XFire proxy.
	 * @param tdChain list of trust delegations.
	 * @param user certificate of USER or null if User assertion shouldn't be added.
	 * @param callerDN DN of CONSIGNOR or null if User assertion shouldn't be added.
	 */
	public static void addTrustDelegation(Client xfireClient, 
			List<TrustDelegation> tdChain, X509Certificate userCert,
			String callerDN)
	{
		addTrustDelegation(xfireClient, tdChain, userCert, null, callerDN);
	}

	/**
	 * Configures trust delegation for the Xfire proxy. It is assumed that standard
	 * XFireProxy was used (so don't use this method clients obtained with WSRFLite
	 * or other higher level frameworks -- see other methods).  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * This version allows for setting trust delegation and manually set the User 
	 * (identified by a DN). 
	 *  
	 * @param xfireProxy Object used to make WS calls via XFire.
	 * @param tdChain list of trust delegations.
	 * @param user certificate of USER or null if User assertion shouldn't be added.
	 * @param callerDN DN of CONSIGNOR or null if User assertion shouldn't be added.
	 */
	public static void addTrustDelegation(Object xfireProxy, 
			List<TrustDelegation> tdChain, String userDN,
			String callerDN)
	{
		Client xfireClient = ClientProxy.getClient(xfireProxy);
		addTrustDelegation(xfireClient, tdChain, null, userDN, callerDN);
	}

	/**
	 * Configures trust delegation for the Xfire client. This method is for use 
	 * with custom code with manipulates XFire default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * This version allows for setting trust delegation and manually set the User
	 * (identified by a DN). 
	 *  
	 * @param xfireClient XFire client underlying XFire proxy.
	 * @param tdChain list of trust delegations.
	 * @param user certificate of USER or null if User assertion shouldn't be added.
	 * @param callerDN DN of CONSIGNOR or null if User assertion shouldn't be added.
	 */
	public static void addTrustDelegation(Client xfireClient, 
			List<TrustDelegation> tdChain, String userDN,
			String callerDN)
	{
		addTrustDelegation(xfireClient, tdChain, null, userDN, callerDN);
	}
	
	/**
	 * Configures trust delegation for the Xfire client. This method is for use 
	 * with custom code with manipulates XFire default implementations of clients 
	 * and proxies.  
	 * <p>
	 * The handler is either added or updated with the new configuration. 
	 * <p>
	 * This version allows for setting trust delegation and manually set the User. 
	 *  
	 * @param xfireClient XFire client underlying XFire proxy.
	 * @param tdChain list of trust delegations.
	 * @param user certificate of USER or null if User assertion shouldn't be added.
	 * @param callerDN DN of CONSIGNOR or null if User assertion shouldn't be added.
	 */
	private static void addTrustDelegation(Client xfireClient, 
			List<TrustDelegation> tdChain, X509Certificate user, String userDN,
			String callerDN)
	{
		List<?> outHandlers = xfireClient.getOutInterceptors();
		TDOutHandler tdHandler = null;
		for (Object h: outHandlers)
			if (h instanceof TDOutHandler)
			{
				tdHandler = (TDOutHandler)h;
				break;
			}
		if (tdHandler != null)
			outHandlers.remove(tdHandler);
		if (userDN == null)
			tdHandler = new TDOutHandler(tdChain, user, callerDN);
		else
			tdHandler = new TDOutHandler(tdChain, userDN, callerDN);
		xfireClient.getOutInterceptors().add(tdHandler);
	}

	/**
	 * Removes all trust delegation handlers from the given proxy.
	 * <p>
	 * It is assumed that standard XFireProxy was used (so don't use this 
	 * method clients obtained with WSRFLite or other higher level frameworks
	 *  -- see other method).
	 * @param xfireProxy Object used to make WS calls via XFire.
	 */
	public static void removeTrustDelegation(Object xfireProxy)
	{
		Client xfireClient = ClientProxy.getClient(xfireProxy);
		removeTrustDelegation(xfireClient);
	}
	
	/**
	 * Removes all trust delegation handlers from the given proxy.
	 * <p>
	 * @param xfireClient XFire client underlying XFire proxy.
	 */
	public static void removeTrustDelegation(Client xfireClient)
	{
		List<?> outHandlers = xfireClient.getOutInterceptors();
		for (int i=outHandlers.size()-1; i>=0; i--)
		{
			Object h = outHandlers.get(i);
			if (h instanceof TDOutHandler)
				outHandlers.remove(i);
		}
	}
}





