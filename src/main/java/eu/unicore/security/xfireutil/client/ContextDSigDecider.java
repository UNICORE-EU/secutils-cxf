/*
 * Copyright (c) 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 2008-12-22
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.xfireutil.client;

import java.util.Set;

import org.apache.cxf.message.Message;
import org.apache.cxf.message.MessageUtils;

import eu.unicore.security.xfireutil.CXFUtils;
import eu.unicore.security.xfireutil.DSigDecider;

/**
 * Simple implementation of {@link DSigDecider} for client calls. 
 * It decides basing on information which is retrieved from {@link MessageContext}.
 * Additionally one may set SIGN_MESSAGE context property to true to turn on digital 
 * signature for the call. 
 * 
 * @see XFireClientFactory
 * @author golbi
 */
public class ContextDSigDecider implements DSigDecider
{
	public final static String SIGN_MESSAGE = ContextDSigDecider.class.getName() + "doSign";
	public final static String SIGNED_OPERATIONS = ContextDSigDecider.class.getName() + "signedOperations";
	
	public boolean isMessageDSigCandidate(Message message)
	{
		if(MessageUtils.isOutbound(message))
			return clientCall(message);
		
		return false;
	}

	private boolean clientCall(Message ctx)
	{
		//manually set (e.g. for non-WSA call)?
		if (Boolean.TRUE.equals(ctx.get(SIGN_MESSAGE)))
			return true;
		
		//TODO
		
		@SuppressWarnings("unchecked")
		Set<String> signedOperations = (Set<String>) ctx.get(SIGNED_OPERATIONS);
		if (signedOperations == null)
			return false;
		
		//check if this request was signed, decided by SOAP /WSA action
		
		String action=CXFUtils.getAction(ctx.getExchange());
		if (action==null)
			return false;
		
		return signedOperations.contains(action);
	}
}








