/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil.samlclient;

import java.net.MalformedURLException;

import eu.unicore.samly2.exceptions.SAMLResponderException;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.trust.PKISamlTrustChecker;
import eu.unicore.samly2.webservice.SAMLLogoutInterface;
import eu.unicore.util.httpclient.IClientConfiguration;
import jakarta.xml.ws.soap.SOAPFaultException;
import xmlbeans.org.oasis.saml2.protocol.LogoutRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.LogoutResponseDocument;

/**
 * High level API to use SAML SOAP binding of the Single Logout protocol. Pretty simplistic - a request 
 * must be provided directly and response is returned without further parsing.
 * 
 * @author K. Benedyczak
 */
public class SAMLLogoutClient extends AbstractSAMLClient
{
	private SAMLLogoutInterface logoutProxy;

	
	public SAMLLogoutClient(String address, IClientConfiguration clientConfiguration) 
		throws MalformedURLException
	{
		super(address, clientConfiguration, new PKISamlTrustChecker(clientConfiguration.getValidator(), true));
		logoutProxy = factory.createPlainWSProxy(SAMLLogoutInterface.class, address);
	}

	/**
	 * Sends a prepared request and returns an answer.
	 * @param request
	 * @throws SAMLValidationException
	 */
	public LogoutResponseDocument logout(LogoutRequestDocument request) throws SAMLValidationException
	{
		return performSAMLQuery(request);
	}
	
	/*-********************************************************
	 * INTERNAL methods 
	 *-********************************************************/

	/**
	 * Performs a SAML query using a provided LogoutRequestDocument argument. 
	 *  
	 * @param request
	 * @return response
	 * @throws SAMLValidationException
	 */
	protected LogoutResponseDocument performSAMLQuery(LogoutRequestDocument request)
			throws SAMLValidationException
	{
		LogoutResponseDocument xmlRespDoc;

		try
		{
			xmlRespDoc = logoutProxy.logoutRequest(request);
		} catch (SOAPFaultException e)
		{
			throw new SAMLResponderException("SAML service invocation failed: " + e.getMessage(), e);
		}
		
		return xmlRespDoc;
	}
}
