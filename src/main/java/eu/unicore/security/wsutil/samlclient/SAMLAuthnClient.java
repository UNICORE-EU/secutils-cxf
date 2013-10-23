/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil.samlclient;

import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.ws.soap.SOAPFaultException;

import eu.unicore.samly2.SAMLBindings;
import eu.unicore.samly2.assertion.AssertionParser;
import eu.unicore.samly2.assertion.AttributeAssertionParser;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.exceptions.SAMLResponderException;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.proto.AuthnRequest;
import eu.unicore.samly2.trust.PKISamlTrustChecker;
import eu.unicore.samly2.validators.AssertionValidator;
import eu.unicore.samly2.validators.SSOAuthnResponseValidator;
import eu.unicore.samly2.webservice.SAMLAuthnInterface;
import eu.unicore.util.httpclient.IClientConfiguration;

import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.protocol.AuthnRequestDocument;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;

/**
 * High level API to use SAML SOAP binding of the Authentication Request protocol.
 * <p>
 * Requests are not signed. Authentication to the service is done using any of HTTP Basic or TLS.
 * It is possible to select the desired identity format, which should be returned by the IdP.
 * <p>
 * The class setups SAML trust model in a very permissive way: it is assumed that 
 * a secure (TLS) connection is used and the peer is trusted. Therefore returned assertion
 * signatures are not required, and are checked only if are present. Issuer must use a trusted certificate.
 * <p>
 * Response is parsed the assertions are returned. Such returned assertions are
 * validated first.
 * <p>
 * It is possible to control the request issuer. The issuer is used by the IdP to set up the audience restriction.
 * Additionally it is possible to send a raw request, if it was received with other means, e.g. using the PAOS binding.
 * 
 * @author K. Benedyczak
 */
public class SAMLAuthnClient extends AbstractSAMLClient
{
	private SAMLAuthnInterface authnProxy;

	
	public SAMLAuthnClient(String address, IClientConfiguration clientConfiguration) 
		throws MalformedURLException
	{
		super(address, clientConfiguration, new PKISamlTrustChecker(clientConfiguration.getValidator(), true));
		authnProxy = factory.createPlainWSProxy(SAMLAuthnInterface.class, address);
	}

	/**
	 * Request is created locally, send and verified and parsed response returned. 
	 * It is possible to set the desired identity format.
	 * @param requestedNameFormat name format to be requested
	 * @param consumerURL consumer URL, should be placed in the returned assertion as restriction
	 * @param requesterSamlName used as issuer of the request, may be placed in the returned assertion as condition.
	 * @return
	 * @throws SAMLValidationException
	 */
	public AuthnResponseAssertions authenticate(String requestedNameFormat, 
			NameID requesterSamlName, String consumerURL) throws SAMLValidationException
	{
		return getAssertionsGeneric(requestedNameFormat, consumerURL, requesterSamlName);
	}

	/**
	 * Request is created locally, send and verified and parsed response returned. 
	 * Desired identity format is undefined.
	 * @param consumerURL consumer URL, should be placed in the returned assertion as restriction
	 * @param requesterSamlName used as issuer of the request, may be placed in the returned assertion as condition.
	 * @return
	 * @throws SAMLValidationException
	 */
	public AuthnResponseAssertions authenticate(NameID requesterSamlName, String consumerURL) throws SAMLValidationException
	{
		return getAssertionsGeneric(null, consumerURL, requesterSamlName);
	}

	/**
	 * Sends a prepared request and returns a verified and parsed answer.
	 * @param request
	 * @return
	 * @throws SAMLValidationException
	 */
	public AuthnResponseAssertions authenticate(AuthnRequestDocument request) throws SAMLValidationException
	{
		return performSAMLQuery(request);
	}
	
	/*-********************************************************
	 * INTERNAL methods 
	 *-********************************************************/

	/**
	 * Gets an assertion using high level API arguments.
	 * @param whose
	 * @param attributes
	 * @return
	 * @throws SAMLValidationException
	 */
	protected AuthnResponseAssertions getAssertionsGeneric(String format, String consumerURL, 
			NameID requesterSamlName) throws SAMLValidationException
	{
		if (requesterSamlName == null)
			requesterSamlName = getLocalIssuer();
		if (requesterSamlName == null)
			throw new SAMLValidationException("No SAML issuer was given and it is not " +
					"possible to generate one as local credential is missing.");
		AuthnRequest request = new AuthnRequest(requesterSamlName.getXBean());
		if (format != null)
			request.setFormat(format);
		if (consumerURL != null)
			request.getXMLBean().setAssertionConsumerServiceURL(consumerURL);
		return performSAMLQuery(request.getXMLBeanDoc());
	}
	
	
	/**
	 * Performs a SAML query using a provided AttributeQUery argument. 
	 * Response is parsed and validated.
	 *  
	 * @param attrQuery what to query for
	 * @return parsed and verified assertion
	 * @throws SAMLValidationException
	 */
	protected AuthnResponseAssertions performSAMLQuery(AuthnRequestDocument request)
			throws SAMLValidationException
	{
		ResponseDocument xmlRespDoc;

		try
		{
			xmlRespDoc = authnProxy.authnRequest(request);
		} catch (SOAPFaultException e)
		{
			throw new SAMLResponderException("SAML service invocation failed: " + e.getMessage(), e);
		}
		
		SSOAuthnResponseValidator validator = new SSOAuthnResponseValidator(
				null, 
				null, 
				request.getAuthnRequest().getID(),
				AssertionValidator.DEFAULT_VALIDITY_GRACE_PERIOD, 
				trustChecker,
				null, //replay checking not needed for direct connection
				SAMLBindings.SOAP);
		validator.validate(xmlRespDoc);
		
		List<AssertionDocument> authnAssertionsXml = validator.getAuthNAssertions();
		List<AssertionParser> authAssertions = new ArrayList<AssertionParser>(authnAssertionsXml.size());
		for (int i=0; i<authnAssertionsXml.size(); i++)
			authAssertions.add(new AssertionParser(authnAssertionsXml.get(i)));
		
		List<AssertionDocument> otherAssertionsXml = validator.getOtherAssertions();
		List<AttributeAssertionParser> attributeAssertions = new ArrayList<AttributeAssertionParser>(
				otherAssertionsXml.size());
		for (int i=0; i<otherAssertionsXml.size(); i++)
		{
			AssertionDocument aD = otherAssertionsXml.get(i);
			if (aD.getAssertion().sizeOfAttributeStatementArray() > 0)
			{
				attributeAssertions.add(new AttributeAssertionParser(otherAssertionsXml.get(i)));
				otherAssertionsXml.remove(i);
				i--;
			}
		}
		
		return new AuthnResponseAssertions(authAssertions, attributeAssertions, otherAssertionsXml);
	}
}