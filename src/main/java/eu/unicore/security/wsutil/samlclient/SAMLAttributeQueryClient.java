/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Sep 24, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.wsutil.samlclient;

import java.net.MalformedURLException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.xml.ws.soap.SOAPFaultException;

import org.apache.logging.log4j.Logger;

import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.samly2.SAMLUtils;
import eu.unicore.samly2.assertion.AttributeAssertionParser;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.elements.SAMLAttribute;
import eu.unicore.samly2.elements.Subject;
import eu.unicore.samly2.exceptions.SAMLResponderException;
import eu.unicore.samly2.exceptions.SAMLValidationException;
import eu.unicore.samly2.proto.AttributeQuery;
import eu.unicore.samly2.trust.PKISamlTrustChecker;
import eu.unicore.samly2.trust.SamlTrustChecker;
import eu.unicore.samly2.validators.AssertionValidator;
import eu.unicore.samly2.validators.AttributeAssertionResponseValidator;
import eu.unicore.samly2.webservice.SAMLQueryInterface;
import eu.unicore.security.dsig.DSigException;
import eu.unicore.security.dsig.DigSignatureUtil;
import eu.unicore.util.Log;
import eu.unicore.util.httpclient.IClientConfiguration;
import xmlbeans.org.oasis.saml2.assertion.AssertionDocument;
import xmlbeans.org.oasis.saml2.assertion.NameIDType;
import xmlbeans.org.oasis.saml2.protocol.ResponseDocument;

/**
 * High level API to use SAML SOAP binding of the AssertionQuery protocol. This class is
 * useful for one type of assertion query: attributeQuery.
 * <p>
 * Requests are not signed. Authentication to the service is done using any of HTTP Basic or TLS.
 * It is possible to query for the specific attributes, or for all attributes.
 * <p>
 * The class setups SAML trust model in a very permissive way: it is assumed that 
 * a secure (TLS) connection is used and the peer is trusted. Therefore returned assertion
 * signatures are not required, and are checked only if are present. Issuer must use a trusted certificate.
 * <p>
 * Response is parsed and assertion is returned.
 * <p>
 * Warning: SAML responses with more than one AssertionStatement are unsupported.
 * 
 * @author K. Benedyczak
 */
public class SAMLAttributeQueryClient extends AbstractSAMLClient
{
	private static final Logger logger = Log.getLogger(Log.CLIENT, SAMLAttributeQueryClient.class);
	
	private final SAMLQueryInterface queryProxy;

	
	public SAMLAttributeQueryClient(String address, IClientConfiguration clientConfiguration)
			throws MalformedURLException
	{
		this(address, clientConfiguration, new PKISamlTrustChecker(clientConfiguration.getValidator(), true));

	}

	public SAMLAttributeQueryClient(String address, IClientConfiguration clientConfiguration,
			SamlTrustChecker trustChecker) throws MalformedURLException
	{
		super(address, clientConfiguration, trustChecker);
		queryProxy = factory.createPlainWSProxy(SAMLQueryInterface.class, address);

	}
	
	public SAMLAttributeQueryClient(String address, IClientConfiguration clientConfiguration,
			SamlTrustChecker trustChecker, SAMLQueryInterface queryProxy) throws MalformedURLException
	{
		super(address, clientConfiguration, trustChecker);
		this.queryProxy = queryProxy;

	}

	public AttributeAssertionParser getAssertion(NameID whose, NameID requesterSamlName) throws SAMLValidationException
	{
		return getAssertionGeneric(whose, requesterSamlName, null, Optional.empty(), Optional.empty());
	}

	public AttributeAssertionParser getAssertion(NameID whose, NameID requesterSamlName, SAMLAttribute attribute) 
			throws SAMLValidationException
	{
		return getAssertionGeneric(whose, requesterSamlName, Collections.singleton(attribute), Optional.empty(), Optional.empty());
	}

	public AttributeAssertionParser getAssertion(NameID whose, NameID requesterSamlName, Set<SAMLAttribute> attributes) 
			throws SAMLValidationException
	{
		return getAssertionGeneric(whose, requesterSamlName, attributes, Optional.empty(), Optional.empty());
	}

	public AttributeAssertionParser getAssertion(NameID whose, NameID requesterSamlName,
			Optional<X509Credential> signingCredential, Optional<X509Credential> decryptionCredential)
			throws SAMLValidationException
	{
		return getAssertionGeneric(whose, requesterSamlName, null, signingCredential, decryptionCredential);
	}

	public ResponseDocument getRawAssertion(NameID whose, NameID requesterSamlName, Set<SAMLAttribute> attributes,
			Optional<X509Credential> signingCredential) throws SAMLValidationException
	{
		return performRawSAMLQuery(prepareQuery(whose, requesterSamlName, attributes, signingCredential));
	}
	
	/*-********************************************************
	 * INTERNAL methods 
	 *-********************************************************/

	protected AttributeAssertionParser getAssertionGeneric(NameID whose, NameID requesterSamlName,
			Set<SAMLAttribute> attributes, Optional<X509Credential> signingCredential, Optional<X509Credential> decryptionCredential)
			throws SAMLValidationException
	{
		return performSAMLQuery(prepareQuery(whose, requesterSamlName, attributes, signingCredential), decryptionCredential);
	}
	
	private AttributeQuery prepareQuery(NameID whose, NameID requesterSamlName, Set<SAMLAttribute> attributes,
			Optional<X509Credential> signingCredential) throws SAMLValidationException
	{
		AttributeQuery attrQuery = createQuery(whose, requesterSamlName);
		if (attributes != null && attributes.size() > 0)
			attrQuery.setAttributes(attributes.toArray(new SAMLAttribute[attributes.size()]));
		if (signingCredential.isPresent())
		{
			try
			{
				attrQuery.sign(signingCredential.get().getKey(), signingCredential.get().getCertificateChain());
			} catch (Exception e)
			{
				throw new SAMLValidationException("Can't sign request", e);
			}
		}

		try
		{
			logger.trace("Attribute query document: " + DigSignatureUtil
					.dumpDOMToString(SAMLUtils.getDOM(attrQuery.getXMLBeanDoc())));
		} catch (DSigException e)
		{
			logger.error("Can not dump query document to log");
		}
		return attrQuery;
	}
	/**
	 * Performs a SAML query using a provided AttributeQUery argument. 
	 * Response is parsed and validated.
	 *  
	 * @param attrQuery what to query for
	 * @param credential for assertion decryption
	 * @return parsed and verified assertion
	 * @throws SAMLValidationException
	 */
	protected AttributeAssertionParser performSAMLQuery(AttributeQuery attrQuery, Optional<X509Credential> decryptionCredential)
			throws SAMLValidationException
	{
		ResponseDocument xmlRespDoc = performRawSAMLQuery(attrQuery);

		AttributeAssertionResponseValidator validator = new AttributeAssertionResponseValidator(
				null, 
				null, 
				null, //no we don't want to check 'inResponseTo'
				AssertionValidator.DEFAULT_VALIDITY_GRACE_PERIOD, 
				trustChecker, 
				attrQuery.getXMLBean().getSubject().getNameID(),
				//support assertion decryption
				decryptionCredential.isPresent() ? decryptionCredential.get().getKey() : null);
		validator.validate(xmlRespDoc);
		
		List<AssertionDocument> assertions = validator.getAttributeAssertions();
		
		if (assertions.size() == 0)
			return null;
		if (assertions.size() > 1)
			throw new SAMLValidationException(
				"More than one assertion was returned. It is OK," +
					"however this implementation supports only " +
					"responses with a single assertion.");
		AssertionDocument assertion = assertions.get(0);

		return new AttributeAssertionParser(assertion);
	}
	
	/**
	 * Performs a SAML query using a provided AttributeQUery argument.
	 * Response is not parsed and validated.
	 * 
	 * @param attrQuery what to query for
	 * @return raw assertion document
	 * @throws SAMLValidationException
	 */
	protected ResponseDocument performRawSAMLQuery(AttributeQuery attrQuery) throws SAMLValidationException
	{
		ResponseDocument xmlRespDoc;

		try
		{
			xmlRespDoc = queryProxy.attributeQuery(attrQuery.getXMLBeanDoc());
		} catch (SOAPFaultException e)
		{
			throw new SAMLResponderException("SAML service invocation failed: " + e.getMessage(), e);
		}

		return xmlRespDoc;
	}

	protected AttributeQuery createQuery(NameID whose, NameID requesterSamlName) throws SAMLValidationException
	{
		NameIDType subjectN = whose.getXBean();
		Subject subject = new Subject(subjectN.getStringValue(), subjectN.getFormat());
		if (requesterSamlName == null)
			requesterSamlName = getLocalIssuer();
		if (requesterSamlName == null)
			throw new SAMLValidationException("No SAML issuer was given and it is not " +
					"possible to generate one as local credential is missing.");
		return new AttributeQuery(requesterSamlName.getXBean(), subject.getXBean());
	}
}
