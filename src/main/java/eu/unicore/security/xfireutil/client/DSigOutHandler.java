package eu.unicore.security.xfireutil.client;


import java.io.ByteArrayOutputStream;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.xml.crypto.dsig.Reference;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.binding.soap.saaj.SAAJOutInterceptor.SAAJOutEndingInterceptor;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.phase.Phase;
import org.apache.log4j.Logger;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.security.util.Log;
import eu.unicore.security.xfireutil.DSigDecider;


/**
 * Outgoing handler that signs the body of the SOAP message<br>
 * 
 * This handler can be used both to sign reply messages, and
 * as a client handler for signing requests.<br>
 * <p>
 * Only selected messages are signed as decided by a callback object provided
 * in constructor.
 * <p>
 * @see DSigDecider
 * @see ToBeSignedDecider 
 * 
 * @author K. Benedyczak
 * @author schuller
 */
public class DSigOutHandler extends AbstractSoapInterceptor 
{
	static final Logger logger = Log.getLogger(Log.SECURITY + ".dsig", DSigOutHandler.class); 
	
	private static final String WSS_NS_STRING = 
		"http://docs.oasis-open.org/wss/2004/01/" +
		"oasis-200401-wss-wssecurity-secext-1.0.xsd"; 

	public final static QName WS_SECURITY = new QName(WSS_NS_STRING, "Security");
	
	private Crypto merlin;
	
	private DSigDecider decider;
	private X509Credential credential;
	private ToBeSignedDecider partsDecider;
	private boolean disabled = false;
	
	private static final Set<QName>qnameSet=new HashSet<QName>();
	static{
		qnameSet.add(WS_SECURITY);
	}
	
	/**
	 * Constructor initializes this handler. 
	 * @param credential Mandatory credential of the signature creator, used to get a private key
	 * for making signatures.
	 * @param decider Per message decider saying if it should be signed or not.
	 * Can be null meaning that all messages should be signed.
	 */
	public DSigOutHandler(X509Credential credential, 
			DSigDecider decider)
	{
		this(credential, decider, null);
	}

	/**
	 * Constructor initializes this handler. 
	 * @param credential Mandatory credential of the signature creator, used to get a private key
	 * for making signatures.
	 * @param decider Per message decider saying if it should be signed or not.
	 * Can be null meaning that all messages should be signed.
	 * @param partsDecider Per message decider saying what parts should be signed.
	 * Can be null meaning that only SOAP body should be signed.
	 */
	public DSigOutHandler(X509Credential credential, 
			DSigDecider decider, ToBeSignedDecider partsDecider)
	{
		super(Phase.PRE_PROTOCOL_ENDING);
		getBefore().add(SAAJOutEndingInterceptor.class.getName());
		reinit(credential, decider, partsDecider);
	}
	
	/**
	 * (Re) initializes this handler. 
	 * @param credential Mandatory credential of the signature creator, used to get a private key
	 * for making signatures.
	 * @param decider Per message decider saying if it should be signed or not.
	 * Can be null meaning that all messages should be signed.
	 * @param partsDecider Per message decider saying what parts should be signed.
	 * Can be null meaning that only SOAP body should be signed.
	 */
	protected void reinit(X509Credential credential, 
			DSigDecider decider, ToBeSignedDecider partsDecider)
	{
		this.decider = decider;
		this.partsDecider = partsDecider;
		this.credential = credential;
		try
		{
			merlin = new WSS4JCryptoImpl(credential);
		} catch(Exception e)
		{
			logger.fatal("Could not set up digital signature out handler.", e);
		}
	}
	
	
	public void handleMessage(SoapMessage message)
	{
		if (disabled || (decider != null && !decider.isMessageDSigCandidate(message)))
			return;
		
		long start = System.currentTimeMillis();
		//build DOM
		Document docToSign;
		try
		{
			SOAPMessage saajMessage=message.getContent(SOAPMessage.class);
			if(saajMessage==null){
				logger.fatal("No DOM representation of message found!");
				return;
			}
			docToSign=saajMessage.getSOAPPart();
		} catch(Exception e)
		{
			logger.fatal("IO exception while building DOM of SOAP envelope " +
					"before signing: ", e);
			return;
		}
		
		if(logger.isTraceEnabled())
		{
			try 
			{
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				DOMUtils.writeXml(docToSign.getDocumentElement(), bos);
				logger.trace("Message before signing:\n" + bos.toString());
			} catch (TransformerException e) 
			{
				logger.fatal("",e);
			}
		}
		//prepare for signing
		WSSecSignature signatory = new MyWSSecSignature();
		WSSConfig config = WSSConfig.getNewInstance();
		config.setWsiBSPCompliant(true);
		signatory.setWsConfig(config);
		
		Vector<WSEncryptionPart> toBeSigned = getElementsToBeSigned(docToSign);
		WSSecHeader secHeader = new WSSecHeader();
	        
	    //sign
		try
		{
			secHeader.insertSecurityHeader(docToSign);
			signatory.setUserInfo(credential.getKeyAlias(), 
					new String(credential.getKeyPassword()));
			signatory.prepare(docToSign, merlin, secHeader);
			List<Reference> references = signatory.addReferencesToSign(toBeSigned, secHeader);
			signatory.computeSignature(references);
		} catch (WSSecurityException e)
		{
			logger.fatal("Problem while signing SOAP message: ", e);
			return;
		}
		long end = System.currentTimeMillis();
		logger.debug("Signed outgoing message, processing time: " + (end-start));
		if(logger.isTraceEnabled())
		{
			try 
			{
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				DOMUtils.writeXml(docToSign.getDocumentElement(), bos);
				logger.trace("Signed message:\n" + bos.toString());
			} catch (TransformerException e)
			{
				logger.fatal("",e);
			}
		}
		
	}

	@Override
	public Set<QName> getUnderstoodHeaders() 
	{
		return qnameSet;
	}

	/**
	 * If there is no special decider then (as according to the TAB agreement)
	 * only body is to be signed.
	 * @param docToSign
	 * @return
	 */
	private Vector<WSEncryptionPart> getElementsToBeSigned(Document docToSign)
	{
		if (partsDecider != null)
			return partsDecider.getElementsToBeSigned(docToSign);
		Vector<WSEncryptionPart> toBeSigned = new Vector<WSEncryptionPart>();
		
		toBeSigned.add(new WSEncryptionPart("Body",
				"http://schemas.xmlsoap.org/soap/envelope/", ""));

		return toBeSigned;
	}
	
	/**
	 * Extremely dirty hack to fix bug (?) in WSSecSignature from WSS4j.
	 * In the original code, when WS-I compatibility is on, there is small error
	 * in determination of inclusive prefixes list, for the SignedInfo c14n (note that
	 * in case of references actually digested it is ok). The problem is that
	 * only SignedInfo is signed, but the inclusive namespaces list is computed over
	 * containing it Security header element, what in effect includes always SOAP envelope 
	 * NS (from mustUnderstand attribute). And SOAP envelope NS prefix is likely to be 
	 * changed by e.g. gateway.
	 * 
	 * @author K. Benedyczak <golbi@mat.umk.pl>
	 */
	private static class MyWSSecSignature extends WSSecSignature
	{
		public List<String> getInclusivePrefixes(Element target, boolean excludeVisible) 
		{
			if (target.getLocalName().equals("Security"))
			{
				String ns = target.getNamespaceURI();
				if (ns == null)
					return super.getInclusivePrefixes(target, excludeVisible);
				if (target.getNamespaceURI().equals(WSConstants.WSSE_NS))
				{
					NodeList nl = target.getElementsByTagName("SignedInfo");
					if (nl.getLength() == 0)
						return Collections.emptyList();
					return super.getInclusivePrefixes((Element) nl.item(0), 
							excludeVisible);
				}
			}
			return super.getInclusivePrefixes(target, excludeVisible);
		}
	}
}
