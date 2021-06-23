package eu.unicore.security.wsutil;


import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.binding.soap.interceptor.ReadHeadersInterceptor;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.staxutils.W3CDOMStreamReader;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;

import eu.unicore.util.Log;



/**
 * This handler is responsible for building a DOM tree of the whole incoming message,
 * and storing it in message context, for further signature verification in 
 * {@link DSigSecurityInHandler}.
 * 
 * It can be used both server-side and on the client side (for verifying messages 
 * returned from server).
 * 
 * <p>
 * This handler must have an access to the whole message through STAX reader. The
 * read message is later replied to the reader, so it can be read again and parsed by 
 * other handlers.
 * <p>
 * To improve performance only selected messages are converted to DOM. The selection
 * is done by special callback object passed as a constructor argument
 * (see {@link DSigDecider}).
 * 
 * @author K. Benedyczak
 */
public class DSigParseInHandler extends AbstractSoapInterceptor
{
	protected static final Logger logger = Log.getLogger(Log.SECURITY + ".dsig",
			DSigParseInHandler.class);
	public final static String DOCUMENT_DOM_KEY = DSigParseInHandler.class.getName() + "_DOM";

	private DSigDecider decider;

	/**
	 * Creates the handler.
	 * @param decider callback object used to make per request decision if message DOM
	 * should be created or not. If null then DOM is created for every message.
	 */
	public DSigParseInHandler(DSigDecider decider)
	{
		super(Phase.READ);
		getBefore().add(ReadHeadersInterceptor.class.getName());
		this.decider = decider;
	}

	public void handleMessage(SoapMessage message){
		if (decider == null || decider.isMessageDSigCandidate(message)){
			try{
				buildDOM(message);
			}
			catch(Exception ex){
				throw new Fault(ex);
			}
		}
	}

	protected void buildDOM(Message message) throws XMLStreamException, ParserConfigurationException
	{
		logger.debug("Creating DOM from SOAP message");
		long start = System.currentTimeMillis();

		Document doc;
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		XMLStreamReader xmlStreamReader = message.getContent(XMLStreamReader.class);
		if (xmlStreamReader == null)
		{
			logger.warn("XML Stream reader content is not available for the message content. Can not build DOM");
			return;
		}
		try
		{
				
			doc = StaxUtils.read(dbf.newDocumentBuilder(), xmlStreamReader, false);
		} catch (XMLStreamException e1)
		{
			logger.warn("Can't parse XML stream as W3C DOM: " + e1.getMessage());
			throw e1;
		} catch (ParserConfigurationException e1)
		{
			logger.warn("Can't create W3C DOM document builder: " + 
					e1.getMessage());
			throw e1;
		}

		W3CDOMStreamReader replayStream = new W3CDOMStreamReader(doc.getDocumentElement());
		message.setContent(XMLStreamReader.class,replayStream);
		message.put(DOCUMENT_DOM_KEY, doc);
		long stop = System.currentTimeMillis();
		logger.debug("DOM creation time: {}", (stop-start));
	}

}



