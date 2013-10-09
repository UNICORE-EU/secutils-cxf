package eu.unicore.security.wsutil;

import java.io.OutputStream;
import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.headers.Header;
import org.apache.cxf.helpers.CastUtils;
import org.apache.cxf.message.Exchange;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.PhaseInterceptorChain;
import org.apache.cxf.service.invoker.MethodDispatcher;
import org.apache.cxf.service.model.BindingOperationInfo;
import org.apache.cxf.transport.http.AbstractHTTPDestination;
import org.apache.cxf.transport.servlet.ServletDestination;
import org.apache.cxf.ws.addressing.AddressingProperties;
import org.apache.cxf.ws.addressing.ContextUtils;
import org.apache.cxf.ws.addressing.Names;
import org.w3c.dom.Node;

public class CXFUtils {

	public static boolean isLocalCall(Exchange exch){
		return isLocalCall(exch.getInMessage());
	}

	public static boolean isLocalCall(Message msg){
		return msg.getDestination()==null || !(msg.getDestination() instanceof ServletDestination);
	}

	public static String getAction(Message message){
		if(message==null)return null;
		
		String action=null;
		
		if(message.get(Message.PROTOCOL_HEADERS)!=null){
			Map<String, List<String>> headers = CastUtils.cast((Map<?, ?>)message.get(Message.PROTOCOL_HEADERS));
			if (headers != null) {
				List<String> sa = headers.get("SOAPAction");
				if (sa != null && sa.size() > 0) {
					action = sa.get(0);
					if (action.startsWith("\"")) {
						action = action.substring(1, action.length() - 1);
					}
				}
			}
		}
		
		if(action==null && message instanceof SoapMessage){
			Header wsaAction=((SoapMessage)message).getHeader(Names.WSA_ACTION_QNAME);
			if(wsaAction!=null){
				action=String.valueOf(wsaAction.getObject());
			}
		}
		if(action==null){
			Method m=getMethod(message);
			action = m!=null ? m.getName() : null;
		}
		return  action;
	}

	public static Method getMethod(Message message){
		Exchange ex=message.getExchange();
		BindingOperationInfo bop = ex.get(BindingOperationInfo.class);
		if(bop==null)
			return null;
		
		MethodDispatcher md = (MethodDispatcher)ex.getService().get(MethodDispatcher.class.getName());
		return md.getMethod(bop);
	}

	/**
	 * write DOM node to output stream in raw format (no indent)
	 * @param n
	 * @param os
	 * @throws TransformerException
	 */
	public static void writeXml(Node n, OutputStream os) throws TransformerException{
		TransformerFactory tf = TransformerFactory.newInstance();
		// identity
		Transformer t = tf.newTransformer();
		t.setOutputProperty(OutputKeys.INDENT, "no");
		t.transform(new DOMSource(n), new StreamResult(os));
	}
	
	/**
	 * get the current message (stored thread-locally)
	 */
	public static Message getCurrentMessage(){
		return PhaseInterceptorChain.getCurrentMessage();
	}
	
	/**
	 * get the ws-addressing properties from the current message
	 */
	public static AddressingProperties getAddressingProperties(){
		return ContextUtils.retrieveMAPs(getCurrentMessage(), false, false);
	}
	
	/**
	 * get the client's SSL certificates from the SOAP message
	 * @param message - the incomping SOAP message
	 * @return client's certificate path retrieved via the HttpServletRequest
	 */
	public static X509Certificate[] getSSLCerts(SoapMessage message){
		X509Certificate[] certs =null;
		HttpServletRequest req =(HttpServletRequest)message.get(AbstractHTTPDestination.HTTP_REQUEST);
		if(req!=null){
			certs = (X509Certificate[])req.getAttribute("javax.servlet.request.X509Certificate");
		}
		return certs;
	}
	
	/**
	 * get the client's IP address from the SOAP message
	 * @param message - the incoming SOAP message
	 * @return the remote address as retrieved via the HttpServletRequest
	 */
	public static String getClientIP(SoapMessage message){
		HttpServletRequest req = (HttpServletRequest)message.get(AbstractHTTPDestination.HTTP_REQUEST);
		return req!=null? req.getRemoteAddr() : null ;
	}
	
	/**
	 * get the HttpServletRequest
	 * @param message - the incoming SOAP message
	 */
	public static HttpServletRequest getServletRequest(SoapMessage message){
		return (HttpServletRequest)message.get(AbstractHTTPDestination.HTTP_REQUEST);
	}
	
}
