package eu.unicore.security.xfireutil;

import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

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
import org.apache.cxf.service.invoker.MethodDispatcher;
import org.apache.cxf.service.model.BindingOperationInfo;
import org.apache.cxf.ws.addressing.Names;
import org.w3c.dom.Node;

public class CXFUtils {

	public static boolean isLocalCall(Exchange exch){
		return isLocalCall(exch.getInMessage());
	}

	public static boolean isLocalCall(Message msg){
		return msg.getDestination().getAddress().getAddress().getValue().startsWith("local://");
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
			return getMethod(message).getName();
		}
		return  action;
	}

	public static Method getMethod(Message message){
		Exchange ex=message.getExchange();
		BindingOperationInfo bop = ex.get(BindingOperationInfo.class);
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
	
}
