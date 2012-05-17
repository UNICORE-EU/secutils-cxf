package eu.unicore.security.xfireutil.client;

import java.io.IOException;

import org.codehaus.xfire.MessageContext;
import org.codehaus.xfire.exchange.InMessage;
import org.codehaus.xfire.exchange.OutMessage;
import org.codehaus.xfire.transport.http.CommonsHttpMessageSender;

public class HttpMessageSender extends CommonsHttpMessageSender {

	public HttpMessageSender(OutMessage message, MessageContext context) {
		super(message, context);
	}

	@Override
	public InMessage getInMessage() throws IOException {
		String ct = getMethod().getResponseHeader("Content-Type").getValue();
		if(ct!=null){
			int i=ct.indexOf("charset=");
			if(i>1){
				encodingFromInMessage=ct.split("charset=")[1].trim();
			}
		}
		try{
			return super.getInMessage();
		}
		finally{
			encodingFromInMessage=null;
		}
	}

	private String encodingFromInMessage;
	
	@Override
	public String getEncoding() {
		return encodingFromInMessage!=null? encodingFromInMessage : super.getEncoding();
	}

	
	
}
