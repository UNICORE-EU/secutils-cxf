package eu.unicore.security.wsutil.client;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.xml.namespace.QName;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.ws.addressing.Names;

/**
 * A hack to let USE accept various SOAP headers.
 *
 * This class is thread safe, i.e. one can dynamically add or remove QNames at runtime.
 * 
 * @author schuller
 * @author golbi
 */
public class CheckUnderstoodHeadersHandler extends AbstractSoapInterceptor {

	private final Set<QName> understoodHeaders=new HashSet<QName>();
	private final ReadWriteLock rwLock = new ReentrantReadWriteLock();
	
	//default headers that the stack understands. This can be
	//important what talking to clients/servers that are not our own,
	//and which set the SOAP mustUnderstand flag on these headers
	public static final QName[] defaultHeaders =new QName[]{
		Names.WSA_ACTION_QNAME,
		Names.WSA_ADDRESS_QNAME,
		Names.WSA_FROM_QNAME,
		Names.WSA_TO_QNAME,
		Names.WSA_FAULTTO_QNAME,
		Names.WSA_REPLYTO_QNAME,
		Names.WSA_MESSAGEID_QNAME,
		Names.WSA_RELATESTO_QNAME,
	}; 
	
	/**
	 * add a handler which claims to understand the default list of headers
	 * @see CheckUnderstoodHeadersHandler#defaultHeaders
	 */
	public CheckUnderstoodHeadersHandler()
	{
		super(Phase.PRE_PROTOCOL);
		addUnderstoodHeaders(defaultHeaders);
	}
	
	public void addUnderstoodHeaders(QName[] qn){
		rwLock.writeLock().lock();
		for(int l=0;l<qn.length;l++)understoodHeaders.add(qn[l]);
		rwLock.writeLock().unlock();
	}

	@Override
	public Set<QName> getUnderstoodHeaders() {
		rwLock.readLock().lock();
		Set<QName> ret = new HashSet<QName>();
		ret.addAll(understoodHeaders);
		rwLock.readLock().unlock();
		return ret;
	}

	@Override
	public void handleMessage(SoapMessage message) throws Fault {
	}
	
}
