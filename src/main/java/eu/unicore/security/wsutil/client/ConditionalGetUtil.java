package eu.unicore.security.wsutil.client;

import java.security.MessageDigest;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import eu.unicore.security.wsutil.ConditionalGetServerInHandler;
import eu.unicore.security.wsutil.ConditionalGetServerOutHandler;

/**
 * utility methods for handling the conditional gets
 *
 * @author schuller
 */
public class ConditionalGetUtil {


	static DateFormat iso=new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");

	static DateFormat[] formats=new DateFormat[]{
		iso,
	};

	public static class Client {

		/**
		 * get the Etag from the current server reply
		 * 
		 * @return Etag (hash value) of the representation
		 */
		public static String getEtag(){
			return ConditionalGetInHandler.getEtag();
		}

		/**
		 * get the last-modified time from the current server reply
		 * 
		 * @return modified time (usually in millis)
		 */
		public static String getLastModified(){
			return ConditionalGetInHandler.getLastModified();
		}

		/**
		 * Check if the server-side data was modified. If this is <code>true</code> the 
		 * client must use the representation it has, the server reply will not be complete
		 * 
		 * @return <code>true</code> iff the server-side data was not modified 
		 */
		public static boolean isNotModified(){
			return ConditionalGetInHandler.isNotModified();
		}


		/**
		 * before an outgoing call, tell the server to only send a representation if it has
		 * changed, by sending back the exact Etag value as received previously
		 * 
		 * @param etag - the Etag (hash value) of the client-cached representation.
		 */
		public static void setIfNoneMatch(String etag){
			ConditionalGetOutHandler.setEtag(etag);
		}

		/**
		 * before an outgoing call, tell the server to only send a representation if it has
		 * changed after the specified instant
		 * 
		 * @param lastModified - the last-modified time of the client-cached representation.
		 */
		public static void setIfModifiedSince(String lastModified){
			ConditionalGetOutHandler.setLastModified(lastModified);
		}

	}

	public static class Server {

		/**
		 * get the Etag from the current server reply
		 * 
		 * @return Etag (hash value) of the representation
		 */
		public static String getIfNoneMatch(){
			return ConditionalGetServerInHandler.getIfNoneMatch();
		}

		/**
		 * get the last-modified time from the current client request
		 * 
		 * @return modified time or <code>null</code> if it is not set OR could not be parsed
		 */
		public static Calendar getIfModifiedSince(){
			String raw=ConditionalGetServerInHandler.getIfModifiedSince();
			Calendar c=null;
			if(raw!=null){
				for(DateFormat f: ConditionalGetUtil.formats){
					synchronized(f){
						try{
							Date d=f.parse(raw);
							c=Calendar.getInstance();
							c.setTime(d);
							break;
						}catch(ParseException pe){}
					}
				}
			}
			return c;
		}

		/**
		 * check if the server-side last-modified time is later than the time provided by the
		 * client, within a grace period of 5 seconds. If this returns <code>true</code> the 
		 * new Etag should be computed and compared to the one sent by the client.
		 * If this returns <code>false</code> the server need not send any data, but can
		 * use the {@link #setNotModified()} method to tell the client to reuse the existing representation
		 * 
		 * @param lastModified - server-side last modification time
		 * @return <code>true</code> if the client did not supply a modification time, or the client-side representation 
		 * is older than the server-side one
		 */
		public static boolean wasModifiedSince(Calendar lastModified){
			Calendar clientMod=getIfModifiedSince();
			if(clientMod==null)return true;
			// grace of 5 seconds
			clientMod.add(Calendar.SECOND, -5);
			return clientMod == null || lastModified.compareTo(clientMod)>=0 ; 
		}

		/**
		 * Compares the client-side Etag to the new one. If they do not match, the
		 * server needs to send the new data. The outgoing handler is set up correctly.
		 * To avoid computing the new etag, the server should in all cases check
		 * the modification time using {@link #mustSendData(Calendar)} before invoking 
		 * this method
		 * 
		 * @param lastModified - the server-side modification time 
		 * @param newEtag - the new etag
		 * @return <code>true</code> iff the data should be sent
		 */
		public static boolean mustSendData(Calendar lastModified, String newEtag){
			String etag=getIfNoneMatch();
			if(newEtag.equals(etag)){
				setNotModified();
				return false;
			}
			else{
				// fill in new values for the client
				ConditionalGetServerOutHandler.setEtag(newEtag);
				synchronized (ConditionalGetUtil.iso) {
					ConditionalGetServerOutHandler.setLastModified(ConditionalGetUtil.iso.format(lastModified.getTime()));	
				}
				return true;
			}
		}

		/**
		 * Tell the client that the server-side data was not modified, and there will be no
		 * data sent
		 */
		public static void setNotModified(){
			ConditionalGetServerOutHandler.setNotModified();
		}


		/**
		 * compute md5 of the passed-in string
		 * @param string
		 * @return
		 */
		public static String md5(String string){
			try{
				MessageDigest md=MessageDigest.getInstance("MD5");
				md.update(string.getBytes());
				return hexString(md.digest());
			}catch(Exception ex){
				throw new RuntimeException(ex);
			}
		}
		

		/**
		 * converts the  byte-array into a more user-friendly hex string
		 * @param bytes
		 */
		public static String hexString(byte[] bytes){
			StringBuilder hexString = new StringBuilder();
			for (int i=0;i<bytes.length;i++) {
				String hex = Integer.toHexString(0xFF & bytes[i]); 
				if(hex.length()==1)hexString.append('0');
				hexString.append(hex);
			}
			return hexString.toString();
		}
	}

}
