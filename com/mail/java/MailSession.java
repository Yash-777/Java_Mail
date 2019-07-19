package com.mail.java;

import java.util.Properties;

import javax.mail.Session;

public class MailSession {
	public static Session getTransport(boolean auth, String transportProtocal) {
		Log4J.log("==- Outgoing Mail (SMTP) Server details like SMTP properties and Authenticate -==");
		Properties props = new Properties();
		if(transportProtocal.equalsIgnoreCase("SMTPS")) {
			props.put("mail.transport.protocol", "smtps");
			props.put("mail.smtp.starttls.enable", "true");
		} else {
			props.put("mail.transport.protocol", "smtp");
			props.put("mail.smtps.ssl.enable", "true");
			// props.put("mail.smtp.ssl.trust", "*");
		}
		props.put("mail.smtp.timeout", "60000");
		
		props.put("mail.smtp.host", EMail.SMTP_HOST.getValue());
		props.put("mail.smtp.port", EMail.SMTP_PORT.getValue());
		
		props.put("mail.smtp.socketFactory", "javax.net.ssl.SSLSocketFactory");
		props.put("mail.smtp.socketFactory.port", EMail.SMTP_PORT.getValue());
		props.put("mail.smtp.socketFactory.fallback", "false");
		props.put("mail.smtp.debug", "true");
		props.put("mail.smtp.quitwait", "false");
		
		// Get the Session object by Authenticating Password.
		if ( auth ){
			props.put("mail.smtp.auth", "true");
			
			props.put("mail.smtp.user", EMail.USER_NAME.getValue());
			props.put("mail.smtp.password", EMail.PASSWORD.getValue());
		} else {
			props.put("mail.smtp.auth", "false");
		}
		Session defaultInstance = Session.getDefaultInstance(props); // Session.getInstance(props);
		Log4J.log("Session DefaultInstance : "+defaultInstance.toString());
		return defaultInstance;
	}
}
