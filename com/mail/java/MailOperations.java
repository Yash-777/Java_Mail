package com.mail.java;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.mail.BodyPart;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;

@SuppressWarnings("all")
public class MailOperations {
	private final static Log log = LogFactory.getLog(MailOperations.class);
	
	private static String TO_ADDRESS = "***************";
	
	public static void main(String[] args) throws IOException {
		tetMail(false, true);
		
		// https://github.com/protocol7/smime-java-example/blob/master/src/main/java/com/protocol7/smime/Verify.java
	}

	public static boolean sendMessage = false, auth = false, useAttachementFile = true;
	
	public static String secretMessage = "Confidential Information between sender and User Need to be Signed as Base64.";
	public static void tetMail(boolean isClassPath, boolean isSigned) {
		String subject = "Testing Subject";
		String electronic_Message = "MIME message Body - Test Mail using JavaMailAPI";
		if( sendMail(subject, electronic_Message, TO_ADDRESS, isSigned, isClassPath) ) {
			Log4J.log("Sent message successfully.");
		} else {
			Log4J.log("message failed.");
		}
	}
	// https://stackoverflow.com/q/24738657/5081877
	public static boolean sendMail(String subject, String mailMessage, String recipients, boolean isSigned, boolean isClassPath) {
		try {
			Session mailSession = getSessionObject(auth, EMail.PROTOCAL.getValue());
			Log4J.log("getSessionObject. : "+mailSession.toString());
			// Create a default MimeMessage object.
			Message message = new MimeMessage( mailSession );
			message.setFrom( new InternetAddress( EMail.USER_NAME.getValue() ) );
			message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(TO_ADDRESS));
			message.setSubject( subject );
			message.setSentDate(new Date());
			//message.setText( mailMessage );
			
			String header_name = "Content-ID", header_value = "<b>";
			message.addHeader( header_name, header_value );
			
			if ( useAttachementFile || isSigned) {
				MimeMultipart finalPart = new MimeMultipart();
				
				MimeBodyPart part1 = new MimeBodyPart();
				part1.setText(mailMessage); // Encoding: 7bit Display Message
				
				finalPart.addBodyPart(part1);
				
				if (useAttachementFile) {
					MimeBodyPart attachementPart = setAttachement();
					
					finalPart.addBodyPart( attachementPart );
				}
				
				if (isSigned) { // Generating a pkcs7-signature message (if (signSecretMessage) {)
					MimeMultipart signedParts = setSMIMEDigitallySignedData(isClassPath, mailMessage);
					// setSMIMEData_P7SCert(isClassPath, mailMessage);
					
					// Message + Attachment file + ( Secret Message + Certificate(smime.p7s) ) = Multipart
					int count = signedParts.getCount();
					for (int index = 0; index < count; index++) {
						BodyPart signedPart = signedParts.getBodyPart(index);
						finalPart.addBodyPart( signedPart );
					}
				}
				message.setContent(finalPart, finalPart.getContentType());
			} else { //Simple Message - [Plain Text | HTML Content]
				message.setContent( mailMessage, "text/plain" );
			}
      
			message.saveChanges();
			Log4J.log("Message is Ready to Send/Store.");
			
			/*ByteArrayOutputStream outStream = new ByteArrayOutputStream();
			message.writeTo(outStream);*/
			
			// https://github.com/protocol7/smime-java-example/blob/master/src/main/java/com/protocol7/smime/Sign.java
			message.writeTo(System.out);
			// Content-Type: application/pkcs7-signature; name=smime.p7s; smime-type=signed-data
			// https://www.reviversoft.com/file-extensions/p7s
			message.writeTo(new FileOutputStream(EMail.SAVE_MESSAGE.getValue()));
			if (sendMessage) {
				/*ByteArrayInputStream inStream = new ByteArrayInputStream(outStream.toByteArray());
				Message messageCopy = new MimeMessage(mailSession, inStream);*/
				
				// Send message
				Transport transport = mailSession.getTransport(EMail.PROTOCAL.getValue());
				if (auth) {
					transport.connect(EMail.SMTP_HOST.getValue(), EMail.USER_NAME.getValue(), EMail.PASSWORD.getValue());
				} else {
					transport.connect();
				}
				transport.sendMessage(message, message.getAllRecipients());
				transport.close();
			}
			Log4J.log("Message Sent/Stored Succesfully.");
			return true;
		} catch(Exception ex) {
			ex.printStackTrace();
			Log4J.log(ex.getMessage());
		}
		return false;
	}
	public static Session getSessionObject(boolean auth, String protocal) {
		if(protocal.equalsIgnoreCase("SMTPS") || protocal.equalsIgnoreCase("SMTP") ) {
			return MailSession.getTransport(auth, protocal);
		}
		return getStoreSessionObject(auth, protocal);
	}
	public static Session getStoreSessionObject(boolean auth, String storeProtocal) {
		return null;
	}
	static boolean useClassPath = false;
	public static InputStream getCerFileStream(boolean isClassPath) throws FileNotFoundException {
		InputStream stream = null;
		if (isClassPath) {
			useClassPath = isClassPath;
			ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
			stream = classLoader.getResourceAsStream(EMail.CERTIFICATE_FILE.getValue());
		} else {
			stream = new FileInputStream(EMail.CERTIFICATE_FILE.getValue());
		}
		return stream;
	}
	// https://stackoverflow.com/a/34387472/5081877
	public static File getFileFromStream() throws IOException {
		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
		InputStream stream = classLoader.getResourceAsStream(EMail.AttachmentFile.getValue());
		
		File tempFile = File.createTempFile("MyServer", ".jks");
		tempFile.deleteOnExit();
		FileOutputStream out = new FileOutputStream(tempFile);
		IOUtils.copy(stream, out); // org.apache.pdfbox.io.IOUtils
		return tempFile;
	}
	
	private static MimeMultipart setSMIMEDigitallySignedData(boolean isClassPath, String mailMessage) throws Exception {
		try {
			// -keystore "D:/Yash/MyServer.jks" -storetype JKS -keypass password -storepass password
		InputStream inputStream = getCerFileStream(isClassPath);
		String password = EMail.ALIAS_PASSWORD.getValue();
		Log4J.log("FIS : "+inputStream.available()+ " toString() : "+ inputStream.toString());
		
		// cryptographicOperations
		HashMap<String, Object> certMap = BC_Cryptography.unLockToGetCertificates(inputStream, password);
		if (!certMap.isEmpty()) {
			X509Certificate signCert = (X509Certificate) certMap.get("signCert");
			PrivateKey privateKey_PEM = (PrivateKey) certMap.get("privateKey");
			KeyStore keyStore = (KeyStore) certMap.get("keystore");
			
			SMIMESignedGenerator gen = BC_Cryptography.buildSignedGenerator(signCert, privateKey_PEM, keyStore, true);
			
			// generate() method to create a CMS signed-data object, which also carries a CMS signature.
			// SecretMessage + Certificate(smime.p7s) = Multipart
			MimeMultipart signedParts = new MimeMultipart();
				
			// Signing Part - Encoding: base64
			MimeBodyPart content = new MimeBodyPart();
			String signedMsg = BC_Cryptography.getSignedMessage(signCert, privateKey_PEM, secretMessage);
			
			content.setText( signedMsg );
			signedParts = gen.generate(content);
			
			return signedParts;
		}
		
		} catch (Exception e) {
			Log4J.log("getMultipart : "+e.getMessage());
			throw new Exception(e);
		}
		return null;
	}
	
	public static MimeBodyPart setAttachement() throws MessagingException, IOException {
		MimeBodyPart fileBodyPart = new MimeBodyPart();
		DataSource source = new javax.activation.FileDataSource( EMail.AttachmentFile.getValue() );
		if (useClassPath) {
			source = new javax.activation.FileDataSource( getFileFromStream() );
		} else {
			source = new javax.activation.FileDataSource( EMail.AttachmentFile.getValue() );
		}
		fileBodyPart.setDataHandler( new DataHandler( source ) );
		fileBodyPart.setFileName( EMail.AttachmentFile.getValue() );
		return fileBodyPart;
		
	}
}
