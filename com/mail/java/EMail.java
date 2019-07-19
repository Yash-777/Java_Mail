package com.mail.java;

public enum EMail {
	USER_NAME("**********"), PASSWORD("***********"),
	SMTP_HOST("*****"), SMTP_PORT("25"),
	
	PROTOCAL("smtp"), // smtp, imap, pop3,smtps, imaps, pop3s
	
	CERTIFICATE_FILE("MyServer.jks"), ALIAS_NAME(""), ALIAS_PASSWORD("password"),
	SIGNATURE_AlgorithmIdentifier("SHA256withRSA"),
	EMAIL_PROVIDER(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME), // BC
	CERTIFICATE_TYPE("X.509"),
	KEYSTORE_TYPE("JKS", "PKCS12"), //*.jks, *.p12, *.pfx
	SAVE_MESSAGE("D:/SendingMessage.txt"),
	AttachmentFile(CERTIFICATE_FILE.getValue())
	;
	
	private String value;
	EMail(final String value) {
		this.value = value;
	}
	public String getValue() {
		return value;
	}
	public void setValue(String value) {
		this.value = value;
	}
	
	private String[] values;
	EMail(final String value1, final String value2) {
		this.values = new String[]{value1, value2};
	}
	public String[] getValues() {
		return values;
	}
}
