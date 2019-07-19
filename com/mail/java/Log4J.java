package com.mail.java;

import org.apache.log4j.Logger;

@SuppressWarnings("all")
public class Log4J {
	static boolean log = false;
	
	public static void log(String msg) {
		int callerFrame = 2; // Frames [Log4J.log(), CallerClass.methodCall()] 
		StackTraceElement callerFrameStack = null;
		
		StackTraceElement[] stackTraceElements = (new Throwable()).getStackTrace(); // Frame1:Log4J.log(), Frame2:CallerClass
		//StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();// Frame1:Thread.getStackTrace(), Frame2:Log4J.log(), Frame3:CallerClass
		int callerMethodFrameDepth = callerFrame; // Caller Class Frame = Throwable:2(callerFrame), Thread.currentThread:2(callerFrame+1)
		for (int i = 0; i < stackTraceElements.length; i++) {
			StackTraceElement threadFrame = stackTraceElements[i];
			if (i+1 == callerMethodFrameDepth) {
				callerFrameStack = threadFrame;
				System.out.format("Called form Clazz:%s, Method:%s, Line:%d\n", threadFrame.getClassName(), threadFrame.getMethodName(), threadFrame.getLineNumber());
			}
		}
		
		System.out.println(msg);
		if (!log){
			Logger logger = Logger.getLogger(callerFrameStack.getClass());
			logger.info(msg);
		}
	}
}
