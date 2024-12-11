

import java.io.IOException;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
class UseException extends Exception {
	public UseException() {
		super();
	}

	public UseException(String s) {
		super(s);
	}
}

public class TFTPClient {
	public static void main(String argv[]) throws TftpException, UseException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, SignatureException {
		
		String userName 	= argv[0];
		String password 	= argv[1];
		String server_host 	= argv[2];
		int tcp_port 		= Integer.parseInt(argv[3]);
		String typeRW 		= argv[4];
		String fileName 	= argv[5];
		String mode 		= "octet";
		
		//String host = "";
		//String fileName = "";
		//String mode="octet"; //default mode
		//String type="";
		//try {
			// Process command line
			//if (argv.length == 0)
				//throw new UseException("--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]" );
			//use default mode(octet)
			//if(argv.length == 3){
				//host =argv[0];
			    //type = argv[argv.length - 2];
			    //fileName = argv[argv.length - 1];}
			//use other modes
			//else if(argv.length == 4){
				//host = argv[0];
				//mode =argv[argv.length-1];
				//type = argv[argv.length - 3];
				//fileName = argv[argv.length - 2];
			//}
			//else throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");
		
			client_shp_phase1 test = new client_shp_phase1(userName, password, fileName, "null");
			test.startConnection(null, tcp_port);
		
			InetAddress server = InetAddress.getByName(server_host);
			
			//process read request
			if(typeRW.matches("R")){
				TFTPclientRRQ r = new TFTPclientRRQ(server, fileName, mode);}
			//process write request
			else if(typeRW.matches("W")){
				TFTPclientWRQ w = new TFTPclientWRQ(server, fileName, mode);
			}
			else{throw new UseException("wrong command. \n--Usage-- \nocter mode:  TFTPClient [host] [Type(R/W?)] [filename] \nother mode:  TFTPClient [host] [Type(R/W?)] [filename] [mode]");}
			
		//} catch (UnknownHostException e) {
			//System.out.println("Unknown host " );
		//} catch (UseException e) {
			//System.out.println(e.getMessage());
		//}
	}
}