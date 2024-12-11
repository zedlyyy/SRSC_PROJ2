import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.io.*;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class TFTPServer {

	public static void main(String argv[]) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

		int tcp_port = Integer.parseInt(argv[0]);

		server_shp_phase1 test = new server_shp_phase1();
        String [] parameters = test.startConnection();
   
		try {
			//use port 6973
			DatagramSocket sock = new DatagramSocket(6973);
			System.out.println("Server Ready.  Port:  " + sock.getLocalPort());

			// Listen for requests
			while (true) {
				TFTPpacket in = TFTPpacket.receive(sock);
				// receive read request
				if (in instanceof TFTPread) {
					System.out.println("Read Request from " + in.getAddress());
					TFTPserverRRQ r = new TFTPserverRRQ((TFTPread) in, parameters[0]);
				}
				// receive write request
				else if (in instanceof TFTPwrite) {
					System.out.println("Write Request from " + in.getAddress());
					TFTPserverWRQ w = new TFTPserverWRQ((TFTPwrite) in, parameters[0]);
				}
			}
		} catch (SocketException e) {
			System.out.println("Server terminated(SocketException) " + e.getMessage());
		} catch (TftpException e) {
			System.out.println("Server terminated(TftpException)" + e.getMessage());
		} catch (IOException e) {
			System.out.println("Server terminated(IOException)" + e.getMessage());
		}
	}
}