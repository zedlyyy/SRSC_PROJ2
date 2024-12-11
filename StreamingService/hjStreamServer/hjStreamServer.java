/*
* hjStreamServer.java 
* Streaming server: emitter of video streams (movies)
* Can send in unicast or multicast IP for client listeners
* that can play in real time the transmitted movies
*/

import java.io.*;
import java.net.*;

class hjStreamServer {

	static public void main( String []args ) throws Exception {
	        //if (args.length != 3)
	        //{
	         //System.out.println("Use: hjStramSrver <movie> <ip-multicast-address> <port>");
	         //System.out.println("Ex: hjStreamSrver  <movie> 224.2.2.2 9000");		 		 
	         //System.out.println(" or: hjStreamSrver  <movie> <ip-unicast-address> <port>");
	         //System.out.println("Ex: hjStreamSrver  <movie> 127.0.0.1 10000");		 		 		 

		 
	         //System.exit(-1);
	        //}
      
		server_shp_phase1 test = new server_shp_phase1();
		String [] parameters = test.startConnection();
		String movie = parameters[0];
		String udpPort = parameters[1];
			
		int size;
		int count = 0;
 		long time;
		DataInputStream g = new DataInputStream( new FileInputStream(movie) );
		byte[] buff = new byte[65000];
		DatagramSocket s = new DatagramSocket();
		InetSocketAddress addr =
		    new InetSocketAddress("127.0.0.1",Integer.parseInt(udpPort));
		DatagramPacket p=new DatagramPacket(buff,buff.length,addr);
		long t0 = System.nanoTime(); // tempo de referencia
		long q0 = 0;

		while ( g.available() > 0 ) {
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time; // tempo de referencia no stream
			count += 1;
			g.readFully(buff, 0, size );
			p.setData(buff, 0, size );
			p.setSocketAddress( addr );
			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
			s.send( p );
			//System.out.print( "." );
		}

		System.out.println("\nEND ! packets with frames sent: "+count);
	}

}
