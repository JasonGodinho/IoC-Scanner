import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.simple.*;
import org.json.simple.parser.JSONParser;

public class HoneypotImplementation {
	public JSONObject j;
	private static Pattern pattern;
	private static Pattern URLNameOnly;
	private static Pattern portNumberOnly;
	private static Matcher matcher;
	private final String USER_AGENT = "Mozilla/5.0";
	private static final String URL_PATTERN = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}$";
	private static final String IPADDRESS_PATTERN =	"^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." + "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +	"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +"([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
	private static final String PORT_PATTERN = "^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$" ;

	public HoneypotImplementation(){
		// Initialize the patterns to detect whether the argument or arguments entered		
		// are IP addresses, port numbers or URLS. 
		pattern = Pattern.compile(IPADDRESS_PATTERN);
		URLNameOnly = Pattern.compile(URL_PATTERN);
		portNumberOnly = Pattern.compile(PORT_PATTERN);
	}
	
	//Check whether entered argument is an IP address
	public static boolean isValidIpAddress(final String ip){		  
	  matcher = pattern.matcher(ip);
	  return matcher.matches();	    	    
	}
	
	//Check whether entered argument is a URL
	public static boolean isValidURL(String domainName) {
		return URLNameOnly.matcher(domainName).find();
	}

	//Check whether entered argument is a Port number
	public static boolean isValidPortNumber(String domainName) {
		return portNumberOnly.matcher(domainName).find();
	}

	
	//Method for sending GET request to API
	private String sendGet(String url) throws Exception {

		//Create the URL object
		URL obj = new URL(url);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();

		con.setRequestMethod("GET");
		con.setRequestProperty("User-Agent", USER_AGENT);
		con.setInstanceFollowRedirects(true);  //you still need to handle redirect manully.
		HttpURLConnection.setFollowRedirects(true);
		int responseCode = con.getResponseCode();
		
		// Follow the redirect in case of URL redirection response code 301.
		if(responseCode == 301){
			// get redirect url from "location" header field
			String newUrl = con.getHeaderField("Location");

			// get the cookie if need, for login
			String cookies = con.getHeaderField("Set-Cookie");
			con = (HttpURLConnection) new URL(newUrl).openConnection();
			con.setRequestProperty("Cookie", cookies);
			con.addRequestProperty("Accept-Language", "en-US,en;q=0.8");
			con.addRequestProperty("User-Agent", "Mozilla");
			con.addRequestProperty("Referer", "google.com");
		}
		
		BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();
		String resString = response.toString();
		return resString;
	}
	
	public static void main(String[] args) throws Exception {
      FileInputStream in = null;
      FileOutputStream out = null;
  	  HoneypotImplementation m1 = new HoneypotImplementation();
      try {
      	 //Read json data from Json file -> (honeypot.json)
      	 File file = new File(args[0]);
      	 
      	 System.out.println(file.getAbsolutePath());
    	 BufferedReader bf = new BufferedReader(new FileReader(file));
         StringBuffer sCurrentLine = new StringBuffer();
         sCurrentLine.append("[");
         String currLine;
         long startTime = System.currentTimeMillis();
         System.out.println("Starting Program:");
         while ((currLine = bf.readLine()) != null) {
        	sCurrentLine.append(currLine);
 		 }
         sCurrentLine.append("]");
		
		//Parse data retrieved from the Json file and create a Json array
 		JSONParser p = new JSONParser();
        JSONArray t = (JSONArray) p.parse(sCurrentLine.toString());

		// Run the loop for the total number of arguments.
        for(int i = 1; i< args.length;i++){
        	boolean domainFlag = false;
        	boolean ipFlag = false;
        	boolean portFlag = false;
        	
        	//Check whether the arguments entered are IP addresses, Url or Port numbers.
  		  if(m1.isValidIpAddress(args[i])){
  			  System.out.println("\n\n*********** IP address: " + args[i]+" ********************");
  			  ipFlag = true;	
  		  } else if(isValidURL(args[i])){
  			  System.out.println("\n\n************** Domain: " + args[i]+" **************************");
  			  domainFlag = true;
  		  } else if(isValidPortNumber(args[i])){
			  System.out.println("\n\n*********** Port Number: " + args[i]+" *******************");
			  portFlag = true;
		  }
	 
    		if(ipFlag){
    			// IP Address Results from VirusTotal
				System.out.println("\nQuerying VirusTotal API for IP address: " + args[i]);
    			String virusTotalRequest = "http://www.virustotal.com/vtapi/v2/ip-address/report?ip="+args[i]+"&apikey=d9ef8f0705ebdb1288ced4e251e730f232c9fe89878a81d81e3b1b8693f805ca";
  		      	String virusTotalResults = m1.sendGet(virusTotalRequest);
  		      	JSONParser parser = new JSONParser();
  		      	JSONObject virusTotalJsonObject =(JSONObject) parser.parse(virusTotalResults); 
  		      	
  		      	Iterator it2 = virusTotalJsonObject.entrySet().iterator();
				while(it2.hasNext()){
					Map.Entry pair = (Map.Entry)it2.next();
					if(pair.getValue()!=null && (pair.getKey().toString().equals("country") || pair.getKey().toString().equals("as_owner") || pair.getKey().toString().equals("asn")|| pair.getKey().toString().equals("response_code"))){
						System.out.println(pair.getKey() + " : " + pair.getValue());
						it2.remove();
					}
				}
    		  	//retrieve IP address details using ISC.SANS API
    		  	System.out.println("\nQuerying ISC.SANS API for IP address details: " + args[i]+". Please wait......");    			 
    		  	String iscRequest = "http://isc.sans.edu/api/ip/"+args[i]+"?json";
  		      	String iscResults = m1.sendGet(iscRequest);
  		      	JSONObject j =(JSONObject) parser.parse(iscResults); 
				//print result
				JSONObject k = (JSONObject) j.get("ip");
				System.out.println("\nIP address results from ISC API: "+args[i]);	
				Iterator it = k.entrySet().iterator();
				while(it.hasNext()){
					Map.Entry pair = (Map.Entry)it.next();
					if(pair.getValue()!=null){
						System.out.println(pair.getKey() + " : " + pair.getValue());
						it.remove();
					}
				}
    		} else if(domainFlag){
				 System.out.println("\n\nQuerying VirusTotal API for URL details:" + args[i]);
    			 String s = "http://www.virustotal.com/vtapi/v2/url/report?resource="+ args[i] +"&apikey=d9ef8f0705ebdb1288ced4e251e730f232c9fe89878a81d81e3b1b8693f805ca";
  		       	 String virusTotalResults =	m1.sendGet(s);
	  		     JSONParser parser = new JSONParser();
  			     JSONObject virusTotalJsonObject =(JSONObject) parser.parse(virusTotalResults); 
  		     
	  		     if(virusTotalJsonObject.get("positives").toString() != null)
  			     	System.out.println("Malware positives found: " + virusTotalJsonObject.get("positives").toString());
  		     
  		     	 Iterator it2 = virusTotalJsonObject.entrySet().iterator();
				 while(it2.hasNext()){
					Map.Entry pair = (Map.Entry)it2.next();
					if(pair.getValue()!=null && (pair.getKey().toString().equals("permalink") || pair.getKey().toString().equals("scan_date") || pair.getKey().toString().equals("url"))){
						System.out.println(pair.getKey() + " : " + pair.getValue());
						it2.remove();
					}
				}
    		} else if(portFlag){
    			 // Query SANS API for port details
    			 String s = "http://isc.sans.edu/api/port/"+args[i]+"?json";
  		      	 String iscResults= m1.sendGet(s);
  		      	
   		      	 JSONParser parser = new JSONParser();
  		      	 JSONObject j =(JSONObject) parser.parse(iscResults); 
				 System.out.println("Querying ISC.SANS API for port details: " + args[i]);	
				 
				 // Detect whether the port belongs to UDP or TCP
				 JSONObject services =(JSONObject) j.get("services");
				 JSONObject udp =(JSONObject) services.get("udp");
				 JSONObject tcp =(JSONObject) services.get("tcp");
				 
				 //Print corresponding UDP or TCP related info.
				 if(!udp.get("service").toString().equals("0")){
				 	System.out.println("UDP Service Type: " + udp.get("service"));
				 	System.out.println("UDP Service Name: " + udp.get("name"));
				 } else if(!tcp.get("service").equals("0")) {
				 	System.out.println("TCP Service Type: " + tcp.get("service"));
				 	System.out.println("TCP Service Name: " + tcp.get("name"));
				 }
				 System.out.println("Source: ISC.SANS API"); 
    		}
	 //end
	 	if(!domainFlag)
			System.out.println("\nQuerying honeypot");
        int numberOfRecordsFoundinHoneypot = 0;
        for(Object o : t){
        	if(o.toString().contains(args[i])){	

        		JSONObject t2 = (JSONObject) o;
        		JSONObject jj = (JSONObject)p.parse((String) t2.get("payload"));
        		if(ipFlag){
        			if(jj.get("victimIP")!=null && jj.get("victimIP").toString().equals(args[i])){
        			System.out.println("\nRecord " +numberOfRecordsFoundinHoneypot+":");
        			System.out.println("Information for Victim IP: " + args[i]);
        			numberOfRecordsFoundinHoneypot++;
        		    JSONObject timestampData = (JSONObject) t2.get("timestamp");
        			String timestamp = (String) timestampData.get("$date");
    
    				//Print details to console
        			System.out.println("TimeStamp: "  + timestamp.substring(0,10)+" "+ timestamp.substring(11,19));
	        		System.out.println("attackerIP: " + jj.get("attackerIP"));
    	    		System.out.println("attackerPort: " + jj.get("attackerPort"));
        			System.out.println("Source: Honeypot");
        			System.out.println("victimIP: " + jj.get("victimIP"));
        			System.out.println("victimPort: " + jj.get("victimPort"));
	        		System.out.println("ConnectionType: " + jj.get("connectionType"));
    	    		} 
        		} else if(portFlag){ 
        			if(jj.get("victimPort")!=null && jj.get("victimPort").toString().equals(args[i])){
        				System.out.println("\nRecord " + numberOfRecordsFoundinHoneypot+":");
        				System.out.println("Port Details for port: " + args[i]);
        				numberOfRecordsFoundinHoneypot++;
        				System.out.println("Source: Honeypot");
        				JSONObject timestampData = (JSONObject) t2.get("timestamp");
        				String timestamp = (String) timestampData.get("$date");
    					
    					//Print details to console
		        		System.out.println("TimeStamp: "  + timestamp.substring(0,10)+" "+ timestamp.substring(11,19));
	        			System.out.println("attackerIP: " + jj.get("attackerIP"));
        				System.out.println("attackerPort: " + jj.get("attackerPort"));
		        		System.out.println("victimIP: " + jj.get("victimIP"));
        				System.out.println("victimPort: " + jj.get("victimPort"));
        				System.out.println("ConnectionType: " + jj.get("connectionType"));
        			}
        		}
        	}
        }
        if(!domainFlag)
        System.out.println("\nTotal no of records found in honeypot: " + numberOfRecordsFoundinHoneypot + "\n");
      }
        	System.out.println("*********** End of program *************");
      } finally {
         	 if (in != null) {
         	   in.close();
	         }
    	     if (out != null) {
        	    out.close();
         	 }
      }
   }
}