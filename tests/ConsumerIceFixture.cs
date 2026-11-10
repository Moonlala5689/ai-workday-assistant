using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
class ConsumerIceFixture {
 static void Request(int port,string token,string body){using(var client=new TcpClient()){client.Connect(IPAddress.Loopback,port);using(var stream=client.GetStream()){string host="127.0.0.1:"+port;byte[] data=body==null?new byte[0]:Encoding.UTF8.GetBytes(body);string head=body==null?"GET /"+token+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n":"POST /"+token+" HTTP/1.1\r\nHost: "+host+"\r\nOrigin: http://"+host+"\r\nContent-Type: application/json\r\nContent-Length: "+data.Length+"\r\nConnection: close\r\n\r\n";byte[] header=Encoding.ASCII.GetBytes(head);stream.Write(header,0,header.Length);if(data.Length>0)stream.Write(data,0,data.Length);stream.Flush();var buf=new byte[1024];while(stream.Read(buf,0,buf.Length)>0){}}}}
 static int Main(string[] args){if(args.Length!=3)return 2;string mode=args[0],token=args[2];int port;if(!Int32.TryParse(args[1],out port))return 2;if(mode=="exit")return 23;if(mode=="launcher-child"){var info=new System.Diagnostics.ProcessStartInfo{FileName=System.Reflection.Assembly.GetExecutingAssembly().Location,Arguments="child-return "+port+" "+token,UseShellExecute=false,CreateNoWindow=true};System.Diagnostics.Process.Start(info).Dispose();return 0;}if(mode=="child-return")Thread.Sleep(200);if(mode=="no-page"){Thread.Sleep(3000);return 0;}Request(port,token,null);if(mode=="before-ice"){Thread.Sleep(3000);return 0;}Request(port,token,"{\"phase\":\"ice-started\"}");if(mode=="no-return"){Thread.Sleep(3000);return 0;}string candidates=mode=="empty"?"":"{\"type\":\"srflx\",\"protocol\":\"udp\",\"address\":\"192.0.2.10\"}";string error=mode=="partial"?"gather timeout":"";Request(port,token,"{\"candidates\":["+candidates+"],\"error\":\""+error+"\"}");return 0;}
}
