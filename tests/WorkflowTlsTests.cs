using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using WorkEnv;
class WorkflowTlsTests {
 static int count,failures;
 static void Test(bool ok,string name){count++;if(!ok)failures++;Console.WriteLine((ok?"PASS ":"FAIL ")+name);}
 static Item Probe(X509Certificate2 cert,int code,bool trust,int delay,CancellationToken token){var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;var server=new Thread(delegate(){try{using(var client=listener.AcceptTcpClient())using(var ssl=new SslStream(client.GetStream(),false)){ssl.AuthenticateAsServer(cert,false,SslProtocols.Tls12,false);var request=new List<byte>();while(request.Count<2048){int c=ssl.ReadByte();if(c<0)break;request.Add((byte)c);int n=request.Count;if(n>=4&&request[n-4]==13&&request[n-3]==10&&request[n-2]==13&&request[n-1]==10)break;}if(delay>0)Thread.Sleep(delay);var response=Encoding.ASCII.GetBytes("HTTP/1.0 "+code+" Fixture\r\nContent-Length: 0\r\n\r\n");ssl.Write(response,0,response.Length);ssl.Flush();}}catch(IOException){}catch(AuthenticationException){}catch(SocketException){}finally{listener.Stop();}});server.IsBackground=true;server.Start();try{return Functional.LoopbackServiceFixture("ext-ai-openai",port,trust?cert:null,token);}finally{server.Join(9000);}}
 static int Main(){string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"test-data","workflow","tls-loopback-fixture.pfx");using(var cert=new X509Certificate2(path,"fixture-only",X509KeyStorageFlags.Exportable)){foreach(int code in new[]{401,403,404,421,429,503}){var item=Probe(cert,code,true,0,CancellationToken.None);Test(item.transportState=="pass"&&item.subject=="http-"+code&&item.rawResult==code.ToString()&&ScoreAssessment.HttpLabel(item).Contains(code.ToString()),"回环 TLS 成功，保留 HTTP "+code);}var bad=Probe(cert,200,false,0,CancellationToken.None);Test(bad.transportState=="attention"&&bad.failureCode.StartsWith("certificate-"),"未受信证书不能算 TLS 成功");using(var cancel=new CancellationTokenSource()){cancel.CancelAfter(150);var item=Probe(cert,200,true,700,cancel.Token);Test(item.transportState=="pass"&&item.failureCode=="cancelled"&&item.evidencePhase=="HTTP","TLS 已完成后取消 HTTP 保留传输证据");}var slow=Probe(cert,200,true,6500,CancellationToken.None);Test(slow.transportState=="pass"&&slow.failureCode=="timeout"&&slow.evidencePhase=="HTTP","HTTP 读取超时保留 TLS 成功");}Console.WriteLine("TOTAL "+count+" FAIL "+failures);return failures==0?0:1;}
}
