using System;
using System.IO;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Threading;

namespace WorkEnv {
 public class TransportResult {public string value, peer, resolved, tlsHost;public bool direct, certificateValid, cancelled;}
 public sealed class ProbeStageException : Exception {public readonly string Phase,Code;public ProbeStageException(string phase,string code,Exception inner):base(code,inner){Phase=phase;Code=code;}}
 public interface IProbeTransport {TransportResult Query(Uri uri,AddressFamily family,CancellationToken cancel);}
 public class DirectTlsTransport : IProbeTransport {
  const int MaxBytes=16384;
  public static IPAddress SelectAddress(IPAddress[] addresses,AddressFamily family){foreach(var ip in addresses??new IPAddress[0])if(ip.AddressFamily==family)return ip;throw new ProbeStageException("DNS","no-address-family",null);}
  public TransportResult Query(Uri uri,AddressFamily family,CancellationToken cancel) {string stage="DNS";try{
   if(uri.Scheme!=Uri.UriSchemeHttps||uri.Port!=443)throw new InvalidOperationException("only HTTPS port 443");
   var dns=Dns.BeginGetHostAddresses(uri.DnsSafeHost,null,null);int wait=WaitHandle.WaitAny(new[]{dns.AsyncWaitHandle,cancel.WaitHandle},6500);if(wait==WaitHandle.WaitTimeout)throw new TimeoutException();if(wait!=0)throw new OperationCanceledException();
   var addresses=Dns.EndGetHostAddresses(dns);IPAddress selected=SelectAddress(addresses,family);stage="TCP";
   using(var client=new TcpClient(family)) using(cancel.Register(delegate{try{client.Close();}catch{}})) {
    client.ReceiveTimeout=6500;client.SendTimeout=6500;var pending=client.BeginConnect(selected,443,null,null);wait=WaitHandle.WaitAny(new[]{pending.AsyncWaitHandle,cancel.WaitHandle},6500);if(wait==WaitHandle.WaitTimeout)throw new TimeoutException();if(wait!=0)throw new OperationCanceledException();client.EndConnect(pending);
    var peer=(IPEndPoint)client.Client.RemoteEndPoint;if(peer==null||peer.Address.AddressFamily!=family||!peer.Address.Equals(selected))throw new InvalidOperationException("unexpected remote endpoint");
    stage="TLS";using(var ssl=new SslStream(client.GetStream(),false)) {
     ssl.ReadTimeout=6500;ssl.WriteTimeout=6500;
     // No certificate-validation override: SslStream uses the platform trust and hostname checks.
     ssl.AuthenticateAsClient(uri.DnsSafeHost,null,SslProtocols.Tls12,false);
     if(!ssl.IsAuthenticated||!ssl.IsEncrypted||!ssl.IsSigned)throw new AuthenticationException("TLS security properties unavailable");
     stage="HTTP";string request="GET "+uri.PathAndQuery+" HTTP/1.0\r\nHost: "+uri.DnsSafeHost+"\r\nUser-Agent: WorkEnv-Observation/0.2\r\nAccept: text/plain\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
     var b=Encoding.ASCII.GetBytes(request);ssl.Write(b,0,b.Length);ssl.Flush();var data=new MemoryStream();var buf=new byte[512];int n;
     while((n=ssl.Read(buf,0,buf.Length))>0){if(data.Length+n>MaxBytes)throw new InvalidDataException("response exceeds limit");data.Write(buf,0,n);}
     string body=DecodeResponse(data.ToArray());
     return new TransportResult{value=body,peer=peer.Address.ToString(),resolved=selected.ToString(),tlsHost=uri.DnsSafeHost,direct=true,certificateValid=true};
    }
   }}catch(ProbeStageException){throw;}catch(Exception e){string code=e is OperationCanceledException?"cancelled":e is TimeoutException?"timeout":e is AuthenticationException?"tls-failed":e is InvalidDataException?"invalid-http":e is SocketException&&((SocketException)e).SocketErrorCode==SocketError.ConnectionRefused?"connection-refused":stage=="DNS"?"dns-failed":stage=="TCP"?"connection-failed":stage=="TLS"?"tls-failed":stage=="HTTP"?"http-failed":"tool-failed";throw new ProbeStageException(stage,code,e);}
  }
  public static string DecodeResponse(byte[] bytes){if(bytes==null||bytes.Length>MaxBytes)throw new InvalidDataException("response exceeds limit");string response=Encoding.ASCII.GetString(bytes);int sep=response.IndexOf("\r\n\r\n",StringComparison.Ordinal);if(sep<0)throw new InvalidDataException("invalid HTTP response");string head=response.Substring(0,sep),body=response.Substring(sep+4);string[] lines=head.Split(new[]{"\r\n"},StringSplitOptions.None);if(!System.Text.RegularExpressions.Regex.IsMatch(lines[0],@"^HTTP/1\.[01] 200(?: |$)"))throw new InvalidDataException("unexpected HTTP status");
   bool chunked=false;int? length=null;foreach(var line in lines){int colon=line.IndexOf(':');if(colon<0)continue;string key=line.Substring(0,colon).Trim(),val=line.Substring(colon+1).Trim();if(key.Equals("transfer-encoding",StringComparison.OrdinalIgnoreCase)){if(!val.Equals("chunked",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("unknown transfer encoding");chunked=true;}if(key.Equals("content-length",StringComparison.OrdinalIgnoreCase)){int parsed;if(length.HasValue||!Int32.TryParse(val,out parsed)||parsed<0)throw new InvalidDataException("invalid content length");length=parsed;}}
   if(chunked){if(length.HasValue)throw new InvalidDataException("ambiguous response framing");var decoded=new StringBuilder();int pos=0;while(true){int end=body.IndexOf("\r\n",pos,StringComparison.Ordinal);if(end<0)throw new InvalidDataException("incomplete chunk");string sizeText=body.Substring(pos,end-pos).Split(';')[0];int count;if(!Int32.TryParse(sizeText,System.Globalization.NumberStyles.HexNumber,System.Globalization.CultureInfo.InvariantCulture,out count)||count<0)throw new InvalidDataException("invalid chunk size");pos=end+2;if(count==0){if(pos+2>body.Length||body.Substring(pos,2)!="\r\n")throw new InvalidDataException("unsupported trailers");break;}if(count>100-decoded.Length||pos+count+2>body.Length||body.Substring(pos+count,2)!="\r\n")throw new InvalidDataException("chunk length exceeds limit");decoded.Append(body.Substring(pos,count));pos+=count+2;}body=decoded.ToString();}else if(length.HasValue&&length.Value!=body.Length)throw new InvalidDataException("incomplete response body");
   body=body.Trim();if(body.Length>100)throw new InvalidDataException("response body exceeds limit");return body;}
 }
 public static class ProbeExecution {
  public static Probe Fetch(string url,AddressFamily family,IProbeTransport transport,CancellationToken cancel) {
   using(var limit=CancellationTokenSource.CreateLinkedTokenSource(cancel)){try {var uri=new Uri(url);limit.CancelAfter(6500);limit.Token.ThrowIfCancellationRequested();var x=transport.Query(uri,family,limit.Token);limit.Token.ThrowIfCancellationRequested();IPAddress peer,resolved,value;
    if(x==null||x.cancelled||!x.direct||!x.certificateValid||!String.Equals(x.tlsHost,uri.DnsSafeHost,StringComparison.OrdinalIgnoreCase)||!IPAddress.TryParse(x.peer,out peer)||!IPAddress.TryParse(x.resolved,out resolved)||!peer.Equals(resolved)||peer.AddressFamily!=family||!IPAddress.TryParse(x.value,out value)||value.AddressFamily!=family)
     return new Probe(null,"连接地址族、对端、TLS 或返回值未通过校验");
    return new Probe(value.ToString(),null){route="指定地址族的直接 TLS 连接；未使用系统 HTTP 代理"};
   }catch(Exception e){var stage=e as ProbeStageException;string phase=stage==null?"工具":stage.Phase,code=stage==null?"tool-failed":stage.Code;if(cancel.IsCancellationRequested)return new Probe(null,"用户已取消"){phase=phase,failureCode="cancelled"};if(limit.IsCancellationRequested||e is OperationCanceledException||code=="timeout")return new Probe(null,"探针超时"){phase=phase,failureCode="timeout"};string label=code=="no-address-family"?"DNS 未返回请求的地址族":code=="dns-failed"?"DNS 解析失败":code=="connection-refused"?"连接被拒绝":code=="connection-failed"?"连接未建立":code=="tls-failed"?"TLS 验证失败":code=="http-failed"||code=="invalid-http"?"HTTP 响应未完成或无效":"探针工具未完成";return new Probe(null,label){phase=phase,failureCode=code};}}
  }
 }
}
