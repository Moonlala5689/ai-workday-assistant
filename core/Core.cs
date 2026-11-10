using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Management;
using System.Web.Script.Serialization;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;

namespace WorkEnv {
 public class Item {
  public string key, status, observedAt, source, observation, limitation, next, subject, role, identity;
  // Machine-readable evidence; missing values remain unknown, never inferred from display text.
  public string evidencePhase, evidenceScope, failureCode, rawResult, transportState;
  public ServiceSummary serviceEvidence;
  public Item(string k,string s,string src,string o,string l,string n) { key=k;status=s;source=src;observation=o;limitation=l;next=n;observedAt=DateTimeOffset.Now.ToString("o"); }
 }
 public class Report { public string observedAt, overall, conclusion, action; public List<Item> items=new List<Item>(); [ScriptIgnore] public Ipv6PathSnapshot ipv6Before; }
 public class Probe { public string value, error, route,phase,failureCode; public Probe(string v,string e){value=v;error=e;} }
 public class ProcessEvidence { public int pid, parent; public string name,path; public DateTime? started; public bool inaccessible, service; }
 public class ConnectionEvidence { public int pid; public string kind; }
 public class LeaveResult { public string state,conclusion,action,observedAt;public List<Item> items; }
 public class NotificationTracker {
  readonly Dictionary<string,string> previous=new Dictionary<string,string>();readonly Dictionary<string,DateTime> signals=new Dictionary<string,DateTime>(),lastGroupNotice=new Dictionary<string,DateTime>();
  public List<string> Signal(string key,string message,DateTime now) {var a=new List<string>();DateTime prior;if(!signals.TryGetValue(key,out prior)||(now-prior).TotalSeconds>=30){signals[key]=now;a.Add(message);}return a;}
  public List<string> Observe(Report r,DateTime now) {
   var result=new List<string>();
   foreach(string group in new[]{"network","process","evidence"}) {
    if(!r.items.Any(i=>Group(i)==group))continue;
    var a=r.items.Where(i=>Group(i)==group&&(i.status=="attention"||i.status=="unknown")).ToList();
    var parts=a.Select(i=>i.key+":"+i.status+":"+(group=="network"&&i.status=="unknown"?i.observation:group=="process"?i.observation:"")).Distinct().OrderBy(x=>x).ToArray();
    string signature=String.Join("|",parts);string old;previous.TryGetValue(group,out old);
    if(signature!=old){previous[group]=signature;if(signature.Length>0){lastGroupNotice[group]=now;result.Add(group=="network"?"网络观察出现需要核对或未验证的变化，请打开详情。":group=="process"?"应用或后台进程观察有变化，请在收工页面核对。":"部分检查证据不可用或发生变化，请查看详情。");}else if(old!=null&&old.Length>0)result.Add(group=="network"?"本次网络观察已恢复；仍有其他范围限制。":group=="process"?"进程观察结果发生变化，请核对任务。":"相关证据状态已更新。");}else{DateTime last;if(signature.Length>0&&lastGroupNotice.TryGetValue(group,out last)&&(now-last).TotalSeconds>=300){lastGroupNotice[group]=now;result.Add(group=="network"?"网络观察仍有需要核对的项目。":group=="process"?"应用或后台进程仍需核对。":"仍有检查证据不可用。");}}
   }return result;
  }
  static string Group(Item i){if(i.key.StartsWith("ipv4")||i.key.StartsWith("ipv6")||i.key=="system-proxy")return "network";if(i.key=="process"||i.key=="service-scope"||i.key=="runtime-scope")return "process";return "evidence";}
 }
 public class Engine {
  [StructLayout(LayoutKind.Sequential)] struct TcpRow { public uint state, localAddr, localPort, remoteAddr, remotePort, pid; }
  [StructLayout(LayoutKind.Sequential)] struct UdpRow { public uint localAddr, localPort, pid; }
  [DllImport("iphlpapi.dll", SetLastError=true)] static extern uint GetExtendedTcpTable(IntPtr table,ref int size,bool order,int family,int tableClass,uint reserved);
  [DllImport("iphlpapi.dll", SetLastError=true)] static extern uint GetExtendedUdpTable(IntPtr table,ref int size,bool order,int family,int tableClass,uint reserved);
  public static readonly string[] Targets={"https://api.ipify.org/","https://v4.ident.me/","https://api6.ipify.org/","https://v6.ident.me/"};
  public static string ErrorCategory(Exception e) {
   var win=e as System.ComponentModel.Win32Exception;if(win!=null){if(win.NativeErrorCode==5)return "权限不足";if(win.NativeErrorCode==1460)return "超时";}
   var socket=e as SocketException;if(socket!=null){if(socket.SocketErrorCode==SocketError.HostNotFound||socket.SocketErrorCode==SocketError.NoData||socket.SocketErrorCode==SocketError.TryAgain)return "DNS 失败";if(socket.SocketErrorCode==SocketError.TimedOut)return "超时";if(socket.SocketErrorCode==SocketError.AccessDenied)return "权限不足";}
   var web=e as WebException;
   if(web!=null) {
    if(web.Status==WebExceptionStatus.TrustFailure||web.Status==WebExceptionStatus.SecureChannelFailure) return "TLS 失败";
    if(web.Status==WebExceptionStatus.NameResolutionFailure||web.Status==WebExceptionStatus.ProxyNameResolutionFailure) return "DNS 失败";
    if(web.Status==WebExceptionStatus.Timeout) return "超时";
   }
   if(e is UnauthorizedAccessException) return "权限不足";
   string s=e.ToString().ToLowerInvariant();
   if(s.Contains("trustfailure")||s.Contains("securechannelfailure")||s.Contains("authenticationexception")||s.Contains("certificate")) return "TLS 失败";
   if(s.Contains("nameresolutionfailure")||s.Contains("无法解析")||s.Contains("no such host")) return "DNS 失败";
   if(s.Contains("timeout")||s.Contains("timed out")||s.Contains("超时")) return "超时";
   if(s.Contains("unauthorized")||s.Contains("access denied")||s.Contains("拒绝访问")) return "权限不足";
   return "探针或网络错误";
  }
  public static Probe Fetch(string url,AddressFamily family) {
   return ProbeExecution.Fetch(url,family,new DirectTlsTransport(),System.Threading.CancellationToken.None);
  }
  public static List<Item> CompareV4(Probe a,Probe b,string expected) {return CompareV4(a,b,!String.IsNullOrWhiteSpace(expected),expected);}
  public static List<Item> CompareV4(Probe a,Probe b,bool expectedEnabled,string expected) {
   var r=new List<Item>(); IPAddress parsed;
   bool valid=!String.IsNullOrWhiteSpace(expected)&&IPAddress.TryParse(expected.Trim(),out parsed)&&parsed.AddressFamily==AddressFamily.InterNetwork;
   foreach(var pair in new[]{new KeyValuePair<string,Probe>(Targets[0],a),new KeyValuePair<string,Probe>(Targets[1],b)}) {
    Probe p=pair.Value; bool ok=p!=null&&p.error==null&&!String.IsNullOrEmpty(p.value);
    r.Add(new Item("ipv4-source",ok?"pass":"unknown",pair.Key,ok?p.value:(p==null?"未执行":p.error),"本次探针为指定地址族直接 TLS 连接，不使用系统 HTTP 代理；可能受 VPN/TUN/网络路径影响，不能代表其他应用。","失败时检查网络或稍后重试。"));
   }
   bool complete=a!=null&&b!=null&&a.error==null&&b.error==null&&!String.IsNullOrEmpty(a.value)&&!String.IsNullOrEmpty(b.value);
   bool same=complete&&a.value==b.value;
   r.Add(new Item("ipv4-compare",!complete?"unknown":same?"pass":"attention","两个 HTTPS 观察源",!complete?"至少一个来源未得到有效结果":same?"两个来源本次一致":"两个来源返回不同地址","只比较本次探针，不代表所有应用或固定出口。","如有差异或失败，请核对网络后重试。"));
   string state=!expectedEnabled?"not-applicable":String.IsNullOrWhiteSpace(expected)?"unknown":!valid?"attention":!complete?"unknown":!same?"unknown":a.value==expected.Trim()?"pass":"attention";
   string desc=!expectedEnabled?"固定出口核对未启用":String.IsNullOrWhiteSpace(expected)?"已启用，尚未填写预期 IPv4":!valid?"预期 IPv4 格式无效":!complete?"来源不完整，无法核对预期":!same?"来源矛盾，无法核对预期":state=="pass"?"两个来源与预期一致":"观察值与预期不一致";
   r.Add(new Item("ipv4-expected",state,"选配的固定出口核对",desc,"未启用不代表固定出口已验证；只比较当前检查请求。","需要核对时填写有效 IPv4；异常时检查预期和网络。"));
   return r;
  }
  public static Item IPv6Probe(Probe p) { return new Item("ipv6-public",p!=null&&p.error==null&&!String.IsNullOrEmpty(p.value)?"pass":"unknown",Targets[2],p==null?"未执行":(p.error??p.value),"指定 IPv6 地址族直接 TLS 连接，不使用系统 HTTP 代理；可能经过 VPN/TUN。失败不证明没有 IPv6 或没有泄漏。","如需核实，检查工具和网络后复测。"); }
  public static List<Item> CompareV6(Probe a,Probe b){var probes=new[]{a,b};var list=new List<Item>();for(int i=0;i<2;i++){var p=probes[i];bool ok=p!=null&&p.error==null&&!String.IsNullOrEmpty(p.value);var item=new Item("ipv6-source",ok?"pass":"unknown",Targets[i+2],ok?p.value:p==null?"未执行":p.error,"仅本源的直接 IPv6 HTTPS 结果；失败不证明 IPv6 关闭或无泄漏。","需要时可稍后重新检查。"){evidencePhase=p==null?"未执行":p.phase,failureCode=p==null?"not-run":p.failureCode,evidenceScope="IPv6;direct;one-source"};list.Add(item);}var good=probes.Where(p=>p!=null&&p.error==null&&!String.IsNullOrEmpty(p.value)).ToList();bool conflict=good.Count==2&&good[0].value!=good[1].value;var aggregate=new Item("ipv6-public",conflict?"attention":good.Count>0?"pass":"unknown",good.Count>0?Targets[Array.IndexOf(probes,good[0])+2]:"两个 IPv6 HTTPS 来源",conflict?"两个来源观察到不同 IPv6 地址":good.Count>0?good[0].value:"两个来源均未取得公网 IPv6 地址","仅反映本轮直接 IPv6 请求；单源失败或全部失败不证明关闭或无泄漏。",conflict?"请核对两个来源的 IPv6 路径。":"其他服务仍按各自连接结果判断。"){identity=good.Count==1?"one-source":good.Count==2?"two-sources":"none",evidenceScope="IPv6;direct;two-sources"};list.Add(aggregate);return list;}
  public static Item Classify(ProcessEvidence p, IDictionary<int,ProcessEvidence> all) {
   ProcessEvidence cur=p,root=null;var seen=new HashSet<int>();bool uncertain=false;int depth=0;
   while(cur!=null){if(!seen.Add(cur.pid)){uncertain=true;break;}if(IsRoot(cur)){root=cur;break;}ProcessEvidence parent;if(cur.parent<=0||!all.TryGetValue(cur.parent,out parent))break;
    if(!cur.started.HasValue||!parent.started.HasValue||parent.started.Value>cur.started.Value)uncertain=true;
    if(cur.inaccessible||String.IsNullOrEmpty(cur.path)||parent.inaccessible||String.IsNullOrEmpty(parent.path))uncertain=true;
    cur=parent;depth++;if(depth>256){uncertain=true;break;}
   }
   string name=(p.name??"未知进程");name=System.IO.Path.GetFileName(name);string lower=name.ToLowerInvariant();
   bool suspicious=lower.Contains("codex")||lower.Contains("claude")||lower.Contains("cowork");
   if(root==null&&!suspicious)return null;
   if(root==null)uncertain=true;
   if(p.inaccessible||String.IsNullOrEmpty(p.path)||(root!=null&&(root.inaccessible||String.IsNullOrEmpty(root.path))))uncertain=true;
   string owner=root==null?(lower.Contains("claude")?"Claude":lower.Contains("codex")?"Codex":"Cowork"):Owner(root);
   string role=p.service?"后台服务":depth>0&&root!=null&&root.service?"后台服务派生进程":depth>0?"派生子进程":"应用或命令行根进程";
   string basis=root==null?"名称线索，归属未确认":depth>0?"路径可读且创建时间相符的父子链；根身份为候选":"名称或服务登记及可读取路径；未核验发布者";
   var item=new Item("process",uncertain?"unknown":"attention",basis,"软件候选："+owner+"；进程："+name+"；"+role+"；任务状态未知", "进程存在不证明任务在运行；快照与 PID 可发生变化；未检查 WSL / VM。","保存工作，在应用中确认并正常退出。");item.subject=owner+" / "+name;item.role=role;item.identity=uncertain?"疑似，归属未确认":depth>0?"派生关联，根身份为候选":"根进程候选";return item;
  }
  static bool IsRoot(ProcessEvidence p){string n=(p.name??"").ToLowerInvariant();return n=="claude.exe"||n=="claude"||n=="codex.exe"||n=="codex"||n.Contains("cowork")||p.service;}
  static string Owner(ProcessEvidence p){string n=(p.name??"").ToLowerInvariant(),path=(p.path??"").ToLowerInvariant();if(n.Contains("claude")||path.Contains("claude"))return "Claude";if(n.Contains("codex")||path.Contains("codex"))return "Codex";if(n.Contains("cowork")||path.Contains("cowork"))return "Cowork";return "已登记关联服务";}
  public static List<Item> ProcessesFromFixtures(IEnumerable<ProcessEvidence> ps) {
   var a=ps.ToList();var map=new Dictionary<int,ProcessEvidence>();foreach(var p in a) if(!map.ContainsKey(p.pid)) map[p.pid]=p;
   var result=new List<Item>(); foreach(var p in a){var x=Classify(p,map);if(x!=null)result.Add(x);}
   if(result.Count==0)result.Add(new Item("process","unknown","本机进程快照","未识别到候选进程","未观察到不等于绝对离线，WSL / VM 内部未检查。","在应用内核对并保存工作。"){role="未检出"});
   return result;
  }
  public static LeaveResult Leave(Func<List<Item>> sample) {
   List<Item> items;try{items=sample();if(items==null)throw new InvalidOperationException("empty sample");}catch(Exception e){items=new List<Item>{new Item("process","unknown","收工扫描","进程枚举失败："+ErrorCategory(e),"检查范围不完整。","在应用内确认工作状态。") {role="枚举失败"}};}
   var ps=items.Where(i=>i.key=="process").ToList();var serviceItems=items.Where(i=>i.key=="service-scope").ToList();var runtimeItems=items.Where(i=>i.key=="runtime-scope").ToList();bool failed=ps.Count==0||ps.Any(i=>i.role=="枚举失败")||serviceItems.Count!=1||serviceItems.Any(i=>i.status=="unknown"||i.serviceEvidence==null||!i.serviceEvidence.complete||i.serviceEvidence.observedRunning!=i.serviceEvidence.running||i.serviceEvidence.observedStarting>0||i.serviceEvidence.running!=i.serviceEvidence.matched||i.serviceEvidence.unmatched>0||i.serviceEvidence.starting>0||i.serviceEvidence.changed>0)||runtimeItems.Count!=1||runtimeItems.Any(i=>i.status=="unknown");
   bool application=ps.Any(i=>i.status=="attention"&&i.role!="后台服务"&&i.role!="后台服务派生进程");bool service=ps.Any(i=>i.status=="attention"&&(i.role=="后台服务"||i.role=="后台服务派生进程"));bool uncertain=ps.Any(i=>i.status=="unknown"&&i.role!="未检出");
   if(serviceItems.Count==1&&serviceItems[0].serviceEvidence!=null){var evidence=serviceItems[0].serviceEvidence;if((evidence.running>0)!=service)failed=true;}
   string state=application?"application-present":failed||uncertain?"unknown":service?"service-only":"not-detected";
   string conclusion=state=="application-present"?"发现相关应用或子进程，任务状态未知。"+(failed||uncertain?"另有扫描缺口，请查看详情。":""):state=="service-only"?"仅观察到相关后台服务，任务状态未知。":state=="not-detected"?"本次未检出相关候选进程。":"扫描不完整或存在未确认的候选，状态未知。";
   string action=state=="application-present"?"保存工作，在对应应用中确认任务；需要退出时由您正常退出。":state=="service-only"?"到相关应用核对是否仍有任务；后台服务状态不能证明任务完成。":state=="not-detected"?"确认工作已保存；是否关机或休眠由您自行决定。":"检查列出的扫描缺口，并在相关应用内核对任务状态。";
   return new LeaveResult{state=state,conclusion=conclusion,action=action,observedAt=DateTimeOffset.Now.ToString("o"),items=items};
  }
  public static Item RuntimeScope(IEnumerable<ProcessEvidence> processes,IDictionary<int,ProcessEvidence> map){int unassigned=0,unreadable=0;foreach(var p in processes){string n=(p.name??"").ToLowerInvariant();if((n=="node.exe"||n=="node")&&Classify(p,map)==null){unassigned++;if(p.inaccessible||String.IsNullOrEmpty(p.path))unreadable++;}}return new Item("runtime-scope",unassigned>0?"unknown":"pass","进程名称、可读取路径与父子关系",unassigned>0?"存在 "+unassigned+" 个未归属 node 运行时（其中路径不可读 "+unreadable+" 个）；无法确认其中是否包含 CLI 任务。":"本次未观察到未归属 node 运行时。","不读取完整命令行；无法覆盖所有运行时版本及 WSL/VM。","在对应应用中核对任务状态。");}
  public static Item ConnectionSummary(IEnumerable<ConnectionEvidence> rows,ICollection<int> candidatePids) {
   var relevant=rows.Where(x=>candidatePids.Contains(x.pid)).ToList();int tcp=relevant.Count(x=>x.kind=="tcp"),listen=relevant.Count(x=>x.kind=="tcp-listen"),udp=relevant.Count(x=>x.kind=="udp-bound");
   return new Item("candidate-connections","unknown","Windows IPv4 PID 表与候选进程快照","候选进程 IPv4 TCP 非监听 "+tcp+"；TCP 监听 "+listen+"；UDP 绑定 "+udp,"仅 IPv4；UDP 为绑定快照而非流量，进程与连接快照有时间差和 PID 复用可能；连接不等于任务运行，无连接不等于离线，WSL / VM 未检查。","在应用内核对任务并保存工作。");
  }
  static List<ConnectionEvidence> Ipv4ConnectionRows() {
   var rows=new List<ConnectionEvidence>();int size=0;GetExtendedTcpTable(IntPtr.Zero,ref size,false,2,5,0);if(size<=0)throw new InvalidOperationException("TCP table unavailable");IntPtr ptr=Marshal.AllocHGlobal(size);
   try{uint code=GetExtendedTcpTable(ptr,ref size,false,2,5,0);if(code!=0)throw new System.ComponentModel.Win32Exception((int)code);int count=Marshal.ReadInt32(ptr);int stride=Marshal.SizeOf(typeof(TcpRow));for(int i=0;i<count;i++){var row=(TcpRow)Marshal.PtrToStructure(IntPtr.Add(ptr,4+i*stride),typeof(TcpRow));rows.Add(new ConnectionEvidence{pid=(int)row.pid,kind=row.state==2?"tcp-listen":"tcp"});}}finally{Marshal.FreeHGlobal(ptr);}
   size=0;GetExtendedUdpTable(IntPtr.Zero,ref size,false,2,1,0);if(size<=0)throw new InvalidOperationException("UDP table unavailable");ptr=Marshal.AllocHGlobal(size);
   try{uint code=GetExtendedUdpTable(ptr,ref size,false,2,1,0);if(code!=0)throw new System.ComponentModel.Win32Exception((int)code);int count=Marshal.ReadInt32(ptr);int stride=Marshal.SizeOf(typeof(UdpRow));for(int i=0;i<count;i++){var row=(UdpRow)Marshal.PtrToStructure(IntPtr.Add(ptr,4+i*stride),typeof(UdpRow));rows.Add(new ConnectionEvidence{pid=(int)row.pid,kind="udp-bound"});}}finally{Marshal.FreeHGlobal(ptr);}return rows;
  }
  static string Str(ManagementBaseObject o,string key){try{return Convert.ToString(o[key]);}catch{return null;}}
  static ServiceSnapshot ReadServices(){var snapshot=new ServiceSnapshot{observedAt=DateTime.Now,complete=true};try{using(var q=new ManagementObjectSearcher("SELECT Name, ProcessId, State FROM Win32_Service"))foreach(ManagementObject s in q.Get()){string name=Str(s,"Name");if(String.IsNullOrEmpty(name)){snapshot.complete=false;continue;}string n=name.ToLowerInvariant();if(n.Contains("claude")||n.Contains("codex")||n.Contains("cowork")){int id;if(!Int32.TryParse(Str(s,"ProcessId"),out id))snapshot.complete=false;string state=Str(s,"State");if(String.IsNullOrEmpty(state))snapshot.complete=false;snapshot.services.Add(new ServiceEvidence{name=name,state=state,pid=id});}}}catch{snapshot.complete=false;}return snapshot;}
  public static List<Item> LocalProcesses() {
   try {
    var firstServices=ReadServices();var a=new List<ProcessEvidence>();bool processesComplete=true;
    using(var q=new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate FROM Win32_Process")) foreach(ManagementObject x in q.Get()) {
     int id,parent;if(!Int32.TryParse(Str(x,"ProcessId"),out id)){processesComplete=false;continue;}if(!Int32.TryParse(Str(x,"ParentProcessId"),out parent)){processesComplete=false;parent=0;}string path=Str(x,"ExecutablePath"),name=Str(x,"Name");if(String.IsNullOrWhiteSpace(name))processesComplete=false;DateTime dt;DateTime? start=null;
     try{string d=Str(x,"CreationDate");if(!String.IsNullOrEmpty(d)){dt=ManagementDateTimeConverter.ToDateTime(d);start=dt;}}catch{}
     a.Add(new ProcessEvidence{pid=id,parent=parent,name=name,path=path,started=start,inaccessible=String.IsNullOrEmpty(path)});
    }
    var secondServices=ReadServices();var assessment=ServiceCheck.Assess(firstServices,secondServices,a,processesComplete);foreach(var p in a)p.service=assessment.matchedPids.Contains(p.pid);
    var res=ProcessesFromFixtures(a);var map=new Dictionary<int,ProcessEvidence>();foreach(var p in a)if(!map.ContainsKey(p.pid))map[p.pid]=p;
    res.Add(RuntimeScope(a,map));
    var ids=new HashSet<int>(a.Where(p=>Classify(p,map)!=null).Select(p=>p.pid));
    try{res.Add(ConnectionSummary(Ipv4ConnectionRows(),ids));}catch(Exception e){res.Add(new Item("candidate-connections","unknown","Windows IPv4 PID 表",ErrorCategory(e),"未完成候选进程连接观察。","在应用内核对任务。"));}
    res.Add(ServiceCheck.ToItem(assessment));return res;
   } catch(Exception e) { return new List<Item>{new Item("process","unknown","Windows WMI",ErrorCategory(e),"未能读取进程快照。","检查权限后重试；不要据此认定已经退出。") {role="枚举失败"}}; }
  }
  public static List<Item> LocalNetwork() {
   var r=new List<Item>();try {
    int addresses=0, gateways=0;foreach(var nic in NetworkInterface.GetAllNetworkInterfaces()) {var p=nic.GetIPProperties();addresses+=p.UnicastAddresses.Count(x=>x.Address.AddressFamily==AddressFamily.InterNetworkV6 && !IPAddress.IsLoopback(x.Address));gateways+=p.GatewayAddresses.Count(x=>x.Address.AddressFamily==AddressFamily.InterNetworkV6);}
    r.Add(new Item("ipv6-local","pass","本机网卡地址","观察到 IPv6 地址数："+addresses,"地址存在或缺失均不能证明公网可达或泄漏。","结合公网探针与路由核对。"));
    r.Add(new Item("ipv6-gateway","pass","网卡网关摘要","观察到 IPv6 网关数："+gateways,"网关数量不能代替实际路由。","结合路由表查看。"));
   }catch(Exception e){r.Add(new Item("ipv6-local","unknown","本机网卡",ErrorCategory(e),"未完成地址读取。","核对权限后复查。"));}
   r.Add(new Item("ipv6-tool","unknown","应用内 HTTPS 实现","已加载 IPv6 探针代码，工具本身尚未独立验证","加载代码不证明工具正常或网络可达；不依赖系统 curl。","查看公网探针的实际结果。"));
   r.AddRange(LocalState.ReadIpv6Routes());r.Add(LocalState.ReadProxy());return r;
  }
  public static Item Traffic() { try {long rx=0,tx=0;foreach(var n in NetworkInterface.GetAllNetworkInterfaces()){var s=n.GetIPv4Statistics();rx+=s.BytesReceived;tx+=s.BytesSent;}return new Item("traffic","pass","本机网卡累计字节","接收 "+rx+" 字节；发送 "+tx+" 字节","这是网卡累计值，不是某应用流量或运营商账单，重启等可重置。","结合后续快照自行比较。");}catch(Exception e){return new Item("traffic","unknown","本机网卡",ErrorCategory(e),"未读取到完整快照。","检查权限后重试。");} }
  public static Report Assemble(List<Item> items) {var r=new Report{items=items,observedAt=DateTimeOffset.Now.ToString("o")};
   bool att=items.Any(i=>i.status=="attention"),unk=items.Count==0||items.Any(i=>i.status=="unknown"),pass=items.Any(i=>i.status=="pass");r.overall=att?"attention":unk?"unknown":pass?"pass":"not-applicable";
   r.conclusion=att?"发现需要核对的项目；仍可能有未验证项。":unk?"检查完成，仍有未验证项。":pass?"本次已检查项目未发现异常。":"没有适用的检查项。";
   r.action=att?"请查看需要核对的项目。":unk?"请查看未知项及建议。":pass?"继续留意状态变化。":"核对检查范围。";return r; }
  public static Report WorkSummary(Report r){return Assemble(r.items.Where(i=>!(i.key=="process"&&i.status=="attention")).ToList());}
  public static string WorkDetail(Report r){bool hasNetwork=r.items.Any(i=>i.key.StartsWith("ipv4")||i.key.StartsWith("ipv6")||i.key=="system-proxy"||i.key=="connections");bool networkUnknown=!hasNetwork||r.items.Any(i=>(i.key.StartsWith("ipv4")||i.key.StartsWith("ipv6")||i.key=="system-proxy"||i.key=="connections"||i.key=="check")&&(i.status=="unknown"||i.status=="attention"));bool taskUnknown=r.items.Any(i=>(i.key=="process"||i.key=="runtime-scope"||i.key=="service-scope"||i.key=="candidate-connections")&&i.status=="unknown");if(networkUnknown&&taskUnknown)return "网络观察与任务范围均有待核对项；请查看详情并在收工时另行检查。";if(networkUnknown)return "网络观察有待核对项；请查看详情，收工时另行检查任务。";if(taskUnknown)return "网络观察项目未显示异常；任务范围仍有未知，请查看收工页。";return "查看本次观察详情，收工时另行检查任务。";}
  public static Report Run(string expected) {return Run(!String.IsNullOrWhiteSpace(expected),expected,System.Threading.CancellationToken.None);}
  public static Report Run(string expected,System.Threading.CancellationToken cancellation) {return Run(!String.IsNullOrWhiteSpace(expected),expected,cancellation);}
  public static Report BracketIpv6(Func<Ipv6PathSnapshot> capture,Func<Report> probe){var before=capture();var report=probe();var after=capture();report.items.Add(LocalState.EvaluateIpv6Path(before,after));var final=Assemble(report.items);final.ipv6Before=before;return final;}
  public static Report Run(bool expectedEnabled,string expected,System.Threading.CancellationToken cancellation) {return BracketIpv6(LocalState.CaptureIpv6PathSafe,delegate{using(var limit=System.Threading.CancellationTokenSource.CreateLinkedTokenSource(cancellation)){limit.CancelAfter(18000);var items=new List<Item>();if(!limit.IsCancellationRequested)items.AddRange(LocalNetwork());var transport=new DirectTlsTransport();var probes=new Probe[4];System.Threading.Tasks.Parallel.For(0,4,i=>{probes[i]=ProbeExecution.Fetch(Targets[i],i<2?AddressFamily.InterNetwork:AddressFamily.InterNetworkV6,transport,limit.Token);});items.AddRange(CompareV4(probes[0],probes[1],expectedEnabled,expected));items.AddRange(CompareV6(probes[2],probes[3]));if(probes.Skip(2).Any(p=>p!=null&&p.error==null&&!String.IsNullOrEmpty(p.value))){var tool=items.FirstOrDefault(x=>x.key=="ipv6-tool");if(tool!=null){tool.status="pass";tool.observation="内置 IPv6 探针本次得到有效地址";}}if(limit.IsCancellationRequested)items.Add(new Item("check","unknown","检查控制","检查已取消或超时，未完成全部本机观察。","未完成不等于通过。","需要时重新检查。"));return Assemble(items);}});}
  public static string Redact(string s) {if(s==null)return null;
   s=Regex.Replace(s,@"\\\\[^\\\s]+\\[^\r\n\""<>|]*","[路径已隐去]");
   s=Regex.Replace(s,@"(?i)(?<![a-z0-9:])/(?:home|users|mnt|root)/[^\r\n\s\""<>|]*","[路径已隐去]");
   s=Regex.Replace(s,@"(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b","[IP已隐去]");
   s=Regex.Replace(s,@"(?i)(?<![0-9a-z_])(?:(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]+|::)(?:%[0-9a-z_.-]+)?(?![0-9a-z_])","[IP已隐去]");
   s=Regex.Replace(s,@"(?i)\b[a-z]:\\[^\r\n\""<>|]*","[路径已隐去]");
   s=Regex.Replace(s,@"(?i)(ssid|username|用户名|用户|命令行|commandline|token|cookie|password|密码|secret|密钥|唯一id|uniqueid|guid)\s*[:=：]\s*[^\r\n,;]+","$1=[已隐去]");
   s=Regex.Replace(s,@"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b","[标识已隐去]");
   return s; }
  public static string SafeJson(Report r) { // No arbitrary user note enters an export: it is replaced wholesale.
   var safe=new Report{observedAt=r.observedAt,overall=r.overall,conclusion=Redact(r.conclusion),action=Redact(r.action)};
   foreach(var i in r.items)safe.items.Add(new Item(i.key,i.status,Redact(i.source),i.key=="ipv6-route-entry"?"[路由详情已隐去]":Redact(i.observation),Redact(i.limitation),Redact(i.next)){observedAt=i.observedAt,subject=Redact(i.subject),role=Redact(i.role),identity=Redact(i.identity),serviceEvidence=i.serviceEvidence});
   return new JavaScriptSerializer().Serialize(safe);
  }
 }
}
