using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using WorkEnv;
class ConsumerIceTests {
 static int count,failed;static void T(bool ok,string name){count++;if(!ok)failed++;Console.WriteLine((ok?"PASS ":"FAIL ")+name);}
 static int Main(){string root=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"test-data","consumer");Directory.CreateDirectory(root);var baseline=Engine.Assemble(Engine.CompareV4(new Probe("192.0.2.10",null),new Probe("192.0.2.10",null),false,""));baseline.items.Add(new Item("ipv6-path","pass","虚构","无路径","虚构",""){identity="ipv6-path-no-path"});string created=null;Func<string,List<Item>> run=delegate(string mode){return BrowserIce.CollectFixture(baseline,root,mode,CancellationToken.None,delegate(string p){created=p;},false);};
  var result=run("launcher-child");T(result.First(i=>i.key=="ext-rtc-compare").status=="pass"&&!Directory.Exists(created),"启动器退出后，同 Job 子进程仍能返回回环结果并清理");result=run("success");T(result.First(i=>i.key=="ext-rtc-compare").status=="pass"&&!Directory.Exists(created),"回报到达即使发送端退出仍可接收");result=run("exit");var first=result.First(i=>i.key=="ext-rtc-browser");Console.WriteLine("DIAG exit="+first.failureCode+" phase="+first.evidencePhase+" raw="+first.rawResult+" dir="+Directory.Exists(created));T(first.failureCode=="browser-exited"&&(first.rawResult??"").Contains("exit=23")&&!Directory.Exists(created),"所有进程退出保留退出码并清理");
  foreach(string mode in new[]{"no-page","before-ice","no-return"}){result=run(mode);first=result.First(i=>i.key=="ext-rtc-browser");string phase=mode=="no-page"?"page-request":mode=="before-ice"?"before-ice":"ice-return";T(first.failureCode=="timeout"&&first.evidencePhase==phase&&!Directory.Exists(created),"独立超时阶段 "+phase);}
  result=run("partial");T(result.First(i=>i.key=="ext-rtc-path").status=="unknown"&&result.First(i=>i.key=="ext-rtc-path").observation.Contains("srflx"),"部分候选保留且不冒充完整");result=run("empty");T(result.First(i=>i.key=="ext-rtc-browser").failureCode=="no-candidates","无候选不认作无泄漏");
  var dirs=new List<string>();result=BrowserIce.CollectFixtureRetry(baseline,root,CancellationToken.None,delegate(string p){dirs.Add(p);});T(dirs.Count==2&&dirs.All(p=>!Directory.Exists(p))&&result.First(i=>i.key=="ext-rtc-compare").status=="pass","启动失败一次后回退自建进程且均清理");
  using(var cancel=new CancellationTokenSource()){cancel.CancelAfter(150);result=BrowserIce.CollectFixture(baseline,root,"no-page",cancel.Token,delegate(string p){created=p;},false);T(result.First(i=>i.key=="ext-rtc-browser").failureCode=="cancelled"&&!Directory.Exists(created),"取消有界且只清理自身会话");}
  result=BrowserIce.CollectFixture(baseline,root,"success",CancellationToken.None,delegate(string p){created=p;},true);try{T(result.Any(i=>i.key=="ext-rtc-cleanup"&&i.failureCode=="cleanup-failed")&&Directory.Exists(created),"清理失败独立记录");}finally{if(Directory.Exists(created))BrowserIce.CleanupFixture(root,created);}T(!Directory.Exists(created),"仅清理本次自建测试会话");Console.WriteLine("TOTAL "+count+" FAIL "+failed);return failed==0?0:1;
 }
}
