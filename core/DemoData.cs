using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;

namespace WorkEnv {
 public static class DemoData {
  public const string Banner="模拟预览；全部虚构数据，不读取本机网络或进程，不访问外部探针。";
  public static Report Check(){var items=Engine.CompareV4(new Probe("192.0.2.10",null),new Probe("192.0.2.10",null),"192.0.2.10");int n=0;foreach(var item in items)if(item.key=="ipv4-source")item.source="虚构观察源 "+(++n);items.Add(new Item("ipv6-public","unknown","虚构样本","模拟：公网 IPv6 尚未验证","此项是固定虚构数据，不是本机状态。","真实环境需另行检查。"));items.Add(new Item("runtime-scope","unknown","虚构样本","模拟：存在未归属运行时","此项是固定虚构数据。","在真实环境的应用中确认。"));items.Add(new Item("demo","not-applicable","虚构样本",Banner,"所有结果只展示界面。","切换收工情境查看不同结果。"));return Engine.Assemble(items);}
  public static List<Item> Leave(int scenario){var items=new List<Item>();var service=new ServiceSummary{complete=true};var process=new Item("process","unknown","虚构样本","本次未检出相关候选进程","模拟结果，不代表本机。","查看演示。 "){role="未检出"};
   if(scenario<0||scenario>3){process=new Item("process","unknown","虚构样本","模拟场景不可用","未读取真实状态。","重新选择场景。"){role="枚举失败"};service.complete=false;}
   else if(scenario==1){process=new Item("process","attention","虚构样本","软件候选：示例；进程：示例后台服务；任务未知","模拟结果，不代表本机。","查看演示。"){role="后台服务"};service.observedRunning=1;service.running=1;service.matched=1;}
   else if(scenario==2){service.complete=false;service.observedRunning=1;service.running=1;service.unmatched=1;}
   else if(scenario==3){process=new Item("process","attention","虚构样本","软件候选：示例；进程：示例应用；任务未知","模拟结果，不代表本机。","查看演示。"){role="应用或命令行根进程"};}
   items.Add(process);items.Add(new Item("service-scope",service.complete?"pass":"unknown","虚构样本",service.complete?"服务样本可对照":"模拟：服务快照存在缺口","模拟结果，不代表本机。","查看演示。"){serviceEvidence=service});items.Add(new Item("runtime-scope","pass","虚构样本","模拟：无未归属运行时","模拟结果，不代表本机。","查看演示。"));return items;}
  public static List<TrafficCounter> Traffic(int turn){long step=Math.Max(0,turn);return new List<TrafficCounter>{new TrafficCounter{id="demo-only-a",name="虚构有线网卡",type="Ethernet",received=1000+step*120,sent=2000+step*40},new TrafficCounter{id="demo-only-b",name="虚构虚拟网卡",type="Tunnel",received=500+step*80,sent=600+step*20}};}
 }
}
