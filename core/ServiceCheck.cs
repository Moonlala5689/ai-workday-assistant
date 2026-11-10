using System;
using System.Collections.Generic;
using System.Linq;

namespace WorkEnv {
 public class ServiceEvidence {public string name,state;public int pid;}
 public class ServiceSnapshot {public DateTime observedAt;public bool complete;public List<ServiceEvidence> services=new List<ServiceEvidence>();}
 public class ServiceSummary {public bool complete;public int observedRunning,observedStarting,running,starting,matched,unmatched,changed,stopped;}
 public class ServiceAssessment {public ServiceSummary summary=new ServiceSummary();public HashSet<int> matchedPids=new HashSet<int>();}
 public static class ServiceCheck {
  public static ServiceAssessment Assess(ServiceSnapshot before,ServiceSnapshot after,IEnumerable<ProcessEvidence> processes,bool processesComplete){
   var result=new ServiceAssessment();var summary=result.summary;summary.complete=before!=null&&after!=null&&before.complete&&after.complete&&processesComplete;
   if(before==null||after==null){summary.complete=false;return result;}
   var first=new Dictionary<string,ServiceEvidence>(StringComparer.OrdinalIgnoreCase);var second=new Dictionary<string,ServiceEvidence>(StringComparer.OrdinalIgnoreCase);
   foreach(var s in before.services){if(String.IsNullOrEmpty(s.name)||first.ContainsKey(s.name)){summary.complete=false;continue;}first[s.name]=s;}
   foreach(var s in after.services){if(String.IsNullOrEmpty(s.name)||second.ContainsKey(s.name)){summary.complete=false;continue;}second[s.name]=s;}
   var processMap=new Dictionary<int,ProcessEvidence>();foreach(var p in processes??new ProcessEvidence[0]){if(processMap.ContainsKey(p.pid)){summary.complete=false;continue;}processMap[p.pid]=p;}
   var names=new HashSet<string>(first.Keys,StringComparer.OrdinalIgnoreCase);names.UnionWith(second.Keys);
   foreach(string name in names){ServiceEvidence a,b;bool hasA=first.TryGetValue(name,out a),hasB=second.TryGetValue(name,out b);
    if((hasA&&String.Equals(a.state,"Running",StringComparison.OrdinalIgnoreCase))||(hasB&&String.Equals(b.state,"Running",StringComparison.OrdinalIgnoreCase)))summary.observedRunning++;
    if((hasA&&IsStarting(a.state))||(hasB&&IsStarting(b.state)))summary.observedStarting++;
    if(!hasA||!hasB){summary.changed++;summary.complete=false;continue;}
    if(!String.Equals(a.state,b.state,StringComparison.OrdinalIgnoreCase)||a.pid!=b.pid){summary.changed++;summary.complete=false;continue;}
    string state=(b.state??"").Trim();if(state.Equals("Stopped",StringComparison.OrdinalIgnoreCase)){if(a.pid!=0||b.pid!=0){summary.changed++;summary.complete=false;}else summary.stopped++;continue;}
    if(state.Equals("Start Pending",StringComparison.OrdinalIgnoreCase)||state.Equals("Starting",StringComparison.OrdinalIgnoreCase)){summary.starting++;summary.complete=false;continue;}
    if(!state.Equals("Running",StringComparison.OrdinalIgnoreCase)){summary.changed++;summary.complete=false;continue;}
    summary.running++;ProcessEvidence p;
    if(b.pid<=0||!processMap.TryGetValue(b.pid,out p)||p.inaccessible||String.IsNullOrEmpty(p.path)||!p.started.HasValue||p.started.Value>before.observedAt){summary.unmatched++;summary.complete=false;continue;}
    summary.matched++;result.matchedPids.Add(b.pid);
   }return result;
  }
  static bool IsStarting(string state){return String.Equals(state,"Start Pending",StringComparison.OrdinalIgnoreCase)||String.Equals(state,"Starting",StringComparison.OrdinalIgnoreCase);}
  public static Item ToItem(ServiceAssessment assessment){var s=assessment.summary;string state=s.complete?"pass":"unknown";var item=new Item("service-scope",state,"两次关联服务登记与中间进程快照","观察到运行线索 "+s.observedRunning+"、启动线索 "+s.observedStarting+"；稳定运行 "+s.running+"，已匹配 "+s.matched+"，未匹配 "+s.unmatched+"，启动中 "+s.starting+"，状态变化 "+s.changed+"，已停止 "+s.stopped,"仅按已知服务名称匹配；快照非原子，未覆盖全部版本、WSL 或 VM。","如有不确定，请在相关应用中确认任务。");item.serviceEvidence=s;return item;}
 }
}
