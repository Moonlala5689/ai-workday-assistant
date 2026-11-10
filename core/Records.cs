using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Web.Script.Serialization;

namespace WorkEnv {
 public class TrafficCounter {public string id,name,type;public long received,sent;}
 public class TrafficDelta {public string name,type,status,reason;public long received,sent;}
 public static class TrafficSnapshots {
  public static List<TrafficCounter> Capture(){var result=new List<TrafficCounter>();foreach(var n in NetworkInterface.GetAllNetworkInterfaces()){var c=n.GetIPStatistics();result.Add(new TrafficCounter{id=n.Id,name=n.Name,type=n.NetworkInterfaceType.ToString(),received=c.BytesReceived,sent=c.BytesSent});}return result;}
  public static List<TrafficDelta> Compare(IEnumerable<TrafficCounter> before,IEnumerable<TrafficCounter> after){var old=before.ToDictionary(x=>x.id);var latest=after.ToList();var result=new List<TrafficDelta>();foreach(var current in latest){TrafficCounter prior;bool found=old.TryGetValue(current.id,out prior);bool valid=found&&current.received>=prior.received&&current.sent>=prior.sent;result.Add(new TrafficDelta{name=current.name,type=current.type,status=valid?"pass":"unknown",reason=valid?"同一网卡累计值差额":found?"计数回退，可能重置":"首次出现",received=valid?current.received-prior.received:0,sent=valid?current.sent-prior.sent:0});}foreach(var prior in old.Values)if(!latest.Any(x=>x.id==prior.id))result.Add(new TrafficDelta{name=prior.name,type=prior.type,status="unknown",reason="网卡已消失"});return result;}
 }
 public class RecordStore {
  readonly string dir;readonly long maxBytes;
  public RecordStore(string directory):this(directory,1048576){}
  public RecordStore(string directory,long limit){if(limit<1)throw new ArgumentOutOfRangeException("limit");dir=directory;maxBytes=limit;}
  void Append(string kind,string json,DateTime when){Directory.CreateDirectory(dir);string stem=kind+"-"+when.ToString("yyyy-MM");int n=0;string file;do{file=Path.Combine(dir,stem+(n==0?"":"-"+n)+".jsonl");n++;}while(File.Exists(file)&&new FileInfo(file).Length>=maxBytes);File.AppendAllText(file,json+Environment.NewLine,new UTF8Encoding(false));}
  public void Report(Report report,DateTime when){Append("history",Engine.SafeJson(report),when);}
  public void Note(string note,DateTime when){var json=new JavaScriptSerializer().Serialize(new{observedAt=when.ToString("o"),kind="note",text=Engine.Redact(note)});Append("notes",json,when);}
  public void Traffic(List<TrafficDelta> data,DateTime when){var rows=data.Select((x,i)=>new{adapter="网卡 "+(i+1),type=x.type,status=x.status,reason=x.reason,received=x.received,sent=x.sent}).ToArray();var json=new JavaScriptSerializer().Serialize(new{observedAt=when.ToString("o"),kind="traffic",items=rows,limitation="网卡累计计数差值，不是应用或运营商账单；不保存网卡名或标识"});Append("traffic",json,when);}
  public string Recent(){if(!Directory.Exists(dir))return "尚无记录。";var files=new DirectoryInfo(dir).GetFiles("*.jsonl").OrderByDescending(x=>x.LastWriteTimeUtc).Take(6);var all=new List<string>();foreach(var f in files){var lines=File.ReadAllLines(f.FullName,Encoding.UTF8);all.AddRange(lines.Skip(Math.Max(0,lines.Length-20)).Reverse());}return all.Count==0?"尚无记录。":String.Join(Environment.NewLine+Environment.NewLine,all.Take(60).ToArray());}
 }
}
