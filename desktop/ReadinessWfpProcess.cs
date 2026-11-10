using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

public sealed class WfpProcessResult {public bool Started,TimedOut,Cancelled;public int ExitCode=-1;public string Output="",Failure="";}
public static class ReadinessWfpProcess {
 // The returned process object is the only process this method may terminate.
 static WfpProcessResult RunOwned(string executable,string arguments,int timeout,CancellationToken token){var result=new WfpProcessResult();if(token.IsCancellationRequested){result.Cancelled=true;return result;}if(timeout<1||timeout>30000){result.Failure="invalid-timeout";return result;}var text=new StringBuilder();var sync=new object();var outputDone=new ManualResetEvent(false);using(var process=new Process()){process.StartInfo=new ProcessStartInfo{FileName=executable,Arguments=arguments,UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=Path.GetDirectoryName(executable)};process.OutputDataReceived+=delegate(object sender,DataReceivedEventArgs e){if(e.Data==null){outputDone.Set();return;}lock(sync)if(text.Length<16384){int take=Math.Min(e.Data.Length,16384-text.Length);text.Append(e.Data.Substring(0,take));}};process.ErrorDataReceived+=delegate{};var watch=Stopwatch.StartNew();try{if(!process.Start()){result.Failure="start-failed";return result;}result.Started=true;process.BeginOutputReadLine();process.BeginErrorReadLine();while(!process.WaitForExit(30)){if(token.IsCancellationRequested||watch.ElapsedMilliseconds>=timeout){result.Cancelled=token.IsCancellationRequested;result.TimedOut=!result.Cancelled;try{process.Kill();}catch(InvalidOperationException){}catch(System.ComponentModel.Win32Exception){result.Failure="own-process-terminate-failed";}process.WaitForExit(250);break;}}if(process.HasExited){result.ExitCode=process.ExitCode;int remain=Math.Max(0,timeout-(int)watch.ElapsedMilliseconds);if(!result.TimedOut&&!result.Cancelled)outputDone.WaitOne(remain);}else if(String.IsNullOrEmpty(result.Failure))result.Failure="own-process-did-not-exit";lock(sync)result.Output=text.ToString();return result;}catch(Exception e){result.Failure="process-"+e.GetType().Name;return result;}}}
 public static WfpProcessResult Inventory(int timeout,CancellationToken token){string executable=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"WorkEnv.Readiness.Wfp.exe");return RunOwned(executable,"--read-only-wfp-inventory",timeout,token);}
 public static WfpProcessResult Observe(int timeout,CancellationToken token){
#if CONSUMER
  string executable=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"WorkEnv.Consumer.Wfp.exe");
#elif WORKFLOW
  string executable=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"WorkEnv.Workflow.Wfp.exe");
#else
  string executable=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"WorkEnv.Readiness.Wfp.exe");
#endif
  return RunOwned(executable,"--read-only-wfp-observe",timeout,token);}
#if READINESS_TEST
 public static WfpProcessResult Fixture(string executable,string mode,int timeout,CancellationToken token){string expected=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"WorkEnv.Readiness.WfpFixture.exe");if(!String.Equals(Path.GetFullPath(executable),expected,StringComparison.OrdinalIgnoreCase)||!(mode=="done"||mode=="sleep"))throw new ArgumentException();return RunOwned(expected,mode,timeout,token);}
#endif
}
