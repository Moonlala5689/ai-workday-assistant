using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Windows.Forms;

// Visual tokens are local to the native candidate; semantic status remains in Score/Core.
static class VisualTheme {
 public static Color C(string value){return ColorTranslator.FromHtml(value);}
 public static readonly Color Page=C("#F3F4F6"),Card=C("#FFFFFF"),Border=C("#D1D5DB"),Divider=C("#E5E7EB"),Ink=C("#111827"),Muted=C("#4B5563"),Hero=C("#111827"),HeroPanel=C("#263447"),HeroText=C("#F9FAFB"),HeroMuted=C("#D1D5DB"),Accent=C("#1D4ED8"),AccentHover=C("#1E40AF"),AccentDown=C("#1E3A8A"),Focus=C("#FBBF24"),Green=C("#24593C"),Amber=C("#785018"),Red=C("#912D2B"),GreenBg=C("#E5F2E8"),AmberBg=C("#FBF0DA"),RedBg=C("#F9E8E5"),Gray=C("#475467"),GrayBg=C("#EBEAE5"),HeroGreen=C("#A7F3D0"),HeroAmber=C("#FDE68A"),HeroRed=C("#FECACA"),Disabled=C("#D1D5DB"),DisabledInk=C("#374151");
 public static readonly Color DarkHover=C("#34465D"),DarkPressed=C("#405671"),LightHover=C("#E5E7EB"),LightPressed=C("#D1D5DB");
 public const int Gap=12,CardRadius=14,ButtonRadius=12,HeroPad=24;
 static readonly HashSet<string> available=new HashSet<string>(FontFamily.Families.Select(f=>f.Name),StringComparer.OrdinalIgnoreCase);
 static string Pick(params string[] names){return names.FirstOrDefault(n=>available.Contains(n))??SystemFonts.MessageBoxFont.FontFamily.Name;}
 public static readonly string TextFamily=Pick("Microsoft YaHei UI","Microsoft YaHei","Segoe UI");
 public static readonly string MonoFamily=Pick("Cascadia Mono","Consolas","Courier New");
 public static int Scale(int px,float dpi){return Math.Max(1,(int)Math.Round(px*dpi/96f));}
 static float ScreenDpi(){using(var g=Graphics.FromHwnd(IntPtr.Zero))return g.DpiX;}
 public static readonly float Dpi=ScreenDpi();internal static float SimulationScale=1f;public static int Px(int px){return Scale(px,Dpi*SimulationScale);}public static float PointSize(float pt){return pt*SimulationScale;}
 public static GraphicsPath Rounded(Rectangle rect,int radius){var p=new GraphicsPath();int d=Math.Max(2,Math.Min(radius*2,Math.Min(rect.Width,rect.Height)));if(rect.Width<=1||rect.Height<=1){p.AddRectangle(new Rectangle(0,0,1,1));return p;}p.AddArc(rect.X,rect.Y,d,d,180,90);p.AddArc(rect.Right-d,rect.Y,d,d,270,90);p.AddArc(rect.Right-d,rect.Bottom-d,d,d,0,90);p.AddArc(rect.X,rect.Bottom-d,d,d,90,90);p.CloseFigure();return p;}
 public static Color Tone(string state){return state=="green"?Green:state=="yellow"?Amber:state=="red"?Red:Gray;}
 public static Color Badge(string state){return state=="green"?GreenBg:state=="yellow"?AmberBg:state=="red"?RedBg:GrayBg;}
 public static Color HeroTone(string state){return state=="red"?HeroRed:state=="yellow"?HeroAmber:state=="green"?HeroGreen:HeroMuted;}
}
sealed class VisualButton:Button {
 public enum Kind { Primary, Secondary, Text }
 readonly Kind kind;bool hovered,pressed;public int PaintCount;internal bool PreviewFocus;internal Color LastDrawnText,LastDrawnFill;internal bool ActualFocusCue{get{return Focused&&ShowFocusCues;}}
 public VisualButton(Kind k){kind=k;SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.ResizeRedraw|ControlStyles.Selectable,true);FlatStyle=FlatStyle.Flat;FlatAppearance.BorderSize=0;UseVisualStyleBackColor=false;Cursor=Cursors.Hand;AccessibleRole=AccessibleRole.PushButton;TabStop=true;}
 public override Size GetPreferredSize(Size proposedSize){if(kind!=Kind.Text)return base.GetPreferredSize(proposedSize);var size=TextRenderer.MeasureText(Text,Font,Size.Empty,TextFormatFlags.NoPadding);return new Size(size.Width+VisualTheme.Px(24),Math.Max(VisualTheme.Px(32),size.Height+VisualTheme.Px(8)));}
 protected override void OnTextChanged(EventArgs e){base.OnTextChanged(e);AccessibleName=Text;Invalidate();}
 protected override void OnMouseEnter(EventArgs e){base.OnMouseEnter(e);hovered=true;Invalidate();}
 protected override void OnMouseLeave(EventArgs e){base.OnMouseLeave(e);hovered=false;pressed=false;Invalidate();}
 protected override void OnMouseDown(MouseEventArgs e){base.OnMouseDown(e);if(e.Button==MouseButtons.Left){pressed=true;Invalidate();}}
 protected override void OnMouseUp(MouseEventArgs e){base.OnMouseUp(e);pressed=false;Invalidate();}
 protected override void OnGotFocus(EventArgs e){base.OnGotFocus(e);Invalidate();}
 protected override void OnLostFocus(EventArgs e){base.OnLostFocus(e);pressed=false;Invalidate();}
 protected override void OnEnabledChanged(EventArgs e){base.OnEnabledChanged(e);if(!Enabled){hovered=false;pressed=false;}Invalidate();}
 protected override void OnPaint(PaintEventArgs e){PaintCount++;var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;g.PixelOffsetMode=PixelOffsetMode.HighQuality;Color parent=Parent==null?VisualTheme.Page:Parent.BackColor;g.Clear(parent);bool dark=parent==VisualTheme.Hero||parent==VisualTheme.HeroPanel;Color fill=kind==Kind.Primary?(Enabled?(pressed?VisualTheme.AccentDown:hovered?VisualTheme.AccentHover:VisualTheme.Accent):VisualTheme.Disabled):kind==Kind.Secondary?(Enabled&&pressed?(dark?VisualTheme.DarkPressed:VisualTheme.LightPressed):Enabled&&hovered?(dark?VisualTheme.DarkHover:VisualTheme.LightHover):(dark?VisualTheme.HeroPanel:VisualTheme.Card)):(Enabled&&pressed?(dark?VisualTheme.DarkHover:VisualTheme.LightPressed):Enabled&&hovered?(dark?VisualTheme.HeroPanel:VisualTheme.LightHover):parent);Color text=kind==Kind.Primary?(Enabled?Color.White:VisualTheme.DisabledInk):(Enabled?(dark?VisualTheme.HeroText:VisualTheme.Ink):(dark?VisualTheme.HeroMuted:VisualTheme.Muted));LastDrawnText=text;LastDrawnFill=fill;int inset=VisualTheme.Px(Focused?3:2);var r=new Rectangle(inset,inset,Math.Max(1,Width-inset*2-1),Math.Max(1,Height-inset*2-1));if(kind!=Kind.Text||(Enabled&&(hovered||pressed))){using(var path=VisualTheme.Rounded(r,VisualTheme.Scale(VisualTheme.ButtonRadius,g.DpiX*VisualTheme.SimulationScale))){using(var b=new SolidBrush(fill))g.FillPath(b,path);if(kind==Kind.Secondary)using(var p=new Pen(dark?VisualTheme.HeroMuted:VisualTheme.Muted,VisualTheme.Px(1)))g.DrawPath(p,path);}}if((Focused&&ShowFocusCues)||PreviewFocus){using(var path=VisualTheme.Rounded(new Rectangle(VisualTheme.Px(1),VisualTheme.Px(1),Math.Max(1,Width-VisualTheme.Px(3)),Math.Max(1,Height-VisualTheme.Px(3))),VisualTheme.Scale(VisualTheme.ButtonRadius,g.DpiX*VisualTheme.SimulationScale)))using(var p=new Pen(dark?VisualTheme.Focus:VisualTheme.Accent,VisualTheme.Px(2)))g.DrawPath(p,path);}var tr=new Rectangle(VisualTheme.Px(8),VisualTheme.Px(pressed?2:1),Math.Max(1,Width-VisualTheme.Px(16)),Math.Max(1,Height-VisualTheme.Px(2)));TextRenderer.DrawText(g,Text,Font,tr,text,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter|TextFormatFlags.NoPadding|TextFormatFlags.WordBreak);}
 public void SimulateKey(Keys key){OnKeyDown(new KeyEventArgs(key));OnKeyUp(new KeyEventArgs(key));}
 public void SimulateHover(bool value){if(value)OnMouseEnter(EventArgs.Empty);else OnMouseLeave(EventArgs.Empty);}
 public void SimulatePress(bool value){if(value)OnMouseDown(new MouseEventArgs(MouseButtons.Left,1,4,4,0));else OnMouseUp(new MouseEventArgs(MouseButtons.Left,1,4,4,0));}
}
static class VisualShadow {
 static readonly Dictionary<string,Bitmap> cache=new Dictionary<string,Bitmap>();static readonly Queue<string> order=new Queue<string>();const long Limit=32L*1024*1024;static long bytes;public static int Count{get{return cache.Count;}}public static long Bytes{get{return bytes;}}
 public static void Draw(Graphics target,int width,int height){if(width<4||height<4)return;string key=width+"x"+height+"@"+Math.Round(target.DpiX);Bitmap b;if(!cache.TryGetValue(key,out b)){long needed=(long)width*height*4;if(needed>Limit)return;while(cache.Count>0&&(cache.Count>=12||bytes+needed>Limit)){string oldest=order.Dequeue();Bitmap old=cache[oldest];bytes-=(long)old.Width*old.Height*4;old.Dispose();cache.Remove(oldest);}b=new Bitmap(width,height);using(var g=Graphics.FromImage(b)){g.SmoothingMode=SmoothingMode.AntiAlias;for(int i=3;i>=1;i--){using(var path=VisualTheme.Rounded(new Rectangle(i,Math.Min(height-2,i+1),Math.Max(2,width-2*i-1),Math.Max(2,height-2*i-2)),VisualTheme.Scale(VisualTheme.CardRadius,target.DpiX*VisualTheme.SimulationScale)))using(var p=new Pen(Color.FromArgb(7+(3-i)*2,20,30,50),1))g.DrawPath(p,path);}}cache[key]=b;order.Enqueue(key);bytes+=needed;}target.DrawImageUnscaled(b,0,0);}
 public static void Clear(){foreach(var b in cache.Values)b.Dispose();cache.Clear();order.Clear();bytes=0;}
}
