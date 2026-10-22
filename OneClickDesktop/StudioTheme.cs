using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace ChomcioRecovery.Desktop;

internal interface IInlineFeedback { void ShowFeedback(string text); }

internal static class StudioTheme
{
    internal static readonly Color Background=Color.FromArgb(13,18,27), Sidebar=Color.FromArgb(10,14,22), Surface=Color.FromArgb(22,29,41), Raised=Color.FromArgb(29,39,53), Line=Color.FromArgb(43,55,72), Ink=Color.FromArgb(240,244,250), Muted=Color.FromArgb(151,168,189), Accent=Color.FromArgb(84,224,189), Blue=Color.FromArgb(113,160,255), Amber=Color.FromArgb(245,193,103);
    internal static Font Font(float size=10,FontStyle style=FontStyle.Regular)=>new("Segoe UI",size,style);
    internal static Icon BrandIcon()
    {using var stream=typeof(StudioTheme).Assembly.GetManifestResourceStream("ChomcioRecovery.Brand.ico")!;using var icon=new Icon(stream);return (Icon)icon.Clone();}
    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr handle,int attribute,ref int value,int size);
    internal static void Form(Form form)
    {
        form.BackColor=Background; form.ForeColor=Ink; form.Font=Font();
        form.AutoScaleMode=AutoScaleMode.Dpi;
        form.Icon=BrandIcon();
        form.HandleCreated+=(_,_)=>{ int dark=1; DwmSetWindowAttribute(form.Handle,20,ref dark,4); };
    }
    internal static Label Label(string text,float size=10,Color? color=null,bool bold=false)=>new()
    { Text=text,Font=Font(size,bold?FontStyle.Bold:FontStyle.Regular),ForeColor=color??Ink,AutoSize=true,BackColor=Color.Transparent,Margin=new(0,0,0,8) };
    internal static StudioButton Button(string text,Action action,bool primary=false)
    { var button=new StudioButton{Text=text,Primary=primary}; button.Click+=(_,_)=>action(); return button; }
    internal static StudioButton AsyncButton(string text,Func<Task> action,bool primary=false)
    { var button=new StudioButton{Text=text,Primary=primary}; button.Click+=async(_,_)=>{button.Enabled=false;try{await action();}catch(Exception e){if(button.FindForm() is IInlineFeedback feedback)feedback.ShowFeedback(JobEngine.SafeError(e));}finally{if(!button.IsDisposed)button.Enabled=true;}}; return button; }
    internal static TextBox Input(bool secret=false)=>new()
    { BackColor=Raised,ForeColor=Ink,BorderStyle=BorderStyle.FixedSingle,Font=Font(11),UseSystemPasswordChar=secret,Dock=DockStyle.Fill,Height=32,Margin=new(0,5,0,12) };
    internal static GraphicsPath Rounded(RectangleF r,float radius=16)
    {
        float d=radius*2; var path=new GraphicsPath();
        path.AddArc(r.X,r.Y,d,d,180,90); path.AddArc(r.Right-d,r.Y,d,d,270,90);
        path.AddArc(r.Right-d,r.Bottom-d,d,d,0,90); path.AddArc(r.X,r.Bottom-d,d,d,90,90); path.CloseFigure();return path;
    }
    internal static string Bytes(long value)=>value>=1L<<30?$"{value/(double)(1L<<30):0.0} GB":value>=1<<20?$"{value/(double)(1<<20):0.0} MB":$"{value/1024d:0.#} KB";
    internal static string State(RunState state)=>state switch {RunState.Success=>"Sprawdzona",RunState.Running=>"W trakcie",RunState.Cancelled=>"Anulowano",RunState.Interrupted=>"Przerwano",_=>"Wymaga uwagi"};
}

internal sealed class StudioCard : Panel
{
    [System.ComponentModel.DefaultValue(false)] internal bool Highlight { get; set; }
    internal StudioCard(){DoubleBuffered=true;BackColor=StudioTheme.Surface;Padding=new(24);Margin=new(0,0,0,16);}
    protected override void OnPaintBackground(PaintEventArgs e)
    {
        e.Graphics.Clear(Parent?.BackColor??StudioTheme.Background);e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
        using var path=StudioTheme.Rounded(new RectangleF(.5f,.5f,Width-1,Height-1));
        using var brush=new LinearGradientBrush(ClientRectangle,BackColor,Highlight?Color.FromArgb(22,53,54):BackColor,25f);
        using var border=new Pen(Highlight?Color.FromArgb(48,93,84):StudioTheme.Line);
        e.Graphics.FillPath(brush,path);e.Graphics.DrawPath(border,path);
    }
}
internal sealed class StudioButton : Button
{
    [System.ComponentModel.DefaultValue(false)] internal bool Primary { get; set; }
    private bool hovered;
    internal StudioButton()
    { SetStyle(ControlStyles.UserPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.AllPaintingInWmPaint,true); Height=42;Width=180;Font=StudioTheme.Font(10,FontStyle.Bold);Cursor=Cursors.Hand;Margin=new(0,0,10,6);FlatStyle=FlatStyle.Flat;FlatAppearance.BorderSize=0; }
    protected override void OnMouseEnter(EventArgs e){hovered=true;Invalidate();base.OnMouseEnter(e);}
    protected override void OnMouseLeave(EventArgs e){hovered=false;Invalidate();base.OnMouseLeave(e);}
    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.Clear(Parent?.BackColor??StudioTheme.Background);e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
        using var shape=StudioTheme.Rounded(new RectangleF(.5f,.5f,Width-1,Height-1),9);
        Color background=!Enabled?StudioTheme.Surface:Primary?(hovered?Color.FromArgb(125,240,211):StudioTheme.Accent):(hovered?Color.FromArgb(43,58,76):StudioTheme.Raised);
        using var fill=new SolidBrush(background);using var pen=new Pen(Primary?background:StudioTheme.Line);
        e.Graphics.FillPath(fill,shape);e.Graphics.DrawPath(pen,shape);
        TextRenderer.DrawText(e.Graphics,Text,Font,ClientRectangle,!Enabled?StudioTheme.Muted:Primary?StudioTheme.Sidebar:StudioTheme.Ink,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
        if(Focused) ControlPaint.DrawFocusRectangle(e.Graphics,Rectangle.Inflate(ClientRectangle,-5,-5),StudioTheme.Blue,background);
    }
}
internal sealed class ProtectionArt : Control
{
    internal ProtectionArt(){DoubleBuffered=true;SetStyle(ControlStyles.SupportsTransparentBackColor,true);BackColor=Color.Transparent;}
    protected override void OnPaint(PaintEventArgs e)
    {
        var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;
        float scale=Math.Min(Width/240f,Height/210f);g.ScaleTransform(scale,scale);
        using var faint=new Pen(Color.FromArgb(33,91,83),1);
        g.DrawEllipse(faint,36,17,172,172);g.DrawEllipse(faint,19,0,206,206);
        using var path=new GraphicsPath();path.AddLines(new PointF[]{new(122,39),new(178,60),new(171,119),new(151,149),new(122,165),new(93,149),new(73,119),new(66,60)});path.CloseFigure();
        using var fill=new LinearGradientBrush(new Rectangle(65,39,114,126),Color.FromArgb(40,119,101),Color.FromArgb(24,51,51),90);
        using var edge=new Pen(StudioTheme.Accent,2);g.FillPath(fill,path);g.DrawPath(edge,path);
        using var tick=new Pen(StudioTheme.Accent,6){StartCap=LineCap.Round,EndCap=LineCap.Round,LineJoin=LineJoin.Round};
        g.DrawLines(tick,new[]{new PointF(101,100),new PointF(117,116),new PointF(145,84)});
        using var dot=new SolidBrush(StudioTheme.Accent);g.FillEllipse(dot,37,49,7,7);g.FillEllipse(dot,199,139,7,7);
    }
}
