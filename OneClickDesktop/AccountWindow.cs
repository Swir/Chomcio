using ChomcioRecovery.Chomikuj;
namespace ChomcioRecovery.Desktop;

internal sealed class AccountWindow : Form,IInlineFeedback
{
    internal bool Forgotten{get;private set;}
    private readonly Label status=StudioTheme.Label("",10,StudioTheme.Muted);
    private readonly TextBox login=StudioTheme.Input(),password=StudioTheme.Input(true);
    private readonly StudioStore store;
    private readonly CancellationTokenSource close=new();
    internal AccountWindow(StudioStore store)
    {
        this.store=store;StudioTheme.Form(this);Text="Konto i zapisane hasła";ClientSize=new(590,500);StartPosition=FormStartPosition.CenterParent;
        var body=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,Padding=new(28)};Controls.Add(body);
        body.Controls.Add(StudioTheme.Label("Zaloguj się raz",24,null,true));
        body.Controls.Add(StudioTheme.Label("Hasła zostają na tym PC, zaszyfrowane przez Windows.\nNie zapisujemy ich jawnym tekstem w ustawieniach.",10,StudioTheme.Muted));
        body.Controls.Add(StudioTheme.Label("Login Chomikuj",10));body.Controls.Add(login);body.Controls.Add(StudioTheme.Label("Hasło Chomikuj",10));body.Controls.Add(password);
        try {var account=StudioCredentials.Account(store);login.Text=account?.CloudLogin??"";password.Text=account?.CloudPassword??"";}catch(System.Security.Cryptography.CryptographicException){status.Text="Wpisz konto ponownie — Windows nie odblokował wcześniejszego zapisu.";}
        var save=StudioTheme.AsyncButton("Połącz i zapamiętaj",ConnectAsync,true);save.Width=240;body.Controls.Add(save);status.MaximumSize=new(530,68);body.Controls.Add(status);
        var forget=StudioTheme.Button("Usuń zapamiętane hasła",()=>{StudioCredentials.Forget(store);Forgotten=true;password.Clear();ShowFeedback("Usunięto zapis haseł i wyłączono automatyczne kopie. Same kopie pozostają.");});forget.Width=260;body.Controls.Add(forget);
        body.Controls.Add(StudioTheme.Label("Po usunięciu haseł program poprosi o nie ponownie.\nAutomat wymaga zapamiętanych haseł.",9,StudioTheme.Muted));
        FormClosing+=(_,_)=>close.Cancel();FormClosed+=(_,_)=>close.Dispose();AcceptButton=save;
    }
    private async Task ConnectAsync()
    {
        if(login.Text.Trim().Length==0||password.Text.Length==0){ShowFeedback("Wpisz login i hasło konta Chomikuj.");return;}
        login.Enabled=password.Enabled=false;
        try
        {
            ShowFeedback("Sprawdzanie połączenia…");using var client=new ChomikujClient();await client.LoginAsync(login.Text.Trim(),password.Text,close.Token);
            StudioCredentials.RememberAccount(store,new("",login.Text.Trim(),password.Text));store.Save();ShowFeedback("Połączono. Konto zapamiętane — możesz zamknąć to okno.");
        }
        finally{if(!IsDisposed)login.Enabled=password.Enabled=true;}
    }
    public void ShowFeedback(string text){if(!IsDisposed)status.Text=text;}
}
