using ChomcioRecovery.Desktop;

internal static class RecoveryGuideScenarios
{
    internal static void Run(string root, Action<bool,string> check)
    {
        var command = WindowsRecoveryGuide.MediaCommand();
        check(command.FileName == Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "RecoveryDrive.exe") &&
            command.UseShellExecute && command.Verb == "runas" && command.ArgumentList.Count == 0 && command.Arguments.Length == 0,
            "only the installed Windows recovery wizard is selectable, with no disk, shell or format arguments");
        int launches = 0;
        using var guide = new WindowsRecoveryGuideWindow(launchForTest: () => launches++);
        guide.ShowInTaskbar = false; guide.Opacity = 0;
        guide.Show(); Application.DoEvents();
        var controls = Work9Scenarios.All(guide).ToArray();
        var button = (Button)controls.Single(c => c.Name == "CreateWindowsRecoveryMedia");
        var consent = (CheckBox)controls.Single(c => c.Name == "RecoveryMediaConsent");
        check(launches == 0 && !button.Enabled, "opening recovery guide never opens elevation or a formatting wizard");
        button.PerformClick();
        check(launches == 0, "media wizard cannot launch without empty USB acknowledgement");
        consent.Checked = true; button.PerformClick(); button.PerformClick();
        check(launches == 1 && !button.Enabled, "explicit consent launches once, duplicate click is suppressed");
        check(controls.OfType<Label>().Any(c => c.Text.Contains("nie potwierdził jeszcze")), "wizard launch never claims a bootable medium was created");
        guide.Hide();
        using var declined = new WindowsRecoveryGuideWindow(launchForTest: () => throw new System.ComponentModel.Win32Exception(1223));
        declined.ShowInTaskbar = false; declined.Opacity = 0;
        declined.Show(); Application.DoEvents();
        var declinedControls = Work9Scenarios.All(declined).ToArray();
        ((CheckBox)declinedControls.Single(c => c.Name == "RecoveryMediaConsent")).Checked = true;
        var retry = (Button)declinedControls.Single(c => c.Name == "CreateWindowsRecoveryMedia"); retry.PerformClick();
        check(retry.Enabled && declinedControls.OfType<Label>().Any(c => c.Text.Contains("Nie udzielono zgody")), "declined elevation is recoverable and does not claim media creation");
        declined.Hide();
        string instructions = WindowsRecoveryGuide.Instructions();
        check(instructions.Contains("Odblokuj kopię swoim kluczem") && instructions.Contains("Odzyskiwanie obrazu systemu") && instructions.Contains("zastąpi jego dane"), "offline instructions cover cloud key, native image recovery and destructive target confirmation");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root,"instructions.txt"),instructions);
        guide.ClientSize = new(790,730); guide.Show(); guide.PerformLayout(); Application.DoEvents();
        using var bitmap = new Bitmap(guide.Width, guide.Height);
        guide.DrawToBitmap(bitmap, new Rectangle(0,0,guide.Width,guide.Height));
        bitmap.Save(Path.Combine(root,"recovery-guide.png")); guide.Hide();
        Console.WriteLine("RECOVERY_GUIDE=PASS (consent, cancelled elevation, duplicate launch, offline instructions; native USB creation not performed)");
    }
}
