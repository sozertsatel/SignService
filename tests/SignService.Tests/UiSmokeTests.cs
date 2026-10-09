using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Threading;
using Avalonia.VisualTree;
using SignService.Services;
using SignService.ViewModels;
using SignService.Views;

// Смоук интерфейса без экрана (Avalonia.Headless): окна и диалоги загружаются,
// команды меню «Инструменты» и контекстного меню файла привязаны и выполняются.
internal static class UiSmokeTests
{
    public static void Run(string tempRoot)
    {
        // Avalonia и её диспетчер живут в одном потоке — смоук идёт в отдельном.
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try { RunOnUiThread(tempRoot); }
            catch (Exception e) { failure = e; }
        });
        thread.Start();
        thread.Join();
        if (failure is not null)
            throw new Exception("UI smoke failed: " + failure.Message, failure);
    }

    private static void RunOnUiThread(string tempRoot)
    {
        AppBuilder.Configure<SignService.App>()
            .UseSkia()
            .WithInterFont()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .SetupWithoutStarting();

        var dir = Path.Combine(tempRoot, "ui_smoke");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "договор.pdf");
        File.WriteAllText(document, "%PDF-1.4");
        var settings = new AppSettings(Path.Combine(dir, "settings")) { CheckUpdatesOnStart = false };
        var vm = new MainWindowViewModel(new CertificateProvider(), new DocumentSigner(), settings,
            new CertificateVault(Path.Combine(dir, "vault")));
        vm.AddFiles(document);

        var window = new MainWindow { DataContext = vm };
        window.Show();
        Dispatcher.UIThread.RunJobs();
        Assert(window.CaptureRenderedFrame() is not null, "main window must render");

        // Контекстное меню — отдельное всплывающее окно вне дерева элементов списка.
        var row = window.GetVisualDescendants().OfType<Border>().First(b => b.ContextMenu is not null);
        var rowButtons = row.GetVisualDescendants().OfType<Button>().ToList();
        Assert(rowButtons.Count >= 2 && rowButtons.All(b => b.Command is not null), "file row buttons must be bound");
        var menu = row.ContextMenu!;
        menu.Open(row);
        Dispatcher.UIThread.RunJobs();
        var items = menu.Items.OfType<MenuItem>().ToList();
        var unbound = items.Where(i => i.Command is null || !i.Command.CanExecute(i.CommandParameter)).Select(i => i.Header).ToList();
        Assert(items.Count >= 9 && unbound.Count == 0, "file context menu commands must be bound: " + string.Join("; ", unbound));
        var inspect = items.First(i => i.Header?.ToString()?.StartsWith("Подписанты", StringComparison.Ordinal) == true);
        inspect.Command!.Execute(inspect.CommandParameter);
        Dispatcher.UIThread.RunJobs();
        Assert(vm.StatusText.Contains("не найден файл подписи"), "context menu command must run for the clicked file: " + vm.StatusText);
        menu.Close();

        var tools = window.GetVisualDescendants().OfType<Button>()
            .First(b => b.Flyout is MenuFlyout && b.Content?.ToString()?.StartsWith("Инструменты", StringComparison.Ordinal) == true);
        var flyout = (MenuFlyout)tools.Flyout!;
        flyout.ShowAt(tools);
        Dispatcher.UIThread.RunJobs();
        var toolItems = flyout.Items.OfType<MenuItem>().ToList();
        Assert(toolItems.Count >= 7 && toolItems.All(i => i.Command is not null), "tools menu commands must be bound");
        flyout.Hide();

        var signers = new[]
        {
            new CmsExtractor.SignerInfo("A", "1. Иванов Иван — сертификат 01"),
            new CmsExtractor.SignerInfo("B", "2. Петров Пётр — сертификат 02"),
        };
        var dialogs = new Window[]
        {
            new SignerDialog(signers),
            new VerificationDialog(settings),
            new StampOptionsDialog(vm.BuildInitialStampOptions(), vm.StampSignCopy, showSignCopy: true),
            new SettingsDialog(vm),
            new AboutDialog(settings),
            new PasswordDialog("Пароль", "Предупреждение", requireConfirmation: true),
            new ConfirmDialog("Подтверждение", "Продолжить?"),
        };
        foreach (var dialog in dialogs)
        {
            dialog.Show();
            Dispatcher.UIThread.RunJobs();
            Assert(dialog.CaptureRenderedFrame() is not null, dialog.GetType().Name + " must render");
            dialog.Close();
        }

        window.Close();
        SaveCoSignScreenshots(tempRoot);
        Console.WriteLine("ui: main window, file context menu (bound, runs for the file), tools menu, 7 dialogs: OK");
    }

    /// <summary>Снимки новых состояний очереди: соподписание, новый файл, подтверждение, итог, предупреждение.</summary>
    private static void SaveCoSignScreenshots(string tempRoot)
    {
        var dir = Path.Combine(tempRoot, "ui_shots");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "договор.pdf");
        File.WriteAllBytes(document, "%PDF-1.4 договор"u8.ToArray());
        using var certA = MakeCert("CN=Подписант А");
        var data = File.ReadAllBytes(document);
        var signer = new DocumentSigner();
        var odd = Path.Combine(dir, "договор-.pdf .sig");
        File.WriteAllBytes(odd, signer.Sign(data, certA));

        var settings = new AppSettings(Path.Combine(dir, "settings")) { CheckUpdatesOnStart = false };
        var vm = new MainWindowViewModel(new CertificateProvider(), signer, settings, new CertificateVault(Path.Combine(dir, "vault")));
        vm.AddFiles(document);
        var window = new MainWindow { DataContext = vm, Width = 980, Height = 720 };
        window.Show();
        Dispatcher.UIThread.RunJobs();
        SaveFrame(window, "queue-add-existing");

        vm.MergeWithExisting = false;
        Dispatcher.UIThread.RunJobs();
        SaveFrame(window, "queue-create-new");

        vm.MergeWithExisting = true;
        Dispatcher.UIThread.RunJobs();
        var item = vm.Files.Single();
        item.AppendedToExisting = true;
        item.PreviousSignerCount = 1;
        item.SignerCount = 2;
        item.SignaturePath = odd;
        item.Warning = null;
        item.Status = SignStatus.Signed;
        Dispatcher.UIThread.RunJobs();
        SaveFrame(window, "signed-appended");

        item.Status = SignStatus.Signed;
        item.AppendedToExisting = true;
        item.PreviousSignerCount = 2;
        item.SignerCount = 2;
        item.Warning = "Внимание: исключены подписанты, подпись которых не соответствует документу: Подписант Б";
        Dispatcher.UIThread.RunJobs();
        SaveFrame(window, "excluded-warning");

        var dialog = new ConfirmDialog("Подтверждение подписания",
            "«договор.pdf»: в папке уже есть подходящая подпись «договор-.pdf .sig» (2 подписанта). "
            + "Будет создан новый файл «договор.pdf.sig», эта подпись не изменится и не будет объединена.\n\n"
            + "«договор.pdf»: при объединении будут исключены подписанты, чья подпись не соответствует документу: Подписант Б. "
            + "Они не попадут в файл подписи.\n\nПродолжить?");
        dialog.Show();
        Dispatcher.UIThread.RunJobs();
        SaveFrame(dialog, "confirm-risks");
        dialog.Close();
        window.Close();
    }

    private static void SaveFrame(Window window, string name)
    {
        var frame = window.CaptureRenderedFrame() ?? throw new Exception("no frame: " + name);
        var output = Path.Combine("/opt/cursor/artifacts/screenshots", name + ".png");
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        frame.Save(output);
        frame.Dispose();
    }

    private static X509Certificate2 MakeCert(string subject)
    {
        using var key = RSA.Create(2048);
        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
    }

    private static void Assert(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }
}
