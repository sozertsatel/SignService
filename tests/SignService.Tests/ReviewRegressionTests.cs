using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SignService.Services;
using SignService.ViewModels;

// Регрессии ревью: соподписание с устаревшим/прикреплённым входом, разделение
// и исключение подписантов, повторная постановка в очередь, автообновление.
internal static class ReviewRegressionTests
{
    public static async Task RunAsync(string tempRoot, DocumentSigner signer)
    {
        var root = Path.Combine(tempRoot, "review_regressions");
        Directory.CreateDirectory(root);
        using var certA = MakeCertificate("CN=Одинаковое Имя, OID.1.2.643.3.131.1.1=771378577706");
        using var certB = MakeCertificate("CN=Одинаковое Имя");
        var current = Encoding.UTF8.GetBytes("current document");
        var previous = Encoding.UTF8.GetBytes("previous document");
        var doc = Path.Combine(root, "document.txt");
        await File.WriteAllBytesAsync(doc, current);

        // Прикреплённая старая версия не должна попасть в новый контейнер.
        await File.WriteAllBytesAsync(doc + ".sig", signer.Sign(previous, certB, detached: false));
        var staleResult = await signer.SignFileAsync(doc, certA, new DocumentSigner.SignOptions
        {
            Detached = false, MergeWithExisting = true,
        });
        Assert(staleResult.ExcludedSigners.Count == 1, "stale signer must be excluded");
        var rebuilt = ReadAttached(staleResult.SignaturePath);
        Assert(rebuilt.ContentInfo.Content.SequenceEqual(current), "old embedded content leaked into new signature");
        Assert(rebuilt.SignerInfos.Count == 1, "wrong signer count after stale merge");
        Console.WriteLine("regression: stale attached input → current attached document verifies: OK");

        // Выбранный откреплённый режим соблюдается даже с прикреплённым входом.
        await File.WriteAllBytesAsync(doc + ".sig", signer.Sign(current, certB, detached: false));
        var detachedResult = await signer.SignFileAsync(doc, certA, new DocumentSigner.SignOptions
        {
            Detached = true, MergeWithExisting = true,
        });
        var detachedBytes = await File.ReadAllBytesAsync(detachedResult.SignaturePath);
        var raw = new SignedCms();
        raw.Decode(detachedBytes);
        Assert(raw.ContentInfo.Content.Length == 0, "detached option ignored");
        var verified = ReadDetached(detachedResult.SignaturePath, current);
        Assert(verified.SignerInfos.Count == 2, "cosigning lost a signer");
        Console.WriteLine("regression: attached input + detached mode → two valid detached signatures: OK");

        // Одинаковые ФИО различаются по идентификатору сертификата.
        var descriptors = CmsExtractor.ListSigners(detachedResult.SignaturePath);
        Assert(descriptors.Count == 2 && descriptors[0].Id != descriptors[1].Id, "signer IDs must be distinct");
        var split = CmsExtractor.SplitSignatureFile(detachedResult.SignaturePath);
        Assert(split.SignerFiles.Count == 2 && split.SignerFiles.Distinct().Count() == 2, "split filenames collide");
        var splitThumbprints = split.SignerFiles.Select(path =>
        {
            var cms = ReadDetached(path, current);
            Assert(cms.SignerInfos.Count == 1, "split must have exactly one signer");
            return cms.SignerInfos[0].Certificate!.Thumbprint;
        }).ToHashSet();
        Assert(splitThumbprints.SetEquals(new[] { certA.Thumbprint, certB.Thumbprint }), "split lost or duplicated a signer");
        var splitAgain = CmsExtractor.SplitSignatureFile(detachedResult.SignaturePath);
        Assert(!splitAgain.SignerFiles.Intersect(split.SignerFiles).Any(), "split overwrote earlier files");
        var removed = CmsExtractor.RemoveSignerFromFile(detachedResult.SignaturePath, descriptors[0].Id);
        Assert(ReadDetached(removed.OutputPath, current).SignerInfos.Count == 1, "remove must leave one valid signer");
        Assert(File.ReadAllBytes(detachedResult.SignaturePath).SequenceEqual(detachedBytes), "remove changed source file");
        ExpectFailure(() => CmsExtractor.RemoveSignerFromFile(removed.OutputPath,
            CmsExtractor.ListSigners(removed.OutputPath)[0].Id), "last signer must be protected");
        ExpectFailure(() => CmsExtractor.RemoveSignerFromFile(detachedResult.SignaturePath, "unknown"), "unknown signer must fail");
        ExpectFailure(() => CmsExtractor.SplitSignatureFile(removed.OutputPath), "single signer split must fail");

        var attachedPath = Path.Combine(root, "attached.sig");
        var merger = typeof(DocumentSigner).Assembly.GetType("SignService.Services.CmsMerger")!;
        var attached = (byte[])merger.GetMethod("AttachContent")!.Invoke(null, new object[] { detachedBytes, current })!;
        await File.WriteAllBytesAsync(attachedPath, attached);
        var attachedRemoved = CmsExtractor.RemoveSignerFromFile(attachedPath, CmsExtractor.ListSigners(attachedPath)[1].Id);
        Assert(ReadAttached(attachedRemoved.OutputPath).ContentInfo.Content.SequenceEqual(current), "remove lost attached document");
        var attachedSplit = CmsExtractor.SplitSignatureFile(attachedPath);
        Assert(attachedSplit.DocumentPath is not null && File.ReadAllBytes(attachedSplit.DocumentPath).SequenceEqual(current), "split lost document");
        foreach (var path in attachedSplit.SignerFiles) ReadDetached(path, current);
        Console.WriteLine("regression: split/remove attached and detached CMS, duplicate names, source preservation: OK");

        var queueItem = new SignFileItem(doc) { Status = SignStatus.Signed, SignerCount = 2, SignaturePath = doc + ".sig" };
        queueItem.AttachSignatures(new[] { removed.OutputPath });
        Assert(queueItem.Status == SignStatus.Pending && queueItem.SignerCount == 0, "new extra signature must requeue file");
        Console.WriteLine("regression: attaching .sig requeues a signed file: OK");

        CheckCertificateChangeRequeue(root, signer, certA, certB, doc);

        if (OperatingSystem.IsWindows())
            await CheckUpdaterAsync(root);
        else
            Console.WriteLine("regression: updater (PowerShell) — only on Windows, skipped");
    }

    // Обновление списка сертификатов создаёт новые элементы с тем же отпечатком —
    // это не смена сертификата, подписанные файлы не должны возвращаться в очередь.
    private static void CheckCertificateChangeRequeue(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, string doc)
    {
        var settings = new AppSettings(Path.Combine(root, "vm_settings")) { CheckUpdatesOnStart = false };
        var vm = new MainWindowViewModel(new CertificateProvider(), signer, settings,
            new CertificateVault(Path.Combine(root, "vm_vault")));
        vm.SelectedCertificate = new CertificateItem(certA);
        var file = new SignFileItem(doc) { Status = SignStatus.Signed, SignerCount = 1, SignaturePath = doc + ".sig" };
        vm.Files.Add(file);

        vm.SelectedCertificate = null;                          // Clear() списка при обновлении
        vm.SelectedCertificate = new CertificateItem(certA);    // тот же сертификат, новый элемент
        Assert(file.Status == SignStatus.Signed && file.SignaturePath is not null,
            "refresh with the same certificate must not requeue signed files");

        vm.SelectedCertificate = new CertificateItem(certB);
        Assert(file.Status == SignStatus.Pending && file.SignaturePath is null,
            "switching to another certificate must requeue signed files for co-signing");
        Assert(settings.SignCertThumbprint == certB.Thumbprint, "selected certificate not remembered");
        Console.WriteLine("regression: certificate refresh keeps statuses, real change requeues: OK");
    }

    private static async Task CheckUpdaterAsync(string root)
    {
        var dir = Path.Combine(root, "update space ' $ % тест");
        Directory.CreateDirectory(dir);
        var current = Path.Combine(dir, "current.exe");
        var downloaded = Path.Combine(dir, "downloaded.exe");
        var build = typeof(UpdateService).GetMethod("BuildInstallScript", BindingFlags.Static | BindingFlags.NonPublic)!;

        Process Start(bool restart, int replaceTimeoutMs)
        {
            var script = (string)build.Invoke(null, new object[] { current, downloaded, 0, restart, replaceTimeoutMs })!;
            var info = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe"))
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            info.ArgumentList.Add("-NoProfile");
            info.ArgumentList.Add("-NonInteractive");
            info.ArgumentList.Add("-EncodedCommand");
            info.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
            return Process.Start(info)!;
        }

        async Task<int> Wait(Process process)
        {
            using (process)
            {
                var stdout = process.StandardOutput.ReadToEndAsync();
                var stderr = process.StandardError.ReadToEndAsync();
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
                try { await process.WaitForExitAsync(timeout.Token); }
                catch { process.Kill(entireProcessTree: true); throw; }
                await Task.WhenAll(stdout, stderr);
                return process.ExitCode;
            }
        }

        Task<int> Run(bool restart = false, int replaceTimeoutMs = 1_000) => Wait(Start(restart, replaceTimeoutMs));

        await File.WriteAllTextAsync(current, "working old version");
        Assert(await Run() != 0 && File.ReadAllText(current) == "working old version", "missing download destroyed executable");
        await File.WriteAllTextAsync(downloaded, "new version");
        using (new FileStream(current, FileMode.Open, FileAccess.Read, FileShare.Read))
            Assert(await Run() != 0, "locked executable must fail safely after the retry window");
        Assert(File.ReadAllText(current) == "working old version", "failed replacement destroyed executable");

        // Файл освобождается во время ожидания (процесс ещё завершался) — замена повторяется и проходит.
        Process pending;
        using (new FileStream(current, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            pending = Start(restart: false, replaceTimeoutMs: 60_000);
            await Task.Delay(TimeSpan.FromSeconds(3));
            Assert(!pending.HasExited, "updater must keep retrying while the executable is locked");
        }
        Assert(await Wait(pending) == 0 && File.ReadAllText(current) == "new version", "replacement must succeed once unlocked");
        Assert(Directory.GetFiles(dir, "*.bak").Any(path => File.ReadAllText(path) == "working old version"), "working backup missing");

        await File.WriteAllTextAsync(current, "working old version");
        Assert(await Run() == 0 && File.ReadAllText(current) == "new version", "successful replacement failed");
        // Текстовый fixture не является EXE: отказ запуска должен восстановить старый файл.
        await File.WriteAllTextAsync(current, "rollback version");
        Assert(await Run(restart: true) != 0 && File.ReadAllText(current) == "rollback version", "restart failure did not roll back");
        Assert(Directory.GetFiles(dir, "*.new").Length == 0, "staging files leaked");
        Console.WriteLine("regression: updater missing source, locked target, retry until unlocked, backup and launch rollback: OK");
    }

    private static X509Certificate2 MakeCertificate(string subject)
    {
        using var key = RSA.Create(2048);
        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
    }

    private static SignedCms ReadAttached(string path)
    {
        var cms = new SignedCms();
        cms.Decode(File.ReadAllBytes(path));
        cms.CheckSignature(true);
        return cms;
    }

    private static SignedCms ReadDetached(string path, byte[] document)
    {
        var cms = new SignedCms(new ContentInfo(document), true);
        cms.Decode(File.ReadAllBytes(path));
        cms.CheckSignature(true);
        return cms;
    }

    private static void Assert(bool value, string message)
    {
        if (!value) throw new Exception(message);
    }

    private static void ExpectFailure(Action action, string message)
    {
        try { action(); }
        catch (Exception e) when (e is IOException or InvalidOperationException) { return; }
        throw new Exception(message);
    }
}
