using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using SignService.Services;
using SignService.ViewModels;

// Регрессии ревью: соподписание с устаревшим/прикреплённым входом, разделение
// и исключение подписантов, повторная постановка в очередь, автообновление,
// проверка МЧД, устойчивость проверки ЭЦП, настройки доверия и кеши.
internal static class ReviewRegressionTests
{
    private static readonly VerificationOptions Crypto = new()
        { CheckCertificateTrust = false, CheckRevocation = false, UseSystemTrustStore = false };

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
        await CheckPowerOfAttorneyAsync(root, signer);
        CheckVerifierRobustness(signer, certA, certB, current);
        await CheckVerificationSettingsAsync(root, signer);
        await CheckCachesAsync(root, signer, certA, certB, current);

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

    // Ошибки 1 и 2: МЧД при истёкшем после выдачи сертификате руководителя и ИНН
    // организации (1.2.643.100.4, «00» + ИНН ЮЛ) в сертификате представителя.
    private static async Task CheckPowerOfAttorneyAsync(string root, DocumentSigner signer)
    {
        var dir = Path.Combine(root, "poa_review");
        Directory.CreateDirectory(dir);
        var xmlPath = Path.Combine(dir, "mchd.xml");
        var sigPath = xmlPath + ".sig";
        using var headKey = RSA.Create(2048);
        X509Certificate2 Head(string subject, DateTimeOffset from, DateTimeOffset to) =>
            new CertificateRequest(subject, headKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(from, to);
        async Task<PowerOfAttorneyService.CheckResult> Check(DateTime issued, X509Certificate2 head, X509Certificate2 representative)
        {
            await File.WriteAllTextAsync(xmlPath,
                $"<Доверенность><СвДов НомДовер=\"77\" ДатаВыдДовер=\"{issued:yyyy-MM-dd}\" СрокДейст=\"{DateTime.Today.AddYears(1):yyyy-MM-dd}\"/>"
                + "<СвРосОрг НаимОрг=\"ООО Тест\" ИННЮЛ=\"1234567890\"/><СвУпПред><СведФизЛ ИННФЛ=\"123456789012\" СНИЛС=\"12345678901\">"
                + "<ФИО Фамилия=\"Представитель\"/></СведФизЛ></СвУпПред></Доверенность>");
            await File.WriteAllBytesAsync(sigPath, signer.Sign(await File.ReadAllBytesAsync(xmlPath), head));
            return PowerOfAttorneyService.Validate(PowerOfAttorneyService.Parse(xmlPath, sigPath), representative);
        }

        var now = DateTimeOffset.Now;
        using var representative = MakeCertificate("CN=Представитель, OID.1.2.643.3.131.1.1=123456789012, OID.1.2.643.100.3=12345678901");

        using (var expiredAfterIssue = Head("CN=Руководитель", now.AddDays(-30), now.AddDays(-2)))
        {
            var result = await Check(DateTime.Today.AddDays(-10), expiredAfterIssue, representative);
            Assert(result.State == PowerOfAttorneyService.CheckState.Warning && result.Message.Contains("после выдачи МЧД"),
                "head certificate expired after POA issue must warn, not reject: " + result.Message);
        }
        using (var expiredBeforeIssue = Head("CN=Руководитель", now.AddDays(-30), now.AddDays(-5)))
            Assert((await Check(DateTime.Today.AddDays(-1), expiredBeforeIssue, representative)).State == PowerOfAttorneyService.CheckState.Error,
                "head certificate expired before POA issue must be rejected");
        using (var notYetValidAtIssue = Head("CN=Руководитель", now.AddDays(-5), now.AddHours(-1)))
            Assert((await Check(DateTime.Today.AddDays(-10), notYetValidAtIssue, representative)).State == PowerOfAttorneyService.CheckState.Error,
                "head certificate not yet valid at POA issue must be rejected");
        Assert(PowerOfAttorneyService.MomentOnIssueDay(new DateTime(2026, 3, 10), new DateTime(2026, 3, 10, 21, 0, 0), new DateTime(2027, 1, 1)) is not null
            && PowerOfAttorneyService.MomentOnIssueDay(new DateTime(2026, 3, 10), new DateTime(2026, 3, 11), new DateTime(2027, 1, 1)) is null,
            "issue day window covers Russian time zones only");
        Console.WriteLine("regression: POA head expired after issue → warning; before issue / not yet valid → error: OK");

        using var head = Head("CN=Руководитель, OID.1.2.643.3.131.1.1=001234567890", now.AddDays(-1), now.AddYears(1));
        using var orgInnOnly = MakeCertificate("CN=Представитель, OID.1.2.643.100.4=1234567890, OID.1.2.643.100.3=12345678901");
        var withOrgInn = await Check(DateTime.Today.AddDays(-1), head, orgInnOnly);
        Assert(withOrgInn.State != PowerOfAttorneyService.CheckState.Error,
            "organization INN (1.2.643.100.4) must not be compared with personal INN: " + withOrgInn.Message);
        Assert(!withOrgInn.Message.Contains("не подтверждена по ИНН"), "legacy «00» organization INN of the head must be recognized");
        using var legacyOrgInn = MakeCertificate("CN=Представитель, OID.1.2.643.3.131.1.1=001234567890, OID.1.2.643.100.3=12345678901");
        Assert((await Check(DateTime.Today.AddDays(-1), head, legacyOrgInn)).State != PowerOfAttorneyService.CheckState.Error,
            "legacy «00» organization INN must not be treated as personal INN");
        using var conflictingInn = MakeCertificate("CN=Представитель, OID.1.2.643.3.131.1.1=111111111111, OID.1.2.643.100.3=12345678901");
        Assert((await Check(DateTime.Today.AddDays(-1), head, conflictingInn)).State == PowerOfAttorneyService.CheckState.Error,
            "conflicting personal INN must be rejected even when SNILS matches");
        using var foreignHead = Head("CN=Руководитель, OID.1.2.643.3.131.1.1=009999999999", now.AddDays(-1), now.AddYears(1));
        Assert((await Check(DateTime.Today.AddDays(-1), foreignHead, representative)).State == PowerOfAttorneyService.CheckState.Error,
            "head organization INN must match the principal");
        Console.WriteLine("regression: POA representative by SNILS with organization INN; personal INN conflicts rejected: OK");
    }

    // Ошибка 3: исключение библиотеки при проверке не исключает соподписанта из объединения.
    private static void CheckVerifierRobustness(DocumentSigner signer, X509Certificate2 certA, X509Certificate2 certB, byte[] document)
    {
        var odd = WithSignatureAlgorithm(signer.Sign(document, certA), "1.2.840.10045.4.3.2"); // ECDSA, а ключ RSA
        var oddCheck = SignatureVerifier.Verify(odd, document, Crypto).Signers.Single();
        Assert(oddCheck.Signature.State == VerificationState.Unknown && oddCheck.Document.State == VerificationState.Valid,
            "library exception during verification must be «unknown», not «invalid»: " + oddCheck.Signature.Message);
        var merged = CmsMerger.MergeForDocument(new[] { odd, signer.Sign(document, certB) }, document);
        Assert(merged.SignerCount == 2 && merged.ExcludedSigners.Count == 0 && merged.UnverifiedSigners.Count == 1,
            "unverifiable co-signer must be kept (reported as unverified), not excluded");
        var stale = signer.Sign(Encoding.UTF8.GetBytes("other version"), certA);
        var staleCheck = SignatureVerifier.Verify(stale, document, Crypto).Signers.Single();
        Assert(staleCheck.Document.State == VerificationState.Invalid && staleCheck.Signature.State == VerificationState.Invalid,
            "signature over another document stays invalid");
        Console.WriteLine("regression: verifier exceptions → unknown, co-signer kept; mismatched document still invalid: OK");
    }

    // Ошибка 7: недоступные файлы доверенных корней не ломают проверку и не теряют МЧД;
    // разрешение сетевых запросов берётся из настроек.
    private static async Task CheckVerificationSettingsAsync(string root, DocumentSigner signer)
    {
        var dir = Path.Combine(root, "verification_settings");
        Directory.CreateDirectory(dir);
        using var rootCertificate = MakeCertificate("CN=Доверенный корень");
        var pemPath = Path.Combine(dir, "root.pem");
        await File.WriteAllTextAsync(pemPath, rootCertificate.ExportCertificatePem());
        var garbagePath = Path.Combine(dir, "garbage.cer");
        await File.WriteAllTextAsync(garbagePath, "not a certificate");
        var settings = new AppSettings(Path.Combine(dir, "settings"))
        {
            CheckUpdatesOnStart = false,
            VerificationAllowNetwork = true,
            VerificationTrustedRootPaths = new List<string> { Path.Combine(dir, "missing.cer"), garbagePath, pemPath },
        };
        var problems = new List<string>();
        var options = settings.CreateVerificationOptions(problems);
        Assert(options.TrustedRoots.Count == 1 && options.TrustedRoots[0].SequenceEqual(rootCertificate.RawData),
            "readable PEM root must be loaded as DER");
        Assert(problems.Count == 2 && problems.All(p => p.Contains("пропущен")), "missing and broken roots must be reported, not thrown");
        Assert(options.AllowNetwork, "VerificationAllowNetwork setting ignored");

        // Сохранённая МЧД восстанавливается при запуске, даже если файл корня пропал.
        var xmlPath = Path.Combine(dir, "mchd.xml");
        await File.WriteAllTextAsync(xmlPath,
            $"<Доверенность><СвДов НомДовер=\"88\" ДатаВыдДовер=\"{DateTime.Today.AddDays(-1):yyyy-MM-dd}\" СрокДейст=\"{DateTime.Today.AddYears(1):yyyy-MM-dd}\"/>"
            + "<СвРосОрг ИННЮЛ=\"1234567890\"/><СвУпПред><СведФизЛ СНИЛС=\"12345678901\"><ФИО Фамилия=\"Представитель\"/></СведФизЛ></СвУпПред></Доверенность>");
        using var head = MakeCertificate("CN=Руководитель");
        await File.WriteAllBytesAsync(xmlPath + ".sig", signer.Sign(await File.ReadAllBytesAsync(xmlPath), head));
        settings.PoaXmlPath = xmlPath;
        settings.PoaSigPath = xmlPath + ".sig";
        var vm = new MainWindowViewModel(new CertificateProvider(), signer, settings, new CertificateVault(Path.Combine(dir, "vault")));
        for (var waited = 0; vm.IsBusy && waited < 600; waited++)
            await Task.Delay(100);
        Assert(!vm.IsBusy && vm.Poa?.Number == "88", "saved POA must be restored despite a missing trusted root: " + vm.LogText);
        Assert(vm.LogText.Contains("пропущен"), "missing trusted root must be logged");
        Console.WriteLine("regression: trusted roots — missing/broken skipped and logged, PEM loaded, network setting used, POA restored: OK");
    }

    // Пункты 8–9: МЧД проверяется один раз на пакет, хранилища ОС кешируются,
    // документ хешируется один раз на алгоритм, режим результата объединения задаётся явно.
    private static async Task CheckCachesAsync(string root, DocumentSigner signer, X509Certificate2 certA,
        X509Certificate2 certB, byte[] document)
    {
        var dir = Path.Combine(root, "caches");
        var poaDir = Path.Combine(dir, "poa");
        var docDir = Path.Combine(dir, "docs");
        Directory.CreateDirectory(poaDir);
        Directory.CreateDirectory(docDir);
        var xmlPath = Path.Combine(poaDir, "batch.xml");
        await File.WriteAllTextAsync(xmlPath,
            $"<Доверенность><СвДов НомДовер=\"99\" ДатаВыдДовер=\"{DateTime.Today.AddDays(-1):yyyy-MM-dd}\" СрокДейст=\"{DateTime.Today.AddYears(1):yyyy-MM-dd}\"/>"
            + "<СвРосОрг ИННЮЛ=\"1234567890\"/><СвУпПред><СведФизЛ ИННФЛ=\"771378577706\"><ФИО Фамилия=\"Представитель\"/></СведФизЛ></СвУпПред></Доверенность>");
        await File.WriteAllBytesAsync(xmlPath + ".sig", signer.Sign(await File.ReadAllBytesAsync(xmlPath), certB));
        var package = PowerOfAttorneyService.Prepare(PowerOfAttorneyService.Parse(xmlPath, xmlPath + ".sig"), certA, Crypto);
        Assert(package.Check.State != PowerOfAttorneyService.CheckState.Error, "batch POA rejected: " + package.Check.Message);
        await File.WriteAllTextAsync(xmlPath, "replaced after the batch check");   // повторная проверка упала бы на разборе
        foreach (var name in new[] { "one.txt", "two.txt", "three.txt" })
        {
            var path = Path.Combine(docDir, name);
            await File.WriteAllBytesAsync(path, document);
            await signer.SignFileAsync(path, certA, new DocumentSigner.SignOptions
                { PowerOfAttorney = package.Info, PreparedPowerOfAttorney = package });
        }
        Assert(File.ReadAllBytes(Path.Combine(docDir, "batch.xml")).SequenceEqual(package.Xml),
            "batch must copy the verified POA snapshot without re-verifying per file");
        Console.WriteLine("regression: POA verified once per batch, snapshot copied to every document: OK");

        var signature = signer.Sign(document, certA);
        var loads = CertificateValidator.SystemStoreLoads;
        var withTrust = new VerificationOptions { CheckRevocation = false };
        SignatureVerifier.Verify(signature, document, withTrust);
        SignatureVerifier.Verify(signature, document, withTrust);
        Assert(CertificateValidator.SystemStoreLoads - loads <= 1, "system certificate stores must be cached between verifications");
        Console.WriteLine("regression: OS certificate stores cached between verifications: OK");

        var digests = new DocumentDigests(document);
        foreach (var cosigner in new[] { certA, certB, certA })
            Assert(SignatureVerifier.VerifyWithDigests(signer.Sign(document, cosigner), digests, Crypto).CryptographicallyValid,
                "verification with shared digests failed");
        Assert(digests.Computations == 1, "document must be hashed once per algorithm, not per signer");
        var attachedInput = signer.Sign(document, certA, detached: false);
        var detachedInput = signer.Sign(document, certB);
        var detachedOut = CmsMerger.MergeForDocument(new[] { attachedInput, detachedInput }, document, attach: false);
        var attachedOut = CmsMerger.MergeForDocument(new[] { detachedInput, signer.Sign(document, certA) }, document, attach: true);
        var automatic = CmsMerger.MergeForDocument(new[] { attachedInput, detachedInput }, document);
        Assert(CmsMerger.ExtractContent(detachedOut.Signature) is null && detachedOut.SignerCount == 2
            && SignatureVerifier.Verify(detachedOut.Signature, document, Crypto).CryptographicallyValid, "merge to detached");
        Assert(CmsMerger.ExtractContent(attachedOut.Signature)!.SequenceEqual(document)
            && SignatureVerifier.Verify(attachedOut.Signature, null, Crypto).CryptographicallyValid, "merge to attached");
        Assert(CmsMerger.ExtractContent(automatic.Signature)!.SequenceEqual(document), "merge keeps attached form by default");
        Console.WriteLine("regression: one document hash per algorithm; merge output mode attached/detached/auto: OK");
    }

    // Подменяет алгоритм подписи первого подписанта (значение подписи не меняется).
    private static byte[] WithSignatureAlgorithm(byte[] encoded, string oid)
    {
        var content = Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(Asn1Object.FromByteArray(encoded));
        var signed = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(content.Content);
        var signerInfo = Org.BouncyCastle.Asn1.Cms.SignerInfo.GetInstance(signed.SignerInfos[0]);
        var changed = new Org.BouncyCastle.Asn1.Cms.SignerInfo(signerInfo.SignerID, signerInfo.DigestAlgorithm,
            signerInfo.SignedAttrs, new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new DerObjectIdentifier(oid)),
            signerInfo.Signature, signerInfo.UnsignedAttrs);
        return new Org.BouncyCastle.Asn1.Cms.ContentInfo(content.ContentType, new Org.BouncyCastle.Asn1.Cms.SignedData(
            signed.DigestAlgorithms, signed.EncapContentInfo, signed.Certificates, signed.CRLs, new DerSet(changed))).GetEncoded();
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
        Assert(Directory.GetFiles(dir, "*.bak").Length == 0, "failed replacement must not leave backup copies");

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
