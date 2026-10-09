using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using SignService.Services;
using SignService.ViewModels;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

// Соподписание (по ветке форка sozertsatel/SignService): поиск подписей документа по
// содержимому, явный режим, подтверждения, резервные копии, имя результата
// «Объединить .sig» и проверка ГОСТ с параметрами в signatureAlgorithm (КриптоПро/CryptoAPI).
internal static class CoSignTests
{
    private static readonly VerificationOptions Crypto = new()
        { CheckCertificateTrust = false, CheckRevocation = false, UseSystemTrustStore = false };

    public static async Task RunAsync(string tempRoot, DocumentSigner signer)
    {
        var root = Path.Combine(tempRoot, "cosign");
        Directory.CreateDirectory(root);
        using var certA = MakeCert("CN=Подписант А");
        using var certB = MakeCert("CN=Подписант Б");
        using var certC = MakeCert("CN=Подписант В");
        var data = System.Text.Encoding.UTF8.GetBytes("актуальный документ");
        var other = System.Text.Encoding.UTF8.GetBytes("другая версия документа");

        await CheckDiscoveryAndAppend(root, signer, certA, certB, data);
        await CheckCreateNewConfirmation(root, signer, certA, certB, data);
        await CheckExclusionConfirmation(root, signer, certA, certB, certC, data, other);
        await CheckUnmatchedSignatureListed(root, signer, certA, data, other);
        await CheckDroppedFromOtherFolder(root, signer, certA, certB, data);
        await CheckDiscoveryInBackground(root, signer, certA, data);
        await CheckCanonicalWithoutSignedAttributes(root, signer, certA, certB, data);
        await CheckStampedCopyLeavesOriginalSignatures(root, signer, certA, certB, certC);
        CheckMergeNamesOutput(root, signer, certA, certB, data);
        CheckGostParameters();
        await CheckSamplesIfPresent(root);
        Console.WriteLine("cosign: discovery, confirmation, backup, merge name, GOST parameters: OK");
    }

    private static async Task CheckDiscoveryAndAppend(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, byte[] data)
    {
        var dir = Path.Combine(root, "append");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "договор.pdf");
        var odd = Path.Combine(dir, "договор-.pdf .sig");
        await File.WriteAllBytesAsync(document, data);
        var original = signer.Sign(data, certA);
        await File.WriteAllBytesAsync(odd, original);

        var vm = ViewModel(dir);
        await vm.AddFilesAsync(odd, document); // подпись раньше документа — всё равно находится по содержимому
        var item = vm.Files.Single();
        Assert(item.StatusDisplay.Contains("будет добавлена подпись №2")
            && item.StatusDisplay.Contains("договор-.pdf .sig")
            && item.StatusDisplay.Contains("1 подписант")
            && !item.StatusDisplay.Contains("приложенные"),
            "plan must name the odd signature and the next signer number: " + item.StatusDisplay);
        Assert(item.SelectedCoSignOption is { CreateNew: false }, "default mode adds to the discovered signature");
        Assert(SignatureDiscovery.SamePath(item.PlannedOutputPath, odd), "output is the discovered file, not a new имя.sig");

        vm.SelectedCertificate = new CertificateItem(certB);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Signed, "append sign failed: " + item.Message);
        Assert(item.StatusDisplay.StartsWith("Подписан: 2 (1 + ваша) → договор-.pdf .sig", StringComparison.Ordinal),
            "signed row must show previous count and target: " + item.StatusDisplay);
        Assert(!File.Exists(document + ".sig"), "canonical имя.sig must not appear when appending to the odd file");
        Assert(CmsMerger.CountSigners(await File.ReadAllBytesAsync(odd)) == 2, "odd file must now have 2 signers");
        Assert(Directory.GetFiles(dir, "*.bak").Length == 0,
            "appending keeps every previous signer, a backup copy would only clutter the folder");
        var appended = await File.ReadAllBytesAsync(odd);
        Assert(SignatureValues(appended).Any(value => value.SequenceEqual(SignatureValues(original)[0])),
            "the previous signer must be kept byte for byte");
        Assert(signer.VerifyDetached(data, appended), "appended signature must verify");

        // После подписания вариант обновлён: соподписание следующим сертификатом дописывает в тот же файл.
        vm.SelectedCertificate = new CertificateItem(certA);
        Assert(item.Status == SignStatus.Pending && SignatureDiscovery.SamePath(item.PlannedOutputPath, odd)
            && item.StatusDisplay.Contains("2 подписанта"),
            "after a certificate change the row must offer the updated file: " + item.StatusDisplay);
        Console.WriteLine("cosign: odd name discovered by content, append shows «2 (1 + ваша)», no backup clutter: OK");
    }

    private static async Task CheckCreateNewConfirmation(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, byte[] data)
    {
        var dir = Path.Combine(root, "create_new");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "заявка.pdf");
        var odd = Path.Combine(dir, "заявка-.pdf .sig");
        var canonical = document + ".sig";
        await File.WriteAllBytesAsync(document, data);
        var originalOdd = signer.Sign(data, certA);
        var originalCanonical = signer.Sign(data, certA);
        await File.WriteAllBytesAsync(odd, originalOdd);
        await File.WriteAllBytesAsync(canonical, originalCanonical);

        var vm = ViewModel(dir);
        await vm.AddFilesAsync(document);
        vm.MergeWithExisting = false;
        var item = vm.Files.Single();
        Assert(item.StatusDisplay.Contains("будет создан новый файл подписи")
            && item.StatusDisplay.Contains("будет заменён"),
            "create-new row must warn that the canonical file will be replaced: " + item.StatusDisplay);
        var risks = vm.DescribeSignRisks(vm.Files.ToList());
        Assert(risks is not null && risks.Contains("заявка-.pdf .sig") && risks.Contains("перезаписан без объединения"),
            "confirmation must mention the matching signature and the overwrite: " + risks);

        vm.SelectedCertificate = new CertificateItem(certB);
        vm.RequestConfirmAsync = (_, _) => Task.FromResult(false);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Pending, "declined confirmation must leave the file unsigned");
        Assert((await File.ReadAllBytesAsync(odd)).SequenceEqual(originalOdd), "declined sign must not touch the odd signature");
        Assert((await File.ReadAllBytesAsync(canonical)).SequenceEqual(originalCanonical), "declined sign must not overwrite canonical .sig");

        vm.RequestConfirmAsync = (_, _) => Task.FromResult(true);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Signed && item.StatusDisplay.StartsWith("Подписан: 1, новый файл", StringComparison.Ordinal),
            "confirmed create-new must say so: " + item.StatusDisplay);
        Assert((await File.ReadAllBytesAsync(odd)).SequenceEqual(originalOdd), "create-new must leave the other signature untouched");
        Assert(CmsMerger.CountSigners(await File.ReadAllBytesAsync(canonical)) == 1, "overwritten canonical file has only the new signer");
        var backup = Directory.GetFiles(dir, "заявка.pdf.sig.*.bak").Single();
        Assert((await File.ReadAllBytesAsync(backup)).SequenceEqual(originalCanonical), "overwrite keeps a backup of the previous .sig");
        Console.WriteLine("cosign: create-new asks before ignoring a match and before overwrite; backup kept: OK");
    }

    private static async Task CheckExclusionConfirmation(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, X509Certificate2 certC, byte[] data, byte[] other)
    {
        var dir = Path.Combine(root, "exclude");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "смета.pdf");
        var odd = Path.Combine(dir, "смета-.pdf .sig");
        await File.WriteAllBytesAsync(document, data);
        var mixed = CmsMerger.Merge(new[] { signer.Sign(data, certA), signer.Sign(other, certB) });
        await File.WriteAllBytesAsync(odd, mixed);

        var vm = ViewModel(dir);
        await vm.AddFilesAsync(document);
        var item = vm.Files.Single();
        Assert(item.HasWarning && item.WarningDisplay!.Contains("Перед исключением"),
            "row must warn before signers would be dropped: " + item.WarningDisplay);
        var risks = vm.DescribeSignRisks(vm.Files.ToList());
        Assert(risks is not null && risks.Contains("исключены подписанты") && risks.Contains("Подписант Б"),
            "confirmation must name the signer that would be dropped: " + risks);

        vm.SelectedCertificate = new CertificateItem(certC);
        vm.RequestConfirmAsync = (_, _) => Task.FromResult(false);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert((await File.ReadAllBytesAsync(odd)).SequenceEqual(mixed), "declined exclusion must keep the original signature");

        vm.RequestConfirmAsync = (_, _) => Task.FromResult(true);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Signed, "sign after confirmed exclusion failed: " + item.Message);
        Assert(item.HasWarning && item.WarningDisplay!.StartsWith("Внимание: исключены подписанты", StringComparison.Ordinal)
            && item.WarningDisplay.Contains("Подписант Б"),
            "excluded signer must stay visible after signing: " + item.WarningDisplay);
        var result = SignatureVerifier.Verify(await File.ReadAllBytesAsync(odd), data, Crypto);
        Assert(result.Signers.Count == 2 && result.Signers.All(s => s.CryptographicallyValid),
            "kept signers must verify; dropped signer must be gone");
        var backup = Directory.GetFiles(dir, "*.bak").Single();
        Assert((await File.ReadAllBytesAsync(backup)).SequenceEqual(mixed), "exclusion keeps a backup with the dropped signer");
        Console.WriteLine("cosign: exclusion needs confirmation, stays a warning on the row, backup kept: OK");
    }

    private static async Task CheckUnmatchedSignatureListed(string root, DocumentSigner signer,
        X509Certificate2 certA, byte[] data, byte[] other)
    {
        var dir = Path.Combine(root, "unmatched");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "письмо.txt");
        await File.WriteAllBytesAsync(document, data);
        var foreign = Path.Combine(dir, "чужая подпись.sig");
        await File.WriteAllBytesAsync(foreign, signer.Sign(other, certA));
        var garbage = Path.Combine(dir, "битая.p7s");
        await File.WriteAllBytesAsync(garbage, new byte[] { 1, 2, 3, 4 });

        var vm = ViewModel(dir);
        await vm.AddFilesAsync(document, foreign, garbage);
        Assert(vm.Files.Count == 1, "signature files must not become documents in the queue");
        Assert(vm.StatusText.Contains("«чужая подпись.sig»") && vm.StatusText.Contains("«битая.p7s»")
            && vm.StatusText.Contains("не сопоставлены", StringComparison.OrdinalIgnoreCase),
            "unmatched signatures must be listed, not silently skipped: " + vm.StatusText);
        Assert(!vm.Files[0].StatusDisplay.Contains("чужая"), "foreign signature must not be attached: " + vm.Files[0].StatusDisplay);

        await vm.AddFilesAsync(Path.Combine(dir, "письмо-.txt .sig"));
        await File.WriteAllBytesAsync(Path.Combine(dir, "письмо-.txt .sig"), signer.Sign(data, certA));
        await vm.AddFilesAsync(Path.Combine(dir, "письмо-.txt .sig"));
        Assert(vm.Files[0].StatusDisplay.Contains("будет добавлена подпись №2")
            && vm.Files[0].StatusDisplay.Contains("письмо-.txt .sig"),
            "a signature dropped later must attach by hash: " + vm.Files[0].StatusDisplay);
        Console.WriteLine("cosign: unmatched .sig/.p7s are listed; a later drop still matches by hash: OK");
    }

    private static void CheckMergeNamesOutput(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, byte[] data)
    {
        var dir = Path.Combine(root, "merge_name");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "акт.pdf");
        File.WriteAllBytes(document, data);
        var odd = Path.Combine(dir, "акт-.pdf .sig");
        var second = Path.Combine(dir, "вторая.p7s");
        File.WriteAllBytes(odd, signer.Sign(data, certA));
        File.WriteAllBytes(second, signer.Sign(data, certB));
        var canonical = document + ".sig";
        File.WriteAllBytes(canonical, new byte[] { 9, 9, 9 });

        var merged = CmsExtractor.MergeSignatureFiles(new[] { odd, second });
        Assert(Path.GetFileName(merged.OutputPath) == "акт.pdf (1).sig",
            "taken canonical name must get a unique suffix, not the odd input name: " + merged.OutputPath);
        Assert(File.ReadAllBytes(canonical).SequenceEqual(new byte[] { 9, 9, 9 }), "existing акт.pdf.sig must stay untouched");
        Assert(merged.DocumentNote.Contains("акт.pdf") && merged.DocumentNote.Contains("не перезаписан"),
            "note must say the document was found and the existing file was kept: " + merged.DocumentNote);
        Assert(CmsMerger.CountSigners(File.ReadAllBytes(merged.OutputPath)) == 2, "merged file keeps both signers");

        File.Delete(canonical);
        var cleanDir = Path.Combine(dir, "clean");
        Directory.CreateDirectory(cleanDir);
        var cleanDoc = Path.Combine(cleanDir, "акт.pdf");
        File.WriteAllBytes(cleanDoc, data);
        var cleanOdd = Path.Combine(cleanDir, "акт-.pdf .sig");
        File.WriteAllBytes(cleanOdd, signer.Sign(data, certA));
        File.WriteAllBytes(Path.Combine(cleanDir, "вторая.p7s"), signer.Sign(data, certB));
        var named = CmsExtractor.MergeSignatureFiles(new[] { cleanOdd, Path.Combine(cleanDir, "вторая.p7s") });
        Assert(Path.GetFileName(named.OutputPath) == "акт.pdf.sig",
            "when the document is known and имя.sig is free, that is the output: " + named.OutputPath);
        Console.WriteLine("cosign: merge output is «документ.sig» and does not clobber an existing file: OK");
    }

    // Подпись, перетащенная из другой папки, — приложенная: объединяется с вашей,
    // результат пишется рядом с документом, сам перетащенный файл не меняется.
    private static async Task CheckDroppedFromOtherFolder(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, byte[] data)
    {
        var dir = Path.Combine(root, "dropped");
        var mail = Path.Combine(root, "dropped_mail");
        Directory.CreateDirectory(dir);
        Directory.CreateDirectory(mail);
        var document = Path.Combine(dir, "акт сверки.pdf");
        await File.WriteAllBytesAsync(document, data);
        var fromMail = Path.Combine(mail, "подпись контрагента.p7s");
        var foreignBytes = signer.Sign(data, certA);
        await File.WriteAllBytesAsync(fromMail, foreignBytes);

        var vm = ViewModel(dir);
        await vm.AddFilesAsync(document, fromMail);
        var item = vm.Files.Single();
        Assert(item.ExtraCount == 1 && item.StatusDisplay.Contains("приложенные подписи (1)"),
            "a matching signature from another folder must be attached: " + item.StatusDisplay);
        vm.SelectedCertificate = new CertificateItem(certB);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Signed && CmsMerger.CountSigners(await File.ReadAllBytesAsync(document + ".sig")) == 2,
            "result must be «документ.sig» with both signers: " + item.StatusDisplay);
        Assert((await File.ReadAllBytesAsync(fromMail)).SequenceEqual(foreignBytes), "the dropped file must stay untouched");
        Console.WriteLine("cosign: signature from another folder is attached, result next to the document, source untouched: OK");
    }

    // Поиск подписей идёт в фоне: добавление файла не держит поток интерфейса, подписание ждёт поиска.
    private static async Task CheckDiscoveryInBackground(string root, DocumentSigner signer, X509Certificate2 certA, byte[] data)
    {
        var dir = Path.Combine(root, "background");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "отчёт.pdf");
        await File.WriteAllBytesAsync(document, data);
        await File.WriteAllBytesAsync(Path.Combine(dir, "отчёт-.pdf .sig"), signer.Sign(data, certA));
        var vm = ViewModel(dir);
        vm.SelectedCertificate = new CertificateItem(certA);
        var adding = vm.AddFilesAsync(document);
        var item = vm.Files.Single();
        if (!adding.IsCompleted)
        {
            Assert(item.IsDiscovering && item.StatusDisplay.Contains("поиск подписей") && !item.CanChooseCoSign,
                "row must show the search while it runs: " + item.StatusDisplay);
            Assert(!vm.SignAllCommand.CanExecute(null), "signing must wait until the search finishes");
        }

        await adding;
        Assert(!item.IsDiscovering && item.CanChooseCoSign && vm.SignAllCommand.CanExecute(null)
            && item.StatusDisplay.Contains("будет добавлена подпись №2"), "search result must be applied: " + item.StatusDisplay);
        Console.WriteLine("cosign: signature search runs in the background, signing waits for it: OK");
    }

    // «документ.sig» с подписью без подписанных атрибутов (голый PKCS#7) по messageDigest не
    // сопоставить — он всё равно предлагается, проверяется по содержимому и сохраняется.
    private static async Task CheckCanonicalWithoutSignedAttributes(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, byte[] data)
    {
        var dir = Path.Combine(root, "direct");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "приказ.pdf");
        await File.WriteAllBytesAsync(document, data);
        var key = DotNetUtilities.GetRsaKeyPair(certA.GetRSAPrivateKey()!);
        var bcCert = new X509CertificateParser().ReadCertificate(certA.RawData);
        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().SetDirectSignature(true)
            .Build(new Asn1SignatureFactory("SHA256WITHRSA", key.Private), bcCert));
        generator.AddCertificates(Org.BouncyCastle.Utilities.Collections.CollectionUtilities.CreateStore(new[] { bcCert }));
        var direct = generator.Generate(new CmsProcessableByteArray(data), false).GetEncoded();
        await File.WriteAllBytesAsync(document + ".sig", direct);

        var vm = ViewModel(dir);
        await vm.AddFilesAsync(document);
        var item = vm.Files.Single();
        Assert(item.SelectedCoSignOption is { CreateNew: false } option && SignatureDiscovery.SamePath(option.SignaturePath!, document + ".sig")
            && !item.HasWarning, "«документ.sig» with a direct signature must be offered without exclusion warnings: " + item.StatusDisplay);
        vm.SelectedCertificate = new CertificateItem(certB);
        await vm.SignAllCommand.ExecuteAsync(null);
        var check = SignatureVerifier.Verify(await File.ReadAllBytesAsync(document + ".sig"), data, Crypto);
        Assert(item.Status == SignStatus.Signed && check.Signers.Count == 2 && check.Signers.All(s => s.CryptographicallyValid),
            "the direct signer must be kept next to the new one: " + item.StatusDisplay);
        Console.WriteLine("cosign: «документ.sig» with a plain PKCS#7 signer is offered and kept: OK");
    }

    // Режим «подписывать копию со штампом»: подпись ставится на другой документ (копию),
    // поэтому найденная групповая подпись оригинала не трогается и не «исключается».
    private static async Task CheckStampedCopyLeavesOriginalSignatures(string root, DocumentSigner signer,
        X509Certificate2 certA, X509Certificate2 certB, X509Certificate2 certC)
    {
        var dir = Path.Combine(root, "stamped_copy");
        Directory.CreateDirectory(dir);
        var document = Path.Combine(dir, "договор.pdf");
        _ = PdfStamper.IsPdf(document); // инициализация шрифтов PDFsharp
        using (var pdf = new PdfSharp.Pdf.PdfDocument())
        {
            pdf.AddPage();
            pdf.Save(document);
        }

        var data = await File.ReadAllBytesAsync(document);
        var group = Path.Combine(dir, "договор-.pdf .sig");
        var groupBytes = CmsMerger.Merge(new[] { signer.Sign(data, certA), signer.Sign(data, certB) });
        await File.WriteAllBytesAsync(group, groupBytes);

        var vm = ViewModel(dir);
        vm.UseStamp = true;
        vm.StampSignCopy = true;
        vm.RequestStampOptionsAsync = _ => Task.FromResult<SignService.Views.StampOptionsDialog.Result?>(
            new SignService.Views.StampOptionsDialog.Result(vm.BuildInitialStampOptions(), SignCopy: true));
        await vm.AddFilesAsync(document);
        var item = vm.Files.Single();
        Assert(item.SignsStampedCopy && item.StatusDisplay.Contains("копия со штампом") && !item.CanChooseCoSign,
            "sign-copy mode must not offer the original's signatures: " + item.StatusDisplay);
        Assert(vm.DescribeSignRisks(vm.Files.ToList()) is null, "sign-copy mode must not ask about the original's signatures");
        vm.SelectedCertificate = new CertificateItem(certC);
        await vm.SignAllCommand.ExecuteAsync(null);
        Assert(item.Status == SignStatus.Signed && string.IsNullOrEmpty(item.Warning),
            "stamped copy must be signed without exclusions: " + item.StatusDisplay + " " + item.Warning);
        Assert((await File.ReadAllBytesAsync(group)).SequenceEqual(groupBytes), "the original's group signature must stay untouched");
        Assert(item.SignaturePath is { } copySignature && !SignatureDiscovery.SamePath(copySignature, group)
            && CmsMerger.CountSigners(await File.ReadAllBytesAsync(copySignature)) == 1,
            "the stamped copy gets its own signature file: " + item.SignaturePath);
        Console.WriteLine("cosign: «sign the stamped copy» leaves the original's group signature untouched: OK");
    }

    // КриптоПро и CryptoAPI записывают в signatureAlgorithm OID ключа ГОСТ с его параметрами.
    // Такие подписи проверяются полностью, без ослабления проверок.
    private static void CheckGostParameters()
    {
        var variants = new[]
        {
            (Name: "2012-256", Curve: RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA,
                Digest: RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,
                Algorithm: "GOST3411-2012-256WITHECGOST3410-2012-256", KeyOid: "1.2.643.7.1.1.1.1",
                Parameters: new[] { "1.2.643.7.1.2.1.1.1", "1.2.643.7.1.1.2.2" }),
            (Name: "2012-512", Curve: RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA,
                Digest: RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512,
                Algorithm: "GOST3411-2012-512WITHECGOST3410-2012-512", KeyOid: "1.2.643.7.1.1.1.2",
                Parameters: new[] { "1.2.643.7.1.2.1.2.1", "1.2.643.7.1.1.2.3" }),
            (Name: "2001", Curve: CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                Digest: CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet,
                Algorithm: "GOST3411WITHECGOST3410", KeyOid: "1.2.643.2.2.19",
                Parameters: new[] { "1.2.643.2.2.35.1", "1.2.643.2.2.30.1" }),
        };
        var data = System.Text.Encoding.UTF8.GetBytes("ГОСТ с параметрами signatureAlgorithm");
        var other = System.Text.Encoding.UTF8.GetBytes("другой документ");
        foreach (var variant in variants)
        {
            var curve = ECGost3410NamedCurves.GetByOid(variant.Curve);
            var generator = new ECKeyPairGenerator("ECGOST3410");
            generator.Init(new ECKeyGenerationParameters(new ECGost3410Parameters(
                new ECNamedDomainParameters(variant.Curve, curve), variant.Curve, variant.Digest, null), new SecureRandom()));
            var pair = generator.GenerateKeyPair();
            var cert = GostCert("GOST " + variant.Name, pair, pair, variant.Algorithm);
            var plain = GostSign(data, cert, pair, variant.Algorithm, withMessageDigest: true);
            Assert(SignatureVerifier.Verify(plain, data, Crypto).CryptographicallyValid, variant.Name + ": GOST without parameters still verifies");

            foreach (var (label, signed) in new[]
            {
                ("signature OID + parameters", WithSignatureAlgorithm(plain, null, variant.Parameters)),
                ("key OID + parameters (CryptoAPI)", WithSignatureAlgorithm(plain, variant.KeyOid, variant.Parameters)),
                ("key OID without parameters", WithSignatureAlgorithm(plain, variant.KeyOid, null)),
            })
            {
                var check = SignatureVerifier.Verify(signed, data, Crypto).Signers.Single();
                Assert(check.CryptographicallyValid, $"{variant.Name} {label} must verify: {check.Signature.Message}");
                Assert(SignatureVerifier.Verify(signed, other, Crypto).Signers.Single().Document.State == VerificationState.Invalid,
                    $"{variant.Name} {label}: another document must be rejected");
                var damaged = signed.ToArray();
                var value = SignatureValues(signed)[0];
                damaged[damaged.AsSpan().IndexOf(value) + value.Length - 1] ^= 1;
                Assert(SignatureVerifier.Verify(damaged, data, Crypto).Signers.Single().Signature.State == VerificationState.Invalid,
                    $"{variant.Name} {label}: damaged value must be invalid");
            }

            // Без messageDigest подпись не связана с документом — параметры не дают обойти проверку.
            var unbound = WithSignatureAlgorithm(GostSign(data, cert, pair, variant.Algorithm, withMessageDigest: false),
                variant.KeyOid, variant.Parameters);
            var unboundCheck = SignatureVerifier.Verify(unbound, other, Crypto).Signers.Single();
            Assert(!unboundCheck.CryptographicallyValid && unboundCheck.Document.State == VerificationState.Invalid,
                $"{variant.Name}: signed attributes without messageDigest must not verify any document: {unboundCheck.Document.Message}");

            var second = generator.GenerateKeyPair();
            var secondCert = GostCert("GOST second " + variant.Name, second, second, variant.Algorithm);
            var cryptoApi = WithSignatureAlgorithm(plain, variant.KeyOid, variant.Parameters);
            var merged = CmsMerger.MergeForDocument(new[] { cryptoApi, GostSign(data, secondCert, second, variant.Algorithm, true) }, data);
            Assert(merged.SignerCount == 2 && merged.ExcludedSigners.Count == 0 && merged.UnverifiedSigners.Count == 0,
                $"{variant.Name}: CryptoAPI-style signer must be verified, not excluded or unverified");
            Assert(new CmsSignedData(merged.Signature).GetSignerInfos().GetSigners()
                    .Any(signer => signer.SignatureAlgorithm.Algorithm.Id == variant.KeyOid && signer.SignatureAlgorithm.Parameters is not null),
                $"{variant.Name}: merge must keep the original signatureAlgorithm with parameters");
        }

        Console.WriteLine("cosign: GOST 2001/2012 with signatureAlgorithm parameters verify fully; unbound and damaged rejected: OK");
    }

    private static async Task CheckSamplesIfPresent(string root)
    {
        // Архив с реальными подписями (групповая на 8 подписантов + одиночная) — по желанию.
        var zip = Environment.GetEnvironmentVariable("SIGNSERVICE_SAMPLES");
        if (string.IsNullOrWhiteSpace(zip) || !File.Exists(zip))
        {
            Console.WriteLine("cosign: real samples not set (SIGNSERVICE_SAMPLES), synthetic GOST cases covered the verifier");
            return;
        }

        var dir = Path.Combine(root, "samples");
        Directory.CreateDirectory(dir);
        ZipFile.ExtractToDirectory(zip, dir, overwriteFiles: true);
        var pdf = Directory.GetFiles(dir, "*.pdf").Single(path => !path.EndsWith(".sig", StringComparison.OrdinalIgnoreCase));
        var signatures = Directory.GetFiles(dir, "*.sig");
        var eight = signatures.Single(path => CmsMerger.CountSigners(File.ReadAllBytes(path)) == 8);
        var one = signatures.Single(path => CmsMerger.CountSigners(File.ReadAllBytes(path)) == 1);
        var document = await File.ReadAllBytesAsync(pdf);
        var oldSignature = await File.ReadAllBytesAsync(eight);
        var newSignature = await File.ReadAllBytesAsync(one);
        var oldValues = SignatureValues(oldSignature);

        var oldCheck = SignatureVerifier.Verify(oldSignature, document, Crypto);
        Assert(oldCheck.Signers.Count == 8 && oldCheck.Signers.All(s => s.CryptographicallyValid),
            "sample 8 signers: " + string.Join(" | ", oldCheck.Signers.Select(s => s.Signature.State + " " + s.Document.State + " " + s.CertificateBinding.State)));

        var merged = CmsMerger.MergeForDocument(new[] { oldSignature, newSignature }, document, attach: false);
        var mergedValues = SignatureValues(merged.Signature);
        var preserved = oldValues.Count(value => mergedValues.Any(item => item.SequenceEqual(value)));
        var check = SignatureVerifier.Verify(merged.Signature, document, Crypto);
        Assert(merged.SignerCount == 9 && check.Signers.Count == 9 && check.Signers.All(s => s.CryptographicallyValid),
            "sample merge 9 signers: " + string.Join(" | ", check.Signers.Select(s =>
                $"{s.Number}:{s.Signature.State}/{s.Document.State}/{s.CertificateBinding.State} {s.Signature.Message}")));
        Assert(preserved == 8, $"original signature values preserved {preserved}/8");

        // В папке образца лежит и ошибочный одноподписный файл — он тоже совпадает по хешу.
        // Сценарий пользователя: только групповая подпись с нестандартным именем.
        var clean = Path.Combine(dir, "only_group");
        Directory.CreateDirectory(clean);
        var cleanPdf = Path.Combine(clean, Path.GetFileName(pdf));
        var cleanSig = Path.Combine(clean, Path.GetFileName(eight));
        await File.WriteAllBytesAsync(cleanPdf, document);
        await File.WriteAllBytesAsync(cleanSig, oldSignature);
        var vm = ViewModel(clean);
        await vm.AddFilesAsync(cleanPdf);
        var plan = vm.Files.Single().StatusDisplay;
        Assert(plan.Contains("будет добавлена подпись №9") && plan.Contains("8 подписантов")
            && plan.Contains(Path.GetFileName(eight)),
            "queue must offer to append signer 9 to the 8-signer file: " + plan);
        Console.WriteLine($"cosign samples: signers=9 allValid=true originalSignatureValuesPreserved={preserved}/8 plan={plan}");
    }

    private static MainWindowViewModel ViewModel(string dir)
    {
        var settings = new AppSettings(Path.Combine(dir, "settings")) { CheckUpdatesOnStart = false };
        return new MainWindowViewModel(new CertificateProvider(), new DocumentSigner(), settings,
            new CertificateVault(Path.Combine(dir, "vault")));
    }

    private static X509Certificate2 MakeCert(string subject)
    {
        using var key = RSA.Create(2048);
        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(1));
    }

    private static BcCertificate GostCert(string name, AsymmetricCipherKeyPair key, AsymmetricCipherKeyPair issuerKey, string algorithm)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ValueOf(name.GetHashCode() & 0x7fffffff));
        generator.SetSubjectDN(new X509Name("CN=" + name));
        generator.SetIssuerDN(new X509Name("CN=" + name));
        generator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        generator.SetPublicKey(key.Public);
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature));
        return generator.Generate(new Asn1SignatureFactory(algorithm, issuerKey.Private));
    }

    private static byte[] GostSign(byte[] data, BcCertificate cert, AsymmetricCipherKeyPair key, string algorithm,
        bool withMessageDigest)
    {
        var builder = new SignerInfoGeneratorBuilder();
        if (!withMessageDigest)
            builder.WithSignedAttributeGenerator(new FixedAttributes(new Org.BouncyCastle.Asn1.Cms.AttributeTable(
                new Asn1EncodableVector(new Org.BouncyCastle.Asn1.Cms.Attribute(Org.BouncyCastle.Asn1.Cms.CmsAttributes.ContentType,
                    new DerSet(Org.BouncyCastle.Asn1.Cms.CmsObjectIdentifiers.Data))))));
        var generator = new CmsSignedDataGenerator();
        generator.AddSignerInfoGenerator(builder.Build(new Asn1SignatureFactory(algorithm, key.Private), cert));
        generator.AddCertificates(Org.BouncyCastle.Utilities.Collections.CollectionUtilities.CreateStore(new[] { cert }));
        return generator.Generate(new CmsProcessableByteArray(data), encapsulate: false).GetEncoded();
    }

    /// <summary>signatureAlgorithm первого подписанта: другой OID (null — прежний) и параметры (null — без них).</summary>
    private static byte[] WithSignatureAlgorithm(byte[] encoded, string? oid, string[]? parameters)
    {
        var content = Org.BouncyCastle.Asn1.Cms.ContentInfo.GetInstance(Asn1Object.FromByteArray(encoded));
        var signed = Org.BouncyCastle.Asn1.Cms.SignedData.GetInstance(content.Content);
        var signerInfo = Org.BouncyCastle.Asn1.Cms.SignerInfo.GetInstance(signed.SignerInfos[0]);
        var algorithm = oid is null ? signerInfo.SignatureAlgorithm.Algorithm : new DerObjectIdentifier(oid);
        var identifier = parameters is null
            ? new AlgorithmIdentifier(algorithm)
            : new AlgorithmIdentifier(algorithm, new DerSequence(parameters.Select(p => (Asn1Encodable)new DerObjectIdentifier(p)).ToArray()));
        var changed = new Org.BouncyCastle.Asn1.Cms.SignerInfo(
            signerInfo.SignerID, signerInfo.DigestAlgorithm, signerInfo.SignedAttrs,
            identifier, signerInfo.Signature, signerInfo.UnsignedAttrs);
        return new Org.BouncyCastle.Asn1.Cms.ContentInfo(content.ContentType, new Org.BouncyCastle.Asn1.Cms.SignedData(
            signed.DigestAlgorithms, signed.EncapContentInfo, signed.Certificates, signed.CRLs,
            new DerSet(changed))).GetEncoded();
    }

    private sealed class FixedAttributes(Org.BouncyCastle.Asn1.Cms.AttributeTable table) : CmsAttributeTableGenerator
    {
        public Org.BouncyCastle.Asn1.Cms.AttributeTable GetAttributes(IDictionary<CmsAttributeTableParameter, object> parameters) => table;
    }

    private static List<byte[]> SignatureValues(byte[] signature) =>
        new CmsSignedData(signature).GetSignerInfos().GetSigners().Select(signer => signer.GetSignature()).ToList();

    private static void Assert(bool condition, string message)
    {
        if (!condition)
            throw new Exception("cosign: " + message);
    }
}
