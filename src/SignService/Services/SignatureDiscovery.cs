using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;

namespace SignService.Services;

/// <summary>
/// Поиск существующих подписей документа по содержимому, а не по имени файла:
/// «договор-.pdf .sig» рядом с «договор.pdf» тоже находится. Подписанты проверяются
/// той же криптографической проверкой, что и при объединении, поэтому прогноз
/// «кто будет исключён» совпадает с результатом подписания.
/// </summary>
public static class SignatureDiscovery
{
    /// <summary>Документы больше этого размера по содержимому не сопоставляются.</summary>
    public const long MaxDocumentBytes = 200L * 1024 * 1024;

    /// <summary>
    /// Файл подписи относительно документа: MatchingSigners — подписи этого документа,
    /// MismatchedSignerNames — однозначно не соответствуют ему (при объединении будут
    /// исключены), UnverifiedSignerNames — проверить не удалось (сохранятся с пометкой).
    /// </summary>
    public sealed record SignatureMatch(
        string Path,
        int SignerCount,
        int MatchingSigners,
        IReadOnlyList<string> MismatchedSignerNames,
        IReadOnlyList<string> UnverifiedSignerNames);

    /// <summary>
    /// Итог поиска для документа: подходящие подписи из его папки (и «документ.sig»,
    /// даже если подписанты в нём не совпали), число разных подписантов в них
    /// и перетащенные файлы подписей, относящиеся к этому документу.
    /// </summary>
    public sealed record DocumentDiscovery(
        string DocumentPath,
        IReadOnlyList<SignatureMatch> FolderMatches,
        int FolderSignerCount,
        IReadOnlyList<SignatureMatch> DroppedMatches);

    public static bool IsSignatureFile(string path)
    {
        var extension = Path.GetExtension(path);
        return extension.Equals(".sig", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".p7s", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".p7m", StringComparison.OrdinalIgnoreCase);
    }

    public static bool SamePath(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);

    /// <summary>«имя.sig» / «имя.p7s» → «имя». Для файла без расширения подписи — null.</summary>
    public static string? SiblingDocumentPath(string signaturePath) =>
        IsSignatureFile(signaturePath) ? signaturePath[..^Path.GetExtension(signaturePath).Length] : null;

    /// <summary>Склонение: 1 подписант, 2 подписанта, 8 подписантов.</summary>
    public static string SignerWord(int count)
    {
        var hundred = count % 100;
        var ten = count % 10;
        if (hundred is >= 11 and <= 14)
            return "подписантов";
        if (ten == 1)
            return "подписант";
        if (ten is >= 2 and <= 4)
            return "подписанта";
        return "подписантов";
    }

    /// <summary>
    /// Поиск для набора документов: подписи в их папках и перетащенные файлы подписей.
    /// Каждый документ читается и хешируется один раз, каждый файл подписи читается
    /// один раз на весь набор. Выполняется вне потока интерфейса.
    /// </summary>
    public static IReadOnlyList<DocumentDiscovery> Discover(IReadOnlyList<string> documentPaths,
        IReadOnlyList<string> droppedSignatures, CancellationToken cancellationToken = default)
    {
        var signatureBytes = new Dictionary<string, byte[]?>(StringComparer.OrdinalIgnoreCase);
        byte[]? ReadSignature(string path)
        {
            var key = Path.GetFullPath(path);
            if (!signatureBytes.TryGetValue(key, out var bytes))
            {
                try { bytes = File.ReadAllBytes(key); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { bytes = null; }
                signatureBytes[key] = bytes;
            }

            return bytes;
        }

        var folders = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        var result = new List<DocumentDiscovery>();
        foreach (var documentPath in documentPaths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var directory = Path.GetDirectoryName(Path.GetFullPath(documentPath)) ?? ".";
            if (!folders.TryGetValue(directory, out var candidates))
            {
                candidates = Directory.Exists(directory)
                    ? Directory.EnumerateFiles(directory).Where(IsSignatureFile).ToList()
                    : Array.Empty<string>();
                folders[directory] = candidates;
            }

            var document = ReadDocument(documentPath);
            var canonical = documentPath + ".sig";
            var folderMatches = new List<SignatureMatch>();
            var dropped = new List<SignatureMatch>();
            var folderBytes = new List<byte[]>();
            if (document is not null)
            {
                var digests = new DocumentDigests(document);
                foreach (var candidate in candidates)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (SamePath(candidate, documentPath) || ReadSignature(candidate) is not { } bytes)
                        continue;
                    var isCanonical = SamePath(candidate, canonical);
                    if (Match(candidate, bytes, digests, includeUnrelated: isCanonical) is { } match)
                    {
                        folderMatches.Add(match);
                        folderBytes.Add(bytes);
                    }
                }

                foreach (var signature in droppedSignatures)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (ReadSignature(signature) is { } bytes
                        && Match(signature, bytes, digests, includeUnrelated: false) is { MatchingSigners: > 0 } match)
                        dropped.Add(match);
                }
            }
            else if (File.Exists(canonical) && ReadSignature(canonical) is { } canonicalBytes)
            {
                // Документ слишком велик для сопоставления — остаётся «документ.sig» как раньше.
                var count = SafeCount(canonicalBytes);
                folderMatches.Add(new SignatureMatch(canonical, count, 0, Array.Empty<string>(), Array.Empty<string>()));
                folderBytes.Add(canonicalBytes);
            }

            result.Add(new DocumentDiscovery(documentPath, Order(folderMatches, documentPath),
                UnionSignerCount(folderBytes, folderMatches), dropped));
        }

        return result;
    }

    /// <summary>
    /// Документ в каталоге, хеш которого совпал с messageDigest подписей.
    /// Нужен, когда имя .sig не равно «документ.sig».
    /// </summary>
    public static string? FindDocumentByContent(string directory, IReadOnlyList<string> signaturePaths)
    {
        var needed = new List<(string Oid, byte[] Digest)>();
        foreach (var path in signaturePaths)
        {
            try
            {
                var cms = new CmsSignedData(CmsMerger.Normalize(File.ReadAllBytes(path)));
                foreach (SignerInformation signer in cms.GetSignerInfos().GetSigners())
                {
                    if (!TryGetMessageDigest(signer, out var digest))
                        continue;
                    var oid = signer.DigestAlgorithmID.Algorithm.Id;
                    if (needed.Any(item => item.Oid == oid && item.Digest.AsSpan().SequenceEqual(digest)))
                        continue;
                    needed.Add((oid, digest));
                }
            }
            catch (Exception)
            {
                // не CMS — такой файл не поможет найти документ
            }
        }

        if (needed.Count == 0 || !Directory.Exists(directory))
            return null;

        string? best = null;
        var bestScore = 0;
        foreach (var file in Directory.EnumerateFiles(directory))
        {
            if (IsSignatureFile(file) || signaturePaths.Any(path => SamePath(path, file)))
                continue;
            if (ReadDocument(file) is not { } content)
                continue;

            var digests = new DocumentDigests(content);
            var score = needed.Count(item => digests.Get(item.Oid) is { } actual && actual.AsSpan().SequenceEqual(item.Digest));
            if (score > bestScore)
            {
                bestScore = score;
                best = file;
            }
        }

        return best;
    }

    // Подписи файла относительно документа. Без совпадения messageDigest хотя бы у одного
    // подписанта файл считается чужим (null), кроме «документ.sig» (includeUnrelated).
    private static SignatureMatch? Match(string path, byte[] raw, DocumentDigests digests, bool includeUnrelated)
    {
        byte[] normalized;
        List<SignerInformation> signers;
        try
        {
            normalized = CmsMerger.Normalize(raw);
            signers = new CmsSignedData(normalized).GetSignerInfos().GetSigners().ToList();
        }
        catch (Exception)
        {
            return null;
        }

        if (signers.Count == 0)
            return null;
        // Быстрый отсев чужих файлов по messageDigest — без проверки значения подписи.
        if (!includeUnrelated && !signers.Any(signer => DigestMatches(signer, digests)))
            return null;

        IReadOnlyList<string> names;
        try { names = CmsMerger.GetSigners(raw).Select(signer => signer.Name).ToList(); }
        catch (Exception) { names = Array.Empty<string>(); }

        var verification = SignatureVerifier.VerifyWithDigests(normalized, digests, VerificationOptions.CryptographyOnly);
        var matching = 0;
        var mismatched = new List<string>();
        var unverified = new List<string>();
        for (var i = 0; i < verification.Signers.Count; i++)
        {
            var check = verification.Signers[i];
            var name = i < names.Count ? names[i] : "неизвестный подписант";
            if (check.CryptographicallyValid)
                matching++;
            else if (check.Document.State == VerificationState.Invalid || check.Signature.State == VerificationState.Invalid
                     || check.CertificateBinding.State == VerificationState.Invalid)
                mismatched.Add(name);
            else
                unverified.Add(name);
        }

        if (verification.Signers.Count == 0 && !includeUnrelated)
            return null;
        return new SignatureMatch(path, signers.Count, matching, mismatched, unverified);
    }

    private static IReadOnlyList<SignatureMatch> Order(List<SignatureMatch> matches, string documentPath) => matches
        .OrderByDescending(m => m.MatchingSigners)
        .ThenByDescending(m => m.SignerCount)
        .ThenByDescending(m => SamePath(m.Path, documentPath + ".sig"))
        .ThenBy(m => m.Path, StringComparer.OrdinalIgnoreCase)
        .ToList();

    // Сколько разных подписантов окажется в объединении найденных файлов (до исключений).
    private static int UnionSignerCount(List<byte[]> signatures, List<SignatureMatch> matches)
    {
        if (signatures.Count == 0)
            return 0;
        if (signatures.Count == 1)
            return matches[0].SignerCount;
        try
        {
            return CmsMerger.CountSigners(CmsMerger.Merge(signatures));
        }
        catch (Exception)
        {
            return matches.Max(m => m.SignerCount);
        }
    }

    private static int SafeCount(byte[] signature)
    {
        try { return CmsMerger.CountSigners(signature); }
        catch (Exception) { return 0; }
    }

    private static byte[]? ReadDocument(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length == 0 || info.Length > MaxDocumentBytes)
                return null;
            return File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool DigestMatches(SignerInformation signer, DocumentDigests digests)
    {
        if (!TryGetMessageDigest(signer, out var digest))
            return false;
        var actual = digests.Get(signer.DigestAlgorithmID.Algorithm.Id);
        return actual is not null && actual.AsSpan().SequenceEqual(digest);
    }

    private static bool TryGetMessageDigest(SignerInformation signer, out byte[] digest)
    {
        digest = Array.Empty<byte>();
        try
        {
            var attribute = signer.SignedAttributes?[PkcsObjectIdentifiers.Pkcs9AtMessageDigest];
            if (attribute is null || attribute.AttrValues.Count != 1)
                return false;
            digest = Asn1OctetString.GetInstance(attribute.AttrValues[0]).GetOctets();
            return digest.Length > 0;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
