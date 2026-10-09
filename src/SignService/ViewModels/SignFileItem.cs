using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using SignService.Services;

namespace SignService.ViewModels;

public enum SignStatus
{
    Pending,
    Signing,
    Signed,
    Failed,
}

/// <summary>Вариант в списке файла: добавить подпись в найденный .sig или создать новый.</summary>
public sealed class CoSignOption
{
    public CoSignOption(string? signaturePath, int signerCount)
    {
        SignaturePath = signaturePath;
        SignerCount = signerCount;
        Label = signaturePath is null
            ? "Создать новую подпись"
            : $"Добавить к «{Path.GetFileName(signaturePath)}» ({signerCount} {SignatureDiscovery.SignerWord(signerCount)})";
    }

    /// <summary>null — создать «документ.sig», не объединяя с найденными файлами.</summary>
    public string? SignaturePath { get; }

    public int SignerCount { get; }

    public string Label { get; }

    public bool CreateNew => SignaturePath is null;

    public override string ToString() => Label;
}

/// <summary>
/// Файл в очереди на подписание.
/// </summary>
public partial class SignFileItem : ObservableObject
{
    private readonly List<string> _extraSignatures = new();
    private readonly List<SignatureDiscovery.SignatureMatch> _external = new();
    private List<SignatureDiscovery.SignatureMatch> _discovered = new();
    private bool _adjustingSelection;
    private bool _mentionBackup;
    private bool _followingShared;
    private bool _sharedWantsAdd;
    private int _unionCount;
    private string _planText = "будет создан новый файл подписи";

    public SignFileItem(string filePath)
    {
        FilePath = filePath;
        FileName = Path.GetFileName(filePath);

        var info = new FileInfo(filePath);
        SizeDisplay = info.Exists ? FormatSize(info.Length) : "—";
        CoSignOptions.Add(new CoSignOption(null, 0));
        _adjustingSelection = true;
        SelectedCoSignOption = CoSignOptions[0];
        _adjustingSelection = false;
    }

    public string FilePath { get; }

    /// <summary>
    /// Модель окна, в очереди которой стоит файл: из контекстного меню файла
    /// (всплывающее окно вне дерева элементов) команды доступны только через неё.
    /// </summary>
    public MainWindowViewModel? Owner { get; init; }

    public string FileName { get; }

    public string SizeDisplay { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    [NotifyPropertyChangedFor(nameof(WarningDisplay))]
    [NotifyPropertyChangedFor(nameof(HasWarning))]
    private SignStatus _status = SignStatus.Pending;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private string? _message;

    /// <summary>Предупреждение об исключённых при объединении подписантах — отдельной строкой.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(WarningDisplay))]
    [NotifyPropertyChangedFor(nameof(HasWarning))]
    private string? _warning;

    /// <summary>Путь к созданному файлу подписи (.sig).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private string? _signaturePath;

    /// <summary>Число подписантов в созданном .sig (после соподписания может быть больше 1).</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private int _signerCount;

    /// <summary>Сколько подписантов было в файле, к которому добавили подпись.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private int _previousSignerCount;

    /// <summary>true — подпись дописана в уже существовавший файл, false — создан новый.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StatusDisplay))]
    private bool _appendedToExisting;

    /// <summary>Приложенные подписи других лиц для объединения (пути к .sig).</summary>
    public IReadOnlyList<string> ExtraSignatures => _extraSignatures;

    /// <summary>Подписи из каталога (и приложенные), совпавшие с документом по хешу.</summary>
    public IReadOnlyList<SignatureDiscovery.SignatureMatch> DiscoveredMatches => _discovered;

    /// <summary>Пользователь сам выбрал режим для этого файла — общий переключатель его не сбрасывает, пока не переключат режим целиком.</summary>
    public bool CoSignPinned { get; private set; }

    public ObservableCollection<CoSignOption> CoSignOptions { get; } = new();

    [ObservableProperty]
    private CoSignOption? _selectedCoSignOption;

    /// <summary>Режим задаёт первый файл («Применить ко всем») — список в этой строке только для чтения.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CoSignChoiceEnabled))]
    private bool _coSignLocked;

    public bool CoSignChoiceEnabled => !CoSignLocked;

    /// <summary>Общий режим «добавить» невозможен: у файла нет подходящей подписи.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(WarningDisplay))]
    [NotifyPropertyChangedFor(nameof(HasWarning))]
    private bool _sharedAddUnavailable;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasExtra))]
    [NotifyPropertyChangedFor(nameof(ExtraDisplay))]
    private int _extraCount;

    public bool HasExtra => ExtraCount > 0;

    public string ExtraDisplay => $"＋ подписей: {ExtraCount}";

    public bool HasWarning => !string.IsNullOrEmpty(WarningDisplay);

    public string? WarningDisplay => !string.IsNullOrEmpty(Warning) ? Warning : DiscoveryWarning();

    /// <summary>Заново ищет .sig/.p7s в каталоге документа и обновляет строку очереди.</summary>
    public void RefreshDiscovery(bool preferAdd)
    {
        IReadOnlyList<SignatureDiscovery.SignatureMatch> found;
        try
        {
            found = SignatureDiscovery.FindForDocument(FilePath);
        }
        catch (Exception)
        {
            found = Array.Empty<SignatureDiscovery.SignatureMatch>();
        }

        var all = new List<SignatureDiscovery.SignatureMatch>(found);
        foreach (var extra in _external)
        {
            if (extra.MatchingSigners <= 0 || all.Any(match => SignatureDiscovery.SamePath(match.Path, extra.Path)))
                continue;
            all.Add(extra);
        }

        ApplyMatches(all, preferAdd);
    }

    /// <summary>Подпись, найденная по хешу вне каталога документа (её перетащили или выбрали вручную).</summary>
    public void AddExternalMatch(SignatureDiscovery.SignatureMatch match, bool preferAdd)
    {
        if (match.MatchingSigners <= 0)
            return;
        if (_external.Any(existing => SignatureDiscovery.SamePath(existing.Path, match.Path)))
            return;
        _external.Add(match);
        RefreshDiscovery(preferAdd);
    }

    /// <summary>Показывать ли в плане, что перед заменой сохранится .bak.</summary>
    public void SetBackupMention(bool enabled)
    {
        if (_mentionBackup == enabled)
            return;
        _mentionBackup = enabled;
        UpdatePlan();
    }

    /// <summary>
    /// Повторяет режим первого файла. Если добавить не к чему, остаётся «Создать новую»
    /// и строка явно об этом говорит.
    /// </summary>
    public void FollowSharedMode(bool addToExisting)
    {
        _followingShared = true;
        _sharedWantsAdd = addToExisting;
        _adjustingSelection = true;
        ApplySharedSelection();
        _adjustingSelection = false;
        UpdatePlan();
    }

    /// <summary>Снимает общий режим, не меняя уже выбранный пункт списка.</summary>
    public void StopFollowingSharedMode()
    {
        _followingShared = false;
        if (!SharedAddUnavailable)
            return;
        SharedAddUnavailable = false;
        UpdatePlan();
    }

    /// <summary>Общий переключатель «добавить / создать новую» для файлов без ручного выбора.</summary>
    public void ApplyPreferredMode(bool addToExisting, bool resetPin)
    {
        if (resetPin)
            CoSignPinned = false;
        else if (CoSignPinned)
            return;

        _adjustingSelection = true;
        SelectedCoSignOption = addToExisting
            ? CoSignOptions.FirstOrDefault(option => !option.CreateNew) ?? CoSignOptions.LastOrDefault()
            : CoSignOptions.LastOrDefault(option => option.CreateNew) ?? CoSignOptions.LastOrDefault();
        _adjustingSelection = false;
        UpdatePlan();
    }

    /// <summary>
    /// Файлы, которые войдут в объединение: выбранная подпись и остальные найденные
    /// (в режиме «добавить»), плюс явно приложенные.
    /// </summary>
    public IReadOnlyList<string> PlannedMergeInputs()
    {
        var list = new List<string>();
        if (SelectedCoSignOption is { CreateNew: false, SignaturePath: { } selected })
        {
            list.Add(selected);
            foreach (var match in _discovered)
            {
                if (!list.Any(path => SignatureDiscovery.SamePath(path, match.Path)))
                    list.Add(match.Path);
            }
        }

        foreach (var extra in _extraSignatures)
        {
            if (!list.Any(path => SignatureDiscovery.SamePath(path, extra)))
                list.Add(extra);
        }

        return list;
    }

    /// <summary>Куда будет записан результат: выбранный .sig либо «документ.sig».</summary>
    public string PlannedOutputPath =>
        SelectedCoSignOption is { CreateNew: false, SignaturePath: { } path }
            ? path
            : FilePath + ".sig";

    /// <summary>
    /// Файл для проверки, извлечения и штампа: выбранный для соподписания,
    /// иначе «документ.sig», иначе первая найденная по хешу подпись.
    /// </summary>
    public string SignaturePathForTools()
    {
        if (SelectedCoSignOption is { CreateNew: false, SignaturePath: { } selected } && File.Exists(selected))
            return selected;
        var canonical = FilePath + ".sig";
        if (File.Exists(canonical))
            return canonical;
        return _discovered.FirstOrDefault(match => File.Exists(match.Path))?.Path ?? canonical;
    }

    /// <summary>Прикладывает файлы подписей других лиц (дубликаты пропускаются).</summary>
    public int AttachSignatures(IEnumerable<string> sigPaths)
    {
        var added = 0;
        foreach (var path in sigPaths)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                continue;
            if (_extraSignatures.Any(existing => string.Equals(existing, path, StringComparison.OrdinalIgnoreCase)))
                continue;
            _extraSignatures.Add(path);
            added++;
        }

        ExtraCount = _extraSignatures.Count;
        // Новая подпись другого лица должна попасть в .sig — файл снова ждёт подписания.
        if (added > 0 && Status == SignStatus.Signed)
            ResetForSigning();
        UpdatePlan();
        return added;
    }

    /// <summary>Возвращает файл в очередь (после смены сертификата или новых подписей).</summary>
    public void ResetForSigning()
    {
        Status = SignStatus.Pending;
        Message = null;
        Warning = null;
        SignaturePath = null;
        SignerCount = 0;
        PreviousSignerCount = 0;
        AppendedToExisting = false;
    }

    public string StatusDisplay => Status switch
    {
        SignStatus.Pending => _planText,
        SignStatus.Signing => "Подписывается…",
        SignStatus.Signed when AppendedToExisting && SignerCount == PreviousSignerCount + 1 =>
            $"Подписан: {SignerCount} ({PreviousSignerCount} + ваша) → {FileNameOf(SignaturePath)}{SignedNote}",
        SignStatus.Signed when AppendedToExisting =>
            $"Подписан: {SignerCount} (было {PreviousSignerCount}) → {FileNameOf(SignaturePath)}{SignedNote}",
        SignStatus.Signed when SignerCount <= 1 => $"Подписан: 1, новый файл{SignedNote}",
        SignStatus.Signed => $"Подписан: {SignerCount}, новый файл → {FileNameOf(SignaturePath)}{SignedNote}",
        SignStatus.Failed => $"Ошибка: {Message}",
        _ => string.Empty,
    };

    partial void OnSelectedCoSignOptionChanged(CoSignOption? value)
    {
        if (!_adjustingSelection && value is not null)
            CoSignPinned = true;
        UpdatePlan();
        if (!_adjustingSelection && value is not null)
            Owner?.NotifyCoSignSelectionChanged(this);
    }

    private void ApplyMatches(List<SignatureDiscovery.SignatureMatch> matches, bool preferAdd)
    {
        _discovered = matches
            .OrderByDescending(match => match.MatchingSigners)
            .ThenByDescending(match => match.SignerCount)
            .ThenByDescending(match => SignatureDiscovery.SamePath(match.Path, FilePath + ".sig"))
            .ThenBy(match => match.Path, StringComparer.OrdinalIgnoreCase)
            .ToList();
        _unionCount = UnionSignerCount(_discovered);

        var previous = SelectedCoSignOption?.SignaturePath;
        var pinned = CoSignPinned;
        CoSignOptions.Clear();
        foreach (var match in _discovered)
            CoSignOptions.Add(new CoSignOption(match.Path, match.SignerCount));
        CoSignOptions.Add(new CoSignOption(null, 0));

        _adjustingSelection = true;
        if (_followingShared)
            ApplySharedSelection();
        else if (pinned && previous is null)
            SelectedCoSignOption = CoSignOptions.LastOrDefault(option => option.CreateNew);
        else if (pinned && previous is not null)
            SelectedCoSignOption = CoSignOptions.FirstOrDefault(option =>
                    option.SignaturePath is not null && SignatureDiscovery.SamePath(option.SignaturePath, previous))
                ?? CoSignOptions.FirstOrDefault(option => !option.CreateNew)
                ?? CoSignOptions.LastOrDefault();
        else if (preferAdd)
            SelectedCoSignOption = CoSignOptions.FirstOrDefault(option => !option.CreateNew) ?? CoSignOptions.LastOrDefault();
        else
            SelectedCoSignOption = CoSignOptions.LastOrDefault(option => option.CreateNew) ?? CoSignOptions.LastOrDefault();
        _adjustingSelection = false;
        UpdatePlan();
    }

    private void ApplySharedSelection()
    {
        if (!_sharedWantsAdd)
        {
            SelectedCoSignOption = CoSignOptions.LastOrDefault(option => option.CreateNew) ?? CoSignOptions.LastOrDefault();
            SharedAddUnavailable = false;
            return;
        }

        var add = CoSignOptions.FirstOrDefault(option => !option.CreateNew);
        if (add is null)
        {
            SelectedCoSignOption = CoSignOptions.LastOrDefault(option => option.CreateNew) ?? CoSignOptions.LastOrDefault();
            SharedAddUnavailable = true;
            return;
        }

        SelectedCoSignOption = add;
        SharedAddUnavailable = false;
    }

    private void UpdatePlan()
    {
        _planText = BuildPlan();
        OnPropertyChanged(nameof(StatusDisplay));
        OnPropertyChanged(nameof(WarningDisplay));
        OnPropertyChanged(nameof(HasWarning));
    }

    private string BuildPlan()
    {
        if (SelectedCoSignOption is { CreateNew: false, SignaturePath: { } path })
        {
            var others = _discovered.Where(match => !SignatureDiscovery.SamePath(match.Path, path)).ToList();
            var baseCount = others.Count == 0 ? SelectedCoSignOption.SignerCount : _unionCount;
            var sentence =
                $"будет добавлена подпись №{baseCount + 1} к «{Path.GetFileName(path)}» ({SelectedCoSignOption.SignerCount} {SignatureDiscovery.SignerWord(SelectedCoSignOption.SignerCount)})";
            if (others.Count > 0)
                sentence += "; также объединятся: " + string.Join(", ", others.Select(match => "«" + Path.GetFileName(match.Path) + "»"));
            return sentence;
        }

        var canonical = FilePath + ".sig";
        if (File.Exists(canonical))
        {
            var sentence = "будет создан новый файл подписи — существующий «" + Path.GetFileName(canonical)
                + "» будет заменён";
            if (_mentionBackup)
                sentence += " (сохранится резервная копия)";
            return sentence;
        }

        return "будет создан новый файл подписи";
    }

    private const string SharedFallbackText =
        "Нет подходящей подписи — будет создан новый файл. Режим «Добавить к существующей», как у первого файла, здесь недоступен.";

    private string? DiscoveryWarning()
    {
        if (Status != SignStatus.Pending)
            return null;
        var discovery = MismatchedSignerWarning();
        if (!SharedAddUnavailable)
            return discovery;
        return discovery is null ? SharedFallbackText : SharedFallbackText + " " + discovery;
    }

    private string? MismatchedSignerWarning()
    {
        var names = new List<string>();
        foreach (var path in PlannedMergeInputs())
        {
            var match = _discovered.FirstOrDefault(item => SignatureDiscovery.SamePath(item.Path, path));
            if (match is null)
                continue;
            names.AddRange(match.MismatchedSignerNames);
        }

        if (names.Count == 0)
            return null;
        return "Внимание: при объединении будут исключены подписанты, чья подпись не соответствует документу: "
            + string.Join("; ", names.Distinct()) + ". Перед исключением программа запросит подтверждение.";
    }

    private static int UnionSignerCount(IReadOnlyList<SignatureDiscovery.SignatureMatch> matches)
    {
        if (matches.Count == 0)
            return 0;
        if (matches.Count == 1)
            return matches[0].SignerCount;
        try
        {
            var bytes = matches.Select(match => File.ReadAllBytes(match.Path)).ToList();
            return CmsMerger.CountSigners(CmsMerger.Merge(bytes));
        }
        catch (Exception)
        {
            return matches.Max(match => match.SignerCount);
        }
    }

    private string SignedNote => string.IsNullOrEmpty(Message) ? string.Empty : $" ⚠ {Message}";

    private static string FileNameOf(string? path) =>
        string.IsNullOrEmpty(path) ? "" : Path.GetFileName(path);

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} Б",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} КБ",
        < 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.#} МБ",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.##} ГБ",
    };
}
