// Лабораторна робота №2 — «Захист даних»
// CodinGame: Encryption/Decryption of Enigma Machine
//
// Друга, незалежна реалізація того самого алгоритму мовою C#.
// Призначення — перехресна перевірка: обидві реалізації мають давати
// побітово однаковий результат на всіх шести офіційних тестах.
//
// Запуск:
//   dotnet run --project csharp/Enigma                 -- selftest
//   dotnet run --project csharp/Enigma < input.txt     (режим CodinGame)
//   dotnet run --project csharp/Enigma -- encode 4 AAA

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lab2.Enigma;

/// <summary>Один ротор — таблиця заміни (підстановка алфавіту A..Z).</summary>
public sealed class Rotor
{
    public const int M = 26;
    private const int A = 'A';

    public string Wiring { get; }
    public int[] Forward { get; }
    public int[] Backward { get; }

    public Rotor(string wiring)
    {
        wiring = (wiring ?? string.Empty).Trim().ToUpperInvariant();
        if (wiring.Length != M)
            throw new ArgumentException($"Ротор має містити рівно {M} літер, отримано {wiring.Length}.");
        if (wiring.Distinct().Count() != M || wiring.Any(c => c < 'A' || c > 'Z'))
            throw new ArgumentException($"Ротор '{wiring}' не є підстановкою алфавіту A..Z.");

        Wiring = wiring;
        Forward = wiring.Select(c => c - A).ToArray();
        Backward = new int[M];
        for (int i = 0; i < M; i++) Backward[Forward[i]] = i;
    }
}

/// <summary>
/// Спрощена машина Енігми: інкрементний зсув Цезаря + каскад роторів.
///   c[i] = S[(m[i] + N + i) mod 26],  S = R3 . R2 . R1
/// </summary>
public sealed class EnigmaMachine
{
    private const int M = 26;
    private const int A = 'A';

    private readonly int[] _s;      // композиція роторів
    private readonly int[] _sInv;   // обернена підстановка
    private readonly int _shift;

    public EnigmaMachine(IEnumerable<string> rotors, int shift)
    {
        _shift = ((shift % M) + M) % M;

        // Згортка каскаду в одну підстановку: три таблиці заміни = одна.
        _s = Enumerable.Range(0, M).ToArray();
        foreach (var wiring in rotors)
        {
            var rotor = new Rotor(wiring);
            _s = _s.Select(x => rotor.Forward[x]).ToArray();
        }

        _sInv = new int[M];
        for (int i = 0; i < M; i++) _sInv[_s[i]] = i;
    }

    public string Encode(string message)
    {
        Validate(message);
        var sb = new StringBuilder(message.Length);
        for (int i = 0; i < message.Length; i++)
            sb.Append((char)(A + _s[(message[i] - A + _shift + i) % M]));
        return sb.ToString();
    }

    public string Decode(string ciphertext)
    {
        Validate(ciphertext);
        var sb = new StringBuilder(ciphertext.Length);
        for (int i = 0; i < ciphertext.Length; i++)
        {
            int v = (_sInv[ciphertext[i] - A] - _shift - i) % M;
            if (v < 0) v += M;
            sb.Append((char)(A + v));
        }
        return sb.ToString();
    }

    public string Process(string mode, string message) => mode.Trim().ToUpperInvariant() switch
    {
        "ENCODE" => Encode(message),
        "DECODE" => Decode(message),
        _ => throw new ArgumentException($"Невідомий режим '{mode}': очікується ENCODE або DECODE.")
    };

    private static void Validate(string text)
    {
        foreach (var ch in text)
            if (ch < 'A' || ch > 'Z')
                throw new ArgumentException($"Неприпустимий символ '{ch}': дозволені лише A..Z.");
    }
}

public static class Program
{
    private static readonly string[] Rotors =
    {
        "BDFHJLCPRTXVZNYEIWGAKMUSQO",
        "AJDKSIRUXBLHWTMCQGZNPYFVOE",
        "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
    };

    /// <summary>Шість офіційних валідаційних тестів CodinGame.</summary>
    private static readonly (string Label, string Mode, int Shift, string In, string Out)[] Cases =
    {
        ("Encode 3",  "ENCODE", 4, "AAA", "KQF"),
        ("Encode 23", "ENCODE", 7, "WEATHERREPORTWINDYTODAY", "ALWAURKQEQQWLRAWZHUYKVN"),
        ("Decode 21", "DECODE", 9, "PQSACVVTOISXFXCIAMQEM", "EVERYONEISWELCOMEHERE"),
        ("Encode 21", "ENCODE", 9, "EVERYONEISWELCOMEHERE", "PQSACVVTOISXFXCIAMQEM"),
        ("Encode 42", "ENCODE", 9, "EVERYONEISWELCOMEHEREEVERYONEISWELCOMEHERE",
                                   "PQSACVVTOISXFXCIAMQEMDZIXFJJSTQIENEFQXVZYV"),
        ("Decode 49", "DECODE", 5, "XPCXAUPHYQALKJMGKRWPGYHFTKRFFFNOUTZCABUAEHQLGXREZ",
                                   "THEQUICKBROWNFOXJUMPSOVERALAZYSPHINXOFBLACKQUARTZ")
    };

    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length > 0 && args[0].Equals("selftest", StringComparison.OrdinalIgnoreCase))
            return SelfTest();

        if (args.Length >= 3)
        {
            var machine = new EnigmaMachine(Rotors, int.Parse(args[1]));
            Console.WriteLine(machine.Process(args[0], args[2].ToUpperInvariant()));
            return 0;
        }

        // Режим CodinGame: шість рядків зі стандартного входу.
        var mode = Console.ReadLine()!.Trim();
        var shift = int.Parse(Console.ReadLine()!.Trim());
        var rotors = new[] { Console.ReadLine()!.Trim(), Console.ReadLine()!.Trim(), Console.ReadLine()!.Trim() };
        var message = (Console.ReadLine() ?? string.Empty).Trim();
        Console.WriteLine(new EnigmaMachine(rotors, shift).Process(mode, message));
        return 0;
    }

    private static int SelfTest()
    {
        Console.WriteLine("Офіційні тести CodinGame (реалізація на C#)");
        Console.WriteLine(new string('-', 72));

        int passed = 0;
        foreach (var (label, mode, shift, input, expected) in Cases)
        {
            var got = new EnigmaMachine(Rotors, shift).Process(mode, input);
            var ok = got == expected;
            if (ok) passed++;
            Console.WriteLine($"[{(ok ? "OK" : "FAIL")}] {label,-11} {mode} -> {got}");
        }

        // Властивість: розшифрування — точна інверсія шифрування.
        var rng = new Random(2024);
        int roundTrips = 0;
        for (int t = 0; t < 2000; t++)
        {
            var len = rng.Next(1, 60);
            var msg = new string(Enumerable.Range(0, len)
                .Select(_ => (char)('A' + rng.Next(26))).ToArray());
            var m = new EnigmaMachine(Rotors, rng.Next(26));
            if (m.Decode(m.Encode(msg)) == msg) roundTrips++;
        }

        Console.WriteLine(new string('-', 72));
        Console.WriteLine($"Офіційні тести: пройдено {passed} з {Cases.Length}");
        Console.WriteLine($"Перевірка оборотності: {roundTrips} з 2000 випадкових повідомлень");
        return passed == Cases.Length && roundTrips == 2000 ? 0 : 1;
    }
}
