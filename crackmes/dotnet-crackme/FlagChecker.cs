namespace Crackme;

internal static class FlagChecker
{
    private const byte Key = 0x37;

    private static readonly byte[] PartA =
    {
        0x51, 0x5B, 0x56, 0x50, 0x4C,
        0x5E, 0x5B, 0x44, 0x47, 0x4E,
    };

    private static readonly byte[] PartB =
    {
        0x68, 0x50, 0x07, 0x52, 0x44,
        0x68, 0x55, 0x45, 0x45, 0x45,
        0x4A,
    };

    internal static bool CheckPartA(string s)
    {
        if (s.Length < PartA.Length) return false;
        for (int i = 0; i < PartA.Length; i++)
        {
            if ((byte)(s[i] ^ Key) != PartA[i]) return false;
        }
        return true;
    }

    internal static bool CheckPartB(string s)
    {
        int offset = PartA.Length;
        if (s.Length != offset + PartB.Length) return false;
        for (int i = 0; i < PartB.Length; i++)
        {
            if ((byte)(s[offset + i] ^ Key) != PartB[i]) return false;
        }
        return true;
    }

    internal static bool Verify(string s) => CheckPartA(s) && CheckPartB(s);
}
